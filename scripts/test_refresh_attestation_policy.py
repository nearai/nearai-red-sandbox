"""Tests for refresh-attestation-policy.py. Run: python3 -m pytest -q scripts/"""

import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "refresh-attestation-policy.py"
spec = importlib.util.spec_from_file_location("refresh", SCRIPT)
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)

COMPOSES = {
    "pinned": "services:\n  pinned: {}\n",
    "gw": "services:\n  gateway: {image: gw@sha256:01}\n",
    "model": "services:\n  model: {image: vllm@sha256:02}\n",
}
H = {k: hashlib.sha256(v.encode()).hexdigest() for k, v in COMPOSES.items()}
PINNED, NEW_GW, NEW_MODEL = H["pinned"], H["gw"], H["model"]
BY_HASH = {H[k]: COMPOSES[k] for k in H}


def info(app, compose):
    return {"app_name": app, "tcb_info": json.dumps({"app_compose": compose})}


def report(gw_app, model_app, gw_hash, m_hash):
    return json.dumps({
        "gateway_attestation": {"info": info(gw_app, BY_HASH.get(gw_hash, "x"))},
        "model_attestations": [{"info": info(model_app, BY_HASH.get(m_hash, "x"))}],
    })


PROD = "https://cloud-api.near.ai/v1"
STG = "https://cloud-stg-api.near.ai/v1"


def evidence(model, gw_hash, gw_how, m_hash, m_how, gw_app="dstack-0.5.12", m_app="dstack-nvidia-0.5.12", base_url=PROD):
    return {
        "model": model,
        "base_url": base_url,
        "report": report(gw_app, m_app, gw_hash, m_hash),
        "entries": [
            {"role": "gateway", "compose_hash": gw_hash, "compose_acceptance": gw_how},
            {"role": "model", "index": 0, "compose_hash": m_hash, "compose_acceptance": m_how},
        ],
    }


def write(tmp_path, doc, policy):
    a = tmp_path / "attestation.json"
    a.write_text(json.dumps(doc))
    p = tmp_path / "attestation-policy.json"
    p.write_text(json.dumps(policy, indent=2) + "\n")
    return a, p


def policy_with(*hashes):
    return {"composeHashes": [{"sha256": h, "role": "model", "recorded": "2026-10-29", "source": "s"} for h in hashes]}


def test_proposes_only_verified_unpinned_composes(tmp_path):
    doc = {
        "status": "verified",
        "evidence": [evidence("q", PINNED, "pinned", NEW_MODEL, "mr-config-only")],
        "reattestations": [
            {"evidence": [evidence("q", NEW_GW, "key-continuity", NEW_MODEL, "key-continuity")]},
        ],
    }
    a, p = write(tmp_path, doc, policy_with(PINNED))
    found = refresh.candidates(json.loads(a.read_text()), json.loads(p.read_text()), "2026-11-19")
    assert [c["sha256"] for c in found] == [NEW_MODEL, NEW_GW]
    assert found[0]["recorded"] == "2026-11-19"
    assert "model_attestations[0] for q" in found[0]["source"]
    assert "dstack-nvidia-0.5.12" in found[0]["source"]
    assert "gateway_attestation" in found[1]["source"] and "dstack-0.5.12" in found[1]["source"]
    assert [c["role"] for c in found] == ["model", "gateway"]


def test_user_trusted_evidence_is_proposed(tmp_path):
    # A user trusted it at launch; no reviewer has: proposed as mr-config-only is.
    def found(how):
        doc = {"status": "verified", "evidence": [evidence("q", NEW_GW, how, NEW_MODEL, how)]}
        a, p = write(tmp_path, doc, policy_with(PINNED))
        return refresh.candidates(json.loads(a.read_text()), json.loads(p.read_text()), "2026-11-25")

    user_trusted = found("user-trusted")
    assert [c["sha256"] for c in user_trusted] == [NEW_GW, NEW_MODEL]
    assert [c["role"] for c in user_trusted] == ["gateway", "model"]
    # The same proposals, each source naming how rts accepted it.
    mr_config_only = found("mr-config-only")
    for u, m in zip(user_trusted, mr_config_only):
        assert u["source"].endswith("(user-trusted, verified by rts)")
        assert u["source"].replace("user-trusted", "mr-config-only") == m["source"]
    strip = lambda cs: [{k: v for k, v in c.items() if k != "source"} for c in cs]
    assert strip(user_trusted) == strip(mr_config_only)


def test_endorsed_composes_are_accepted_not_proposed(tmp_path):
    # The signed feed admitted them: CI's rules reviewed them already.
    doc = {"status": "verified", "evidence": [evidence("q", NEW_GW, "endorsed", NEW_MODEL, "endorsed")]}
    a, p = write(tmp_path, doc, policy_with(PINNED))
    assert refresh.candidates(json.loads(a.read_text()), json.loads(p.read_text()), "2026-11-24") == []
    r = subprocess.run([sys.executable, str(SCRIPT), str(a), "--policy", str(p), "--write"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "already pinned or endorsed" in r.stdout
    assert [e["sha256"] for e in json.loads(p.read_text())["composeHashes"]] == [PINNED]


def test_a_compose_endorsed_in_any_batch_is_not_proposed(tmp_path):
    # Endorsed at launch, then key continuity after the feed lapsed: still accepted.
    doc = {
        "status": "verified",
        "evidence": [evidence("q", PINNED, "pinned", NEW_MODEL, "key-continuity")],
        "reattestations": [{"evidence": [evidence("q", PINNED, "pinned", NEW_MODEL, "endorsed")]}],
    }
    a, p = write(tmp_path, doc, policy_with(PINNED))
    assert refresh.candidates(json.loads(a.read_text()), json.loads(p.read_text()), "2026-11-24") == []


def test_refuses_a_record_that_did_not_verify(tmp_path):
    doc = {"status": "refused", "evidence": [evidence("q", PINNED, "pinned", NEW_MODEL, "mr-config-only")]}
    a, p = write(tmp_path, doc, policy_with(PINNED))
    r = subprocess.run([sys.executable, str(SCRIPT), str(a), "--policy", str(p)], capture_output=True, text=True)
    assert r.returncode != 0
    assert "verified" in r.stderr


def test_write_appends_new_entries_once(tmp_path):
    doc = {"status": "verified", "evidence": [evidence("q", PINNED, "pinned", NEW_MODEL, "mr-config-only")]}
    a, p = write(tmp_path, doc, policy_with(PINNED))
    for _ in range(2):
        r = subprocess.run([sys.executable, str(SCRIPT), str(a), "--policy", str(p), "--write"], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    entries = json.loads(p.read_text())["composeHashes"]
    assert [e["sha256"] for e in entries] == [PINNED, NEW_MODEL]
    # rts refuses an entry without a role, so --write always writes one.
    assert [e["role"] for e in entries] == ["model", "model"]
    assert list(entries[1]) == ["sha256", "role", "recorded", "source"]


def test_write_records_the_gateway_role(tmp_path):
    doc = {"status": "verified", "evidence": [evidence("q", NEW_GW, "mr-config-only", PINNED, "pinned")]}
    a, p = write(tmp_path, doc, policy_with(PINNED))
    r = subprocess.run([sys.executable, str(SCRIPT), str(a), "--policy", str(p), "--write"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    entries = json.loads(p.read_text())["composeHashes"]
    assert [(e["sha256"], e["role"]) for e in entries] == [(PINNED, "model"), (NEW_GW, "gateway")]


def test_dry_run_changes_nothing(tmp_path):
    doc = {"status": "verified", "evidence": [evidence("q", PINNED, "pinned", NEW_MODEL, "mr-config-only")]}
    a, p = write(tmp_path, doc, policy_with(PINNED))
    before = p.read_text()
    r = subprocess.run([sys.executable, str(SCRIPT), str(a), "--policy", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert NEW_MODEL in r.stdout
    assert p.read_text() == before
    # The compose itself is shown for review, not just its hash.
    assert "vllm@sha256:02" in r.stdout


def test_rejects_a_compose_hash_that_does_not_match_the_recorded_compose(tmp_path):
    ev = evidence("q", PINNED, "pinned", NEW_MODEL, "mr-config-only")
    ev["entries"][1]["compose_hash"] = "dd" * 32
    a, p = write(tmp_path, {"status": "verified", "evidence": [ev]}, policy_with(PINNED))
    r = subprocess.run([sys.executable, str(SCRIPT), str(a), "--policy", str(p), "--write"], capture_output=True, text=True)
    assert r.returncode != 0
    assert "does not match" in r.stderr
    assert "dd" * 32 not in p.read_text()


def test_a_malformed_report_is_a_clean_error(tmp_path):
    ev = evidence("q", PINNED, "pinned", NEW_MODEL, "mr-config-only")
    ev["report"] = json.dumps({"model_attestations": ["not an object"]})
    a, p = write(tmp_path, {"status": "verified", "evidence": [ev]}, policy_with(PINNED))
    r = subprocess.run([sys.executable, str(SCRIPT), str(a), "--policy", str(p)], capture_output=True, text=True)
    assert r.returncode != 0
    assert "Traceback" not in r.stderr


def test_accepts_object_valued_tcb_info_like_rts(tmp_path):
    ev = evidence("q", PINNED, "pinned", NEW_MODEL, "mr-config-only")
    r = json.loads(ev["report"])
    r["model_attestations"][0]["info"]["tcb_info"] = {"app_compose": COMPOSES["model"]}
    ev["report"] = json.dumps(r)
    a, p = write(tmp_path, {"status": "verified", "evidence": [ev]}, policy_with(PINNED))
    found = refresh.candidates(json.loads(a.read_text()), json.loads(p.read_text()), "2026-11-19")
    assert [c["sha256"] for c in found] == [NEW_MODEL]


def test_rejects_a_malformed_hash(tmp_path):
    doc = {"status": "verified", "evidence": [evidence("q", PINNED, "pinned", "zz", "mr-config-only")]}
    a, p = write(tmp_path, doc, policy_with(PINNED))
    r = subprocess.run([sys.executable, str(SCRIPT), str(a), "--policy", str(p)], capture_output=True, text=True)
    assert r.returncode != 0


def test_each_environment_has_its_own_policy_file():
    assert refresh.policy_path("production").name == "attestation-policy.json"
    assert refresh.policy_path("staging").name == "attestation-policy-staging.json"
    assert refresh.policy_path("production").parent == refresh.policy_path("staging").parent


def test_staging_evidence_is_proposed_for_the_staging_policy(tmp_path):
    doc = {"status": "verified", "evidence": [evidence("q", NEW_GW, "mr-config-only", NEW_MODEL, "mr-config-only", base_url=STG)]}
    a, p = write(tmp_path, doc, policy_with())
    found = refresh.candidates(json.loads(a.read_text()), json.loads(p.read_text()), "2026-11-20", "staging")
    assert [c["sha256"] for c in found] == [NEW_GW, NEW_MODEL]
    assert all(c["source"].startswith("NEAR AI staging cloud-stg-api.near.ai: ") for c in found)


def test_refuses_evidence_from_the_other_environment(tmp_path):
    for env, base in (("staging", PROD), ("production", STG), ("production", None)):
        ev = evidence("q", NEW_GW, "mr-config-only", NEW_MODEL, "mr-config-only", base_url=base)
        if base is None:
            del ev["base_url"]
        a, p = write(tmp_path, {"status": "verified", "evidence": [ev]}, policy_with())
        before = p.read_text()
        r = subprocess.run(
            [sys.executable, str(SCRIPT), str(a), "--environment", env, "--policy", str(p), "--write"],
            capture_output=True, text=True,
        )
        assert r.returncode != 0, (env, base)
        assert "base_url" in r.stderr
        assert p.read_text() == before
