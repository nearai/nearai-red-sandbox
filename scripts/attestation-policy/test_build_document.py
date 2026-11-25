"""Tests for build_document.py and sign-policy.sh. Run: python3 -m pytest -q scripts/"""

import base64
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCRIPT = HERE / "build_document.py"
SIGN = HERE / "sign-policy.sh"
FIXTURES = REPO / "tests" / "fixtures" / "compose-history"

spec = importlib.util.spec_from_file_location("build_document", SCRIPT)
bd = importlib.util.module_from_spec(spec)
sys.modules["build_document"] = bd
spec.loader.exec_module(bd)

NOW = "2026-11-25T00:00:00Z"
NOW_UNIX = 1_795_564_800  # 2026-11-25T00:00:00Z
HOUR = 3600
PROD = "https://cloud-api.near.ai/v1"
A64 = "a" * 64
B64 = "b" * 64


def raw(prefix):
    """The raw app_compose of the compose-history fixture whose sha256 starts with prefix."""
    (path,) = FIXTURES.glob(f"{prefix}*.json")
    return json.loads(path.read_text())


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def rfc3339(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def baselines(tmp_path, revoked=(), **sets):
    """A baselines tree: sets maps 'production_model' to a list of raw composes.
    revoked is the reviewed production revoked.json (staging's is empty)."""
    root = tmp_path / "baselines"
    for key, raws in sets.items():
        env, role = key.split("_")
        d = root / env / role
        d.mkdir(parents=True)
        for r in raws:
            (d / f"{sha(r)}.json").write_bytes(r.encode())
    for env, hashes in (("production", list(revoked)), ("staging", [])):
        (root / env).mkdir(parents=True, exist_ok=True)
        (root / env / "revoked.json").write_text(json.dumps(hashes) + "\n")
    return root


def current_doc(tmp_path, issued, entries=(), revoked=(), environment="production", name="current.json"):
    doc = {
        "schema": 1,
        "environment": environment,
        "version": issued,
        "issued": rfc3339(issued),
        "expires": rfc3339(issued + 72 * HOUR),
        "entries": list(entries),
        "revoked": list(revoked),
    }
    p = tmp_path / name
    p.write_text(json.dumps(doc, indent=2) + "\n")
    return p


def entry(role, match, sha256):
    return {"role": role, "match": match, "sha256": sha256, "app_name": "dstack-nvidia-0.5.11",
            "first_seen": "2026-11-20T09:14:40Z", "endorsed_by": f"rules:{role}-v1"}


def candidates(tmp_path, *raws):
    d = tmp_path / "candidates"
    d.mkdir(exist_ok=True)
    for r in raws:
        (d / f"{sha(r)}.json").write_bytes(r.encode())
    return d


def proposed(tmp_path, entries, environment="production"):
    p = tmp_path / "proposed.json"
    p.write_text(json.dumps({"schema": 1, "environment": environment, "entries": entries, "revoked": []}))
    return p


def run(*args, cwd=None, env=None):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, cwd=cwd, env=env)


def reproduce(tmp_path, base, cands, prop, current=None, now=NOW, extra=()):
    out = tmp_path / "out"
    args = ["reproduce", "--environment", "production", "--candidates", cands, "--proposed", prop,
            "--baselines", base, "--now", now, "--out", out, *extra]
    if current is not None:
        args += ["--current", current]
    return run(*args), out


E390, EDAB, AE66 = raw("e3902667a262"), raw("edabf8039210"), raw("ae66f844658a")
GW = raw("1787a4af87ea")
LABEL_SHA = bd.rules.instance_label_sha256(E390)


# --- the plan's tests ------------------------------------------------------

def test_reproduce_refuses_an_entry_it_cannot_reproduce(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    cands = candidates(tmp_path)  # empty: no candidate file for the proposed hash
    prop = proposed(tmp_path, [entry("model", "exact", sha(EDAB))])
    r, out = reproduce(tmp_path, base, cands, prop)
    assert r.returncode == 1, r.stdout + r.stderr
    assert sha(EDAB) in r.stderr
    assert not (out / "document.json").exists()


def test_reproduce_refuses_an_entry_that_fails_the_rules(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    cands = candidates(tmp_path, AE66)  # C1, C4, M1 against e390
    prop = proposed(tmp_path, [entry("model", "exact", sha(AE66))])
    r, out = reproduce(tmp_path, base, cands, prop)
    assert r.returncode == 1, r.stdout + r.stderr
    assert sha(AE66) in r.stderr
    assert not (out / "document.json").exists()


def test_document_keeps_prior_entries_and_adds_passing_ones(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    prior = entry("gateway", "exact", A64)
    cur = current_doc(tmp_path, NOW_UNIX - 2 * HOUR, [prior])
    cands = candidates(tmp_path, EDAB)  # passes against e390 by instance-label-v1
    new = entry("model", "instance-label-v1", LABEL_SHA)
    prop = proposed(tmp_path, [prior, new])
    r, out = reproduce(tmp_path, base, cands, prop, current=cur)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "reproduced 1 entries" in r.stdout
    doc = json.loads((out / "document.json").read_text())
    keys = [(e["role"], e["match"], e["sha256"]) for e in doc["entries"]]
    assert keys == [("gateway", "exact", A64), ("model", "instance-label-v1", LABEL_SHA)]
    assert doc["entries"][0] == prior
    added = doc["entries"][1]
    assert added["app_name"] == json.loads(EDAB)["name"]
    assert added["endorsed_by"] == "rules:model-v1"
    assert added["first_seen"] == NOW
    assert doc["revoked"] == []


def test_document_is_republished_when_older_than_24h_even_with_no_new_entries(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    prior = entry("model", "exact", A64)
    cands = candidates(tmp_path)

    fresh = current_doc(tmp_path, NOW_UNIX - 23 * HOUR, [prior])
    r, out = reproduce(tmp_path, base, cands, proposed(tmp_path, [prior]), current=fresh)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (out / "document.json").exists()
    assert "nothing to publish" in r.stdout

    stale = current_doc(tmp_path, NOW_UNIX - 25 * HOUR, [prior])
    r, out = reproduce(tmp_path, base, cands, proposed(tmp_path, [prior]), current=stale)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((out / "document.json").read_text())
    assert doc["entries"] == [prior]
    assert doc["version"] == NOW_UNIX


def test_expires_is_issued_plus_72h_and_version_is_issued_unix(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    r, out = reproduce(tmp_path, base, candidates(tmp_path), proposed(tmp_path, []))
    assert r.returncode == 0, r.stdout + r.stderr
    text = (out / "document.json").read_text()
    doc = json.loads(text)
    assert list(doc) == ["schema", "environment", "version", "issued", "expires", "entries", "revoked"]
    assert doc["schema"] == 1 and doc["environment"] == "production"
    assert doc["issued"] == NOW
    assert doc["version"] == NOW_UNIX
    assert doc["expires"] == rfc3339(NOW_UNIX + 72 * HOUR)
    assert text.endswith("}\n")


def test_candidate_sha_must_equal_file_name(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    cands = tmp_path / "candidates"
    cands.mkdir()
    (cands / f"{sha(E390)}.json").write_bytes(EDAB.encode())
    r, out = reproduce(tmp_path, base, cands, proposed(tmp_path, []))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "file name" in r.stderr
    assert not (out / "document.json").exists()


def _openssl():
    exe = shutil.which("openssl")
    if not exe:
        return None
    v = subprocess.run([exe, "version"], capture_output=True, text=True).stdout
    return exe if re.match(r"OpenSSL ([3-9]|[1-9][0-9]+)\.", v) else None


def _keypair(tmp_path, openssl):
    """A fresh Ed25519 key: (base64 of the PEM, public key hex)."""
    pem = subprocess.run([openssl, "genpkey", "-algorithm", "ed25519"], capture_output=True, check=True).stdout
    der = subprocess.run([openssl, "pkey", "-pubout", "-outform", "DER"], input=pem,
                         capture_output=True, check=True).stdout
    return base64.b64encode(pem).decode(), der[-32:].hex()


def _sign(tmp_path, openssl, doc, key_b64, pub_hex, environment="production"):
    out = tmp_path / "signed"
    out.mkdir(exist_ok=True)
    env = dict(os.environ, RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64=key_b64)
    return subprocess.run(["bash", str(SIGN), "--environment", environment, "--in", str(doc),
                           "--public-key-hex", pub_hex, "--dir", str(out), "--openssl", openssl],
                          capture_output=True, text=True, env=env), out


def _rts_verify(doc, sig, pub_hex, environment="production"):
    env = dict(os.environ, RTS_FEED_VERIFY_DOC=str(doc), RTS_FEED_VERIFY_SIG=str(sig),
               RTS_FEED_VERIFY_KEY=pub_hex, RTS_FEED_VERIFY_ENV=environment)
    return subprocess.run(
        ["cargo", "test", "--locked", "--lib", "attest::feed::tests::verify_document_from_env",
         "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"],
        capture_output=True, text=True, cwd=REPO, env=env)


def test_round_trip_through_rts_verifier(tmp_path):
    openssl = _openssl()
    if openssl is None:
        pytest.skip("OpenSSL 3 or later is not on PATH")
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not on PATH")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = baselines(tmp_path, production_model=[E390])
    r, out = reproduce(tmp_path, base, candidates(tmp_path, EDAB),
                       proposed(tmp_path, [entry("model", "instance-label-v1", LABEL_SHA)]), now=now)
    assert r.returncode == 0, r.stdout + r.stderr
    key_b64, pub_hex = _keypair(tmp_path, openssl)
    s, signed = _sign(tmp_path, openssl, out / "document.json", key_b64, pub_hex)
    assert s.returncode == 0, s.stdout + s.stderr
    assert (signed / "production.json").read_bytes() == (out / "document.json").read_bytes()

    ok = _rts_verify(signed / "production.json", signed / "production.json.sig", pub_hex)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "1 passed" in ok.stdout, ok.stdout
    assert "verified version" in ok.stdout and "1 entries" in ok.stdout, ok.stdout

    # One changed byte in the document: rts refuses it.
    tampered = tmp_path / "tampered.json"
    tampered.write_bytes((signed / "production.json").read_bytes().replace(b'"production"', b'"production" '))
    bad = _rts_verify(tampered, signed / "production.json.sig", pub_hex)
    assert bad.returncode != 0
    assert "signature does not verify" in bad.stdout + bad.stderr


# --- sign-policy.sh --------------------------------------------------------

def test_sign_policy_refuses_a_key_that_does_not_match_the_public_key(tmp_path):
    openssl = _openssl()
    if openssl is None:
        pytest.skip("OpenSSL 3 or later is not on PATH")
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []))
    assert r.returncode == 0, r.stdout + r.stderr
    key_b64, _ = _keypair(tmp_path, openssl)
    _, other_pub = _keypair(tmp_path, openssl)
    s, signed = _sign(tmp_path, openssl, out / "document.json", key_b64, other_pub)
    assert s.returncode == 1
    assert "not the matching private key" in s.stderr
    assert not (signed / "production.json").exists()
    assert not (signed / "production.json.sig").exists()


def test_sign_policy_refuses_a_document_for_another_environment(tmp_path):
    openssl = _openssl()
    if openssl is None:
        pytest.skip("OpenSSL 3 or later is not on PATH")
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []))
    assert r.returncode == 0, r.stdout + r.stderr
    key_b64, pub = _keypair(tmp_path, openssl)
    s, signed = _sign(tmp_path, openssl, out / "document.json", key_b64, pub, environment="staging")
    assert s.returncode == 1
    assert "environment" in s.stderr
    assert not (signed / "staging.json").exists()


# --- propose ---------------------------------------------------------------

def attestation(composes, base_url=PROD, how="mr-config-only"):
    """An rts attestation.json with one evidence batch: [(role, raw), ...]."""
    gw = next((c for role, c in composes if role == "gateway"), "x")
    models = [c for role, c in composes if role == "model"] or ["x"]
    report = json.dumps({
        "gateway_attestation": {"info": {"app_name": "gw", "tcb_info": json.dumps({"app_compose": gw})}},
        "model_attestations": [{"info": {"app_name": "m", "tcb_info": json.dumps({"app_compose": m})}}
                               for m in models],
    })
    entries, i = [], 0
    for role, c in composes:
        e = {"role": role, "compose_hash": sha(c), "compose_acceptance": how}
        if role == "model":
            e["index"] = i
            i += 1
        entries.append(e)
    return {"status": "verified",
            "evidence": [{"model": "m", "base_url": base_url, "report": report, "entries": entries}]}


def propose(tmp_path, base, evidence_docs, current=None, extra=()):
    ev = tmp_path / "evidence"
    for n, doc in enumerate(evidence_docs):
        d = ev / f"run-{n}" / "live-production"
        d.mkdir(parents=True)
        (d / "attestation.json").write_text(json.dumps(doc))
    out = tmp_path / "proposal"
    args = ["propose", "--environment", "production", "--evidence", ev, "--baselines", base,
            "--now", NOW, "--out", out, *extra]
    if current is not None:
        args += ["--current", current]
    return run(*args), out


def test_propose_writes_candidates_proposal_and_holds(tmp_path):
    base = baselines(tmp_path, production_model=[E390], production_gateway=[GW])
    r, out = propose(tmp_path, base, [attestation([("model", EDAB)]), attestation([("model", AE66)])])
    assert r.returncode == 0, r.stdout + r.stderr
    names = sorted(p.name for p in (out / "candidates").iterdir())
    assert names == sorted([f"{sha(EDAB)}.json", f"{sha(AE66)}.json"])
    assert (out / "candidates" / f"{sha(EDAB)}.json").read_bytes() == EDAB.encode()
    doc = json.loads((out / "proposed.json").read_text())
    assert [(e["role"], e["match"], e["sha256"]) for e in doc["entries"]] == [
        ("model", "instance-label-v1", LABEL_SHA)]
    holds = json.loads((out / "holds.json").read_text())
    assert [(h["sha256"], h["role"], h["failures"], h["closest"]) for h in holds] == [
        (sha(AE66), "model", ["C1", "C4", "M1"], sha(E390))]
    assert holds[0]["diff"]

    # What propose proposed, reproduce reproduces.
    r2 = run("reproduce", "--environment", "production", "--candidates", out / "candidates",
             "--proposed", out / "proposed.json", "--baselines", base, "--now", NOW, "--out", tmp_path / "signed")
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert "reproduced 1 entries" in r2.stdout


def test_propose_skips_composes_already_endorsed_or_revoked(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    cur = current_doc(tmp_path, NOW_UNIX - HOUR, [entry("model", "instance-label-v1", LABEL_SHA)],
                      revoked=[sha(AE66)])
    r, out = propose(tmp_path, base, [attestation([("model", EDAB), ("model", AE66)])], current=cur)
    assert r.returncode == 0, r.stdout + r.stderr
    assert list((out / "candidates").iterdir()) == []
    assert json.loads((out / "holds.json").read_text()) == []


def test_propose_refuses_evidence_from_the_other_environment(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    r, _ = propose(tmp_path, base, [attestation([("model", EDAB)], base_url="https://cloud-stg-api.near.ai/v1")])
    assert r.returncode == 1
    assert "base_url" in r.stderr


# --- provenance (G2/M2), revocation and document invariants ----------------

def _gateway_with(repo, new_digest):
    """GW with the digest of one image repository replaced."""
    (ref,) = {r for r in bd.rules.image_refs(json.loads(GW)["docker_compose_file"]) if r.repo == repo}
    return GW.replace(ref.digest, f"sha256:{new_digest}")


def _fake_cosign(tmp_path, exit_code):
    log = tmp_path / "cosign.log"
    exe = tmp_path / "cosign"
    exe.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\nexit {exit_code}\n")
    exe.chmod(0o755)
    return exe, log


def test_a_changed_nearaidev_digest_is_endorsed_only_when_cosign_verifies(tmp_path):
    cand = _gateway_with("nearaidev/cloud-api", "c" * 64)
    base = baselines(tmp_path, production_gateway=[GW])
    cands = candidates(tmp_path, cand)
    want = entry("gateway", "exact", sha(cand))

    ok, log = _fake_cosign(tmp_path, 0)
    r, out = reproduce(tmp_path, base, cands, proposed(tmp_path, [want]), extra=["--cosign", ok])
    assert r.returncode == 0, r.stdout + r.stderr
    assert [e["sha256"] for e in json.loads((out / "document.json").read_text())["entries"]] == [sha(cand)]
    (line,) = log.read_text().splitlines()
    assert line == ("verify --certificate-identity-regexp ^https://github\\.com/nearai/[^/]+/\\.github/workflows/ "
                    "--certificate-oidc-issuer https://token.actions.githubusercontent.com "
                    f"nearaidev/cloud-api@sha256:{'c' * 64}")

    # cosign refuses in sign although evaluate proposed the entry: the entry
    # is dropped and held, and the rest of the document is still published.
    (tmp_path / "refusing").mkdir()
    bad, _ = _fake_cosign(tmp_path / "refusing", 1)
    r, out = reproduce(tmp_path, base, cands, proposed(tmp_path, [want]), extra=["--cosign", bad])
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "document.json").read_text())["entries"] == []
    (hold,) = json.loads((out / "holds.json").read_text())
    assert hold["sha256"] == sha(cand) and hold["failures"] == ["G2"]

    # No cosign at all: never endorsed.
    r, out = reproduce(tmp_path, base, cands, proposed(tmp_path, [want]))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "document.json").read_text())["entries"] == []


def test_a_digest_outside_an_image_line_must_not_change(tmp_path):
    obj = json.loads(GW)
    obj["docker_compose_file"] += "\n# pinned elsewhere: tool@sha256:" + "1" * 64
    base_raw = json.dumps(obj)
    obj["docker_compose_file"] = obj["docker_compose_file"].replace("1" * 64, "2" * 64)
    cand = json.dumps(obj)
    base = baselines(tmp_path, production_gateway=[base_raw])
    assert bd.rules.evaluate(cand, "gateway", [base_raw]).passed  # G1 blinds it
    ok, log = _fake_cosign(tmp_path, 0)
    r, out = reproduce(tmp_path, base, candidates(tmp_path, cand), proposed(tmp_path, []), extra=["--cosign", ok])
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "document.json").read_text())["entries"] == []
    (hold,) = json.loads((out / "holds.json").read_text())
    assert hold["failures"] == ["G2"]
    assert hold["diff"] == [f"digest changed outside an image: line: sha256:{'2' * 64}"]


F571 = (REPO / "opencode" / "attestation-baselines" / "production" / "gateway" /
        "f571e5dafe8f96baf116a271b4be9cba228b447dd6ebe502bbda81ede7bcc7ce.json").read_text()


def test_a_reviewed_digest_moved_onto_a_non_image_line_is_held(tmp_path):
    # Only DSTACK_CONTAINER_IMAGE_ID changes, to alpine's digest, which the
    # baseline already holds elsewhere. Digests compare by position, not as sets.
    vpc = "sha256:45f859504c7a66ea562e3230b7a3b482912bdd93f3930d1bb1c2f46e8d84f8f0"
    alpine = "sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412"
    line = f"- DSTACK_CONTAINER_IMAGE_ID=nearaidev/dstack-vpc@{vpc}"
    assert F571.count(line) == 1 and alpine in F571
    cand = F571.replace(line, f"- DSTACK_CONTAINER_IMAGE_ID=nearaidev/dstack-vpc@{alpine}")
    assert bd.rules.evaluate(cand, "gateway", [F571]).passed
    base = {sha(F571): F571}
    for cosign in (None, str(_fake_cosign(tmp_path, 0)[0])):
        o = bd.endorse(cand, "gateway", base, NOW, cosign, {})
        assert o.entry is None
        assert o.hold["failures"] == ["G2"]
        assert o.hold["diff"] == [f"digest changed outside an image: line: {alpine}"]


VPC = "nearaidev/dstack-vpc"
VPC_OLD = "sha256:45f859504c7a66ea562e3230b7a3b482912bdd93f3930d1bb1c2f46e8d84f8f0"
VPC_IMAGE = f"    image: {VPC}@{VPC_OLD}"
VPC_ENV = f"      - DSTACK_CONTAINER_IMAGE_ID={VPC}@{VPC_OLD}"


def _f571_with(image=None, env=None):
    """F571 with the dstack-vpc image line and/or env line digest replaced."""
    lines = json.loads(F571)["docker_compose_file"].split("\n")
    assert lines.count(VPC_IMAGE) == 1 and lines.count(VPC_ENV) == 1
    out = F571
    if image is not None:
        out = out.replace(f"image: {VPC}@{VPC_OLD}", f"image: {VPC}@{image}")
    if env is not None:
        out = out.replace(f"DSTACK_CONTAINER_IMAGE_ID={VPC}@{VPC_OLD}", f"DSTACK_CONTAINER_IMAGE_ID={VPC}@{env}")
    assert bd.rules.evaluate(out, "gateway", [F571]).passed
    return out


def test_a_real_dstack_vpc_bump_is_endorsed_only_when_cosign_verifies(tmp_path):
    new = "sha256:" + "5" * 64
    cand = _f571_with(image=new, env=new)
    base = {sha(F571): F571}
    ok, log = _fake_cosign(tmp_path, 0)
    o = bd.endorse(cand, "gateway", base, NOW, str(ok), {})
    assert o.hold is None, o.hold
    assert o.entry["sha256"] == sha(cand)
    (line,) = log.read_text().splitlines()
    assert line.endswith(f"{VPC}@{new}")

    o = bd.endorse(cand, "gateway", base, NOW, None, {})
    assert o.entry is None and o.hold["failures"] == ["G2"]
    assert o.hold["diff"] == [f"cosign was not run: {VPC}@{new}"]


def test_a_dstack_vpc_env_line_changed_without_its_image_line_is_held(tmp_path):
    new = "sha256:" + "5" * 64
    cand = _f571_with(env=new)
    ok, _ = _fake_cosign(tmp_path, 0)
    for cosign in (None, str(ok)):
        o = bd.endorse(cand, "gateway", {sha(F571): F571}, NOW, cosign, {})
        assert o.entry is None and o.hold["failures"] == ["G2"]
        assert o.hold["diff"] == [f"digest changed outside an image: line: {new}"]


def test_a_dstack_vpc_env_line_set_to_another_repos_verified_digest_is_held(tmp_path):
    # dstack-vpc-client is bumped (and verified) to new; the dstack-vpc env
    # line is set to that digest while the dstack-vpc image line keeps its own.
    new = "sha256:" + "5" * 64
    client = "nearaidev/dstack-vpc-client@sha256:dd570dee92901c6d9cf96909404bb5177294437e3642541225a85b06cefa3d9d"
    assert F571.count(client) == 1
    cand = _f571_with(env=new).replace(client, f"nearaidev/dstack-vpc-client@{new}")
    assert bd.rules.evaluate(cand, "gateway", [F571]).passed
    ok, log = _fake_cosign(tmp_path, 0)
    o = bd.endorse(cand, "gateway", {sha(F571): F571}, NOW, str(ok), {})
    assert o.entry is None and o.hold["failures"] == ["G2"]
    assert o.hold["diff"] == [f"digest changed outside an image: line: {new}"]


def test_a_non_image_line_needs_the_same_repo_on_an_image_line(tmp_path):
    # The env-line exception names the repository of an image: line. A
    # digest on a non-image line of a repository with no image line (or of
    # another repository than the bumped image) is held even when both bump.
    new = "sha256:" + "5" * 64
    other = F571.replace(f"DSTACK_CONTAINER_IMAGE_ID={VPC}@{VPC_OLD}", f"DSTACK_CONTAINER_IMAGE_ID=nearaidev/other@{VPC_OLD}")
    cand = other.replace(f"image: {VPC}@{VPC_OLD}", f"image: {VPC}@{new}").replace(
        f"nearaidev/other@{VPC_OLD}", f"nearaidev/other@{new}")
    assert bd.rules.evaluate(cand, "gateway", [other]).passed
    ok, _ = _fake_cosign(tmp_path, 0)
    o = bd.endorse(cand, "gateway", {sha(other): other}, NOW, str(ok), {})
    assert o.entry is None and o.hold["diff"] == [f"digest changed outside an image: line: {new}"]

    # Commented out, the line does not qualify either.
    commented = F571.replace(f"- DSTACK_CONTAINER_IMAGE_ID={VPC}", f"# - DSTACK_CONTAINER_IMAGE_ID={VPC}")
    cand = commented.replace(VPC_OLD, new)
    assert bd.rules.evaluate(cand, "gateway", [commented]).passed
    o = bd.endorse(cand, "gateway", {sha(commented): commented}, NOW, str(ok), {})
    assert o.entry is None and o.hold["diff"] == [f"digest changed outside an image: line: {new}"]


def _synthetic_gateway(*lines):
    return json.dumps({"name": "dstack-0.5.4", "docker_compose_file": "\n".join(lines), "runner": "docker-compose"})


_D_OLD, _D_OLD2 = "sha256:" + "a" * 64, "sha256:" + "b" * 64
_D_NEW, _D_BAD = "sha256:" + "1" * 64, "sha256:" + "2" * 64


def _vpc_image(d):
    return f"    image: {VPC}@{d}"


@pytest.mark.parametrize("base_lines, cand_lines, diff", [
    # Two digests on the line: the copy of the bumped image's digest must not
    # carry a second changed digest (here evil/x's, whose image line did not
    # change) past cosign.
    ([_vpc_image(_D_OLD), f"    image: evil/x@{_D_OLD2}", f"      - X={VPC}@{_D_OLD} Y=evil/x@{_D_OLD2}"],
     [_vpc_image(_D_NEW), f"    image: evil/x@{_D_OLD2}", f"      - X={VPC}@{_D_NEW} Y=evil/x@{_D_BAD}"],
     [_D_NEW, _D_BAD]),
    # The baseline's env line did not equal an image digest of its repository.
    ([_vpc_image(_D_OLD), f"      - X={VPC}@{_D_OLD2}"],
     [_vpc_image(_D_NEW), f"      - X={VPC}@{_D_NEW}"],
     [_D_NEW]),
    # The env line's reference continues past the digest.
    ([_vpc_image(_D_OLD), f"      - X={VPC}@{_D_OLD}x"],
     [_vpc_image(_D_NEW), f"      - X={VPC}@{_D_NEW}x"],
     [_D_NEW]),
    # The env line's repository is the tail of a longer, @-joined reference.
    ([_vpc_image(_D_OLD), f"      - X=foo@{VPC}@{_D_OLD}"],
     [_vpc_image(_D_NEW), f"      - X=foo@{VPC}@{_D_NEW}"],
     [_D_NEW]),
], ids=["two-digests", "baseline-env-not-an-image-digest", "env-suffix", "env-at-prefixed"])
def test_an_env_line_that_is_not_exactly_one_copied_image_digest_is_held(tmp_path, base_lines, cand_lines, diff):
    base, cand = _synthetic_gateway(*base_lines), _synthetic_gateway(*cand_lines)
    assert bd.rules.evaluate(cand, "gateway", [base]).passed  # held by G2, not G1
    ok, _ = _fake_cosign(tmp_path, 0)  # every reference verifies: not held by cosign
    o = bd.endorse(cand, "gateway", {sha(base): base}, NOW, str(ok), {})
    assert o.entry is None and o.hold["failures"] == ["G2"]
    assert o.hold["diff"] == [f"digest changed outside an image: line: {d}" for d in diff]


def test_a_copied_digest_needs_its_image_line_not_the_script_to_change(tmp_path):
    # A model baseline with a non-image line copying compose-manager's digest.
    # The script's re-pin also verifies nearaidev/compose-manager@<new>, but
    # only the image: line changing to <new> may carry the copy along.
    env = "      - CM_IMAGE_ID=" + CM + "@{}"
    obj = json.loads(E390)
    obj["docker_compose_file"] += "\n" + env.format(CM_OLD)
    base = json.dumps(obj)

    def cand(image):
        o = json.loads(base)
        o["pre_launch_script"] = o["pre_launch_script"].replace(CM_OLD, CM_NEW)
        lines = o["docker_compose_file"].split("\n")
        lines[-1] = env.format(CM_NEW)
        o["docker_compose_file"] = "\n".join(lines).replace(f"{CM}@{CM_OLD}", f"{CM}@{image}")
        return json.dumps(o)

    ok, _ = _fake_cosign(tmp_path, 0)
    held = cand(CM_OLD)
    assert json.loads(held)["docker_compose_file"].count(CM_OLD) == 1
    diff = _held(held, tmp_path, base)
    assert diff == [f"digest changed outside an image: line: {CM_NEW}"], diff
    moved = cand(CM_NEW)
    assert CM_OLD not in moved
    assert _endorse_model(moved, str(ok), base).entry is not None


def test_two_same_repo_image_digests_swapped_are_held_without_cosign(tmp_path):
    obj = json.loads(GW)
    ingress = "nearaidev/cvm-ingress@sha256:9e9aacb7866a06aa6959fe1c6064f4c3ed62609af35e955df1b95e7325578435"
    api = "nearaidev/cloud-api@sha256:d996bb08f36f0cc913ed7763f7c42bf4124e386a679e397a9acd8a3e69f3a704"
    other = "nearaidev/cloud-api@sha256:" + "c" * 64
    assert obj["docker_compose_file"].count(ingress) == 1 and obj["docker_compose_file"].count(api) == 1
    obj["docker_compose_file"] = obj["docker_compose_file"].replace(ingress, other)
    base_raw = json.dumps(obj)
    obj["docker_compose_file"] = (obj["docker_compose_file"].replace(api, "\0")
                                  .replace(other, api).replace("\0", other))
    cand = json.dumps(obj)
    assert cand != base_raw and bd.rules.evaluate(cand, "gateway", [base_raw]).passed
    base = {sha(base_raw): base_raw}

    o = bd.endorse(cand, "gateway", base, NOW, None, {})
    assert o.entry is None and o.hold["failures"] == ["G2"]
    assert sorted(o.hold["diff"]) == sorted([f"cosign was not run: {other}", f"cosign was not run: {api}"])

    # Both re-pointed image lines verified under the gateway identity: endorsed.
    ok, log = _fake_cosign(tmp_path, 0)
    o = bd.endorse(cand, "gateway", base, NOW, str(ok), {})
    assert o.hold is None and o.entry["sha256"] == sha(cand)
    assert sorted(l.rsplit(" ", 1)[1] for l in log.read_text().splitlines()) == sorted([api, other])


def test_a_changed_third_party_gateway_digest_is_held(tmp_path):
    cand = _gateway_with("alpine", "d" * 64)
    base = baselines(tmp_path, production_gateway=[GW])
    ok, log = _fake_cosign(tmp_path, 0)
    r, out = reproduce(tmp_path, base, candidates(tmp_path, cand), proposed(tmp_path, []), extra=["--cosign", ok])
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "document.json").read_text())["entries"] == []
    (hold,) = json.loads((out / "holds.json").read_text())
    assert hold["failures"] == ["G2"]
    assert any("alpine" in line for line in hold["diff"])


def _model_with(repo, new_digest):
    """E390 with the digest of one image repository replaced in docker_compose_file only."""
    obj = json.loads(E390)
    (digest,) = {r.digest for r in bd.rules.image_refs(obj["docker_compose_file"]) if r.repo == repo}
    obj["docker_compose_file"] = obj["docker_compose_file"].replace(digest, f"sha256:{new_digest}")
    return json.dumps(obj)


def _sorting(make, anchor, before):
    """make(digest) for the first digest whose compose sha256 sorts before (or
    after) the anchor baseline's, so the test does not depend on hash luck."""
    for i in range(4096):
        cand = make(hashlib.sha256(str(i).encode()).hexdigest())
        if (sha(cand) < sha(anchor)) == before:
            return cand
    raise AssertionError("no candidate on the wanted side of the anchor")


@pytest.mark.parametrize("before", [True, False], ids=["sorts-before", "sorts-after"])
@pytest.mark.parametrize("role", ["gateway", "model"])
def test_a_held_compose_is_endorsed_once_merged_into_the_baselines(tmp_path, role, before):
    # The approval path: a G2/M2 hold, then a reviewed PR adds the compose to
    # the baselines, then the next run signs it, whichever baseline sorts first.
    if role == "gateway":
        anchor, cand = GW, _sorting(lambda d: _gateway_with("alpine", d), GW, before)
    else:
        anchor, cand = E390, _sorting(lambda d: _model_with("certbot/dns-cloudflare", d), E390, before)
    ok, _ = _fake_cosign(tmp_path, 0)

    held = tmp_path / "held"
    held.mkdir()
    r, out = reproduce(held, baselines(held, **{f"production_{role}": [anchor]}),
                       candidates(held, cand), proposed(held, []), extra=["--cosign", ok])
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "document.json").read_text())["entries"] == []
    (hold,) = json.loads((out / "holds.json").read_text())
    assert hold["failures"] == ["G2" if role == "gateway" else "M2"]

    merged = tmp_path / "merged"
    merged.mkdir()
    r, out = reproduce(merged, baselines(merged, **{f"production_{role}": [anchor, cand]}),
                       candidates(merged, cand), proposed(merged, []), extra=["--cosign", ok])
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "holds.json").read_text()) == []
    doc = json.loads((out / "document.json").read_text())
    assert [(e["role"], e["match"], e["sha256"]) for e in doc["entries"]] == [(role, "exact", sha(cand))]


def test_model_compose_manager_digests_use_the_launcher_anchor(tmp_path):
    (ref,) = {r for r in bd.rules.image_refs(json.loads(E390)["docker_compose_file"])
              if r.repo == "nearaidev/compose-manager"}
    # Only in docker_compose_file; the pre_launch_script bump is tested below.
    obj = json.loads(EDAB)
    obj["docker_compose_file"] = obj["docker_compose_file"].replace(ref.digest, "sha256:" + "e" * 64)
    cand = json.dumps(obj)
    base = baselines(tmp_path, production_model=[E390])
    ok, log = _fake_cosign(tmp_path, 0)
    r, out = reproduce(tmp_path, base, candidates(tmp_path, cand), proposed(tmp_path, []), extra=["--cosign", ok])
    assert r.returncode == 0, r.stdout + r.stderr
    (line,) = log.read_text().splitlines()
    assert "^https://github\\.com/nearai/compose-manager/\\.github/workflows/ " in line
    assert line.endswith(f"nearaidev/compose-manager@sha256:{'e' * 64}")
    doc = json.loads((out / "document.json").read_text())
    assert [(e["match"], e["sha256"]) for e in doc["entries"]] == [
        ("instance-label-v1", bd.rules.instance_label_sha256(cand))]


# --- evaluate and sign get different cosign answers ---------------------------

def _cosign_allowing(tmp_path, name, *refs):
    """A fake cosign that verifies only the given image references."""
    d = tmp_path / name
    d.mkdir()
    exe = d / "cosign"
    cases = "".join(f"  *' {r}') exit 0 ;;\n" for r in refs)
    exe.write_text(f'#!/bin/sh\ncase " $*" in\n{cases}esac\nexit 1\n')
    exe.chmod(0o755)
    return str(exe)


def _model_digest(obj, repo):
    (digest,) = {r.digest for r in bd.rules.image_refs(obj["docker_compose_file"]) if r.repo == repo}
    return digest


def _two_way_model():
    """A model candidate that passes exact against one baseline and
    instance-label-v1 against another, with a different changed digest each.

    The candidate is EDAB with a new compose-manager-launcher digest. Baseline
    X is EDAB itself (exact, and instance-label-v1: the launcher changed).
    Baseline Y is E390 (another INSTANCE_LABEL) carrying the candidate's
    launcher digest and a different collector digest (instance-label-v1 only:
    the collector changed)."""
    launcher, otelcol = "nearaidev/compose-manager-launcher", "nearaidev/compose-manager-otelcol"
    new_launcher, other_otelcol = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    obj = json.loads(EDAB)
    obj["docker_compose_file"] = obj["docker_compose_file"].replace(_model_digest(obj, launcher), new_launcher)
    cand = json.dumps(obj)
    y = json.loads(E390)
    f = y["docker_compose_file"]
    f = f.replace(_model_digest(y, launcher), new_launcher).replace(_model_digest(y, otelcol), other_otelcol)
    y["docker_compose_file"] = f
    base_y = json.dumps(y)
    refs = {"launcher": f"{launcher}@{new_launcher}",
            "otelcol": f"{otelcol}@{_model_digest(obj, otelcol)}"}
    return cand, EDAB, base_y, refs


def _evaluate_side(cand, bases, cosign):
    """What propose would propose for cand: endorse with evaluate's cosign."""
    o = bd.endorse(cand, "model", {sha(b): b for b in sorted(bases, key=sha)}, NOW, cosign, {})
    assert o.entry is not None
    return o.entry


@pytest.mark.parametrize("case", ["cosign-down-in-sign", "evaluate-later-baseline-sign-holds",
                                  "evaluate-first-baseline-sign-later"])
def test_a_different_cosign_answer_in_sign_drops_the_entry_and_still_publishes(tmp_path, case):
    cand, x, y, refs = _two_way_model()
    assert bd.rules.evaluate(cand, "model", [x, y]).passed
    all_ok = _cosign_allowing(tmp_path, "all", refs["launcher"], refs["otelcol"])
    only_otelcol = _cosign_allowing(tmp_path, "otelcol", refs["otelcol"])
    none_ok = _cosign_allowing(tmp_path, "none")
    evaluate_cosign, sign_cosign, want_match, sign_match = {
        "cosign-down-in-sign": (all_ok, none_ok, "exact", None),
        "evaluate-later-baseline-sign-holds": (only_otelcol, none_ok, "instance-label-v1", None),
        "evaluate-first-baseline-sign-later": (all_ok, only_otelcol, "exact", "instance-label-v1"),
    }[case]
    e = _evaluate_side(cand, [x, y], evaluate_cosign)
    assert e["match"] == want_match

    # A revocation sign must publish, which a refusal would hold back.
    keep = entry("gateway", "exact", B64)
    cur = current_doc(tmp_path, NOW_UNIX - HOUR, [keep])
    base = baselines(tmp_path, revoked=[A64], production_model=[x, y])
    r, out = reproduce(tmp_path, base, candidates(tmp_path, cand), proposed(tmp_path, [keep, e]),
                       current=cur, extra=["--cosign", sign_cosign])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "::warning::" in r.stdout and e["sha256"] in r.stdout
    doc = json.loads((out / "document.json").read_text())
    assert doc["revoked"] == [A64]
    got = [(x_["role"], x_["match"], x_["sha256"]) for x_ in doc["entries"]]
    assert (e["role"], e["match"], e["sha256"]) not in got
    if sign_match is None:
        assert got == [("gateway", "exact", B64)]
        (hold,) = json.loads((out / "holds.json").read_text())
        assert hold["failures"] == ["M2"]
    else:
        assert got == [("gateway", "exact", B64),
                       ("model", sign_match, bd.rules.instance_label_sha256(cand))]


def test_a_proposed_key_matching_no_passing_baseline_still_refuses(tmp_path):
    # EDAB passes E390 only by instance-label-v1: an exact entry for it (or one
    # under the other role) is not a cosign disagreement but a divergence.
    base = baselines(tmp_path, production_model=[E390])
    for bad in (entry("model", "exact", sha(EDAB)), entry("gateway", "instance-label-v1", LABEL_SHA)):
        r, out = reproduce(tmp_path, base, candidates(tmp_path, EDAB), proposed(tmp_path, [bad]))
        assert r.returncode == 1, r.stdout + r.stderr
        assert "not reproduced" in r.stderr and bad["sha256"] in r.stderr
        assert not (out / "document.json").exists()


def test_evaluate_installs_the_same_cosign_as_sign():
    wf = (REPO / ".github" / "workflows" / "attestation-policy.yml").read_text()
    steps = re.findall(r"- name: Install cosign\n((?:        .*\n)+)", wf)
    assert len(steps) == 2, steps
    assert steps[0] == steps[1]
    assert "uses: sigstore/cosign-installer@" in steps[0] and "cosign-release: v" in steps[0]


# --- compose-manager bumps in a model's pre_launch_script ---------------------

CM = "nearaidev/compose-manager"
CM_OLD = "sha256:ae4332fdb0bfccf6410bc153a58d0b72a596a989cbb98fd5b6461fe32e079814"
CM_NEW = "sha256:" + "e" * 64
MODEL_ID = "^https://github\\.com/nearai/compose-manager/\\.github/workflows/"


def _bump(script=None, compose=CM_NEW, base=E390):
    """base with the compose-manager digest set to compose in its image line,
    and pre_launch_script replaced by script(old_script) when given."""
    obj = json.loads(base)
    assert obj["docker_compose_file"].count(CM_OLD) == 1
    obj["docker_compose_file"] = obj["docker_compose_file"].replace(CM_OLD, compose)
    if script is not None:
        obj["pre_launch_script"] = script(obj["pre_launch_script"])
    return json.dumps(obj)


def _script_lines(script):
    """The printf and echo lines of the re-pin, which name the digest."""
    lines = [l for l in script.split("\n") if CM_OLD in l]
    assert len(lines) == 2 and lines[0].lstrip().startswith("printf") and lines[1].lstrip().startswith("echo")
    return lines


def _endorse_model(cand, cosign, base=E390):
    return bd.endorse(cand, "model", {sha(base): base}, NOW, cosign, {})


@pytest.mark.parametrize("base", ["E390", "EDAB"])
def test_a_real_compose_manager_bump_is_endorsed_only_when_cosign_verifies(tmp_path, base):
    # EDAB against E390 also exercises the instance-label-v1 path.
    start = {"E390": E390, "EDAB": EDAB}[base]
    cand = _bump(lambda s: s.replace(CM_OLD, CM_NEW), base=start)
    assert json.loads(cand)["pre_launch_script"].count(CM_NEW) == 2
    assert bd.rules.evaluate(cand, "model", [E390]).passed

    ok, log = _fake_cosign(tmp_path, 0)
    o = _endorse_model(cand, str(ok))
    assert o.hold is None, o.hold
    # The image line and both script lines name one ref: cosign runs once.
    (line,) = log.read_text().splitlines()
    assert line.endswith(f"{CM}@{CM_NEW}") and f"--certificate-identity-regexp {MODEL_ID} " in line

    (tmp_path / "refusing").mkdir()
    bad, _ = _fake_cosign(tmp_path / "refusing", 1)
    for cosign in (None, str(bad)):
        o = _endorse_model(cand, cosign)
        assert o.entry is None and o.hold["failures"] == ["M2"]


def test_a_script_only_compose_manager_bump_still_goes_through_cosign(tmp_path):
    # The image line is unchanged; only the script re-pins. Still verified.
    cand = _bump(lambda s: s.replace(CM_OLD, CM_NEW), compose=CM_OLD)
    ok, log = _fake_cosign(tmp_path, 0)
    assert _endorse_model(cand, str(ok)).entry is not None
    assert log.read_text().splitlines()[0].endswith(f"{CM}@{CM_NEW}")
    o = _endorse_model(cand, None)
    assert o.entry is None and o.hold["diff"] == [f"cosign was not run: {CM}@{CM_NEW}"]


def _held(cand, tmp_path, base=E390):
    """cand is held by M2 with a cosign that verifies everything."""
    ok, _ = _fake_cosign(tmp_path, 0)
    assert bd.rules.evaluate(cand, "model", [base]).passed
    o = _endorse_model(cand, str(ok), base)
    assert o.entry is None and o.hold["failures"] == ["M2"], o
    return o.hold["diff"]


@pytest.mark.parametrize("which", ["printf", "echo"])
def test_only_one_script_line_bumped_is_held(tmp_path, which):
    def one(s):
        printf, echo = _script_lines(s)
        target = printf if which == "printf" else echo
        return s.replace(target, target.replace(CM_OLD, CM_NEW))
    _held(_bump(one), tmp_path)


def test_two_different_new_digests_in_the_script_are_held(tmp_path):
    other = "sha256:" + "f" * 64
    def two(s):
        printf, echo = _script_lines(s)
        return s.replace(printf, printf.replace(CM_OLD, CM_NEW)).replace(echo, echo.replace(CM_OLD, other))
    _held(_bump(two), tmp_path)


@pytest.mark.parametrize("token", [
    "nearaidev/compose-manager-otelcol@{}",
    "evilnearaidev/compose-manager@{}",
    "evil_nearaidev/compose-manager@{}",
    "ghcr.io/nearaidev/compose-manager@{}",
    "nearaidev/compose-manager@{}0",
    "other/tool@{}",
])
def test_a_script_digest_that_is_not_exactly_compose_manager_is_held(tmp_path, token):
    # Baseline and candidate both carry an extra line naming the token. The
    # candidate is otherwise a complete, consistent re-pin to CM_NEW, and the
    # extra line moves to CM_NEW too: only the token's spelling holds it.
    def add(d):
        return lambda s: s + "\necho " + token.format(d) + "\n"
    base = _bump(add(CM_OLD), compose=CM_OLD)
    assert base != E390
    cand = _bump(lambda s: s.replace(CM_OLD, CM_NEW), base=base)
    assert cand.count(token.format(CM_NEW)) == 1
    diff = _held(cand, tmp_path, base)
    assert diff == [f"pre_launch_script digest changed outside {CM}@: {CM_NEW}"], diff
    # The same re-pin without the extra line is endorsed.
    ok, _ = _fake_cosign(tmp_path, 0)
    assert _endorse_model(_bump(lambda s: s.replace(CM_OLD, CM_NEW)), str(ok)).entry is not None


@pytest.mark.parametrize("change", ["extra line", "removed line"])
def test_an_extra_or_removed_script_line_is_held(tmp_path, change):
    def edit(s):
        printf, echo = _script_lines(s)
        s = s.replace(CM_OLD, CM_NEW)
        echo = echo.replace(CM_OLD, CM_NEW)
        if change == "extra line":
            return s.replace(echo, echo + "\n" + echo)
        return s.replace(echo + "\n", "")
    cand = _bump(edit)
    assert not bd.rules.evaluate(cand, "model", [E390]).passed
    ok, _ = _fake_cosign(tmp_path, 0)
    o = _endorse_model(cand, str(ok))
    assert o.entry is None and o.hold["failures"] == ["M1"]


def test_script_provenance_pairs_lines_by_itself():
    # M1 already holds these, but _provenance does not rely on it.
    base = "a\necho nearaidev/compose-manager@" + CM_OLD + "\n"
    for cand in ("a\nb\necho nearaidev/compose-manager@" + CM_NEW + "\n",
                 "b\necho nearaidev/compose-manager@" + CM_NEW + "\n",
                 "a\necho nearaidev/compose-manager@" + CM_NEW + " nearaidev/compose-manager@" + CM_NEW + "\n"):
        diff = bd._provenance("", "", "model", None, {}, cand, base)
        assert diff and not any("cosign was not run" in d for d in diff), (cand, diff)


def test_revoked_entries_are_dropped_and_revocations_carried(tmp_path):
    cur = current_doc(tmp_path, NOW_UNIX - 30 * HOUR,
                      [entry("model", "exact", A64), entry("gateway", "exact", B64)], revoked=[A64])
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path),
                       proposed(tmp_path, [entry("gateway", "exact", B64)]), current=cur)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((out / "document.json").read_text())
    assert [e["sha256"] for e in doc["entries"]] == [B64]
    assert doc["revoked"] == [A64]


def test_a_revoked_candidate_is_not_endorsed(tmp_path):
    base = baselines(tmp_path, production_model=[E390])
    cur = current_doc(tmp_path, NOW_UNIX - 30 * HOUR, revoked=[sha(EDAB)])
    r, out = reproduce(tmp_path, base, candidates(tmp_path, EDAB), proposed(tmp_path, []), current=cur)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "document.json").read_text())["entries"] == []


# --- reviewed revocations (revoked.json) and the log floor -------------------

@pytest.mark.parametrize("match,h", [("exact", A64), ("instance-label-v1", LABEL_SHA)])
def test_a_reviewed_revocation_drops_the_entry_and_forces_a_publish(tmp_path, match, h):
    # The current document is an hour old: without the revocation there is nothing to publish.
    keep = entry("gateway", "exact", B64)
    cur = current_doc(tmp_path, NOW_UNIX - HOUR, [entry("model", match, h), keep])
    r, out = reproduce(tmp_path, baselines(tmp_path, revoked=[h]), candidates(tmp_path),
                       proposed(tmp_path, [keep]), current=cur)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((out / "document.json").read_text())
    assert doc["entries"] == [keep]
    assert doc["revoked"] == [h]
    assert doc["version"] == NOW_UNIX


def test_revocations_are_the_union_of_the_document_and_revoked_json(tmp_path):
    cur = current_doc(tmp_path, NOW_UNIX - HOUR, revoked=[A64])
    r, out = reproduce(tmp_path, baselines(tmp_path, revoked=[B64]), candidates(tmp_path),
                       proposed(tmp_path, []), current=cur)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "document.json").read_text())["revoked"] == [A64, B64]


def test_an_already_carried_revocation_does_not_force_a_publish(tmp_path):
    cur = current_doc(tmp_path, NOW_UNIX - HOUR, revoked=[A64])
    r, out = reproduce(tmp_path, baselines(tmp_path, revoked=[A64]), candidates(tmp_path),
                       proposed(tmp_path, []), current=cur)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "nothing to publish" in r.stdout
    assert not (out / "document.json").exists()


@pytest.mark.parametrize("revoke", ["exact", "label"])
def test_a_candidate_revoked_in_revoked_json_is_neither_proposed_nor_endorsed(tmp_path, revoke):
    h = sha(EDAB) if revoke == "exact" else LABEL_SHA
    base = baselines(tmp_path, revoked=[h], production_model=[E390])
    r, out = propose(tmp_path, base, [attestation([("model", EDAB)])])
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((out / "proposed.json").read_text())["entries"] == []
    r, out = reproduce(tmp_path, base, candidates(tmp_path, EDAB), proposed(tmp_path, []))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((out / "document.json").read_text())
    assert doc["entries"] == [] and doc["revoked"] == [h]


def test_reproduce_does_not_refuse_a_proposed_entry_that_is_revoked(tmp_path):
    # evaluate read a rolled-back asset and proposed a revoked entry: sign drops
    # it rather than refusing, so the bad asset is replaced.
    revoked = entry("model", "exact", A64)
    r, out = reproduce(tmp_path, baselines(tmp_path, revoked=[A64]), candidates(tmp_path),
                       proposed(tmp_path, [revoked]))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((out / "document.json").read_text())
    assert doc["entries"] == [] and doc["revoked"] == [A64]


@pytest.mark.parametrize("content", [None, "{}", f'["{A64}", "{A64}"]', f'["{A64.upper()}"]', '["ab"]'])
def test_a_missing_or_malformed_revoked_json_refuses(tmp_path, content):
    base = baselines(tmp_path)
    f = base / "production" / "revoked.json"
    if content is None:
        f.unlink()
    else:
        f.write_text(content)
    r, out = reproduce(tmp_path, base, candidates(tmp_path), proposed(tmp_path, []))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "revoked.json" in r.stderr
    assert not (out / "document.json").exists()


def test_the_repository_has_a_revoked_json_per_environment():
    for env in ("production", "staging"):
        hashes = bd.load_reviewed_revocations(REPO / "opencode" / "attestation-baselines", env)
        assert isinstance(hashes, list)


def _logged(tmp_path, issued, entries=(), revoked=()):
    return current_doc(tmp_path, issued, entries, revoked, name="logged.json")


def test_a_missing_asset_falls_back_to_the_logged_document(tmp_path):
    # Both release assets 404 while the log holds a fresh document: carry the
    # logged one forward (and its revocations), and publish to repair the asset.
    prior = entry("gateway", "exact", B64)
    logged = _logged(tmp_path, NOW_UNIX - HOUR, [prior], revoked=[A64])
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []),
                       extra=["--logged", logged])
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((out / "document.json").read_text())
    assert doc["entries"] == [prior] and doc["revoked"] == [A64]
    assert doc["version"] == NOW_UNIX


def test_an_asset_older_than_the_log_is_replaced_by_the_logged_document(tmp_path):
    # Someone swapped an older, validly signed document back into the release.
    old = current_doc(tmp_path, NOW_UNIX - 5 * HOUR, [entry("model", "exact", A64)])
    logged = _logged(tmp_path, NOW_UNIX - HOUR, revoked=[A64])
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []),
                       current=old, extra=["--logged", logged])
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((out / "document.json").read_text())
    assert doc["entries"] == [] and doc["revoked"] == [A64]


def test_an_asset_newer_than_the_log_is_kept(tmp_path):
    # The upload succeeded and the log commit did not: the asset is the newer one.
    newer = current_doc(tmp_path, NOW_UNIX - HOUR, [entry("gateway", "exact", B64)])
    logged = _logged(tmp_path, NOW_UNIX - 2 * HOUR, [entry("model", "exact", A64)])
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []),
                       current=newer, extra=["--logged", logged])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "nothing to publish" in r.stdout
    # Once it is stale, the asset's entries are the ones carried forward.
    newer = current_doc(tmp_path, NOW_UNIX - 25 * HOUR, [entry("gateway", "exact", B64)])
    logged = _logged(tmp_path, NOW_UNIX - 26 * HOUR, [entry("model", "exact", A64)])
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []),
                       current=newer, extra=["--logged", logged])
    assert r.returncode == 0, r.stdout + r.stderr
    assert [e["sha256"] for e in json.loads((out / "document.json").read_text())["entries"]] == [B64]


def test_a_proposal_built_on_an_unverified_asset_converges_on_the_logged_document(tmp_path):
    # A partial upload: the new document landed and its signature did not. evaluate
    # does not verify, so it proposes on top of that orphan; sign drops the
    # unverified asset (no --current) and builds on the log. The orphan's extra
    # entry has no candidate, so it is dropped with a warning, not refused: the
    # next run, on the repaired asset, proposes it again from evidence.
    base = baselines(tmp_path, production_model=[E390])
    orphan_only = entry("gateway", "exact", B64)
    kept = entry("model", "exact", A64)
    orphan = current_doc(tmp_path, NOW_UNIX - 60, [kept, orphan_only], name="orphan.json")
    logged = _logged(tmp_path, NOW_UNIX - HOUR, [kept])
    (tmp_path / "evidence").mkdir()
    r, out = propose(tmp_path, base, [], current=orphan)
    assert r.returncode == 0, r.stdout + r.stderr
    prop = out / "proposed.json"
    assert orphan_only in json.loads(prop.read_text())["entries"]

    r2 = run("reproduce", "--environment", "production", "--candidates", out / "candidates",
             "--proposed", prop, "--logged", logged, "--baselines", base, "--now", NOW,
             "--out", tmp_path / "signed")
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert "::warning::" in r2.stdout and B64 in r2.stdout
    doc = json.loads((tmp_path / "signed" / "document.json").read_text())
    assert doc["entries"] == [kept]
    assert doc["version"] == NOW_UNIX


def test_on_the_logged_base_a_proposed_entry_from_a_candidate_still_must_reproduce(tmp_path):
    # Dropping unreproduced proposals is only for entries carried from evaluate's
    # base. One that names a candidate in the artifact and fails the rules here
    # is a divergence, and refuses as before.
    base = baselines(tmp_path, production_model=[E390])
    logged = _logged(tmp_path, NOW_UNIX - HOUR)
    cands = candidates(tmp_path, AE66)  # C1, C4, M1 against e390
    prop = proposed(tmp_path, [entry("model", "exact", sha(AE66))])
    r, out = reproduce(tmp_path, base, cands, prop, extra=["--logged", logged])
    assert r.returncode == 1, r.stdout + r.stderr
    assert sha(AE66) in r.stderr
    assert not (out / "document.json").exists()


def test_with_a_verified_asset_an_unreproduced_proposal_still_refuses(tmp_path):
    # The asset verified (--current given), so evaluate and sign share a base:
    # an entry sign cannot reproduce is a divergence even if the log is older.
    base = baselines(tmp_path, production_model=[E390])
    cur = current_doc(tmp_path, NOW_UNIX - HOUR)
    logged = _logged(tmp_path, NOW_UNIX - 2 * HOUR)
    prop = proposed(tmp_path, [entry("gateway", "exact", B64)])
    r, out = reproduce(tmp_path, base, candidates(tmp_path), prop, current=cur, extra=["--logged", logged])
    assert r.returncode == 1, r.stdout + r.stderr
    assert B64 in r.stderr


def test_a_logged_document_for_another_environment_refuses(tmp_path):
    logged = current_doc(tmp_path, NOW_UNIX - HOUR, environment="staging", name="logged.json")
    r, _ = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []),
                     extra=["--logged", logged])
    assert r.returncode == 1
    assert "environment" in r.stderr


def test_reproduce_refuses_a_clock_behind_the_current_version(tmp_path):
    cur = current_doc(tmp_path, NOW_UNIX + 60)
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []), current=cur)
    assert r.returncode == 1
    assert "version" in r.stderr


def test_reproduce_refuses_a_current_document_for_another_environment(tmp_path):
    cur = current_doc(tmp_path, NOW_UNIX - 30 * HOUR, environment="staging")
    r, _ = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []), current=cur)
    assert r.returncode == 1
    assert "environment" in r.stderr


def test_one_hash_under_two_roles_is_refused(tmp_path):
    cur = current_doc(tmp_path, NOW_UNIX - 30 * HOUR,
                      [entry("model", "exact", A64), entry("gateway", "exact", A64)])
    r, _ = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []), current=cur)
    assert r.returncode == 1
    assert "two roles" in r.stderr


def test_a_document_over_256_kib_is_refused(tmp_path):
    many = [entry("model", "exact", hashlib.sha256(str(i).encode()).hexdigest()) for i in range(1500)]
    cur = current_doc(tmp_path, NOW_UNIX - 30 * HOUR, many)
    r, out = reproduce(tmp_path, baselines(tmp_path), candidates(tmp_path), proposed(tmp_path, []), current=cur)
    assert r.returncode == 1
    assert "262144" in r.stderr
    assert not (out / "document.json").exists()


# --- hold issues -------------------------------------------------------------

def test_issues_name_the_rule_the_diff_and_the_baseline_pr_commands(tmp_path):
    holds = tmp_path / "holds.json"
    holds.write_text(json.dumps([{"sha256": sha(AE66), "role": "model", "failures": ["C1", "C4", "M1"],
                                  "closest": sha(E390), "diff": ["allowed_envs: -\"AWS_REGION\""]}]))
    r = run("issues", "--environment", "production", "--holds", holds, "--repo", "nearai/nearai-red-sandbox",
            "--run-id", "1234", "--artifact", "attestation-policy-evaluation", "--out", tmp_path / "issues")
    assert r.returncode == 0, r.stdout + r.stderr
    title = (tmp_path / "issues" / f"{sha(AE66)}.title").read_text()
    body = (tmp_path / "issues" / f"{sha(AE66)}.md").read_text()
    assert title == f"Attestation hold: production model {sha(AE66)[:12]}"
    assert "C1, C4, M1" in body and sha(E390) in body and "AWS_REGION" in body
    assert "https://github.com/nearai/nearai-red-sandbox/actions/runs/1234" in body
    assert "gh run download 1234 --repo nearai/nearai-red-sandbox --name attestation-policy-evaluation" in body
    assert f"opencode/attestation-baselines/production/model/{sha(AE66)}.json" in body
    assert "gh pr create" in body and "gh run download" in body


@pytest.mark.parametrize("failures,warned", [(["C2"], True), (["C1", "C3"], True), (["C1", "M1"], False)])
def test_an_issue_says_c2_and_c3_holds_are_not_cleared_by_a_baseline(tmp_path, failures, warned):
    holds = tmp_path / "holds.json"
    holds.write_text(json.dumps([{"sha256": A64, "role": "model", "failures": failures,
                                  "closest": B64, "diff": ["x"]}]))
    r = run("issues", "--environment", "production", "--holds", holds, "--repo", "nearai/nearai-red-sandbox",
            "--run-id", "1", "--artifact", "a", "--out", tmp_path / "issues")
    assert r.returncode == 0, r.stdout + r.stderr
    body = (tmp_path / "issues" / f"{A64}.md").read_text()
    # Always said, next to the approval commands.
    assert "C2 and C3 holds cannot be cleared by merging" in body
    assert ("merging it into the baselines will not approve it" in body) == warned


def test_a_baseline_pr_for_a_c2_or_c3_hold_refuses_the_next_run(tmp_path):
    # What the issue warns about: the merged baseline makes the run refuse.
    bad = GW.replace('"dstack-0.5.12"', '"dstack-evil"')
    assert bad != GW
    r, out = reproduce(tmp_path, baselines(tmp_path, production_gateway=[GW, bad]),
                       candidates(tmp_path, bad), proposed(tmp_path, []))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "C2" in r.stderr
    assert not (out / "document.json").exists()


def test_an_issue_body_stays_under_githubs_limit(tmp_path):
    holds = tmp_path / "holds.json"
    holds.write_text(json.dumps([{"sha256": A64, "role": "gateway", "failures": ["G1"], "closest": B64,
                                  "diff": ["docker_compose_file: +" + "x" * 200] * 2000}]))
    r = run("issues", "--environment", "staging", "--holds", holds, "--repo", "nearai/nearai-red-sandbox",
            "--run-id", "1", "--artifact", "a", "--out", tmp_path / "issues")
    assert r.returncode == 0, r.stdout + r.stderr
    body = (tmp_path / "issues" / f"{A64}.md").read_text()
    assert len(body) < 65_536
    assert "cut: the diff is longer" in body
