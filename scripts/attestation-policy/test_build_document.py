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


def test_model_compose_manager_digests_use_the_launcher_anchor(tmp_path):
    (ref,) = {r for r in bd.rules.image_refs(json.loads(E390)["docker_compose_file"])
              if r.repo == "nearaidev/compose-manager"}
    # Only in docker_compose_file: pre_launch_script also names the digest,
    # and C1 compares pre_launch_script exactly.
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
