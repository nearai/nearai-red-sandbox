#!/usr/bin/env python3
"""Assemble and reproduce the next signed attestation policy document.

Spec: docs/specs/2026-11-24-signed-attestation-policy-feed-design.md, "CI: the
publisher". Stdlib only; run with `python3 -I`. The workflow
.github/workflows/attestation-policy.yml runs it in two jobs:

    propose    (evaluate job, no secrets) reads rts's own attestation.json
               evidence, drops composes the current document already endorses
               or revokes, runs the content rules and writes OUT/candidates/
               (raw composes), OUT/proposed.json (the proposed next document)
               and OUT/holds.json.
    reproduce  (sign job) trusts nothing propose wrote except the raw bytes in
               candidates/: it hashes each one, runs the rules for both roles
               against the baselines and cosign, assembles the next document
               from the current one and what it reproduced, and refuses (exit
               1) if proposed.json lists any entry it did not reproduce and
               has not revoked. It writes OUT/document.json only when there
               is something to publish (a new entry, a new revocation or
               dropped entry, no current document, a base taken from the
               log, or a current document over 24 hours old), and
               OUT/holds.json for entries cosign refused.
    issues     writes one hold issue (title and Markdown body) per hold.

    build_document.py propose --environment E --evidence DIR [--current CUR.json]
        [--logged LOGGED.json] --baselines DIR --now YYYY-MM-DDTHH:MM:SSZ --out DIR
        [--cosign PATH]
    build_document.py reproduce --environment E --candidates DIR --proposed P.json
        [--current CUR.json] [--logged LOGGED.json] --baselines DIR --now ...
        --out DIR [--cosign PATH]
    build_document.py issues --environment E --holds H.json --repo OWNER/NAME
        --run-id ID --artifact NAME --out DIR

Both take --logged LOGGED.json, the verified document at the head of the
attestation-policy-log branch. When the release asset (--current) is missing
or has a lower version, they build on the logged document instead and publish
at once, so deleting the asset or swapping an older signed pair back in cannot
drop entries from `revoked`. `revoked` is the base document's list plus the
reviewed <baselines>/<environment>/revoked.json (exact or instance-label-v1
hashes), which must exist. It never shrinks, and a hash added to it publishes
at once.

--current is omitted when no release asset verified (none published yet, or a
partly finished upload left an unverifiable pair); --logged when the log holds
no document. On reproduce with --logged and no --current, a proposed entry
that names no candidate (carried from an unverified asset evaluate read) is
dropped with a warning instead of refused; it is never signed. G2 and M2
run here through --cosign: without it, an entry with a changed digest is never
endorsed. A changed gateway digest outside nearaidev/ is held (G2), and so is
a changed model digest outside nearaidev/compose-manager* (M2).
"""

from __future__ import annotations

import argparse
import calendar
import dataclasses
import datetime
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent


def _load(name: str, path: Path):
    # `python3 -I` leaves the script directory off sys.path: load by path.
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


rules = _load("attestation_rules", SCRIPTS / "attestation_rules.py")
refresh = _load("refresh_attestation_policy", SCRIPTS / "refresh-attestation-policy.py")

SCHEMA = 1
VALIDITY_SECS = 72 * 3600
REPUBLISH_AFTER_SECS = 24 * 3600
MAX_DOCUMENT_BYTES = 262_144
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
FIELDS = ("schema", "environment", "version", "issued", "expires", "entries", "revoked")
ENDORSED_BY = {"gateway": "rules:gateway-v1", "model": "rules:model-v1"}
PROVENANCE_RULE = {"gateway": "G2", "model": "M2"}

COSIGN_ISSUER = "https://token.actions.githubusercontent.com"
# G2: any nearaidev/* image, signed by a workflow in a nearai repository.
GATEWAY_IDENTITY = r"^https://github\.com/nearai/[^/]+/\.github/workflows/"
# M2: the launcher's own anchor for nearaidev/compose-manager*.
MODEL_IDENTITY = r"^https://github\.com/nearai/compose-manager/\.github/workflows/"
COSIGN_TIMEOUT_SECS = 120
# GitHub refuses an issue body over 65536 characters.
MAX_ISSUE_DIFF_CHARS = 50_000

_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_CANDIDATE = re.compile(r"([0-9a-f]{64})\.json", re.ASCII)
_ANY_DIGEST = re.compile(r"@(sha256:[0-9a-f]{64})", re.ASCII)
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", re.ASCII)


class Refused(Exception):
    """A reason to publish nothing: exit 1."""


def parse_time(s: str) -> int:
    try:
        return calendar.timegm(datetime.datetime.strptime(s, TIME_FORMAT).timetuple())
    except (TypeError, ValueError):
        raise Refused(f"time {s!r} is not YYYY-MM-DDTHH:MM:SSZ")


def format_time(t: int) -> str:
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime(TIME_FORMAT)


def _hex64(s) -> bool:
    return isinstance(s, str) and _HEX64.fullmatch(s) is not None


def _key(e: dict) -> tuple:
    return (e["role"], e["match"], e["sha256"])


# --- the current document ------------------------------------------------

def load_current(path: Path | None, environment: str) -> dict | None:
    """The published document, checked for shape. None when there is none."""
    if path is None:
        return None
    try:
        doc = json.loads(Path(path).read_bytes().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise Refused(f"current document {path}: {e}")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise Refused(f"current document {path}: schema is not {SCHEMA}")
    if doc.get("environment") != environment:
        raise Refused(f"current document {path}: environment {doc.get('environment')!r} is not {environment!r}")
    if not isinstance(doc.get("version"), int) or isinstance(doc.get("version"), bool):
        raise Refused(f"current document {path}: version is not an integer")
    parse_time(doc.get("issued"))
    entries = doc.get("entries")
    if not isinstance(entries, list):
        raise Refused(f"current document {path}: entries is not a list")
    for e in entries:
        if (not isinstance(e, dict) or e.get("role") not in rules.ROLES
                or not isinstance(e.get("match"), str) or not _hex64(e.get("sha256"))):
            raise Refused(f"current document {path}: malformed entry {e!r}")
    revoked = doc.get("revoked")
    if not isinstance(revoked, list) or not all(_hex64(h) for h in revoked):
        raise Refused(f"current document {path}: revoked is not a list of 64 lowercase hex digests")
    return doc


def load_reviewed_revocations(root: Path, environment: str) -> list:
    """<root>/<environment>/revoked.json: the reviewed list of revoked exact or
    instance-label-v1 hashes. It must exist; a hash is never removed from it."""
    path = Path(root) / environment / "revoked.json"
    try:
        hashes = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise Refused(f"{path}: {e}")
    if not isinstance(hashes, list) or not all(_hex64(h) for h in hashes):
        raise Refused(f"{path}: not a list of 64 lowercase hex digests")
    if len(set(hashes)) != len(hashes):
        raise Refused(f"{path}: lists a hash twice")
    return hashes


def base_document(current: dict | None, logged: dict | None) -> tuple[dict | None, bool]:
    """The document to build on, and whether it came from the log. The release
    asset is used only when its version is at least the logged one: a missing
    or older asset (deleted, or an older signed pair swapped back) falls back to
    the head of attestation-policy-log."""
    if logged is not None and (current is None or current["version"] < logged["version"]):
        return logged, True
    return current, False


def already_covered(raw: str, current: dict | None, revoked=()) -> bool:
    """The compose is revoked by exact or instance-label-v1 hash, or the current
    document endorses it as is."""
    exact = rules.compose_sha256(raw)
    label = rules.instance_label_sha256(raw)
    revoked = set(revoked) | set(current["revoked"] if current else ())
    if exact in revoked or (label is not None and label in revoked):
        return True
    if current is None:
        return False
    have = {(e["match"], e["sha256"]) for e in current["entries"]}
    return (rules.MATCH_EXACT, exact) in have or (label is not None and (rules.MATCH_INSTANCE_LABEL, label) in have)


# --- rules and provenance ------------------------------------------------

@dataclasses.dataclass
class Outcome:
    entry: dict | None   # the endorsement, when every rule passed
    hold: dict | None    # {sha256, role, failures, closest, diff}, otherwise
    # On a G2/M2 hold, the (role, match, sha256) the entry would have had.
    held_key: tuple | None = None


def _hold(raw, role, failures, closest, diff) -> Outcome:
    return Outcome(None, {"sha256": rules.compose_sha256(raw), "role": role,
                          "failures": failures, "closest": closest, "diff": diff})


def run_cosign(cosign: str, identity: str, ref: str) -> tuple[bool, str]:
    try:
        p = subprocess.run([cosign, "verify", "--certificate-identity-regexp", identity,
                            "--certificate-oidc-issuer", COSIGN_ISSUER, ref],
                           capture_output=True, text=True, timeout=COSIGN_TIMEOUT_SECS)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    lines = (p.stderr or p.stdout).strip().splitlines()
    return p.returncode == 0, lines[-1] if lines else f"exit {p.returncode}"


def endorse(raw: str, role: str, baselines: dict, now: str, cosign: str | None, cache: dict) -> Outcome:
    """C1-C4 and G1/M1 against the role's baselines, then G2/M2 provenance of
    every digest that differs from the baseline it passed against."""
    v = rules.evaluate(raw, role, list(baselines.values()))
    if not v.passed:
        return _hold(raw, role, v.failures, v.closest, v.diff)
    cand = json.loads(raw)
    base = json.loads(baselines[v.closest])
    have = {(r.repo, r.digest) for r in rules.image_refs(base["docker_compose_file"])}
    changed = sorted({(r.repo, r.digest) for r in rules.image_refs(cand["docker_compose_file"])} - have)
    rule = PROVENANCE_RULE[role]
    diff = []
    # digest_blind blinds every @sha256: in the file, not only image: lines.
    # A digest the baseline lacks must belong to an image reference checked below.
    new_digests = set(_ANY_DIGEST.findall(cand["docker_compose_file"])) - set(
        _ANY_DIGEST.findall(base["docker_compose_file"]))
    for d in sorted(new_digests - {digest for _, digest in changed}):
        diff.append(f"digest changed outside an image: line: {d}")
    for repo, digest in changed:
        ref = f"{repo}@{digest}"
        if role == "gateway" and repo.startswith("nearaidev/"):
            identity = GATEWAY_IDENTITY
        elif role == "model" and repo.startswith("nearaidev/compose-manager"):
            identity = MODEL_IDENTITY
        else:
            diff.append(f"image digest changed outside NEAR's signed images: {ref}")
            continue
        if not _REPO.fullmatch(repo):
            diff.append(f"image repository is not owner/name: {ref}")
            continue
        if cosign is None:
            diff.append(f"cosign was not run: {ref}")
            continue
        if (identity, ref) not in cache:
            cache[(identity, ref)] = run_cosign(cosign, identity, ref)
        ok, why = cache[(identity, ref)]
        if not ok:
            diff.append(f"cosign verify failed for {ref} (identity {identity}): {why}")
    sha = rules.compose_sha256(raw) if v.match == rules.MATCH_EXACT else rules.instance_label_sha256(raw)
    if diff:
        o = _hold(raw, role, [rule], v.closest, diff)
        o.held_key = (role, v.match, sha)
        return o
    return Outcome({"role": role, "match": v.match, "sha256": sha, "app_name": cand.get("name"),
                    "first_seen": now, "endorsed_by": ENDORSED_BY[role]}, None)


def load_all_baselines(root: Path, environment: str) -> dict:
    out = {}
    for role in rules.ROLES:
        out[role] = {rules.compose_sha256(b): b for b in rules.load_baselines(root, environment, role)}
    return out


# --- the next document ---------------------------------------------------

def assemble(environment: str, current: dict | None, new_entries: list, now_unix: int,
             reviewed_revoked=(), force: bool = False) -> tuple[dict, int, bool]:
    """The next document, how many entries it adds, and whether it is worth
    publishing. revoked is the current document's list plus reviewed_revoked
    (revoked.json), so it never shrinks. Entries whose sha256 is revoked are
    dropped. A grown revoked list, a dropped entry or force publishes at once."""
    revoked = list(current["revoked"]) if current else []
    carried = len(revoked)
    for h in reviewed_revoked:
        if h not in revoked:
            revoked.append(h)
    if current is not None and now_unix < current["version"]:
        raise Refused(f"now ({now_unix}) is before the current document's version {current['version']}")
    prior = current["entries"] if current else []
    entries = [e for e in prior if e["sha256"] not in revoked]
    changed = force or len(revoked) > carried or len(entries) < len(prior)
    roles = {}
    for e in entries:
        roles.setdefault((e["match"], e["sha256"]), set()).add(e["role"])
    added = 0
    for e in new_entries:
        k = (e["match"], e["sha256"])
        if e["sha256"] in revoked or e["role"] in roles.get(k, ()):
            continue
        roles.setdefault(k, set()).add(e["role"])
        entries.append(e)
        added += 1
    for (match, sha), rs in roles.items():
        if len(rs) > 1:
            raise Refused(f"{sha} ({match}) is endorsed under two roles: {sorted(rs)}")
    doc = {
        "schema": SCHEMA,
        "environment": environment,
        "version": now_unix,
        "issued": format_time(now_unix),
        "expires": format_time(now_unix + VALIDITY_SECS),
        "entries": entries,
        "revoked": revoked,
    }
    stale = current is None or now_unix - parse_time(current["issued"]) > REPUBLISH_AFTER_SECS
    return doc, added, (added > 0 or stale or changed)


def serialize(doc: dict) -> bytes:
    data = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise Refused(f"the document is {len(data)} bytes, over rts's cap of {MAX_DOCUMENT_BYTES}")
    return data


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _write_json(path: Path, obj) -> None:
    _write(path, (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


# --- propose ---------------------------------------------------------------

def collect(evidence: Path, environment: str) -> dict:
    """sha256 -> (role, raw app_compose) for every verified, unpinned compose
    in every attestation.json under evidence, in path order."""
    out = {}
    paths = sorted(Path(evidence).rglob("attestation.json"))
    for p in paths:
        try:
            doc = json.loads(p.read_text())
            found = refresh.candidates(doc, {"composeHashes": []}, "", environment)
        except (OSError, ValueError, KeyError) as e:
            raise Refused(f"{p}: {e}")
        for c in found:
            prev = out.setdefault(c["sha256"], (c["role"], c["app_compose"]))
            if prev[0] != c["role"]:
                raise Refused(f"{p}: compose {c['sha256']} was served as both {prev[0]} and {c['role']}")
    return out


def cmd_propose(a) -> int:
    now_unix = parse_time(a.now)
    current, from_log = base_document(load_current(a.current, a.environment),
                                      load_current(a.logged, a.environment))
    reviewed = load_reviewed_revocations(a.baselines, a.environment)
    baselines = load_all_baselines(a.baselines, a.environment)
    found = collect(a.evidence, a.environment)
    out = Path(a.out)
    (out / "candidates").mkdir(parents=True, exist_ok=True)
    new, holds, cache = [], [], {}
    for sha, (role, raw) in found.items():
        if already_covered(raw, current, reviewed):
            continue
        _write(out / "candidates" / f"{sha}.json", raw.encode("utf-8"))
        o = endorse(raw, role, baselines[role], a.now, a.cosign, cache)
        if o.entry:
            new.append(o.entry)
        else:
            holds.append(o.hold)
    doc, added, _ = assemble(a.environment, current, new, now_unix, reviewed, from_log)
    _write(out / "proposed.json", serialize(doc))
    _write_json(out / "holds.json", holds)
    print(f"proposed {added} new entries ({len(doc['entries'])} in all), {len(holds)} held, "
          f"from {len(found)} verified unpinned composes")
    return 0


# --- reproduce -------------------------------------------------------------

def read_candidates(d: Path) -> dict:
    d = Path(d)
    if not d.is_dir():
        raise Refused(f"--candidates is not a directory: {d}")
    out = {}
    for p in sorted(d.iterdir()):
        m = _CANDIDATE.fullmatch(p.name)
        if not m or not p.is_file() or p.is_symlink():
            raise Refused(f"{p}: candidates/ holds only <sha256>.json files")
        data = p.read_bytes()
        if hashlib.sha256(data).hexdigest() != m.group(1):
            raise Refused(f"{p}: sha256 of the contents is not the file name")
        try:
            out[m.group(1)] = data.decode("utf-8")
        except UnicodeDecodeError:
            raise Refused(f"{p}: not UTF-8")
    return out


def cmd_reproduce(a) -> int:
    now_unix = parse_time(a.now)
    current, from_log = base_document(load_current(a.current, a.environment),
                                      load_current(a.logged, a.environment))
    if from_log:
        print(f"the release asset is missing or older than the logged version {current['version']}: "
              "building on the logged document")
    reviewed = load_reviewed_revocations(a.baselines, a.environment)
    try:
        proposed = json.loads(Path(a.proposed).read_bytes().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise Refused(f"proposed document {a.proposed}: {e}")
    if not isinstance(proposed, dict) or proposed.get("environment") != a.environment \
            or not isinstance(proposed.get("entries"), list):
        raise Refused(f"proposed document {a.proposed}: not a {a.environment} document with entries")
    cands = read_candidates(a.candidates)
    baselines = load_all_baselines(a.baselines, a.environment)

    new, holds, cache, held_keys = [], [], {}, set()
    for sha, raw in cands.items():
        if already_covered(raw, current, reviewed):
            continue
        # The role is not taken from evaluate: a compose is endorsed for the
        # role whose rules it passes, and refused if it passes both.
        outcomes = {role: rules.evaluate(raw, role, list(baselines[role].values())) for role in rules.ROLES}
        passing = [role for role, v in outcomes.items() if v.passed]
        if len(passing) > 1:
            raise Refused(f"candidate {sha} passes the rules for both roles")
        if not passing:
            continue
        o = endorse(raw, passing[0], baselines[passing[0]], a.now, a.cosign, cache)
        if o.entry:
            new.append(o.entry)
        else:
            holds.append(o.hold)
            held_keys.add(o.held_key)

    doc, added, publish = assemble(a.environment, current, new, now_unix, reviewed, from_log)
    data = serialize(doc)
    have = {_key(e) for e in doc["entries"]}
    # With no trusted release asset, sign builds on the log while evaluate (which
    # does not verify) may have built on an unverified one, such as the new
    # document of a partly finished upload. An entry carried from that base
    # names no candidate: it is dropped with a warning, and proposed again from
    # evidence once the asset is repaired. Nothing unreproduced is ever signed.
    untrusted_base = from_log and a.current is None
    from_candidates = set(cands)
    for raw in cands.values():
        label = rules.instance_label_sha256(raw)
        if label is not None:
            from_candidates.add(label)
    missing, dropped = [], []
    for e in proposed["entries"]:
        try:
            k = _key(e)
        except (TypeError, KeyError):
            raise Refused(f"proposed entry {e!r} is malformed")
        # Passed the rules here but not G2/M2 (cosign refused or unreachable):
        # dropped and held, not a reason to publish nothing.
        # A revoked proposal (evaluate read a rolled-back asset) is dropped.
        if k not in have and k not in held_keys and k[2] not in doc["revoked"]:
            (dropped if untrusted_base and k[2] not in from_candidates else missing).append(k)
    if dropped:
        print("::warning::proposed entries carried from a base sign did not verify, dropped: "
              + ", ".join(f"{r} {m} {s}" for r, m, s in dropped))
    if missing:
        raise Refused("proposed entries not reproduced: " + ", ".join(f"{r} {m} {s}" for r, m, s in missing))

    out = Path(a.out)
    _write_json(out / "holds.json", holds)
    print(f"reproduced {added} entries ({len(doc['entries'])} in all), {len(holds)} held by provenance")
    if not publish:
        print("no new entries and the current document is under 24 hours old: nothing to publish")
        return 0
    _write(out / "document.json", data)
    print(f"wrote {out / 'document.json'} version {doc['version']}")
    return 0


# --- hold issues -----------------------------------------------------------

def issue(hold: dict, environment: str, repo: str, run_id: str, artifact: str) -> tuple[str, str]:
    sha, role = hold["sha256"], hold["role"]
    if not _hex64(sha) or role not in rules.ROLES:
        raise Refused(f"malformed hold {hold!r}")
    short = sha[:12]
    run_url = f"https://github.com/{repo}/actions/runs/{run_id}"
    dest = f"opencode/attestation-baselines/{environment}/{role}/{sha}.json"
    tmp = f"\"${{TMPDIR:-/tmp}}/attestation-hold-{short}\""
    diff = "\n".join(str(x) for x in hold.get("diff") or []) or "(no diff)"
    if len(diff) > MAX_ISSUE_DIFF_CHARS:
        diff = diff[:MAX_ISSUE_DIFF_CHARS] + "\n... (cut: the diff is longer; compare the candidate with the baseline)"
    longest = max((len(m) for m in re.findall(r"~+", diff)), default=0)
    fence = "~" * max(3, longest + 1)
    title = f"Attestation hold: {environment} {role} {short}"
    body = f"""The attestation policy publisher held a {environment} {role} compose.

- Compose sha256: `{sha}`
- Failed rules: {', '.join(hold.get('failures') or [])}
- Closest baseline: `{hold.get('closest')}`
- Run: {run_url}

Diff against the closest baseline (digests blinded where the rules blind them):

{fence}
{diff}
{fence}

To approve it, open a baseline pull request. Review the compose itself, not
only this diff: merging makes the next run sign it.

```sh
git fetch origin main
git switch -c attestation-baseline/{environment}-{role}-{short} origin/main
gh run download {run_id} --repo {repo} --name {artifact} --dir {tmp}
cp {tmp}/{environment}/candidates/{sha}.json {dest}
shasum -a 256 {dest}   # must print {sha}
git add {dest}
git commit -S -m "Add the {environment} {role} attestation baseline {short}"
git push -u origin HEAD
gh pr create --repo {repo} --base main --title "Add the {environment} {role} attestation baseline {short}" --body "Approves the compose held in {run_url}."
```

To refuse it, close this issue: later runs leave a closed issue alone. While
it is open, each run that still sees the compose updates it.
"""
    return title, body


def cmd_issues(a) -> int:
    if not _REPO.fullmatch(a.repo) or not re.fullmatch(r"[0-9]+", a.run_id) \
            or not re.fullmatch(r"[A-Za-z0-9._-]+", a.artifact):
        raise Refused("--repo, --run-id or --artifact is malformed")
    holds = json.loads(Path(a.holds).read_text())
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for h in holds:
        title, body = issue(h, a.environment, a.repo, a.run_id, a.artifact)
        _write(out / f"{h['sha256']}.title", title.encode())
        _write(out / f"{h['sha256']}.md", body.encode())
    print(f"wrote {len(holds)} hold issues to {out}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("propose", "reproduce"):
        p = sub.add_parser(name)
        p.add_argument("--environment", required=True, choices=rules.ENVIRONMENTS)
        p.add_argument("--current", type=Path, help="the published document; omit only when none exists")
        p.add_argument("--logged", type=Path,
                       help="the verified document at the head of attestation-policy-log; omit only when none exists")
        p.add_argument("--baselines", type=Path, required=True)
        p.add_argument("--now", required=True, help="YYYY-MM-DDTHH:MM:SSZ")
        p.add_argument("--out", type=Path, required=True)
        p.add_argument("--cosign", help="the cosign executable for G2/M2; without it no changed digest is endorsed")
        if name == "propose":
            p.add_argument("--evidence", type=Path, required=True)
        else:
            p.add_argument("--candidates", type=Path, required=True)
            p.add_argument("--proposed", type=Path, required=True)
    p = sub.add_parser("issues")
    p.add_argument("--environment", required=True, choices=rules.ENVIRONMENTS)
    p.add_argument("--holds", type=Path, required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--artifact", required=True)
    p.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    try:
        return {"propose": cmd_propose, "reproduce": cmd_reproduce, "issues": cmd_issues}[a.cmd](a)
    except Refused as e:
        print(f"build_document {a.cmd}: refusing: {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"build_document {a.cmd}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
