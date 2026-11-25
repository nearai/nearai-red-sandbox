#!/usr/bin/env python3
"""Content rules for the signed attestation policy feed.

Spec: docs/specs/2026-11-24-signed-attestation-policy-feed-design.md,
"Normalization instance-label-v1" and "Content rules". Stdlib only; run with
`python3 -I`. CI runs this twice: in the unprivileged `evaluate` job and again
in the `sign` job, which signs only what it reproduces here.

    python3 -I scripts/attestation_rules.py --environment E --role R RAW

RAW holds one `app_compose`, either as its raw bytes (a JSON object) or as a
JSON string wrapping them (the tests/fixtures/compose-history format). Prints
the verdict as JSON. Exit 0 on pass, 3 on hold.

Rules here are C1-C4, G1 and M1. G2 and M2 (cosign provenance of changed
`nearaidev/*` digests) need the network and run in build_document.py, in both
the publisher's jobs. A pass here is not an endorsement: for a model, C1 does
not compare `pre_launch_script` and M1 compares it digest-blind, so a changed
digest there is left to M2.

Byte-level semantics that the Rust side (`src/attest/normalize.rs`) must
reproduce exactly, so both languages produce one hash:

- `docker_compose_file` is split on "\\n" only (not `str.splitlines`, and not
  Rust's `str::lines`, which also strips a trailing "\\r"), and rejoined with
  "\\n".
- The label line must match, in full,
  `[ \\t\\r\\f\\v]*-[ \\t\\r\\f\\v]*INSTANCE_LABEL=[A-Za-z0-9._-]{1,64}`. That is
  the spec's `^(\\s*-\\s*INSTANCE_LABEL=)[A-Za-z0-9._-]{1,64}$` with ASCII
  `\\s` spelled out (it includes \\x0b, which Rust's `is_ascii_whitespace`
  does not), applied to one line with no line terminator. The value is
  replaced with `*`, keeping the prefix byte for byte.
- Exactly one line matches. Every other line containing `INSTANCE_LABEL` must
  start with optional whitespace (same class) and then `#`.
- Canonical JSON: keys sorted by code point at every level, separators "," and
  ":", non-ASCII written as UTF-8 (not escaped), Python `json.dumps` string
  escaping. Any float (including NaN or Infinity), or an integer outside
  [-2**63, 2**64 - 1], refuses normalization, as does a string that is not
  valid Unicode (a lone surrogate). Unparseable input refuses too: `None`,
  never an exception.
- Parsing refuses, at every level, and both normalization (`None`) and
  `evaluate` (a PARSE hold) with it:
  - duplicate keys in any object (`json.loads` keeps the last value and other
    parsers may keep the first, so a rule could compare one value while a
    consumer uses another; serde_json's `Value` does not refuse them on its
    own, so the Rust side must check explicitly);
  - the integer literal `-0`, which serde_json parses as the float -0.0;
  - nesting deeper than 127 arrays or objects (the outer object counts as
    one), serde_json's default recursion limit.
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import hashlib
import json
import re
import sys
from pathlib import Path

ROLES = ("gateway", "model")
ENVIRONMENTS = ("production", "staging")
MATCH_EXACT = "exact"
MATCH_INSTANCE_LABEL = "instance-label-v1"

# The failure reported when the candidate is not a JSON object with a string
# docker_compose_file. It is not a spec rule ID; nothing that fails it is signed.
PARSE_FAILURE = "PARSE"

_WS = "[ \\t\\r\\f\\v]"
_LABEL_LINE = re.compile(f"({_WS}*-{_WS}*INSTANCE_LABEL=)[A-Za-z0-9._-]{{1,64}}", re.ASCII)
_COMMENT_LINE = re.compile(f"{_WS}*#", re.ASCII)
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")
_NAME = re.compile(r"dstack(-nvidia)?-[0-9]+\.[0-9]+\.[0-9]+", re.ASCII)
_IMAGE_LINE = re.compile(f"{_WS}*(?:-{_WS}*)?image:{_WS}*(.*?){_WS}*", re.ASCII)
_INTERPOLATED = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}", re.ASCII)
_PINNED_REF = re.compile(r"([^@\s$]+)@sha256:[0-9a-f]{64}", re.ASCII)

_I64_MIN = -(2 ** 63)
_U64_MAX = 2 ** 64 - 1
# serde_json 1.0.154 (de.rs) starts remaining_depth at 128, decrements it on
# entering each array or object and fails when it reaches 0: 127 levels parse.
_MAX_DEPTH = 127

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINES = REPO_ROOT / "opencode" / "attestation-baselines"


# --- hashing and normalization -------------------------------------------

def compose_sha256(raw: str) -> str:
    """sha256 of the UTF-8 bytes of an app_compose, as lowercase hex."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _check_canonical(obj) -> None:
    if isinstance(obj, bool) or obj is None:
        return
    if isinstance(obj, float):
        raise ValueError("float in canonical JSON")
    if isinstance(obj, int):
        if not _I64_MIN <= obj <= _U64_MAX:
            raise ValueError("integer out of range in canonical JSON")
        return
    if isinstance(obj, str):
        obj.encode("utf-8")  # raises UnicodeEncodeError (a ValueError) on a lone surrogate
        return
    if isinstance(obj, list):
        for v in obj:
            _check_canonical(v)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("non-string key in canonical JSON")
            _check_canonical(k)
            _check_canonical(v)
        return
    raise ValueError(f"unsupported type in canonical JSON: {type(obj).__name__}")


def canonical(obj) -> str:
    """Sorted keys, no whitespace, UTF-8 not escaped. ValueError on any float."""
    _check_canonical(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _no_duplicate_keys(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate key {k!r}")
        obj[k] = v
    return obj


def _int_not_negative_zero(s: str) -> int:
    # serde_json parses `-0` as the float -0.0; Python would read it as int 0.
    if s == "-0":
        raise ValueError("-0 is a float to serde_json")
    return int(s)


def _depth(obj) -> int:
    """Nesting depth in containers: a scalar is 0, {} or [] is 1."""
    deepest = 0
    stack = [(obj, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, dict):
            v = list(v.values())
        elif not isinstance(v, list):
            continue
        deepest = max(deepest, d)
        stack.extend((x, d + 1) for x in v)
    return deepest


def _parse_compose(raw: str):
    """The app_compose as a dict with a string docker_compose_file, or None."""
    try:
        obj = json.loads(raw, object_pairs_hook=_no_duplicate_keys, parse_int=_int_not_negative_zero)
    except (ValueError, RecursionError):
        return None
    if _depth(obj) > _MAX_DEPTH:
        return None
    if not isinstance(obj, dict) or not isinstance(obj.get("docker_compose_file"), str):
        return None
    return obj


def _normalize_compose_file(text: str) -> str | None:
    """The docker_compose_file with its one INSTANCE_LABEL value replaced by *."""
    lines = text.split("\n")
    hits = []
    for i, line in enumerate(lines):
        if _LABEL_LINE.fullmatch(line):
            hits.append(i)
        elif "INSTANCE_LABEL" in line and not _COMMENT_LINE.match(line):
            return None
    if len(hits) != 1:
        return None
    i = hits[0]
    lines[i] = _LABEL_LINE.fullmatch(lines[i]).group(1) + "*"
    return "\n".join(lines)


def normalize_instance_label(raw: str) -> str | None:
    """Canonical JSON of the instance-label-v1 form, or None if it does not apply."""
    obj = _parse_compose(raw)
    if obj is None:
        return None
    text = _normalize_compose_file(obj["docker_compose_file"])
    if text is None:
        return None
    obj = dict(obj)
    obj["docker_compose_file"] = text
    try:
        return canonical(obj)
    except (ValueError, RecursionError):
        return None


def instance_label_sha256(raw: str) -> str | None:
    norm = normalize_instance_label(raw)
    return None if norm is None else hashlib.sha256(norm.encode("utf-8")).hexdigest()


def digest_blind(s: str) -> str:
    """s with every @sha256:<64 lowercase hex> replaced by @sha256:*."""
    return _DIGEST.sub("@sha256:*", s)


# --- image references ----------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ImageRef:
    repo: str
    var: str | None      # the VAR of ${VAR:-repo@sha256:...}, else None
    digest: str | None   # "sha256:<hex>" when pinned by digest, else None


def _strip_value(v: str) -> str:
    if " #" in v:
        v = v.split(" #", 1)[0].rstrip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def _repo_of(ref: str) -> str:
    ref = ref.split("@", 1)[0]
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    return ref[:colon] if colon > slash else ref


def image_refs(compose_file: str) -> list[ImageRef]:
    """Every uncommented `image:` value in a docker_compose_file."""
    refs = []
    for line in compose_file.split("\n"):
        if _COMMENT_LINE.match(line):
            continue
        m = _IMAGE_LINE.fullmatch(line)
        if not m:
            continue
        value = _strip_value(m.group(1))
        var = None
        inner = value
        im = _INTERPOLATED.fullmatch(value)
        if im:
            var, inner = im.group(1), im.group(2)
        pm = _PINNED_REF.fullmatch(inner)
        if pm:
            refs.append(ImageRef(pm.group(1), var, inner[len(pm.group(1)) + 1:]))
        else:
            refs.append(ImageRef(_repo_of(inner), var, None))
    return refs


# --- rules ---------------------------------------------------------------

def _same(a, b) -> bool:
    # Strict equality: Python treats True == 1, JSON does not.
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def _c1(cand: dict, base: dict, role: str) -> bool:
    keys = (set(cand) | set(base)) - {"docker_compose_file", "name"}
    # A model's pre_launch_script re-pins the compose-manager image by digest,
    # so C1 checks only that both have it: M1 compares it digest-blind, and
    # build_document's M2 pairs its digests and verifies each changed one.
    loose = {"pre_launch_script"} if role == "model" else set()
    return all(k in cand and k in base and (k in loose or _same(cand[k], base[k])) for k in keys)


def _c2(cand: dict) -> bool:
    return isinstance(cand.get("name"), str) and _NAME.fullmatch(cand["name"]) is not None


def _c3(cand_refs: list[ImageRef], base_refs: list[ImageRef]) -> bool:
    if any(r.digest is None for r in cand_refs):
        return False
    base_vars: dict[str, set] = {}
    for r in base_refs:
        base_vars.setdefault(r.repo, set()).add(r.var)
    for r in cand_refs:
        # A repository the baseline lacks is C4's to hold. Here, an
        # interpolated reference must reuse the baseline's VAR for its repo.
        if r.var is not None and r.repo in base_vars and r.var not in base_vars[r.repo]:
            return False
    return True


def _c4(cand_refs: list[ImageRef], base_refs: list[ImageRef]) -> bool:
    return {r.repo for r in cand_refs} == {r.repo for r in base_refs}


def _pre_launch(obj: dict):
    return obj.get("pre_launch_script")


def _blind_any(v):
    return digest_blind(v) if isinstance(v, str) else v


def _failures(cand: dict, base: dict, role: str, cand_file: str, base_file: str) -> list[str]:
    cand_refs = image_refs(cand["docker_compose_file"])
    base_refs = image_refs(base["docker_compose_file"])
    out = []
    if not _c1(cand, base, role):
        out.append("C1")
    if not _c2(cand):
        out.append("C2")
    if not _c3(cand_refs, base_refs):
        out.append("C3")
    if not _c4(cand_refs, base_refs):
        out.append("C4")
    if role == "gateway":
        if digest_blind(cand_file) != digest_blind(base_file):
            out.append("G1")
    else:
        if digest_blind(cand_file) != digest_blind(base_file) or not _same(
                _blind_any(_pre_launch(cand)), _blind_any(_pre_launch(base))):
            out.append("M1")
    return out


def _diff(cand: dict, base: dict, cand_file: str, base_file: str) -> list[str]:
    out = []
    for k in sorted((set(cand) | set(base)) - {"docker_compose_file"}):
        if k in cand and k in base and _same(cand[k], base[k]):
            continue
        if k not in base:
            out.append(f"{k}: added {json.dumps(cand[k])[:200]}")
        elif k not in cand:
            out.append(f"{k}: removed")
        elif isinstance(cand[k], list) and isinstance(base[k], list):
            cs = [json.dumps(x) for x in cand[k]]
            bs = [json.dumps(x) for x in base[k]]
            out += [f"{k}: -{x}" for x in bs if x not in cs]
            out += [f"{k}: +{x}" for x in cs if x not in bs]
            if sorted(cs) == sorted(bs):
                out.append(f"{k}: reordered")
        elif isinstance(cand[k], str) and isinstance(base[k], str) and ("\n" in cand[k] or "\n" in base[k]):
            out += [f"{k}: {line}" for line in difflib.unified_diff(
                base[k].split("\n"), cand[k].split("\n"), "baseline", "candidate", n=0, lineterm="")]
        else:
            out.append(f"{k}: {json.dumps(base[k])} -> {json.dumps(cand[k])}")
    cand_refs = image_refs(cand["docker_compose_file"])
    base_refs = image_refs(base["docker_compose_file"])
    for r in sorted({r.repo for r in base_refs} - {r.repo for r in cand_refs}):
        out.append(f"image repository removed: {r}")
    for r in sorted({r.repo for r in cand_refs} - {r.repo for r in base_refs}):
        out.append(f"image repository added: {r}")
    base_digests = {(r.repo, r.digest) for r in base_refs}
    for r in cand_refs:
        if r.digest is None:
            out.append(f"image not pinned by digest: {r.repo}")
        elif (r.repo, r.digest) not in base_digests and r.repo in {b.repo for b in base_refs}:
            out.append(f"image digest changed: {r.repo}@{r.digest}")
    out += [f"docker_compose_file: {line}" for line in difflib.unified_diff(
        digest_blind(base_file).split("\n"), digest_blind(cand_file).split("\n"),
        "baseline", "candidate", n=0, lineterm="")]
    return out


@dataclasses.dataclass
class Verdict:
    passed: bool
    match: str
    failures: list[str]
    closest: str | None
    diff: list[str]
    # Every attempt with no failures, as (match, baseline sha256), in
    # preference order; closest and match are its first element.
    passing: list[tuple[str, str]] = dataclasses.field(default_factory=list)


def evaluate(raw: str, role: str, baselines: list[str]) -> Verdict:
    """Run C1-C4 and G1 or M1 against each baseline; pass if any one passes.

    The exact form (docker_compose_file as served) is tried against every
    baseline first. For a model, the instance-label-v1 form (both files
    normalized) is tried next, only when normalization applies to both and the
    candidate's normalized hash exists. On a hold, the attempt with the fewest
    failures names the closest baseline, its failures and its diff.
    """
    if role not in ROLES:
        raise ValueError(f"role {role!r}: gateway or model")
    cand = _parse_compose(raw)
    if cand is None:
        return Verdict(False, MATCH_EXACT, [PARSE_FAILURE], None, ["candidate is not an app_compose object"])
    parsed = []
    for b in baselines:
        base = _parse_compose(b)
        if base is None:
            raise ValueError(f"baseline {compose_sha256(b)} is not an app_compose object")
        parsed.append((compose_sha256(b), base))
    if not parsed:
        return Verdict(False, MATCH_EXACT, ["C1", "C2", "C3", "C4", "G1" if role == "gateway" else "M1"],
                       None, ["no baselines for this role"])

    attempts = []  # (failures, match, sha, base, cand_file, base_file), in preference order
    for sha, base in parsed:
        cf, bf = cand["docker_compose_file"], base["docker_compose_file"]
        attempts.append((_failures(cand, base, role, cf, bf), MATCH_EXACT, sha, base, cf, bf))
    if role == "model" and instance_label_sha256(raw) is not None:
        cf = _normalize_compose_file(cand["docker_compose_file"])
        for sha, base in parsed:
            bf = _normalize_compose_file(base["docker_compose_file"])
            if bf is not None:
                attempts.append((_failures(cand, base, role, cf, bf), MATCH_INSTANCE_LABEL, sha, base, cf, bf))

    passing = [(a[1], a[2]) for a in attempts if not a[0]]
    if passing:
        match, sha = passing[0]
        return Verdict(True, match, [], sha, [], passing)
    best = min(attempts, key=lambda a: len(a[0]))  # min keeps the first of equals
    failures, match, sha, base, cf, bf = best
    return Verdict(False, match, sorted(failures), sha, _diff(cand, base, cf, bf))


# --- baselines and CLI ---------------------------------------------------

_SEGMENT = re.compile(r"[a-z][a-z0-9-]*", re.ASCII)


def load_baselines(root: Path, environment: str, role: str) -> list[str]:
    """Raw app_compose of every <root>/<environment>/<role>/<sha256>.json, by name.

    A baseline that is not an app_compose, or that fails C2 or C3 against
    itself, refuses (ValueError): C2 and C3's digest pinning check only the
    candidate, so a compose held on them would pass against itself once
    merged into the baselines."""
    if not _SEGMENT.fullmatch(environment) or not _SEGMENT.fullmatch(role):
        raise ValueError(f"bad baseline path segment: {environment!r}/{role!r}")
    d = Path(root) / environment / role
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.glob("*.json")):
        text = p.read_bytes().decode("utf-8")
        if compose_sha256(text) != p.stem:
            raise ValueError(f"{p}: sha256 of the contents is not the file name")
        obj = _parse_compose(text)
        if obj is None:
            raise ValueError(f"{p}: not an app_compose object")
        refs = image_refs(obj["docker_compose_file"])
        failed = [rule for rule, ok in (("C2", _c2(obj)), ("C3", _c3(refs, refs))) if not ok]
        if failed:
            raise ValueError(f"{p}: the baseline itself fails {', '.join(failed)}")
        out.append(text)
    return out


def read_raw(path: Path) -> str:
    """A raw app_compose from a file: its bytes, or a JSON string wrapping them."""
    text = Path(path).read_bytes().decode("utf-8")
    try:
        inner = json.loads(text)
    except ValueError:
        return text
    return inner if isinstance(inner, str) else text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--environment", required=True, choices=ENVIRONMENTS)
    ap.add_argument("--role", required=True, choices=ROLES)
    ap.add_argument("--baselines", type=Path, default=DEFAULT_BASELINES)
    ap.add_argument("raw", type=Path)
    args = ap.parse_args(argv)
    raw = read_raw(args.raw)
    v = evaluate(raw, args.role, load_baselines(args.baselines, args.environment, args.role))
    out = dataclasses.asdict(v)
    out["sha256"] = compose_sha256(raw)
    out["instance_label_sha256"] = instance_label_sha256(raw)
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0 if v.passed else 3


if __name__ == "__main__":
    sys.exit(main())
