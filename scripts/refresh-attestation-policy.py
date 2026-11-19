#!/usr/bin/env python3
"""Propose compose hashes for opencode/attestation-policy.json from a session
that rts verified.

NEAR AI redeploys a model or the gateway to a new TEE build, the compose hash
changes, and a strictly pinned launch refuses it (issue #25). To record the
new build, run one session with `rts launch --compose-policy mr-config-only`
(or use a pinned session that survived the redeploy by key continuity), then:

    scripts/refresh-attestation-policy.py ~/.../sessions/<id>/attestation.json
    scripts/refresh-attestation-policy.py <attestation.json> --write

Only entries rts accepted after every check (TDX quote, TCB, report_data,
mr_config_id == sha256(app_compose), and for models the GPU verdict) but
without a pin are proposed: compose_acceptance "mr-config-only" or
"key-continuity". Nothing is fetched from the network. The policy is compiled
into rts, so rebuild after --write. Each candidate's app_compose is printed:
review it (images, digests, mounts, logging) before pinning, because a pin
makes every future launch trust that build.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import sys

POLICY = pathlib.Path(__file__).resolve().parent.parent / "opencode" / "attestation-policy.json"
UNPINNED = {"mr-config-only", "key-continuity"}
HASH = re.compile(r"^[0-9a-f]{64}$")


def _entry(model, report, entry):
    """(where, info) for an evidence entry, from the report rts verified."""
    parsed = json.loads(report)
    if entry.get("role") == "gateway":
        where, info = "gateway_attestation", parsed["gateway_attestation"]["info"]
    else:
        i = entry.get("index", 0)
        where, info = f"model_attestations[{i}] for {model}", parsed["model_attestations"][i]["info"]
    if not isinstance(info, dict):
        raise ValueError(f"{where}: info is not an object")
    return where, info


def candidates(doc, policy, today):
    """New, verified, unpinned compose hashes in first-seen order. Each
    carries `app_compose` for review; it is not written to the policy."""
    # Evidence is written only once attestation verified; a session that
    # verified and later ended keeps it under one of these statuses.
    if doc.get("status") not in ("verified", "pin-failed", "signature-failed", "model-refused"):
        raise ValueError(
            f"attestation.json status is {doc.get('status')!r}: only a session whose attestation verified can be used"
        )
    if "evidence" not in doc:
        raise ValueError("attestation.json has no verified evidence")
    pinned = {e["sha256"] for e in policy["composeHashes"]}
    batches = [doc["evidence"]] + [r.get("evidence", []) for r in doc.get("reattestations", [])]
    out, seen = [], set(pinned)
    for batch in batches:
        for ev in batch:
            for entry in ev.get("entries", []):
                how = entry.get("compose_acceptance")
                if how not in UNPINNED:
                    continue
                h = entry.get("compose_hash", "")
                if not HASH.match(h):
                    raise ValueError(f"malformed compose_hash {h!r}")
                if h in seen:
                    continue
                try:
                    where, info = _entry(ev.get("model"), ev.get("report"), entry)
                    compose = json.loads(info["tcb_info"])["app_compose"]
                except (TypeError, ValueError, KeyError, IndexError, AttributeError) as e:
                    raise ValueError(f"cannot read the recorded report for compose {h}: {e!r}")
                # Trust the recorded compose, not the recorded hash field.
                if hashlib.sha256(compose.encode()).hexdigest() != h:
                    raise ValueError(f"compose_hash {h} does not match sha256 of the recorded app_compose ({where})")
                seen.add(h)
                app = info.get("app_name", "unknown app_name")
                out.append({
                    "sha256": h,
                    "recorded": today,
                    "source": f"NEAR AI production cloud-api.near.ai: {where}, info.app_name {app} ({how}, verified by rts)",
                    "app_compose": compose,
                })
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("attestation", type=pathlib.Path, help="a session's attestation.json")
    ap.add_argument("--policy", type=pathlib.Path, default=POLICY)
    ap.add_argument("--write", action="store_true", help="append the proposed entries to the policy")
    args = ap.parse_args(argv)
    try:
        doc = json.loads(args.attestation.read_text())
        policy = json.loads(args.policy.read_text())
        found = candidates(doc, policy, datetime.date.today().isoformat())
    except (OSError, ValueError, KeyError) as e:
        print(f"refresh-attestation-policy: {e}", file=sys.stderr)
        return 1
    if not found:
        print("no new compose hashes: every verified entry is already pinned")
        return 0
    for c in found:
        print(f"== {c['sha256']}\n   {c['source']}\n-- app_compose (review before pinning):\n{c['app_compose']}\n")
    if args.write:
        policy["composeHashes"].extend({k: c[k] for k in ("sha256", "recorded", "source")} for c in found)
        args.policy.write_text(json.dumps(policy, indent=2) + "\n")
        print(f"appended {len(found)} to {args.policy}; rebuild rts and review the diff", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
