"""Shell-level tests for .github/workflows/attestation-policy.yml.

Each test lifts one step's `run:` block out of the workflow and runs it under
/bin/bash (3.2 on macOS, the evaluate runner's system bash) with stub tools on
PATH. Run: python3 -m pytest -q scripts/"""

import json
import os
import pathlib
import re
import subprocess
import textwrap

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "attestation-policy.yml"
BASH = "/bin/bash"
KEY = "ab" * 32


def step_names(job):
    """The step names of job, in order."""
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(f"  {job}:")
    names = []
    for line in lines[start + 1:]:
        if re.match(r"  \S", line):
            break
        m = re.match(r"      - (?:name|uses): (.*)", line)
        if m:
            names.append(m.group(1))
    return names


def run_block(job, name):
    """The dedented `run: |` block of the step named name in job."""
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(f"  {job}:")
    i = next(n for n in range(start, len(lines)) if lines[n] == f"      - name: {name}")
    i = next(n for n in range(i, len(lines)) if lines[n] == "        run: |")
    body = []
    for line in lines[i + 1:]:
        if line.strip() and not line.startswith("          "):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


def stub(bin_dir, name, script):
    p = bin_dir / name
    p.write_text("#!/bin/bash\n" + script)
    p.chmod(0o755)


def bash(script, cwd, env):
    return subprocess.run([BASH, "-e", "-c", script], cwd=cwd, env=env, capture_output=True, text=True)


# --- finding: bash 3.2 and empty arrays -----------------------------------

def test_no_empty_array_is_expanded_bare():
    # bash < 4.4 under set -u aborts on "${a[@]}" when a=() ("unbound variable").
    # Every array the workflow may leave empty is expanded as ${a[@]+"${a[@]}"}.
    text = WORKFLOW.read_text()
    for name in set(re.findall(r"\b(\w+)=\(\)", text)):
        bare = re.findall(rf'(?<!\+)"\$\{{{name}\[@\]\}}"', text)
        assert not bare, f"{name}: bare \"${{{name}[@]}}\" expansion(s) in {WORKFLOW.name}"


@pytest.mark.parametrize("job,step,subcommand", [
    ("evaluate", "Propose", "propose"),
    ("sign", "Reproduce", "reproduce"),
])
def test_a_step_with_no_current_document_runs_under_system_bash(tmp_path, job, step, subcommand):
    if not os.path.exists(BASH):
        pytest.skip("no /bin/bash")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    stub(bin_dir, "python3", f'printf "%s\\n" "$*" >> "{calls}"\n')
    stub(bin_dir, "cosign", "exit 0\n")
    temp = tmp_path / "runner"
    (temp / "current").mkdir(parents=True)
    # Only staging has a current document; production has none (first run, or
    # assets deleted).
    (temp / "current" / "staging.json").write_text("{}")
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "RUNNER_TEMP": str(temp)}
    r = bash("set -u\n" + run_block(job, step), tmp_path, env)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = calls.read_text().splitlines()
    assert len(lines) == 2 and all(f" {subcommand} " in l for l in lines)
    production, staging = lines
    assert "--current" not in production
    assert f"--current {temp}/current/staging.json" in staging


# --- finding: a partly finished upload -------------------------------------

CURRENT = "Download and verify the current documents"
LOGGED = "Download and verify the logged documents"


def test_the_logged_documents_are_verified_before_the_current_ones():
    # The current step falls back to the log, so it needs to know whether the
    # log holds a document.
    names = step_names("sign")
    assert names.index(LOGGED) < names.index(CURRENT)


def run_current(tmp_path, statuses, verifies, logged):
    """Run the current-documents step. statuses maps an asset name to the HTTP
    status the stub curl answers; verifies maps environment -> whether the pair
    verifies; logged is the set of environments with a verified logged document."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "statuses.json").write_text(json.dumps(statuses))
    stub(bin_dir, "curl", textwrap.dedent(f"""\
        out=; url=
        while [ $# -gt 0 ]; do
          case "$1" in
            -o) out=$2; shift 2 ;;
            --max-filesize|-w) shift 2 ;;
            -*) shift ;;
            *) url=$1; shift ;;
          esac
        done
        name=${{url##*/}}
        status=$(/usr/bin/python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "{tmp_path}/statuses.json" "$name")
        case "$name" in
          *.sig) printf 'AAAA\\n' > "$out" ;;
          *) printf '{{"asset": "%s"}}\\n' "$name" > "$out" ;;
        esac
        printf '%s' "$status"
        """))
    # pkeyutl -verify succeeds only for the documents named in verifies.
    ok = " ".join(f"{e}.json" for e, v in verifies.items() if v)
    stub(bin_dir, "openssl", textwrap.dedent(f"""\
        case "$1" in
          pkey) exit 0 ;;
          pkeyutl)
            while [ $# -gt 0 ]; do [ "$1" = -in ] && doc=$2; shift; done
            for n in {ok}; do [ "${{doc##*/}}" = "$n" ] && exit 0; done
            exit 1 ;;
        esac
        exit 2
        """))
    temp = tmp_path / "runner"
    (temp / "logged").mkdir(parents=True)
    for e in logged:
        (temp / "logged" / f"{e}.json").write_text("{}")
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "RUNNER_TEMP": str(temp), "KEYS": KEY,
           "FEED_BASE": "https://example.invalid/releases/download/attestation-policy"}
    r = bash("set -u\n" + run_block("sign", CURRENT), tmp_path, env)
    return r, temp / "current"


def statuses(production, staging=(200, 200)):
    return {"production.json": production[0], "production.json.sig": production[1],
            "staging.json": staging[0], "staging.json.sig": staging[1]}


def test_a_verified_pair_is_kept(tmp_path):
    r, cur = run_current(tmp_path, statuses((200, 200)), {"production": True, "staging": True}, set())
    assert r.returncode == 0, r.stdout + r.stderr
    assert (cur / "production.json").exists() and (cur / "staging.json").exists()
    assert "::warning::" not in r.stdout


def test_no_assets_means_no_current_document(tmp_path):
    r, cur = run_current(tmp_path, statuses((404, 404)), {"staging": True}, set())
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (cur / "production.json").exists() and not (cur / "production.json.sig").exists()
    assert (cur / "staging.json").exists()


@pytest.mark.parametrize("production,verifies", [
    ((200, 404), False),  # the document uploaded, the signature's clobber removed the old one
    ((404, 200), False),  # the document's clobber removed it and its upload failed
    ((200, 200), False),  # a new document beside the old signature
])
def test_a_partial_upload_falls_back_to_the_logged_document(tmp_path, production, verifies):
    r, cur = run_current(tmp_path, statuses(production), {"production": verifies, "staging": True},
                         {"production"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "::warning::" in r.stdout and "production" in r.stdout
    # Reproduce keys on current/<env>.json: the unverified download must be gone.
    assert not (cur / "production.json").exists() and not (cur / "production.json.sig").exists()
    assert (cur / "staging.json").exists()


@pytest.mark.parametrize("production,verifies", [
    ((200, 404), False),
    ((404, 200), False),
    ((200, 200), False),
])
def test_a_partial_upload_with_nothing_logged_refuses(tmp_path, production, verifies):
    r, _ = run_current(tmp_path, statuses(production), {"production": verifies, "staging": True}, set())
    assert r.returncode != 0
    assert "refusing" in r.stderr


@pytest.mark.parametrize("production", [(500, 200), (200, 502), (0, 404)])
def test_any_other_status_refuses_even_with_a_logged_document(tmp_path, production):
    r, _ = run_current(tmp_path, statuses(production), {"production": True, "staging": True},
                       {"production", "staging"})
    assert r.returncode != 0
    assert "refusing" in r.stderr


# --- the CI key lives in Cloud KMS -------------------------------------------

def test_the_sign_job_signs_through_cloud_kms_and_holds_no_key():
    text = WORKFLOW.read_text()
    assert "SIGNING_KEY_PEM" not in text
    names = step_names("sign")
    auth = "Authenticate to the Cloud KMS signer"
    # Federation is the last thing before signing: no earlier step can reach the key.
    assert names.index("Reproduce") < names.index(auth) == names.index("Sign") - 1
    sign = run_block("sign", "Sign")
    assert '--kms-key "$CI_KMS_KEY"' in sign
    assert re.search(
        r"^  CI_KMS_KEY: projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[1-9][0-9]*$",
        text, re.M)
    lines = text.splitlines()
    start = lines.index("  sign:")
    end = next((n for n in range(start + 1, len(lines)) if re.match(r"  \S", lines[n])), len(lines))
    job = "\n".join(lines[start:end])
    assert "secrets." not in job, "the sign job must not read any secret"
    assert "      id-token: write" in job
    # Only the sign job may mint an OIDC token.
    assert text.count("id-token: write") == 1
    assert re.search(r"uses: google-github-actions/auth@[0-9a-f]{40} # v", job)
