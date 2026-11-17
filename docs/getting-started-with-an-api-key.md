# Get started with your API key

Use your supplied NEAR AI Cloud API key to start a Red Sandbox session, give the agent files to inspect, and save its results. You do not need to sign in to a personal account while the sponsored key has available credits.

## Before you begin

- An Apple silicon Mac running macOS 26 or newer, the [supported host for the bundled VM runtime](https://github.com/tinylabscom/mvm/blob/v0.22.0/README.md#install). This guide uses Red Sandbox **v0.1.4**. A Linux installer is not yet available.
- A Terminal window and an internet connection. The host uses the connection for downloads and inference even when guest networking is off.
- Your individual API key, delivered privately by the person sponsoring your access. Ask them for your allowance; each recipient has a separate key and allowance.

**First-install caveat:** setup must download the sandbox guest image. An anonymous download can fail with HTTP 302 in the bundled runtime. If that happens, ask your sponsor to arrange guest-image access using the [operator recovery instructions](../opencode/README.md#recorded-live-validation-status). Your NEAR AI API key does not authorize that registry workaround. Complete setup before proceeding to your first session.

## 1. Install Red Sandbox

Paste this into Terminal:

```sh
curl -fsSL https://github.com/nearai/nearai-red-sandbox/releases/download/v0.1.4/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
rts --version
```

The installer installs `rts` under `~/.local` and runs setup to download its dependencies. The version command should report `0.1.4`; that confirms the CLI is available, but does not establish that setup finished. If the installer reported a setup error, resolve it and rerun:

```sh
rts setup
```

For future Terminal windows, add `export PATH="$HOME/.local/bin:$PATH"` to your shell configuration if `rts` is not already on your PATH. Homebrew users can follow the [alternative installation instructions](../README.md#homebrew).

## 2. Save your API key

Keep the key private. Do not paste it into a chat, sandbox prompt, project file, or a shell command.

Copy this entire block into Terminal. When prompted, paste **only your key** and press Return. The pasted key will be hidden:

```sh
/bin/bash <<'BASH'
set -eu
umask 077
key_file="$(mktemp "${TMPDIR:-/tmp}/red-sandbox-key.XXXXXX")"
trap 'rm -f "$key_file"' EXIT
printf 'Paste the API key (hidden), then press Return: ' >/dev/tty
IFS= read -r -s api_key </dev/tty
printf '\n' >/dev/tty
printf '%s\n' "$api_key" >"$key_file"
unset api_key
rts trial --key-file "$key_file"
BASH
```

On success, you will see **“Sponsored API key saved.”** The command stores the key in macOS Keychain, replaces any previously saved connection, and deletes the temporary import file when the block ends. The actual key is not part of your shell history or passed to the agent.

Import checks the key's format; Cloud checks whether it is valid and funded when you launch or make requests. If import fails, check the error and repeat the block with the correct key.

## 3. Run your first session

Create a fresh example directory with a small input file and session configuration:

```sh
(
set -eu
tutorial_dir="$(mktemp -d "$HOME/red-sandbox-start.XXXXXX")"
cd "$tutorial_dir"
mkdir inputs
cat > inputs/hello.py <<'PYTHON'
def greet(name):
    return f"Hello, {name}!"
PYTHON
cat > session.json <<'JSON'
{
  "inputsDir": "./inputs"
}
JSON
rts launch --config ./session.json --prompt 'Read /in/hello.py and save a short explanation of what it does to /out/notes.md.'
)
```

Red Sandbox checks the inference connection, starts a fresh VM, and opens the OpenCode terminal interface. Wait for the agent to finish. If it asks for approval to write the requested report, review and approve that action.

The terminal interface runs on your Mac; the agent's file and command tools run inside the VM:

| Guest path | How to use it |
| --- | --- |
| `/in` | Copies of the files in your `inputs` directory. Editing these copies does not change your originals. |
| `/out` | Put every file you want to keep here. It is exported when the session ends. |
| `/tmp` | Temporary work that is discarded with the VM. |

Guest networking is off for this example. Model inference still works through the host. For later tasks that need downloads, choose allowed hosts before launching; see [network options](operations.md#network-access). Network policy is fixed for each session.

## 4. Exit and open your results

After the agent has saved `/out/notes.md`, type `exit` in the OpenCode prompt and press Return. Let the launcher finish exporting the results and removing the VM.

The launcher prints a line containing `results in` and the session folder. With a standard installation, folders live under:

```text
~/.local/share/nearai-red-sandbox/sessions/
```

Open the folder printed for this session. Your report is **`out/notes.md`**. Check **`launcher.log`** for any export or cleanup errors before relying on the results. Files left elsewhere inside the guest are discarded when the VM is removed.

For your own work, create a directory containing `session.json` and an `inputs` folder, following the example above. Copy the files you want inspected into `inputs`, then launch from that directory with a new prompt. Ask the agent to write its findings under `/out`. Review its findings and any generated code before using them.

## 5. Continue when the included credits run out

Your sponsored key works until Cloud stops accepting it, for example because its allowance is used up or the sponsor revokes it. Sponsor funding can also affect access.

When Cloud reports a recognized key or credit failure, Red Sandbox opens your browser for NEAR AI Cloud sign-in. Sign in to your own account and return to Terminal. Successful sign-in replaces the sponsored key with your personal connection. During an active session, the VM stays open and the rejected request is retried once.

**Your own Cloud account needs available credits.** Signing in does not add credits. If you cancel sign-in or it fails, follow the terminal error; you can sign in again with:

```sh
rts login
```

Then relaunch if needed. You can also run that command to switch accounts before the allowance is exhausted. For Google sign-in or organization/workspace selection, see [account selection](authentication.md).

## If something goes wrong

| Symptom | Next step |
| --- | --- |
| `rts: command not found` | Run `export PATH="$HOME/.local/bin:$PATH"` and try again. |
| Setup fails downloading the guest image, including HTTP 302 | Contact your sponsor for the guest-image recovery above, then rerun `rts setup`. |
| Your key is refused immediately | Check with the issuer that this is your active, funded key. Personal Cloud login may be offered instead. |
| Cloud access fails after personal sign-in | Check the selected account's credits and organization/workspace; see [authentication help](authentication.md). |
| The expected report is missing | Check the printed session folder and `launcher.log`. Only files saved under `/out` are exported. |

If you need help, share the error message and `rts --version`. Never share the API key. Inspect logs for sensitive project information before sending them.

Sponsors can find issuance, allowance, and revocation instructions in [sponsored credits](sponsored-credits.md).
