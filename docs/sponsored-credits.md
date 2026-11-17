# Sponsored trial credits

Issue one Cloud API key per recipient from a dedicated, funded sponsor workspace. Each key has its own spending allowance and no expiration. Sponsor organization credit availability still gates every key: keep the organization funded and monitor its balance.

## Provision a recipient

Use an authorized operator Cloud session to call `POST /v1/workspaces/{workspace_id}/api-keys` with a unique recipient reference in the name. For a $5 allowance:

```json
{
  "name": "rts-sponsored-<recipient-reference>",
  "expires_at": null,
  "spendLimit": { "amount": 5000000000, "currency": "USD" }
}
```

`amount` is an integer in nano-USD: $1 is `1000000000`. Requests do not include `scale`. The creation response returns the plaintext `key` once; verify `expires_at` is null, `is_active` is true, and `spend_limit.amount` matches the intended allowance. Response money fields include `scale: 9` and `currency: "USD"`.

Keep an operator record of the recipient reference, key ID, key prefix, allowance, and issuance date. Deliver the plaintext key privately. Do not put it in source control, shell arguments, shell history, logs, or shared documents.

## Recipient setup

Save the supplied key in a private, regular host file with mode `0600`, then import it:

```sh
rts trial --key-file ./trial.key
rts launch
```

Import stores the credential in the native keyring and replaces the active credential. After successful import, remove the original file using your normal sensitive-file handling procedure. The recipient can run `rts login` at any time to switch to a personal Cloud account early.

When Cloud explicitly rejects the sponsored credential with HTTP 401 `invalid_api_key`, or a recognized HTTP 402 credit failure, RTS opens the existing browser login flow using the configured provider and options. Concurrent failures share one login flow. Successful login replaces the saved sponsored credential with the personal credential and retries each rejected request once, without restarting the VM or OpenCode. Failures using the personal credential do not trigger a repeating login loop.

Recognized credit failure types are `api_key_limit_exceeded`, `insufficient_credits`, `no_credits`, and `no_limit_configured`. These appear in `error.type`, not `error.code`.

## Monitor, adjust, or revoke

- List keys and recorded usage: `GET /v1/workspaces/{workspace_id}/api-keys`.
- Change an allowance: `PATCH /v1/workspaces/{workspace_id}/api-keys/{key_id}/spend-limit` with `{"spendLimit":{"amount":5000000000,"currency":"USD"}}`. This changes the lifetime total allowance; it does not reset recorded spend. `{"spendLimit":null}` removes the allowance, so do not use it for capped trials.
- Revoke one recipient: `DELETE /v1/workspaces/{workspace_id}/api-keys/{key_id}`; success returns HTTP 204.

The allowance is **not a hard financial ceiling**. Admission compares already recorded spend with the limit; it does not reserve the cost of an incoming request. In-flight or concurrent requests can finish after the allowance is reached and cause overage. Organization funding failures can also exhaust access before an individual allowance is used.
