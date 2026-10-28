import { createHash } from "node:crypto"
import { appendFile } from "node:fs/promises"

export type AuditRecord = {
  tool: string
  callID: string
  inputSha256: string
  status: string
  durationMs: number
}

// One JSON object per line. Inputs and outputs are never stored, only a hash.
export async function appendAudit(file: string, rec: AuditRecord): Promise<void> {
  const line = JSON.stringify({
    tool: rec.tool,
    callID: rec.callID,
    inputSha256: rec.inputSha256,
    status: rec.status,
    durationMs: rec.durationMs,
  })
  await appendFile(file, line + "\n", { mode: 0o600 })
}

export function inputSha256(input: unknown): string {
  return createHash("sha256").update(JSON.stringify(input) ?? "undefined").digest("hex")
}
