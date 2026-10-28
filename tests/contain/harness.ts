// Shared setup for the real-mvm suites. Each suite skips, with the reason
// printed, when mvmctl is missing or `mvmctl doctor` fails.

import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { MvmSandbox, spawnRunner, type Runner } from "../../sandbox/mvm.ts"
import { DEFAULT_IMAGE, DEFAULTS, defaultMvmctl, newSessionId } from "../../sandbox/defaults.ts"

export const mvmctl = defaultMvmctl()
export const image = process.env.RTS_IMAGE || DEFAULT_IMAGE
export const scratch = mkdtempSync(join(tmpdir(), "rts-contain-"))
export const emptyGitConfig = join(scratch, "empty.gitconfig")
writeFileSync(emptyGitConfig, "")
export const run: Runner = spawnRunner(mvmctl, emptyGitConfig)

async function probe(): Promise<string | undefined> {
  if (!(await Bun.file(mvmctl).exists())) return `mvmctl not found at ${mvmctl} (set RTS_MVMCTL)`
  try {
    const r = await run(["doctor"], { timeoutMs: 60_000 })
    if (r.code !== 0) return `mvmctl doctor failed: ${new TextDecoder().decode(r.stderr).trim().slice(0, 300)}`
  } catch (e) {
    return `mvmctl doctor could not run: ${(e as Error).message}`
  }
  return undefined
}

export const skipReason = await probe()
if (skipReason) console.warn(`[contain] skipping real-mvm tests: ${skipReason}`)
export const mvmReady = skipReason === undefined

export async function freshMachine(): Promise<MvmSandbox> {
  const sb = new MvmSandbox({ name: `rts-${newSessionId()}`, run })
  try {
    await sb.create({ name: sb.name, image, memoryMiB: 512, cpus: 1 })
  } catch (e) {
    await sb.remove().catch(() => undefined)
    throw e
  }
  return sb
}

export const limits = { timeoutMs: DEFAULTS.toolTimeoutMs, maxOutputBytes: DEFAULTS.maxOutputBytes }
export const text = (b: Uint8Array) => new TextDecoder().decode(b)
