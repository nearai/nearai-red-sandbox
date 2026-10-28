import { homedir } from "node:os"
import { join } from "node:path"

export const DEFAULT_IMAGE =
  "docker.io/library/alpine@sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42"

export function defaultMvmctl(): string {
  return process.env.RTS_MVMCTL || join(homedir(), ".local/mvm/v0.22.0/mvmctl")
}

export const DEFAULTS = {
  toolTimeoutMs: 120_000,
  maxOutputBytes: 65_536,
  memoryMiB: 2048,
  cpus: 2,
  hostRssCeilingMiB: 3072,
  // Base64 characters per argv chunk; 48 KiB was measured to pass mvmctl exec.
  argvChunkChars: 49_152,
  // Raw bytes per copyOut read; base64 of this stays under mvm's ~950 KB stdout truncation.
  copyOutChunkBytes: 524_288,
  extractMaxBytes: 256 * 1024 * 1024,
  extractMaxEntries: 10_000,
  handshakeMs: 30_000,
} as const

export function newSessionId(): string {
  const b = crypto.getRandomValues(new Uint8Array(6))
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
}
