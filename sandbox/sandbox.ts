// The backend seam. The launcher and the plugin talk to this interface,
// never to mvmctl directly.

export type ExecResult = {
  exitCode: number
  timedOut: boolean
  stdout: Uint8Array
  stderr: Uint8Array
  stdoutBytes: number
  stderrBytes: number
  truncated: boolean
}

export type ExecOptions = {
  timeoutMs: number
  maxOutputBytes: number
  // Guest directory to run in, applied by `cd` inside the guest wrapper.
  workdir?: string
}

export type CopyOutResult = { status: "exported"; files: number; bytes: number } | { status: "nothing to export" }

export interface Sandbox {
  create(spec: { name: string; image: string; memoryMiB: number; cpus: number }): Promise<void>
  exec(argv: string[], opts: ExecOptions): Promise<ExecResult>
  copyIn(hostDir: string, guestDir: string): Promise<void>
  copyOut(guestDir: string, hostDir: string): Promise<CopyOutResult>
  remove(): Promise<void>
}

// The machine is gone or can no longer be trusted to run commands. Every
// later call on the same sandbox fails the same way; nothing falls back to
// the host.
export class SandboxUnavailable extends Error {
  constructor(reason: string) {
    super(`sandbox unavailable: ${reason}`)
    this.name = "SandboxUnavailable"
  }
}
