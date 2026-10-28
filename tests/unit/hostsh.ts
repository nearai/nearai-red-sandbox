// TEST ONLY. A Sandbox that runs the real guest wrapper with the host's
// own sh, so unit tests can check the fixed guest scripts end to end
// against a temp directory. It is the opposite of a sandbox and must never
// be used outside tests/unit.

import { newNonce, parseResult, wrapArgv } from "../../sandbox/protocol.ts"
import type { CopyOutResult, ExecOptions, ExecResult, Sandbox } from "../../sandbox/sandbox.ts"

export class HostShellSandbox implements Sandbox {
  execs: string[][] = []
  async create() {}
  async remove() {}
  async copyIn(): Promise<void> {
    throw new Error("not in HostShellSandbox")
  }
  async copyOut(): Promise<CopyOutResult> {
    throw new Error("not in HostShellSandbox")
  }
  async exec(argv: string[], o: ExecOptions): Promise<ExecResult> {
    this.execs.push(argv)
    const nonce = newNonce()
    const wrapped = wrapArgv(argv, { nonce, timeoutSec: Math.max(1, Math.ceil(o.timeoutMs / 1000)), maxOutputBytes: o.maxOutputBytes, workdir: o.workdir })
    const p = Bun.spawn(wrapped, { stdin: "ignore", stdout: "pipe", stderr: "pipe" })
    const [out, err] = await Promise.all([new Response(p.stdout).bytes(), new Response(p.stderr).bytes(), p.exited])
    const r = parseResult(out, err, nonce)
    if (r === "no-trailer") throw new Error("no trailer from host sh")
    return r
  }
}
