import { afterEach, describe, expect, test } from "bun:test"
import type { MvmSandbox } from "../../sandbox/mvm.ts"
import { freshMachine, limits, mvmReady, text } from "./harness.ts"

describe.skipIf(!mvmReady)("exec protocol on real mvm", () => {
  let sb: MvmSandbox | undefined
  afterEach(async () => {
    await sb?.remove()
    sb = undefined
  })

  test("a nonzero exit is reported and does not poison the machine", async () => {
    sb = await freshMachine()
    const r = await sb.exec(["sh", "-c", "exit 3"], limits)
    expect(r.exitCode).toBe(3)
    const ok = await sb.exec(["echo", "ok"], limits)
    expect(text(ok.stdout)).toBe("ok\n")
  }, 120_000)

  test("the guest time limit kills with 137 and the machine stays usable", async () => {
    sb = await freshMachine()
    const r = await sb.exec(["sleep", "30"], { ...limits, timeoutMs: 3000 })
    expect(r.timedOut).toBe(true)
    expect(r.exitCode).toBe(137)
    const ok = await sb.exec(["echo", "ok"], limits)
    expect(ok.exitCode).toBe(0)
  }, 120_000)

  test("large stdout is capped in the guest with the full size reported", async () => {
    sb = await freshMachine()
    const r = await sb.exec(["head", "-c", "2097152", "/dev/zero"], { ...limits, maxOutputBytes: 65536 })
    expect(r.stdout.length).toBe(65536)
    expect(r.truncated).toBe(true)
    expect(r.stdoutBytes).toBe(2097152)
  }, 120_000)

  test("the guest has no network", async () => {
    sb = await freshMachine()
    const links = await sb.exec(["ip", "-o", "link"], limits)
    const names = text(links.stdout).split("\n").filter(Boolean).map((l) => l.split(":")[1]!.trim())
    expect(names).toEqual(["lo"])
    const w = await sb.exec(["wget", "-q", "-T", "5", "-O-", "http://1.1.1.1"], limits)
    expect(w.exitCode).not.toBe(0)
  }, 120_000)
})
