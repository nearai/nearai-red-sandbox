// Leak-detection check: swap `shell` for a host implementation through the
// RTS_TEST_LEAK seam, rerun the sentinel test, and require it to fail on
// the host-sentinel assertion. If the containment suite cannot see a leak
// this blatant, it proves nothing.

import { describe, expect, test } from "bun:test"
import { join } from "node:path"
import { OPENCODE_VERSION, hostExec } from "../../launcher/session.ts"
import { mvmReady } from "./harness.ts"

const opencode = process.env.RTS_OPENCODE || "opencode"
const ocVersion = await hostExec([opencode, "--version"]).catch(() => undefined)
const opencodeReady = ocVersion?.code === 0 && ocVersion.stdout.includes(OPENCODE_VERSION)

describe.skipIf(!mvmReady || !opencodeReady)("leak check", () => {
  test("the sentinel test fails when shell leaks to the host", async () => {
    const proc = Bun.spawn(["bun", "test", join(import.meta.dir, "session.test.ts"), "-t", "sentinel"], {
      env: { ...process.env, RTS_TEST_LEAK: "shell" },
      stdout: "pipe",
      stderr: "pipe",
    })
    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
    const text = out + err
    expect(code).not.toBe(0)
    expect(text).toContain("LEAK: host sentinel present")
  }, 300_000)
})
