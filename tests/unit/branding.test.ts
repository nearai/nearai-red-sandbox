import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { footerText } from "../../plugin/branding/footer.ts"

const ROOT = join(import.meta.dir, "../..")

test("the footer names the product, the model and a verified attestation", () => {
  expect(footerText({ model: "DeepSeek V4.1 Flash Abliterated", attested: true })).toBe(
    "NEAR AI Red · SandBox · DeepSeek V4.1 Flash Abliterated · attested",
  )
})

test("the footer says attested only for the exact boolean true", () => {
  expect(footerText({ model: "glm-5.3-flash", attested: false })).toBe("NEAR AI Red · SandBox · glm-5.3-flash")
  for (const attested of ["true", 1, "verified", undefined, null]) {
    expect(footerText({ model: "m", attested })).toBe("NEAR AI Red · SandBox · m")
  }
})

test("a missing or empty model name leaves only the product", () => {
  expect(footerText(undefined)).toBe("NEAR AI Red · SandBox")
  expect(footerText({ model: "  ", attested: true })).toBe("NEAR AI Red · SandBox · attested")
  expect(footerText({ model: 42 })).toBe("NEAR AI Red · SandBox")
})

// The TUI loads a local plugin directory through its `tui` entry; the
// server-side shim's package.json must not grow one, or the server would
// list the shim as a TUI plugin and the TUI would load it without options.
test("the TUI plugin is a separate directory from the server shim", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "plugin/package.json"), "utf8"))
  expect(Object.keys(pkg.exports)).toEqual(["."])
  const tui = readFileSync(join(ROOT, "plugin/branding/tui.tsx"), "utf8")
  expect(tui).toContain('append: "home.footer"')
  expect(tui).toContain('from "./footer.ts"')
  expect(tui).not.toMatch(/from "@opencode/)
})
