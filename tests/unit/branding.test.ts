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

// Presentation only: tui.tsx draws footerText's exact text, in the splash's
// muted sand, with the trailing "attested" in NEAR AI Red.
test("the footer is drawn in sand with attested in red, from footerText's text", () => {
  const tui = readFileSync(join(ROOT, "plugin/branding/tui.tsx"), "utf8")
  expect(tui).toContain('const SAND = "#A1977F"')
  expect(tui).toContain('const RED = "#EB1924"')
  expect(tui).toContain("const text = footerText(context.options)")
  expect(tui).toContain('const TAIL = " · attested"')
  expect(tui).toContain("context.options.attested === true && text.endsWith(TAIL)")
  expect(tui).toContain("<span style={{ fg: RED }}>attested</span>")
  // The split pieces join back to the footer text.
  const text = footerText({ model: "m", attested: true })
  const TAIL = " · attested"
  expect(text.slice(0, -TAIL.length) + " · " + "attested").toBe(text)
})
