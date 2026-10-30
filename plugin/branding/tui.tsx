// opencode v2.2.2 terminal UI plugin: one muted line in the home screen's
// `home.footer` slot. Loaded only by the TUI from cli.json (written by rts
// with the model display name and attestation status as options); the
// server never loads this directory, so tools, MCP and models are untouched.
//
// No imports from @opencode/*: the default export is the plain
// { id, setup } shape that Plugin.define returns
// (packages/plugin/src/tui/plugin.ts). The published opencode binary
// applies the Solid JSX transform to this file.

import { footerText } from "./footer.ts"

// The splash palette (scripts/splash/sandbox_demo.py): muted sand (S1) and
// NEAR AI Red. Only the colours are set here; the text is footerText's.
const SAND = "#A1977F"
const RED = "#EB1924"
const TAIL = " · attested"

export default {
  id: "rts.branding",
  setup(context: any) {
    // Without rts's options this is an unexpected load; draw nothing.
    if (!context.options || typeof context.options.model !== "string") return
    const text = footerText(context.options)
    const attested = context.options.attested === true && text.endsWith(TAIL)
    const head = attested ? text.slice(0, -TAIL.length) : text
    context.ui.slot({
      append: "home.footer",
      render: () => (
        <box width="100%" paddingLeft={2} flexShrink={0}>
          <text fg={SAND}>
            {head}
            {attested ? <span style={{ fg: SAND }}>{" · "}</span> : null}
            {attested ? <span style={{ fg: RED }}>attested</span> : null}
          </text>
        </box>
      ),
    })
  },
}
