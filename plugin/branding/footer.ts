// The home-screen footer line. Kept apart from tui.tsx so it can be unit
// tested without opencode's Solid JSX runtime.

export type BrandingOptions = { model?: unknown; attested?: unknown }

const MAX_MODEL_CHARS = 64

// rts sanitizes the name too (src/config.rs model_display_name); this is the
// second layer. Control and bidi-format characters could reach the terminal or
// reorder text, and a separator in the name could fake a status segment.
const STRIP = /[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩·•‧∙⋅・･]/g

function cleanModel(model: unknown): string {
  if (typeof model !== "string") return ""
  return [...model.replace(STRIP, " ").replace(/\s+/g, " ").trim()].slice(0, MAX_MODEL_CHARS).join("").trim()
}

export function footerText(o: BrandingOptions | undefined): string {
  const parts = ["NEAR AI Red", "SandBox"]
  const model = cleanModel(o?.model)
  if (model !== "") parts.push(model)
  // Only the exact boolean rts passes after verifying attestation.
  parts.push(o?.attested === true ? "attested" : "unattested")
  return parts.join(" · ")
}
