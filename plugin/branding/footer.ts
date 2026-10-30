// The home-screen footer line. Kept apart from tui.tsx so it can be unit
// tested without opencode's Solid JSX runtime.

export type BrandingOptions = { model?: unknown; attested?: unknown }

export function footerText(o: BrandingOptions | undefined): string {
  const parts = ["NEAR AI Red", "SandBox"]
  if (typeof o?.model === "string" && o.model.trim() !== "") parts.push(o.model.trim())
  // Only the exact boolean rts passes after verifying attestation.
  if (o?.attested === true) parts.push("attested")
  return parts.join(" · ")
}
