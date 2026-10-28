// Operator config for one session, read from a JSON file.

import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { DEFAULT_IMAGE, DEFAULTS, defaultMvmctl } from "../sandbox/defaults.ts"
import { IMAGE_REF_RE } from "../sandbox/mvm.ts"

export type ProviderConfig = {
  id: string
  baseURL: string
  models: string[]
  apiKeyEnv: string
}

export type Limits = {
  toolTimeoutMs: number
  maxOutputBytes: number
  memoryMiB: number
  cpus: number
  hostRssCeilingMiB: number
  handshakeMs: number
}

export type OperatorConfig = {
  image: string
  inputsDir?: string
  provider: ProviderConfig
  limits: Limits
  // Where sessions/<id>/out and tools.jsonl go.
  sessionsDir: string
  opencode: string
  mvmctl: string
}

const REPO_ROOT = resolve(import.meta.dir, "..")

function fail(msg: string): never {
  throw new Error(`config: ${msg}`)
}

export function parseConfig(raw: unknown, baseDir: string): OperatorConfig {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) fail("must be a JSON object")
  const c = raw as Record<string, any>
  const p = c.provider
  if (!p || typeof p !== "object") fail("provider is required")
  for (const k of ["id", "baseURL", "apiKeyEnv"]) if (typeof p[k] !== "string" || p[k] === "") fail(`provider.${k} is required`)
  if (!/^[a-z0-9-]+$/.test(p.id)) fail("provider.id must be lowercase letters, digits and dashes")
  if (!/^https:\/\//.test(p.baseURL)) fail("provider.baseURL must be https")
  if (!/^[A-Z_][A-Z0-9_]*$/.test(p.apiKeyEnv)) fail("provider.apiKeyEnv must be an environment variable name")
  if (!Array.isArray(p.models) || p.models.length === 0 || !p.models.every((m: unknown) => typeof m === "string" && m !== "")) {
    fail("provider.models must be a non-empty list of model IDs")
  }
  const image = c.image ?? DEFAULT_IMAGE
  if (typeof image !== "string" || !IMAGE_REF_RE.test(image)) fail("image must be a digest-pinned reference (name@sha256:<64 hex>)")
  const lim = c.limits ?? {}
  const num = (k: keyof Limits, d: number) => {
    const v = lim[k] ?? d
    if (!Number.isInteger(v) || v <= 0) fail(`limits.${k} must be a positive integer`)
    return v as number
  }
  const path = (v: unknown, k: string) => {
    if (v === undefined) return undefined
    if (typeof v !== "string" || v === "") fail(`${k} must be a path`)
    return resolve(baseDir, v)
  }
  return {
    image,
    inputsDir: path(c.inputsDir, "inputsDir"),
    provider: { id: p.id, baseURL: p.baseURL, models: [...p.models], apiKeyEnv: p.apiKeyEnv },
    limits: {
      toolTimeoutMs: num("toolTimeoutMs", DEFAULTS.toolTimeoutMs),
      maxOutputBytes: num("maxOutputBytes", DEFAULTS.maxOutputBytes),
      memoryMiB: num("memoryMiB", DEFAULTS.memoryMiB),
      cpus: num("cpus", DEFAULTS.cpus),
      hostRssCeilingMiB: num("hostRssCeilingMiB", DEFAULTS.hostRssCeilingMiB),
      handshakeMs: num("handshakeMs", DEFAULTS.handshakeMs),
    },
    sessionsDir: path(c.sessionsDir, "sessionsDir") ?? resolve(REPO_ROOT, "sessions"),
    opencode: typeof c.opencode === "string" && c.opencode !== "" ? c.opencode : "opencode",
    mvmctl: path(c.mvmctl, "mvmctl") ?? defaultMvmctl(),
  }
}

export function loadConfig(file: string): OperatorConfig {
  const text = readFileSync(file, "utf8")
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch (e) {
    fail(`${file} is not valid JSON: ${(e as Error).message}`)
  }
  return parseConfig(raw, dirname(resolve(file)))
}
