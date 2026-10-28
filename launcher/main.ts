// Usage: bun launcher/main.ts --config <path>

import { loadConfig } from "./config.ts"
import { runSession } from "./session.ts"

function usage(): never {
  console.error("usage: bun launcher/main.ts --config <path>")
  process.exit(2)
}

const args = process.argv.slice(2)
const i = args.indexOf("--config")
if (i === -1 || !args[i + 1] || args.length !== 2) usage()

let code: number
try {
  code = await runSession(loadConfig(args[i + 1]!))
} catch (e) {
  console.error(`[rts] ${(e as Error).message}`)
  code = 1
}
process.exit(code)
