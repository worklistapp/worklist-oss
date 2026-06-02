import { stat } from 'node:fs/promises'

import { buildWasm, builtWasmPath, packageWasmPath, sha256File } from './wasm-utils'

const MIN_STRONG_BOX_WASM_BYTES = 1024

const isTruthyEnv = (value: string | undefined) => value === '1' || value?.toLowerCase() === 'true'
const isLinuxX64 = process.platform === 'linux' && process.arch === 'x64'
const isGitHubActions = isTruthyEnv(process.env.GITHUB_ACTIONS)
const requireExactHash = isTruthyEnv(process.env.STRONG_BOX_WASM_VERIFY_EXACT) || isLinuxX64

// GitHub Actions verification is intentionally limited to the canonical linux/x64 runner.
if (isGitHubActions && !isLinuxX64) {
  console.error('StrongBox WASM exact verification in CI requires a linux/x64 runner.')
  process.exit(1)
}

await buildWasm()

const builtPath = builtWasmPath()
await wasmSize(builtPath)
await wasmSize(packageWasmPath)
const builtHash = await sha256File(builtWasmPath())
const packageHash = await sha256File(packageWasmPath)

if (builtHash !== packageHash) {
  if (!requireExactHash) {
    console.warn(`StrongBox WASM rebuilt with a host-specific hash:`)
    console.warn(`  built:   ${builtHash} ${builtPath}`)
    console.warn(`  package: ${packageHash} ${packageWasmPath}`)
    console.warn(`Exact StrongBox WASM hash verification is enforced on linux/x64 CI.`)
    process.exit(0)
  }

  console.error(`StrongBox WASM hash mismatch:`)
  console.error(`  built:   ${builtHash} ${builtPath}`)
  console.error(`  package: ${packageHash} ${packageWasmPath}`)
  process.exit(1)
}

console.log(`StrongBox WASM verified: ${packageHash}`)

async function wasmSize(filePath: string): Promise<number> {
  const size = (await stat(filePath)).size
  if (size < MIN_STRONG_BOX_WASM_BYTES) {
    throw new Error(`StrongBox WASM artifact is unexpectedly small: ${size} bytes at ${filePath}`)
  }
  return size
}
