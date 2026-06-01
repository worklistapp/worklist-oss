import { buildWasm, builtWasmPath, packageWasmPath, sha256File } from './wasm-utils'

await buildWasm()

const builtHash = await sha256File(builtWasmPath())
const packageHash = await sha256File(packageWasmPath)

if (builtHash !== packageHash) {
  console.error(`StrongBox WASM hash mismatch:`)
  console.error(`  built:   ${builtHash} ${builtWasmPath()}`)
  console.error(`  package: ${packageHash} ${packageWasmPath}`)
  process.exit(1)
}

console.log(`StrongBox WASM verified: ${packageHash}`)
