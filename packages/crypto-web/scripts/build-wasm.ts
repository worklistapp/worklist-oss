import { copyBuiltWasm, packageWasmPath, sha256File, writeCommittedWasmHash } from './wasm-utils'

await copyBuiltWasm()
const digest = await sha256File(packageWasmPath)
await writeCommittedWasmHash(digest)
console.log(`Updated ${packageWasmPath}`)
console.log(`sha256 ${digest}`)
