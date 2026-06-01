import { copyBuiltWasm, packageWasmPath, sha256File } from './wasm-utils'

await copyBuiltWasm()
const digest = await sha256File(packageWasmPath)
console.log(`Updated ${packageWasmPath}`)
console.log(`sha256 ${digest}`)
