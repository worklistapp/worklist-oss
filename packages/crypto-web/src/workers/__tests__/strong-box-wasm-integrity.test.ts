import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { STRONG_BOX_WASM_SHA256 } from '../../crypto/wasm/strong_box_wasm_hash'
import { verifyStrongBoxWasmBytes } from '../strong-box-wasm-integrity'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const wasmPath = path.resolve(__dirname, '../../crypto/wasm/strong_box_wasm_bg.wasm')

describe('StrongBox WASM integrity', () => {
  it('keeps the committed hash constant aligned with the bundled WASM artifact', async () => {
    const bytes = await readFile(wasmPath)
    const actual = createHash('sha256').update(bytes).digest('hex')

    expect(actual).toBe(STRONG_BOX_WASM_SHA256)
    await expect(verifyStrongBoxWasmBytes(new Uint8Array(bytes))).resolves.toBeUndefined()
  })

  it('rejects bytes that do not match the expected hash', async () => {
    const expected = createHash('sha256').update(new Uint8Array([1, 2, 3])).digest('hex')

    await expect(verifyStrongBoxWasmBytes(new Uint8Array([1, 2, 4]), expected)).rejects.toThrow(
      'StrongBox WASM hash mismatch',
    )
  })
})
