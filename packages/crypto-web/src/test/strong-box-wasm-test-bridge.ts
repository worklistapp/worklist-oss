import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { StrongBoxBridge } from '../crypto/strong-box'

type StrongBoxExports = {
  memory: WebAssembly.Memory
  strong_box_result_size(): number
  strong_box_alloc(len: number): number
  strong_box_free(ptr: number, capacity: number): void
  strong_box_encrypt(
    keyPtr: number,
    keyLen: number,
    contextPtr: number,
    contextLen: number,
    plaintextPtr: number,
    plaintextLen: number,
    resultPtr: number,
  ): void
  strong_box_decrypt(
    keyPtr: number,
    keyLen: number,
    contextPtr: number,
    contextLen: number,
    ciphertextPtr: number,
    ciphertextLen: number,
    resultPtr: number,
  ): void
}

type WasmRuntime = {
  wasm: StrongBoxExports
  memory: WebAssembly.Memory
  resultStructSize: number
}

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const wasmPath = path.resolve(__dirname, '../crypto/wasm/strong_box_wasm_bg.wasm')

let runtimePromise: Promise<WasmRuntime> | null = null

export async function createStrongBoxWasmTestBridge(): Promise<StrongBoxBridge> {
  const runtime = await loadRuntime()
  return {
    async encrypt({ key, context, plaintext }) {
      return executeStrongBox(runtime, 'encrypt', key, context, plaintext)
    },
    async decrypt({ key, context, ciphertext }) {
      return executeStrongBox(runtime, 'decrypt', key, context, ciphertext)
    },
  }
}

async function loadRuntime(): Promise<WasmRuntime> {
  if (!runtimePromise) {
    runtimePromise = (async () => {
      const bytes = await readFile(wasmPath)
      let memory: WebAssembly.Memory | null = null
      const imports: WebAssembly.Imports = {
        strong_box: {
          strong_box_random(ptr: number, len: number) {
            if (!memory) {
              throw new Error('WASM memory is not initialized')
            }
            const view = new Uint8Array(memory.buffer, ptr, len)
            crypto.getRandomValues(view)
            return 0
          },
        },
      }

      const { instance } = await WebAssembly.instantiate(bytes, imports)
      const wasm = instance.exports as unknown as StrongBoxExports
      memory = wasm.memory
      return {
        wasm,
        memory,
        resultStructSize: Number(wasm.strong_box_result_size()),
      }
    })()
  }
  return runtimePromise
}

function executeStrongBox(
  runtime: WasmRuntime,
  op: 'encrypt' | 'decrypt',
  key: Uint8Array,
  context: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  const { wasm, memory, resultStructSize } = runtime
  const resultPtr = wasm.strong_box_alloc(resultStructSize)
  const keyRef = copyIntoWasm(wasm, memory, key)
  const contextRef = copyIntoWasm(wasm, memory, context)
  const payloadRef = copyIntoWasm(wasm, memory, payload)

  try {
    if (op === 'encrypt') {
      wasm.strong_box_encrypt(
        keyRef.ptr,
        keyRef.len,
        contextRef.ptr,
        contextRef.len,
        payloadRef.ptr,
        payloadRef.len,
        resultPtr,
      )
    } else {
      wasm.strong_box_decrypt(
        keyRef.ptr,
        keyRef.len,
        contextRef.ptr,
        contextRef.len,
        payloadRef.ptr,
        payloadRef.len,
        resultPtr,
      )
    }

    const result = readResult(wasm, memory, resultPtr)
    if (result.errorCode !== 0) {
      throw new Error(result.errorMessage ?? 'StrongBox operation failed')
    }
    return result.bytes
  } finally {
    wasm.strong_box_free(resultPtr, resultStructSize)
    wasm.strong_box_free(keyRef.ptr, keyRef.capacity)
    wasm.strong_box_free(contextRef.ptr, contextRef.capacity)
    wasm.strong_box_free(payloadRef.ptr, payloadRef.capacity)
  }
}

function copyIntoWasm(wasm: StrongBoxExports, memory: WebAssembly.Memory, data: Uint8Array) {
  const capacity = Math.max(data.byteLength, 1)
  const ptr = wasm.strong_box_alloc(capacity)
  if (data.byteLength > 0) {
    new Uint8Array(memory.buffer, ptr, data.byteLength).set(data)
  }
  return { ptr, len: data.byteLength, capacity }
}

function readResult(wasm: StrongBoxExports, memory: WebAssembly.Memory, resultPtr: number) {
  const view = new DataView(memory.buffer)
  const valuePtr = view.getUint32(resultPtr, true)
  const valueLen = view.getUint32(resultPtr + 4, true)
  const valueCapacity = view.getUint32(resultPtr + 8, true)
  const errorCode = view.getUint32(resultPtr + 12, true)

  let bytes = new Uint8Array(0)
  let errorMessage: string | undefined
  if (valueLen > 0) {
    bytes = new Uint8Array(memory.buffer.slice(valuePtr, valuePtr + valueLen))
  }
  if (errorCode !== 0 && bytes.length > 0) {
    errorMessage = new TextDecoder().decode(bytes)
  }
  if (valueCapacity > 0) {
    wasm.strong_box_free(valuePtr, valueCapacity)
  }

  return { bytes, errorCode, errorMessage }
}
