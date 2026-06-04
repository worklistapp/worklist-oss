import wasmUrl from '../crypto/wasm/strong_box_wasm_bg.wasm?url'
import { PlaintextCache } from '../crypto/strong-box-cache'
import { computeStrongBoxDecryptCacheKey } from './strong-box-cache-key'
import { verifyStrongBoxWasmBytes } from './strong-box-wasm-integrity'

type StrongBoxWorkerContext = typeof globalThis & {
  postMessage(message: WorkerResponse, transfer?: Transferable[]): void
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerRequest>) => void): void
}

const ctx = self as StrongBoxWorkerContext
export {}

type WorkerRequest =
  | {
      type: 'request'
      id: number
      op: 'encrypt' | 'decrypt'
      key: ArrayBuffer
      context: ArrayBuffer
      payload: ArrayBuffer
    }
  | {
      type: 'request'
      id: number
      op: 'hpke_encap'
      recipientPublicKey: ArrayBuffer
      info: ArrayBuffer
      aad: ArrayBuffer
      payload: ArrayBuffer
    }
  | {
      type: 'request'
      id: number
      op: 'hpke_decap'
      recipientPrivateKey: ArrayBuffer
      info: ArrayBuffer
      aad: ArrayBuffer
      enc: ArrayBuffer
      payload: ArrayBuffer
    }

type WorkerResponse =
  | { type: 'ready' }
  | { type: 'init-error'; error: SerializedError }
  | { type: 'response'; id: number; status: 'ok'; result: ArrayBuffer; meta?: { cacheHit?: boolean } }
  | { type: 'response'; id: number; status: 'error'; error: SerializedError }

type SerializedError = {
  message: string
  name?: string
}

interface StrongBoxExports {
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
  strong_box_hpke_encap(
    recipient_pub_ptr: number,
    recipient_pub_len: number,
    info_ptr: number,
    info_len: number,
    aad_ptr: number,
    aad_len: number,
    plaintext_ptr: number,
    plaintext_len: number,
    result_ptr: number,
  ): void
  strong_box_hpke_decap(
    recipient_priv_ptr: number,
    recipient_priv_len: number,
    info_ptr: number,
    info_len: number,
    aad_ptr: number,
    aad_len: number,
    enc_ptr: number,
    enc_len: number,
    ciphertext_ptr: number,
    ciphertext_len: number,
    result_ptr: number,
  ): void
}

const cache = new PlaintextCache(64, 120_000)
const decoder = new TextDecoder()

let wasm: StrongBoxExports | null = null
let wasmMemory: WebAssembly.Memory | null = null
let resultStructSize = 0
let cachedUint8: Uint8Array | null = null
let cachedView: DataView | null = null

const readyPromise = initWasm()
readyPromise
  .then(() => ctx.postMessage({ type: 'ready' } satisfies WorkerResponse))
  .catch((error) => ctx.postMessage({ type: 'init-error', error: serializeError(error) } satisfies WorkerResponse))

ctx.addEventListener('message', (event: MessageEvent<WorkerRequest>) => {
  const request = event.data
  if (!request || request.type !== 'request') {
    return
  }

  readyPromise
    .then(async () => {
      try {
        await handleRequest(request)
      } catch (error) {
        ctx.postMessage(
          {
            type: 'response',
            id: request.id,
            status: 'error',
            error: serializeError(error),
          } satisfies WorkerResponse,
        )
      }
    })
    .catch((error) => {
      ctx.postMessage(
        {
          type: 'response',
          id: request.id,
          status: 'error',
          error: serializeError(error),
        } satisfies WorkerResponse,
      )
    })
})

async function handleRequest(request: WorkerRequest) {
  if (!wasm) {
    throw new Error('StrongBox WASM is not initialized')
  }

  switch (request.op) {
    case 'decrypt': {
      const key = new Uint8Array(request.key)
      const context = new Uint8Array(request.context)
      const payload = new Uint8Array(request.payload)

      const cacheKey = await computeStrongBoxDecryptCacheKey(key, context, payload)
      const cachedValue = cache.get(cacheKey)
      if (cachedValue) {
        const buffer = cachedValue.buffer as ArrayBuffer
        ctx.postMessage(
          {
            type: 'response',
            id: request.id,
            status: 'ok',
            result: buffer,
            meta: { cacheHit: true },
          } satisfies WorkerResponse,
          [buffer],
        )
        return
      }

      const plaintext = executeStrongBox('decrypt', key, context, payload)
      cache.set(cacheKey, plaintext)
      const buffer = plaintext.buffer as ArrayBuffer
      ctx.postMessage(
        {
          type: 'response',
          id: request.id,
          status: 'ok',
          result: buffer,
        } satisfies WorkerResponse,
        [buffer],
      )
      return
    }

    case 'encrypt': {
      const key = new Uint8Array(request.key)
      const context = new Uint8Array(request.context)
      const payload = new Uint8Array(request.payload)

      const ciphertext = executeStrongBox('encrypt', key, context, payload)
      const buffer = ciphertext.buffer as ArrayBuffer
      ctx.postMessage(
        {
          type: 'response',
          id: request.id,
          status: 'ok',
          result: buffer,
        } satisfies WorkerResponse,
        [buffer],
      )
      return
    }

    case 'hpke_encap': {
      const recipientPublicKey = new Uint8Array(request.recipientPublicKey)
      const info = new Uint8Array(request.info)
      const aad = new Uint8Array(request.aad)
      const payload = new Uint8Array(request.payload)

      const resultBytes = executeHpke('encap', {
        recipientKey: recipientPublicKey,
        info,
        aad,
        payload,
      })

      const buffer = resultBytes.buffer as ArrayBuffer
      ctx.postMessage(
        {
          type: 'response',
          id: request.id,
          status: 'ok',
          result: buffer,
        } satisfies WorkerResponse,
        [buffer],
      )
      return
    }

    case 'hpke_decap': {
      const recipientPrivateKey = new Uint8Array(request.recipientPrivateKey)
      const info = new Uint8Array(request.info)
      const aad = new Uint8Array(request.aad)
      const enc = new Uint8Array(request.enc)
      const ciphertext = new Uint8Array(request.payload)

      const resultBytes = executeHpke('decap', {
        recipientKey: recipientPrivateKey,
        info,
        aad,
        enc,
        payload: ciphertext,
      })

      const buffer = resultBytes.buffer as ArrayBuffer
      ctx.postMessage(
        {
          type: 'response',
          id: request.id,
          status: 'ok',
          result: buffer,
        } satisfies WorkerResponse,
        [buffer],
      )
      return
    }
  }
}

function executeStrongBox(op: 'encrypt' | 'decrypt', key: Uint8Array, context: Uint8Array, payload: Uint8Array) {
  if (!wasm || !wasmMemory) {
    throw new Error('StrongBox WASM is not ready')
  }

  const resultPtr = wasm.strong_box_alloc(resultStructSize)
  const keyRef = copyIntoWasm(key)
  const contextRef = copyIntoWasm(context)
  const payloadRef = copyIntoWasm(payload)

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

    const result = readResult(resultPtr)
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

function executeHpke(
  op: 'encap' | 'decap',
  params:
    | { recipientKey: Uint8Array; info: Uint8Array; aad: Uint8Array; payload: Uint8Array }
    | { recipientKey: Uint8Array; info: Uint8Array; aad: Uint8Array; enc: Uint8Array; payload: Uint8Array },
): Uint8Array {
  if (!wasm || !wasmMemory) {
    throw new Error('StrongBox WASM is not ready')
  }

  const resultPtr = wasm.strong_box_alloc(resultStructSize)
  const infoRef = copyIntoWasm(params.info)
  const aadRef = copyIntoWasm(params.aad)
  const payloadRef = copyIntoWasm(params.payload)
  const recipientRef = copyIntoWasm(params.recipientKey)
  const encRef = 'enc' in params ? copyIntoWasm(params.enc) : null

  try {
    if (op === 'encap') {
      wasm.strong_box_hpke_encap(
        recipientRef.ptr,
        recipientRef.len,
        infoRef.ptr,
        infoRef.len,
        aadRef.ptr,
        aadRef.len,
        payloadRef.ptr,
        payloadRef.len,
        resultPtr,
      )
    } else {
      if (!encRef) {
        throw new Error('HPKE decap missing encapsulated key')
      }
      wasm.strong_box_hpke_decap(
        recipientRef.ptr,
        recipientRef.len,
        infoRef.ptr,
        infoRef.len,
        aadRef.ptr,
        aadRef.len,
        encRef.ptr,
        encRef.len,
        payloadRef.ptr,
        payloadRef.len,
        resultPtr,
      )
    }

    const result = readResult(resultPtr)
    if (result.errorCode !== 0) {
      throw new Error(result.errorMessage ?? 'HPKE operation failed')
    }

    return result.bytes
  } finally {
    wasm.strong_box_free(resultPtr, resultStructSize)
    wasm.strong_box_free(infoRef.ptr, infoRef.capacity)
    wasm.strong_box_free(aadRef.ptr, aadRef.capacity)
    wasm.strong_box_free(payloadRef.ptr, payloadRef.capacity)
    wasm.strong_box_free(recipientRef.ptr, recipientRef.capacity)
    if (encRef) {
      wasm.strong_box_free(encRef.ptr, encRef.capacity)
    }
  }
}

async function initWasm() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('crypto.getRandomValues is required for StrongBox WASM bridge')
  }

  const imports: WebAssembly.Imports = {
    strong_box: {
      strong_box_random(ptr: number, len: number) {
        if (!wasmMemory) {
          throw new Error('WASM memory is not initialized')
        }
        const view = new Uint8Array(wasmMemory.buffer, ptr, len)
        crypto.getRandomValues(view)
        return 0
      },
    },
  }

  const bytes = await fetchVerifiedWasmBytes()
  const instance = await WebAssembly.instantiate(bytes, imports)

  const exports = instance.instance.exports
  wasm = exports as unknown as StrongBoxExports
  wasmMemory = wasm.memory
  resultStructSize = Number(wasm.strong_box_result_size())
}

function ensureUint8(): Uint8Array {
  if (!wasmMemory) {
    throw new Error('WASM memory is not initialized')
  }
  if (!cachedUint8 || cachedUint8.buffer !== wasmMemory.buffer) {
    cachedUint8 = new Uint8Array(wasmMemory.buffer)
  }
  return cachedUint8
}

function ensureDataView(): DataView {
  if (!wasmMemory) {
    throw new Error('WASM memory is not initialized')
  }
  if (!cachedView || cachedView.buffer !== wasmMemory.buffer) {
    cachedView = new DataView(wasmMemory.buffer)
  }
  return cachedView
}

function copyIntoWasm(data: Uint8Array) {
  if (!wasm) {
    throw new Error('StrongBox WASM is not ready')
  }
  const capacity = Math.max(data.byteLength, 1)
  const ptr = wasm.strong_box_alloc(capacity)
  if (data.byteLength > 0) {
    ensureUint8().set(data, ptr)
  }
  return { ptr, len: data.byteLength, capacity }
}

function readResult(resultPtr: number) {
  const view = ensureDataView()
  const valuePtr = view.getUint32(resultPtr, true)
  const valueLen = view.getUint32(resultPtr + 4, true)
  const valueCapacity = view.getUint32(resultPtr + 8, true)
  const errorCode = view.getUint32(resultPtr + 12, true)

  let bytes = new Uint8Array(0)
  let errorMessage: string | undefined

  if (valueLen > 0) {
    bytes = ensureUint8().slice(valuePtr, valuePtr + valueLen)
  }

  if (errorCode !== 0 && bytes.length > 0) {
    errorMessage = decoder.decode(bytes)
  }

  if (valueCapacity > 0) {
    wasm?.strong_box_free(valuePtr, valueCapacity)
  }

  return { bytes, errorCode, errorMessage }
}

async function fetchVerifiedWasmBytes(): Promise<ArrayBuffer> {
  const response = await fetch(wasmUrl)
  if (!response.ok) {
    throw new Error(`Failed to load StrongBox WASM from ${wasmUrl}`)
  }

  const bytes = await response.arrayBuffer()
  await verifyStrongBoxWasmBytes(new Uint8Array(bytes))
  return bytes
}

function serializeError(error: unknown): SerializedError {
  if (error instanceof Error) {
    return { message: error.message, name: error.name }
  }
  return { message: String(error) }
}
