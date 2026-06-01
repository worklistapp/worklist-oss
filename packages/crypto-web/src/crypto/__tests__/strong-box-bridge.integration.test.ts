import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'

import {
  ATTACHMENT_BLOB_CONTEXT,
  MAX_ATTACHMENT_CIPHERTEXT_BYTES,
  MAX_ATTACHMENT_PLAINTEXT_BYTES,
  buildAttachmentBlobRef,
  decodeAttachmentBlobKey,
  decryptAttachmentBytes,
  encodeAttachmentBlobKey,
  encryptAttachmentBytes,
} from '../attachment'
import { parseSealedPayloadBytes } from '../sealed-payload'
import { getStrongBoxBridge } from '../strong-box'

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
  | { type: 'init-error'; error: { message: string; name?: string } }
  | { type: 'response'; id: number; status: 'ok'; result: ArrayBuffer }
  | { type: 'response'; id: number; status: 'error'; error: { message: string; name?: string } }

type WasmRuntime = {
  wasm: StrongBoxExports
  memory: WebAssembly.Memory
  resultStructSize: number
}

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const wasmPath = path.resolve(__dirname, '../wasm/strong_box_wasm_bg.wasm')

let wasmRuntimePromise: Promise<WasmRuntime> | null = null

async function loadWasmRuntime(): Promise<WasmRuntime> {
  if (!wasmRuntimePromise) {
    wasmRuntimePromise = (async () => {
      const bytes = await readFile(path.resolve(wasmPath))
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
      const resultStructSize = Number(wasm.strong_box_result_size())
      return { wasm, memory, resultStructSize }
    })()
  }
  return wasmRuntimePromise
}

class InlineStrongBoxWorker {
  private listeners = new Set<(event: MessageEvent<WorkerResponse>) => void>()
  private readonly runtimePromise = loadWasmRuntime()

  constructor() {
    this.runtimePromise
      .then(() => this.emit({ type: 'ready' }))
      .catch((error) => this.emit({ type: 'init-error', error: serializeError(error) }))
  }

  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerResponse>) => void) {
    if (type === 'message') {
      this.listeners.add(listener)
    }
  }

  removeEventListener(type: 'message', listener: (event: MessageEvent<WorkerResponse>) => void) {
    if (type === 'message') {
      this.listeners.delete(listener)
    }
  }

  postMessage(message: WorkerRequest, _transfer?: Transferable[]) {
    if (!message || message.type !== 'request') {
      return
    }

    this.runtimePromise
      .then((runtime) => this.handleRequest(runtime, message))
      .catch((error) => {
        this.emit({
          type: 'response',
          id: message.id,
          status: 'error',
          error: serializeError(error),
        })
      })
  }

  private emit(data: WorkerResponse) {
    const event = { data } as MessageEvent<WorkerResponse>
    for (const listener of this.listeners) {
      listener(event)
    }
  }

  private handleRequest(runtime: WasmRuntime, request: WorkerRequest) {
    try {
      if (request.op === 'encrypt' || request.op === 'decrypt') {
        const key = new Uint8Array(request.key)
        const context = new Uint8Array(request.context)
        const payload = new Uint8Array(request.payload)
        const result = executeStrongBox(runtime, request.op, key, context, payload)

        const buffer = new Uint8Array(result).buffer as ArrayBuffer
        this.emit({ type: 'response', id: request.id, status: 'ok', result: buffer })
        return
      }

      if (request.op === 'hpke_encap') {
        const recipient = new Uint8Array(request.recipientPublicKey)
        const info = new Uint8Array(request.info)
        const aad = new Uint8Array(request.aad)
        const payload = new Uint8Array(request.payload)
        const result = executeHpke(runtime, 'encap', { recipientKey: recipient, info, aad, payload })
        const buffer = new Uint8Array(result).buffer as ArrayBuffer
        this.emit({ type: 'response', id: request.id, status: 'ok', result: buffer })
        return
      }

      const decap = request as Extract<WorkerRequest, { op: 'hpke_decap' }>
      const recipientPriv = new Uint8Array(decap.recipientPrivateKey)
      const info = new Uint8Array(decap.info)
      const aad = new Uint8Array(decap.aad)
      const enc = new Uint8Array(decap.enc)
      const ciphertext = new Uint8Array(decap.payload)
      const result = executeHpke(runtime, 'decap', { recipientKey: recipientPriv, info, aad, enc, payload: ciphertext })
      const buffer = new Uint8Array(result).buffer as ArrayBuffer
      this.emit({ type: 'response', id: request.id, status: 'ok', result: buffer })
    } catch (error) {
      this.emit({
        type: 'response',
        id: request.id,
        status: 'error',
        error: serializeError(error),
      })
    }
  }
}

function serializeError(error: unknown) {
  if (error instanceof Error) {
    return { message: error.message, name: error.name }
  }
  return { message: String(error) }
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

function executeHpke(
  runtime: WasmRuntime,
  op: 'encap' | 'decap',
  params:
    | { recipientKey: Uint8Array; info: Uint8Array; aad: Uint8Array; payload: Uint8Array }
    | { recipientKey: Uint8Array; info: Uint8Array; aad: Uint8Array; enc: Uint8Array; payload: Uint8Array },
): Uint8Array {
  const { wasm, memory, resultStructSize } = runtime

  const resultPtr = wasm.strong_box_alloc(resultStructSize)
  const recipientRef = copyIntoWasm(wasm, memory, params.recipientKey)
  const infoRef = copyIntoWasm(wasm, memory, params.info)
  const aadRef = copyIntoWasm(wasm, memory, params.aad)
  const payloadRef = copyIntoWasm(wasm, memory, params.payload)
  const encRef = 'enc' in params ? copyIntoWasm(wasm, memory, params.enc) : null

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
        throw new Error('missing encapsulated public key')
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

    const result = readResult(wasm, memory, resultPtr)
    if (result.errorCode !== 0) {
      throw new Error(result.errorMessage ?? 'HPKE operation failed')
    }
    return result.bytes
  } finally {
    wasm.strong_box_free(resultPtr, resultStructSize)
    wasm.strong_box_free(recipientRef.ptr, recipientRef.capacity)
    wasm.strong_box_free(infoRef.ptr, infoRef.capacity)
    wasm.strong_box_free(aadRef.ptr, aadRef.capacity)
    wasm.strong_box_free(payloadRef.ptr, payloadRef.capacity)
    if (encRef) {
      wasm.strong_box_free(encRef.ptr, encRef.capacity)
    }
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

describe('StrongBox WASM bridge (integration)', () => {
  let originalWorker: typeof Worker | undefined

  beforeEach(() => {
    // Use the actual WASM implementation but bypass the browser Worker by stubbing a local worker.
    // A real Worker is still required, but the inline stub uses the same exports the worker would.
    originalWorker = globalThis.Worker as typeof Worker | undefined
    ;(globalThis as unknown as { Worker?: typeof Worker }).Worker = InlineStrongBoxWorker as unknown as typeof Worker
  })

  afterEach(() => {
    ;(globalThis as unknown as { Worker?: typeof Worker }).Worker = originalWorker
  })

  it('round-trips and rejects tampering via the StrongBox bridge', async () => {
    const bridge = await getStrongBoxBridge()
    const key = crypto.getRandomValues(new Uint8Array(32))
    const context = new TextEncoder().encode('worklist.work_list.v1')
    const plaintext = new TextEncoder().encode('strong-box wasm round trip')

    const ciphertext = await bridge.encrypt({ key, context, plaintext })
    expect(ciphertext).not.toEqual(plaintext)

    const recovered = await bridge.decrypt({ key, context, ciphertext })
    expect(Array.from(recovered)).toEqual(Array.from(plaintext))

    const tampered = new Uint8Array(ciphertext)
    tampered[tampered.length - 1] ^= 0xff
    await expect(bridge.decrypt({ key, context, ciphertext: tampered })).rejects.toThrow()
  })

  it('keeps attachment size overhead aligned with StrongBox framing', async () => {
    const bridge = await getStrongBoxBridge()
    const key = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = new Uint8Array(100_000)
    const ciphertext = await bridge.encrypt({
      key,
      context: ATTACHMENT_BLOB_CONTEXT,
      plaintext,
    })
    const overhead = ciphertext.length - plaintext.length
    const expectedOverhead = MAX_ATTACHMENT_CIPHERTEXT_BYTES - MAX_ATTACHMENT_PLAINTEXT_BYTES
    expect(overhead).toBe(expectedOverhead)
  })

  it('encrypts attachment bytes and blob references before upload metadata is serialized', async () => {
    const bridge = await getStrongBoxBridge()
    const fileKey = crypto.getRandomValues(new Uint8Array(32))
    const listKey = crypto.getRandomValues(new Uint8Array(32))
    const objectKey = 'workspaces/workspace-1/attachments/attachment-1'
    const plaintext = new TextEncoder().encode(
      'sensitive attachment content that must not appear in storage',
    )

    const encrypted = await encryptAttachmentBytes({ plaintext, fileKey, strongBox: bridge })

    expect(encrypted.ciphertext).not.toEqual(plaintext)
    expect(bytesContainSequence(encrypted.ciphertext, plaintext)).toBe(false)
    const recovered = await decryptAttachmentBytes({
      ciphertext: encrypted.ciphertext,
      fileKey,
      encContext: encrypted.enc_context,
      strongBox: bridge,
    })
    expect(Array.from(recovered)).toEqual(Array.from(plaintext))

    const blobRef = buildAttachmentBlobRef({
      objectKey,
      ciphertextBytes: encrypted.ciphertext.length,
      fileKey,
      encContext: encrypted.enc_context,
    })
    const blobKey = await encodeAttachmentBlobKey({ listKey, blobRef, strongBox: bridge })
    const sealedBlobKey = parseSealedPayloadBytes(blobKey)

    expect(bytesContainSequence(sealedBlobKey.ciphertext, new TextEncoder().encode(objectKey))).toBe(
      false,
    )
    expect(bytesContainSequence(sealedBlobKey.ciphertext, fileKey)).toBe(false)
    const decodedBlobRef = await decodeAttachmentBlobKey({ listKey, blobKey, strongBox: bridge })
    expect(decodedBlobRef).toMatchObject({
      version: blobRef.version,
      object_key: blobRef.object_key,
      ciphertext_bytes: blobRef.ciphertext_bytes,
      enc_context: blobRef.enc_context,
    })
    expect(Array.from(decodedBlobRef.file_key)).toEqual(Array.from(blobRef.file_key))
  })

  it('matches the RFC 9180 X25519 ChaCha20-Poly1305 vector in WASM and JS fallback', async () => {
    const originalGetRandomValues = crypto.getRandomValues
    const originalImportKey = crypto.subtle.importKey
    const senderPrivate = hexBytes('f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600')
    const recipientPriv = hexBytes('8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb')
    const recipientPub = hexBytes('4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a')
    const info = hexBytes('4f6465206f6e2061204772656369616e2055726e')
    const aad = hexBytes('436f756e742d30')
    const plaintext = hexBytes('4265617574792069732074727574682c20747275746820626561757479')
    const expectedEnc = hexBytes('1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a')
    const expectedNonce = hexBytes('5c4d98150661b848853b547f')
    const expectedCiphertext = hexBytes(
      '1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db' +
        '21993c62ce81883d2dd1b51a28',
    )
    const rng = createFixedRng(senderPrivate)
    vi.spyOn(crypto, 'getRandomValues').mockImplementation((array) => rng.next(array))
    vi.spyOn(crypto.subtle, 'importKey').mockImplementation((...args) => {
      const algorithm = args[2]
      const algorithmName = typeof algorithm === 'string' ? algorithm : (algorithm as { name?: string })?.name
      if (algorithmName === 'X25519') {
        return Promise.reject(new DOMException('X25519 not supported', 'NotSupportedError'))
      }
      return originalImportKey.apply(crypto.subtle, args as Parameters<typeof originalImportKey>)
    })

    try {
      const { hpkeSeal, hpkeOpen, encodeHpkeEnvelope, decodeHpkeEnvelope } = await import('../hpke')

      const wasmSeal = await hpkeSeal({ recipientPublicKey: recipientPub, info, aad, plaintext })
      const wasmEnvelopeBytes = encodeHpkeEnvelope(wasmSeal)
      const decodedWasmEnvelope = decodeHpkeEnvelope(wasmEnvelopeBytes)
      expect(decodedWasmEnvelope.version).toBe(1)
      expect(decodedWasmEnvelope.suite).toEqual({ kem: 0x0020, kdf: 0x0001, aead: 0x0003, mode: 0x00 })
      expectBytes(wasmSeal.enc, expectedEnc)
      expectBytes(wasmSeal.nonce, expectedNonce)
      expectBytes(wasmSeal.ciphertext, expectedCiphertext)
      const wasmPlaintext = await hpkeOpen({
        recipientPrivateKey: recipientPriv,
        info,
        aad,
        envelope: decodedWasmEnvelope,
      })

      expect(Array.from(wasmPlaintext)).toEqual(Array.from(plaintext))

      // Force JS fallback: remove Worker and reset module + RNG.
      rng.reset()
      ;(globalThis as unknown as { Worker?: typeof Worker }).Worker = undefined as unknown as typeof Worker
      await vi.resetModules()

      const {
        hpkeSeal: hpkeSealFallback,
        hpkeOpen: hpkeOpenFallback,
        encodeHpkeEnvelope: encodeHpkeEnvelopeFallback,
        decodeHpkeEnvelope: decodeHpkeEnvelopeFallback,
      } = await import('../hpke')

      const jsSeal = await hpkeSealFallback({ recipientPublicKey: recipientPub, info, aad, plaintext })
      const fallbackEnvelope = encodeHpkeEnvelopeFallback(jsSeal)
      const decodedFallbackEnvelope = decodeHpkeEnvelopeFallback(fallbackEnvelope)
      expect(decodedFallbackEnvelope.version).toBe(1)
      expect(decodedFallbackEnvelope.suite).toEqual({ kem: 0x0020, kdf: 0x0001, aead: 0x0003, mode: 0x00 })
      expectBytes(jsSeal.enc, expectedEnc)
      expectBytes(jsSeal.nonce, expectedNonce)
      expectBytes(jsSeal.ciphertext, expectedCiphertext)

      const jsPlaintext = await hpkeOpenFallback({
        recipientPrivateKey: recipientPriv,
        info,
        aad,
        envelope: decodedFallbackEnvelope,
      })

      expect(Array.from(jsPlaintext)).toEqual(Array.from(plaintext))
    } finally {
      await vi.resetModules()
      vi.restoreAllMocks()
      ;(globalThis as unknown as { Worker?: typeof Worker }).Worker = originalWorker
      crypto.getRandomValues = originalGetRandomValues
      crypto.subtle.importKey = originalImportKey
    }
  })

  it('opens legacy KEM 0x0010 HPKE envelopes without using the WASM decap path', async () => {
    const recipientPriv = hexBytes('8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb')
    const info = hexBytes('4f6465206f6e2061204772656369616e2055726e')
    const aad = hexBytes('436f756e742d30')
    const plaintext = hexBytes('4265617574792069732074727574682c20747275746820626561757479')
    // Frozen vector from the legacy frontend HPKE implementation in commit 012e0aa:
    // KEM 0x0010 and direct DH-to-key-schedule derivation with X25519 key material.
    // This keeps the frontend's historical CBOR map encoding; the Rust vector
    // uses the Rust CBOR serializer shape for the same legacy schedule.
    const legacyEnvelopeBytes = hexBytes(
      'b900046776657273696f6e01657375697465b90004636b656d10636b646601646165616403646d6f646500' +
        '63656e63d84058201afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a' +
        '6a63697068657274657874d840582de29a6da179f38857a9ad6f110739d9170bad9b2fb125a0ac9361b29dce6ea6e91113c7e30f771b61acd3af6208',
    )
    const consoleInfoSpy = vi.spyOn(console, 'info').mockImplementation(() => undefined)
    const originalImportKey = crypto.subtle.importKey
    vi.spyOn(crypto.subtle, 'importKey').mockImplementation((...args) => {
      const algorithm = args[2]
      const algorithmName = typeof algorithm === 'string' ? algorithm : (algorithm as { name?: string })?.name
      if (algorithmName === 'X25519') {
        return Promise.reject(new DOMException('X25519 not supported', 'NotSupportedError'))
      }
      return originalImportKey.apply(crypto.subtle, args as Parameters<typeof originalImportKey>)
    })

    try {
      await vi.resetModules()
      const { hpkeOpen, decodeHpkeEnvelope } = await import('../hpke')
      const decodedLegacyEnvelope = decodeHpkeEnvelope(legacyEnvelopeBytes)
      expect(decodedLegacyEnvelope.suite).toEqual({ kem: 0x0010, kdf: 0x0001, aead: 0x0003, mode: 0x00 })

      const recovered = await hpkeOpen({
        recipientPrivateKey: recipientPriv,
        info,
        aad,
        envelope: decodedLegacyEnvelope,
      })

      expect(Array.from(recovered)).toEqual(Array.from(plaintext))
      expect(consoleInfoSpy).toHaveBeenCalledWith('[crypto] legacy_hpke_open', {
        operation: 'legacy_hpke_open',
        suiteKem: '0x0010',
      })
    } finally {
      await vi.resetModules()
      vi.restoreAllMocks()
      crypto.subtle.importKey = originalImportKey
    }
  })
})

function bytesContainSequence(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) {
    return true
  }
  if (needle.length > haystack.length) {
    return false
  }
  for (let offset = 0; offset <= haystack.length - needle.length; offset += 1) {
    let matches = true
    for (let index = 0; index < needle.length; index += 1) {
      if (haystack[offset + index] !== needle[index]) {
        matches = false
        break
      }
    }
    if (matches) {
      return true
    }
  }
  return false
}

function expectBytes(actual: Uint8Array | undefined, expected: Uint8Array) {
  expect(actual).toBeDefined()
  expect(bytesToHex(actual ?? new Uint8Array(0))).toBe(bytesToHex(expected))
}

function hexBytes(hex: string): Uint8Array {
  const normalized = hex.replace(/\s+/g, '')
  if (normalized.length % 2 !== 0) {
    throw new Error('hex string must have an even number of digits')
  }
  const bytes = new Uint8Array(normalized.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function createFixedRng(bytes: Uint8Array) {
  return {
    next(target: ArrayBufferView) {
      const view = target as Uint8Array
      if (view.length > bytes.length) {
        throw new Error('fixed RNG target is longer than the configured bytes')
      }
      view.set(bytes.subarray(0, view.length))
      return view
    },
    reset() {},
  }
}
