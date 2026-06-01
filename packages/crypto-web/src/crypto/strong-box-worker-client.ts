import type {
  HpkeDecapInput,
  HpkeEncapInput,
  HpkeEncapResult,
  StrongBoxBridge,
  StrongBoxDecryptInput,
  StrongBoxEncryptInput,
} from './strong-box'

type EncodedRequest =
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
  | { type: 'init-error'; error: SerializedWorkerError }
  | {
      type: 'response'
      id: number
      status: 'ok'
      result: ArrayBuffer
      meta?: { cacheHit?: boolean }
    }
  | {
      type: 'response'
      id: number
      status: 'error'
      error: SerializedWorkerError
    }

type SerializedWorkerError = {
  message: string
  name?: string
}

export class StrongBoxWorkerClient implements StrongBoxBridge {
  private readonly worker: Worker
  private readonly pending = new Map<number, PendingRequest>()
  private nextId = 0

  private constructor(worker: Worker) {
    this.worker = worker
    this.worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
      const data = event.data
      if (!data || data.type !== 'response') {
        return
      }

      const pending = this.pending.get(data.id)
      if (!pending) {
        return
      }

      this.pending.delete(data.id)

      if (data.status === 'ok') {
        const value = pending.transform ? pending.transform(data.result) : new Uint8Array(data.result)
        pending.resolve(value)
      } else {
        pending.reject(new Error(data.error?.message ?? 'StrongBox worker failed'))
      }
    })

    this.worker.addEventListener('error', (event) => {
      for (const pending of this.pending.values()) {
        pending.reject(event.error ?? new Error('StrongBox worker error'))
      }
      this.pending.clear()
    })
  }

  static async create() {
    const worker = new Worker(new URL('../workers/strong-box.worker.ts', import.meta.url), {
      type: 'module',
    })
    await waitForWorkerReady(worker)
    return new StrongBoxWorkerClient(worker)
  }

  async encrypt(input: StrongBoxEncryptInput) {
    return this.invoke('encrypt', input)
  }

  async decrypt(input: StrongBoxDecryptInput) {
    return this.invoke('decrypt', input)
  }

  async hpkeEncap(input: HpkeEncapInput): Promise<HpkeEncapResult> {
    return this.invokeHpke('hpke_encap', input)
  }

  async hpkeDecap(input: HpkeDecapInput): Promise<Uint8Array> {
    return this.invokeHpke('hpke_decap', input)
  }

  private invoke(op: 'encrypt', input: StrongBoxEncryptInput): Promise<Uint8Array>
  private invoke(op: 'decrypt', input: StrongBoxDecryptInput): Promise<Uint8Array>
  private invoke(
    op: 'encrypt' | 'decrypt',
    input: StrongBoxEncryptInput | StrongBoxDecryptInput,
  ): Promise<Uint8Array> {
    const id = this.nextId++
    const payloadView =
      op === 'encrypt'
        ? (input as StrongBoxEncryptInput).plaintext
        : (input as StrongBoxDecryptInput).ciphertext

    const message: EncodedRequest = {
      type: 'request',
      id,
      op,
      key: toTransferableBuffer(input.key),
      context: toTransferableBuffer(input.context),
      payload: toTransferableBuffer(payloadView),
    }

    const transferList = [message.key, message.context, message.payload]

    this.worker.postMessage(message, transferList)

    return new Promise<Uint8Array>((resolve, reject) => {
      this.pending.set(id, { resolve: (v) => resolve(v as Uint8Array), reject, transform: (bytes) => new Uint8Array(bytes) })
    })
  }

  private invokeHpke(op: 'hpke_encap', input: HpkeEncapInput): Promise<HpkeEncapResult>
  private invokeHpke(op: 'hpke_decap', input: HpkeDecapInput): Promise<Uint8Array>
  private invokeHpke(op: 'hpke_encap' | 'hpke_decap', input: HpkeEncapInput | HpkeDecapInput) {
    const id = this.nextId++

    const message: EncodedRequest =
      op === 'hpke_encap'
        ? (() => {
            const encap = input as HpkeEncapInput
            return {
              type: 'request' as const,
              id,
              op,
              recipientPublicKey: toTransferableBuffer(encap.recipientPublicKey),
              info: toTransferableBuffer(encap.info),
              aad: toTransferableBuffer(encap.aad),
              payload: toTransferableBuffer(encap.plaintext),
            }
          })()
        : (() => {
            const decap = input as HpkeDecapInput
            return {
              type: 'request' as const,
              id,
              op,
              recipientPrivateKey: toTransferableBuffer(decap.recipientPrivateKey),
              info: toTransferableBuffer(decap.info),
              aad: toTransferableBuffer(decap.aad),
              enc: toTransferableBuffer(decap.enc),
              payload: toTransferableBuffer(decap.ciphertext),
            }
          })()

    const transferList = (() => {
      if (op === 'hpke_encap') {
        const encap = message as Extract<EncodedRequest, { op: 'hpke_encap' }>
        return [encap.recipientPublicKey, encap.info, encap.aad, encap.payload]
      }
      const decap = message as Extract<EncodedRequest, { op: 'hpke_decap' }>
      return [decap.recipientPrivateKey, decap.info, decap.aad, decap.enc, decap.payload]
    })()

    this.worker.postMessage(message, transferList)

    return new Promise<HpkeEncapResult | Uint8Array>((resolve, reject) => {
      const transform = op === 'hpke_encap' ? decodeHpkeResult : (bytes: ArrayBuffer) => decodeHpkeResult(bytes).payload
      this.pending.set(id, {
        resolve: (value) => resolve(value as HpkeEncapResult | Uint8Array),
        reject,
        transform,
      })
    })
  }
}

type PendingRequest = {
  resolve: (value: Uint8Array | HpkeEncapResult) => void
  reject: (reason?: unknown) => void
  transform?: (value: ArrayBuffer) => Uint8Array | HpkeEncapResult
}

function toTransferableBuffer(view: Uint8Array): ArrayBuffer {
  const copy = view.slice()
  return copy.buffer
}

function decodeHpkeResult(buffer: ArrayBuffer): HpkeEncapResult & { payload: Uint8Array } {
  const view = new DataView(buffer)
  const bytes = new Uint8Array(buffer)
  const nonceLen = view.getUint32(0, true)
  const encLen = view.getUint32(4, true)
  const payloadLen = view.getUint32(8, true)

  const nonceStart = 12
  const encStart = nonceStart + nonceLen
  const payloadStart = encStart + encLen

  const nonce = bytes.slice(nonceStart, nonceStart + nonceLen)
  const enc = bytes.slice(encStart, encStart + encLen)
  const payload = bytes.slice(payloadStart, payloadStart + payloadLen)

  return { nonce, enc, ciphertext: payload, payload }
}

function waitForWorkerReady(worker: Worker) {
  return new Promise<void>((resolve, reject) => {
    const handleMessage = (event: MessageEvent<WorkerResponse>) => {
      const data = event.data
      if (!data) {
        return
      }

      if (data.type === 'ready') {
        cleanup()
        resolve()
      } else if (data.type === 'init-error') {
        cleanup()
        reject(new Error(data.error?.message ?? 'Failed to initialize StrongBox worker'))
      }
    }

    const handleError = (event: ErrorEvent) => {
      cleanup()
      reject(event.error ?? new Error(event.message))
    }

    const cleanup = () => {
      worker.removeEventListener('message', handleMessage as EventListener)
      worker.removeEventListener('error', handleError)
    }

    worker.addEventListener('message', handleMessage as EventListener)
    worker.addEventListener('error', handleError)
  })
}
