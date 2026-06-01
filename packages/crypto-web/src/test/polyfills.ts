import { Buffer } from 'node:buffer'
import { webcrypto } from 'node:crypto'

const createMemoryStorage = () => {
  const store = new Map<string, string>()

  return {
    get length() {
      return store.size
    },
    clear() {
      store.clear()
    },
    getItem(key: string) {
      return store.has(key) ? store.get(key)! : null
    },
    key(index: number) {
      return Array.from(store.keys())[index] ?? null
    },
    removeItem(key: string) {
      store.delete(key)
    },
    setItem(key: string, value: string) {
      store.set(key, value)
    },
  }
}

const storage = createMemoryStorage()

function hasLocalStorage(scope: unknown): boolean {
  try {
    return typeof (scope as { localStorage?: unknown }).localStorage !== 'undefined'
  } catch {
    return false
  }
}

if (!hasLocalStorage(globalThis)) {
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    writable: true,
    value: storage,
  })
}

if (typeof window !== 'undefined' && !hasLocalStorage(window)) {
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    writable: true,
    value: storage,
  })
}

// sessionStorage is also required by MSW's cookie store
if (typeof globalThis.sessionStorage === 'undefined') {
  Object.defineProperty(globalThis, 'sessionStorage', {
    configurable: true,
    writable: true,
    value: createMemoryStorage(),
  })
}

if (typeof window !== 'undefined' && typeof window.sessionStorage === 'undefined') {
  Object.defineProperty(window, 'sessionStorage', {
    configurable: true,
    writable: true,
    value: createMemoryStorage(),
  })
}

type TestSubtleDelegate = {
  decrypt: (...args: unknown[]) => Promise<ArrayBuffer>
  deriveBits: (...args: unknown[]) => Promise<ArrayBuffer>
  deriveKey: (...args: unknown[]) => Promise<CryptoKey>
  digest: (...args: unknown[]) => Promise<ArrayBuffer>
  encrypt: (...args: unknown[]) => Promise<ArrayBuffer>
  exportKey: (...args: unknown[]) => ReturnType<SubtleCrypto['exportKey']>
  generateKey: (...args: unknown[]) => ReturnType<SubtleCrypto['generateKey']>
  importKey: (...args: unknown[]) => Promise<CryptoKey>
  sign: (...args: unknown[]) => Promise<ArrayBuffer>
  unwrapKey: (...args: unknown[]) => Promise<CryptoKey>
  verify: (...args: unknown[]) => Promise<boolean>
  wrapKey: (...args: unknown[]) => Promise<ArrayBuffer>
}

const nodeSubtle = webcrypto.subtle as unknown as TestSubtleDelegate
const testSubtle = {
  decrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource) {
    return nodeSubtle.decrypt(normalizeCryptoInput(algorithm) as AlgorithmIdentifier, key, toNodeBuffer(data))
  },
  deriveBits(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number | null) {
    return nodeSubtle.deriveBits(normalizeCryptoInput(algorithm) as AlgorithmIdentifier, baseKey, length)
  },
  deriveKey(
    algorithm: AlgorithmIdentifier,
    baseKey: CryptoKey,
    derivedKeyType: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ) {
    return nodeSubtle.deriveKey(
      normalizeCryptoInput(algorithm) as AlgorithmIdentifier,
      baseKey,
      normalizeCryptoInput(derivedKeyType) as AlgorithmIdentifier,
      extractable,
      keyUsages,
    )
  },
  digest(algorithm: AlgorithmIdentifier, data: BufferSource) {
    return nodeSubtle.digest(normalizeCryptoInput(algorithm) as AlgorithmIdentifier, toNodeBuffer(data))
  },
  encrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource) {
    return nodeSubtle.encrypt(normalizeCryptoInput(algorithm) as AlgorithmIdentifier, key, toNodeBuffer(data))
  },
  exportKey(format: KeyFormat, key: CryptoKey) {
    return nodeSubtle.exportKey(format, key)
  },
  generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]) {
    return nodeSubtle.generateKey(normalizeCryptoInput(algorithm) as AlgorithmIdentifier, extractable, keyUsages)
  },
  importKey(
    format: KeyFormat,
    keyData: JsonWebKey | BufferSource,
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ) {
    return nodeSubtle.importKey(
      format,
      normalizeCryptoInput(keyData) as JsonWebKey | BufferSource,
      normalizeCryptoInput(algorithm) as AlgorithmIdentifier,
      extractable,
      keyUsages,
    )
  },
  sign(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource) {
    return nodeSubtle.sign(normalizeCryptoInput(algorithm) as AlgorithmIdentifier, key, toNodeBuffer(data))
  },
  unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    unwrappingKey: CryptoKey,
    unwrapAlgorithm: AlgorithmIdentifier,
    unwrappedKeyAlgorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ) {
    return nodeSubtle.unwrapKey(
      format,
      toNodeBuffer(wrappedKey),
      unwrappingKey,
      normalizeCryptoInput(unwrapAlgorithm) as AlgorithmIdentifier,
      normalizeCryptoInput(unwrappedKeyAlgorithm) as AlgorithmIdentifier,
      extractable,
      keyUsages,
    )
  },
  verify(algorithm: AlgorithmIdentifier, key: CryptoKey, signature: BufferSource, data: BufferSource) {
    return nodeSubtle.verify(
      normalizeCryptoInput(algorithm) as AlgorithmIdentifier,
      key,
      toNodeBuffer(signature),
      toNodeBuffer(data),
    )
  },
  wrapKey(format: KeyFormat, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier) {
    return nodeSubtle.wrapKey(
      format,
      key,
      wrappingKey,
      normalizeCryptoInput(wrapAlgorithm) as AlgorithmIdentifier,
    )
  },
} as SubtleCrypto

const testCrypto = {
  subtle: testSubtle,
  getRandomValues<T extends ArrayBufferView | null>(array: T): T {
    if (array === null) {
      return array
    }
    const randomBytes = Buffer.alloc(array.byteLength)
    webcrypto.getRandomValues(randomBytes)
    new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(randomBytes)
    return array
  },
  randomUUID: () => webcrypto.randomUUID(),
} as Crypto

function toNodeBuffer(data: BufferSource): Buffer {
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  }
  return Buffer.from(data)
}

function normalizeCryptoInput(value: unknown): unknown {
  if (isBufferSource(value)) {
    return toNodeBuffer(value)
  }
  if (Array.isArray(value)) {
    return value.map(normalizeCryptoInput)
  }
  if (!isPlainObject(value)) {
    return value
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, normalizeCryptoInput(entry)]),
  )
}

function isBufferSource(value: unknown): value is BufferSource {
  return isArrayBufferLike(value) || ArrayBuffer.isView(value)
}

function isArrayBufferLike(value: unknown): value is ArrayBuffer {
  return Object.prototype.toString.call(value) === '[object ArrayBuffer]'
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Object.prototype.toString.call(value) === '[object Object]'
}

Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  writable: true,
  value: testCrypto,
})

if (typeof window !== 'undefined') {
  Object.defineProperty(window, 'crypto', {
    configurable: true,
    writable: true,
    value: testCrypto,
  })
}

if (typeof globalThis.atob === 'undefined') {
  Object.defineProperty(globalThis, 'atob', {
    configurable: true,
    value: (input: string) => Buffer.from(input, 'base64').toString('binary'),
  })
}

if (typeof globalThis.btoa === 'undefined') {
  Object.defineProperty(globalThis, 'btoa', {
    configurable: true,
    value: (input: string) => Buffer.from(input, 'binary').toString('base64'),
  })
}

if (
  typeof globalThis.crypto !== 'undefined' &&
  typeof globalThis.crypto.randomUUID !== 'function' &&
  typeof globalThis.crypto.getRandomValues === 'function'
) {
  Object.defineProperty(globalThis.crypto, 'randomUUID', {
    configurable: true,
    value: () => {
      const bytes = new Uint8Array(16)
      globalThis.crypto.getRandomValues(bytes)
      bytes[6] = (bytes[6] & 0x0f) | 0x40
      bytes[8] = (bytes[8] & 0x3f) | 0x80
      const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0'))
      return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex
        .slice(8, 10)
        .join('')}-${hex.slice(10).join('')}`
    },
  })
}

// Mock ResizeObserver for tests (used by Radix UI components)
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

// Radix Select + other pointer-based widgets expect these pointer capture APIs.
if (typeof globalThis.HTMLElement !== 'undefined') {
  const proto = globalThis.HTMLElement.prototype as unknown as {
    hasPointerCapture?: (pointerId: number) => boolean
    setPointerCapture?: (pointerId: number) => void
    releasePointerCapture?: (pointerId: number) => void
  }
  if (typeof proto.hasPointerCapture !== 'function') {
    proto.hasPointerCapture = () => false
  }
  if (typeof proto.setPointerCapture !== 'function') {
    proto.setPointerCapture = () => {}
  }
  if (typeof proto.releasePointerCapture !== 'function') {
    proto.releasePointerCapture = () => {}
  }
}

if (typeof globalThis.Element !== 'undefined') {
  const elementProto = globalThis.Element.prototype as unknown as {
    scrollIntoView?: () => void
  }
  if (typeof elementProto.scrollIntoView !== 'function') {
    elementProto.scrollIntoView = () => {}
  }
}

// Provide matchMedia for hooks that rely on it (e.g., theme detection)
if (typeof globalThis.matchMedia === 'undefined') {
  globalThis.matchMedia = () =>
    ({
      matches: false,
      media: '',
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    } as MediaQueryList)
}
