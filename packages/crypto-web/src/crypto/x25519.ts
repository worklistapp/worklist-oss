import { x25519ScalarMult, x25519ScalarMultBase } from './x25519-fallback'

function getSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('WebCrypto subtle API is unavailable for X25519 operations.')
  }
  return subtle
}

const BASEPOINT = (() => {
  const bytes = new Uint8Array(32)
  bytes[0] = 9
  return bytes
})()

class X25519WebCryptoError extends Error {
  unsupported: boolean

  constructor(message: string, options: { cause?: unknown; unsupported?: boolean } = {}) {
    super(message)
    this.name = 'X25519WebCryptoError'
    this.unsupported = options.unsupported ?? false
    if ('cause' in options) {
      ;(this as { cause?: unknown }).cause = options.cause
    }
  }
}

let x25519SupportState: 'unknown' | 'supported' | 'unsupported' = 'unknown'
let warnedAboutFallback = false

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const copy = view.slice()
  return copy.buffer
}

function assertKeyLength(bytes: Uint8Array, label: string) {
  if (bytes.length !== 32) {
    throw new Error(`${label} must be 32 bytes for X25519 operations.`)
  }
}

export function clampScalar(seed: Uint8Array): Uint8Array {
  if (seed.length < 32) {
    throw new Error('Scalar seed must be at least 32 bytes for X25519.')
  }
  const scalar = seed.slice(0, 32)
  scalar[0] &= 248
  scalar[31] &= 127
  scalar[31] |= 64
  return scalar
}

async function importPrivateKey(privateKey: Uint8Array): Promise<CryptoKey> {
  assertKeyLength(privateKey, 'Private key')
  const subtle = getSubtleCrypto()
  try {
    return await subtle.importKey('raw', toArrayBuffer(privateKey), 'X25519', false, ['deriveBits'])
  } catch (error) {
    throw createX25519Error('Failed to import X25519 private key', error)
  }
}

async function importPublicKey(publicKey: Uint8Array): Promise<CryptoKey> {
  assertKeyLength(publicKey, 'Public key')
  const subtle = getSubtleCrypto()
  try {
    return await subtle.importKey('raw', toArrayBuffer(publicKey), 'X25519', false, [])
  } catch (error) {
    throw createX25519Error('Failed to import X25519 public key', error)
  }
}

export async function derivePublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  if (shouldUseFallback()) {
    return derivePublicKeyWithFallback(privateKey)
  }
  try {
    const publicKey = await derivePublicKeyWithWebCrypto(privateKey)
    recordWebCryptoSupport()
    return publicKey
  } catch (error) {
    if (isUnsupportedX25519Error(error)) {
      markWebCryptoUnsupported()
      return derivePublicKeyWithFallback(privateKey)
    }
    throw error
  }
}

export async function deriveSharedSecret(params: {
  privateKey: Uint8Array
  peerPublicKey: Uint8Array
}): Promise<Uint8Array> {
  if (shouldUseFallback()) {
    return deriveSharedSecretWithFallback(params)
  }
  try {
    const secret = await deriveSharedSecretWithWebCrypto(params)
    recordWebCryptoSupport()
    return secret
  } catch (error) {
    if (isUnsupportedX25519Error(error)) {
      markWebCryptoUnsupported()
      return deriveSharedSecretWithFallback(params)
    }
    throw error
  }
}

async function derivePublicKeyWithWebCrypto(privateKey: Uint8Array): Promise<Uint8Array> {
  const subtle = getSubtleCrypto()
  const privateHandle = await importPrivateKey(privateKey)
  const basepointHandle = await importPublicKey(BASEPOINT)
  try {
    const derived = await subtle.deriveBits(
      {
        name: 'X25519',
        public: basepointHandle,
      },
      privateHandle,
      256,
    )
    return new Uint8Array(derived)
  } catch (error) {
    throw createX25519Error('Failed to derive X25519 public key', error)
  }
}

async function deriveSharedSecretWithWebCrypto(params: {
  privateKey: Uint8Array
  peerPublicKey: Uint8Array
}): Promise<Uint8Array> {
  const subtle = getSubtleCrypto()
  const [privateHandle, publicHandle] = await Promise.all([
    importPrivateKey(params.privateKey),
    importPublicKey(params.peerPublicKey),
  ])
  try {
    const secret = await subtle.deriveBits(
      {
        name: 'X25519',
        public: publicHandle,
      },
      privateHandle,
      256,
    )
    return new Uint8Array(secret)
  } catch (error) {
    throw createX25519Error('Failed to derive X25519 shared secret', error)
  }
}

async function derivePublicKeyWithFallback(privateKey: Uint8Array): Promise<Uint8Array> {
  return Promise.resolve(x25519ScalarMultBase(privateKey))
}

async function deriveSharedSecretWithFallback(params: {
  privateKey: Uint8Array
  peerPublicKey: Uint8Array
}): Promise<Uint8Array> {
  return Promise.resolve(x25519ScalarMult(params.privateKey, params.peerPublicKey))
}

function shouldUseFallback(): boolean {
  return x25519SupportState === 'unsupported'
}

function recordWebCryptoSupport() {
  if (x25519SupportState !== 'unsupported') {
    x25519SupportState = 'supported'
  }
}

function markWebCryptoUnsupported() {
  if (x25519SupportState !== 'unsupported') {
    x25519SupportState = 'unsupported'
    if (!warnedAboutFallback && typeof console !== 'undefined' && typeof console.warn === 'function') {
      console.warn('WebCrypto X25519 is unavailable; falling back to a software implementation.')
      warnedAboutFallback = true
    }
  }
}

function isUnsupportedX25519Error(error: unknown): boolean {
  return error instanceof X25519WebCryptoError && error.unsupported
}

function createX25519Error(label: string, cause: unknown): X25519WebCryptoError {
  const unsupported = isUnsupportedDomException(cause)
  const message = cause instanceof Error ? cause.message : String(cause)
  return new X25519WebCryptoError(`${label}: ${message}`, {
    cause,
    unsupported,
  })
}

function isUnsupportedDomException(error: unknown): boolean {
  if (typeof DOMException !== 'undefined' && error instanceof DOMException) {
    return (
      error.name === 'NotSupportedError' ||
      error.name === 'SyntaxError' ||
      error.name === 'OperationError' ||
      error.name === 'InvalidAccessError'
    )
  }
  const message = error instanceof Error ? error.message : ''
  return /not supported/i.test(message) || /invalid or illegal string/i.test(message)
}

export function __resetX25519ImplementationForTesting() {
  x25519SupportState = 'unknown'
  warnedAboutFallback = false
}
