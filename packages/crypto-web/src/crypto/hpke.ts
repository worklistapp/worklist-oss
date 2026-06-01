import { decode as cborDecode, encode as cborEncode } from 'cbor-x'

import { randomBytes } from './random'
import { getStrongBoxBridge, type StrongBoxBridge } from './strong-box'
import { clampScalar, derivePublicKey, deriveSharedSecret } from './x25519'
import { emitCryptoEvent } from './events'

const textEncoder = new TextEncoder()

const HASH_LENGTH = 32
const KEY_LENGTH = 32
const NONCE_LENGTH = 12
const MODE_BASE = 0x00
const KEM_ID = 0x0020
// Legacy Worklist envelopes accidentally used RFC 9180's P-256 KEM codepoint
// for the same X25519 key material. Keep this accept-on-read only; new seals
// must continue to use KEM_ID. This is not true P-256 HPKE support.
const LEGACY_KEM_ID = 0x0010
const KDF_ID = 0x0001
const AEAD_ID = 0x0003
const EMPTY_BYTES = new Uint8Array(0)

const LABEL_PREFIX = textEncoder.encode('HPKE-v1')
const KEM_SUITE_ID = concatBytes(textEncoder.encode('KEM'), i2osp(KEM_ID, 2))
const SUITE_ID = concatBytes(
  textEncoder.encode('HPKE'),
  i2osp(KEM_ID, 2),
  i2osp(KDF_ID, 2),
  i2osp(AEAD_ID, 2),
)
const LEGACY_SUITE_ID = concatBytes(
  textEncoder.encode('HPKE'),
  i2osp(LEGACY_KEM_ID, 2),
  i2osp(KDF_ID, 2),
  i2osp(AEAD_ID, 2),
)

type HpkeSealParams = {
  recipientPublicKey: Uint8Array
  info: Uint8Array
  aad: Uint8Array
  plaintext: Uint8Array
}

export type HpkeSealResult = {
  enc: Uint8Array
  ciphertext: Uint8Array
  nonce?: Uint8Array
}

export type HpkeEnvelope = {
  version: number
  suite: {
    kem: number
    kdf: number
    aead: number
    mode: number
  }
  enc: Uint8Array
  ciphertext: Uint8Array
}

type HpkeOpenParams = {
  recipientPrivateKey: Uint8Array
  info: Uint8Array
  aad: Uint8Array
  envelope: Uint8Array | HpkeEnvelope
}

export async function hpkeSeal(params: HpkeSealParams): Promise<HpkeSealResult> {
  const bridge = await maybeGetHpkeBridge()
  if (bridge?.hpkeEncap) {
    const result = await bridge.hpkeEncap(params)
    return { enc: result.enc, ciphertext: result.ciphertext, nonce: result.nonce }
  }
  return hpkeSealPure(params)
}

export function encodeHpkeEnvelope(result: HpkeSealResult): Uint8Array {
  const payload = {
    version: 1,
    suite: {
      kem: KEM_ID,
      kdf: KDF_ID,
      aead: AEAD_ID,
      mode: MODE_BASE,
    },
    enc: result.enc,
    ciphertext: result.ciphertext,
  }
  return cborEncode(payload)
}

export function decodeHpkeEnvelope(bytes: Uint8Array): HpkeEnvelope {
  const decoded = cborDecode(bytes) as Partial<HpkeEnvelope>
  return normalizeHpkeEnvelope(decoded)
}

export async function hpkeOpen(params: HpkeOpenParams): Promise<Uint8Array> {
  const envelope =
    params.envelope instanceof Uint8Array ? decodeHpkeEnvelope(params.envelope) : normalizeHpkeEnvelope(params.envelope)
  const bridge = await maybeGetHpkeBridge()
  // The WASM bridge implements the current RFC 9180 schedule only; legacy
  // Worklist envelopes need the bug-compatible JS fallback below.
  if (bridge?.hpkeDecap && isCurrentHpkeSuite(envelope.suite)) {
    return bridge.hpkeDecap({
      recipientPrivateKey: params.recipientPrivateKey,
      info: params.info,
      aad: params.aad,
      enc: envelope.enc,
      ciphertext: envelope.ciphertext,
    })
  }

  return hpkeOpenPure({ ...params, envelope })
}

async function hpkeSealPure(params: HpkeSealParams): Promise<HpkeSealResult> {
  if (params.recipientPublicKey.length !== 32) {
    throw new Error('Recipient public key must be 32 bytes for HPKE.')
  }

  const ephemeralSeed = randomBytes(32)
  const privateKey = clampScalar(ephemeralSeed)
  let enc: Uint8Array = new Uint8Array(0)
  let dh: Uint8Array = new Uint8Array(0)
  try {
    enc = await derivePublicKey(privateKey)
    dh = await deriveSharedSecret({
      privateKey,
      peerPublicKey: params.recipientPublicKey,
    })
  } finally {
    zeroBytes(ephemeralSeed)
    zeroBytes(privateKey)
  }

  if (dh.every((byte) => byte === 0)) {
    zeroBytes(dh)
    throw new Error('Derived HPKE shared secret is invalid.')
  }

  const sharedSecret = await (async () => {
    try {
      return await dhkemSharedSecret(dh, enc, params.recipientPublicKey)
    } finally {
      zeroBytes(dh)
    }
  })()

  const { key, baseNonce } = await (async () => {
    try {
      return await keySchedule(sharedSecret, params.info)
    } finally {
      zeroBytes(sharedSecret)
    }
  })()
  try {
    const ciphertext = chacha20Poly1305Seal({
      key,
      nonce: baseNonce,
      aad: params.aad,
      plaintext: params.plaintext,
    })

    const nonceCopy = baseNonce.slice()
    return { enc, ciphertext, nonce: nonceCopy }
  } finally {
    zeroBytes(baseNonce)
    zeroBytes(key)
  }
}

async function hpkeOpenPure(params: HpkeOpenParams): Promise<Uint8Array> {
  if (params.recipientPrivateKey.length !== 32) {
    throw new Error('Recipient private key must be 32 bytes for HPKE.')
  }
  const envelope =
    params.envelope instanceof Uint8Array ? decodeHpkeEnvelope(params.envelope) : normalizeHpkeEnvelope(params.envelope)

  const recipientPublicKey = await derivePublicKey(params.recipientPrivateKey)
  const dh = await deriveSharedSecret({
    privateKey: params.recipientPrivateKey,
    peerPublicKey: envelope.enc,
  })
  if (dh.every((byte) => byte === 0)) {
    zeroBytes(recipientPublicKey)
    zeroBytes(dh)
    throw new Error('Derived HPKE shared secret is invalid.')
  }

  if (isLegacyHpkeSuite(envelope.suite)) {
    const { key, baseNonce } = await (async () => {
      try {
        return await legacyKeySchedule(dh, envelope.enc, recipientPublicKey, params.info)
      } finally {
        zeroBytes(dh)
        zeroBytes(recipientPublicKey)
      }
    })()
    try {
      const plaintext = chacha20Poly1305Open({
        key,
        nonce: baseNonce,
        aad: params.aad,
        ciphertext: envelope.ciphertext,
      })
      emitCryptoEvent({ operation: 'legacy_hpke_open', suiteKem: '0x0010' })
      return plaintext
    } finally {
      zeroBytes(baseNonce)
      zeroBytes(key)
    }
  }

  const sharedSecret = await (async () => {
    try {
      return await dhkemSharedSecret(dh, envelope.enc, recipientPublicKey)
    } finally {
      zeroBytes(dh)
      zeroBytes(recipientPublicKey)
    }
  })()

  const { key, baseNonce } = await (async () => {
    try {
      return await keySchedule(sharedSecret, params.info)
    } finally {
      zeroBytes(sharedSecret)
    }
  })()
  try {
    return chacha20Poly1305Open({
      key,
      nonce: baseNonce,
      aad: params.aad,
      ciphertext: envelope.ciphertext,
    })
  } finally {
    zeroBytes(baseNonce)
    zeroBytes(key)
  }
}

async function legacyKeySchedule(
  dh: Uint8Array,
  enc: Uint8Array,
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
): Promise<{
  key: Uint8Array
  baseNonce: Uint8Array
}> {
  // Legacy Worklist envelopes were not RFC 9180 DHKEM: they fed raw X25519 DH
  // output into the HPKE labeled key schedule and bound enc || recipient || info
  // as context. Keep this only for old 0x0010 accept-on-read envelopes.
  const kemContext = concatBytes(enc, recipientPublicKey)
  const keyScheduleContext = concatBytes(new Uint8Array([MODE_BASE]), kemContext, info)
  zeroBytes(kemContext)

  let secret: Uint8Array | undefined
  try {
    secret = await labeledExtractWithSuite(LEGACY_SUITE_ID, null, 'secret', dh)
    const key = await labeledExpandWithSuite(LEGACY_SUITE_ID, secret, 'key', keyScheduleContext, KEY_LENGTH)
    try {
      const baseNonce = await labeledExpandWithSuite(
        LEGACY_SUITE_ID,
        secret,
        'base_nonce',
        keyScheduleContext,
        NONCE_LENGTH,
      )
      return { key, baseNonce }
    } catch (error) {
      zeroBytes(key)
      throw error
    }
  } finally {
    zeroBytes(secret)
    zeroBytes(keyScheduleContext)
  }
}

export async function computeKeyFingerprint(publicKey: Uint8Array): Promise<Uint8Array> {
  if (publicKey.length === 0) {
    throw new Error('Public key is required to compute a fingerprint.')
  }
  return sha256(publicKey)
}

let hpkeBridgePromise: Promise<StrongBoxBridge | null> | null = null

async function maybeGetHpkeBridge(): Promise<StrongBoxBridge | null> {
  if (!hpkeBridgePromise) {
    hpkeBridgePromise = (async () => {
      try {
        const bridge = await getStrongBoxBridge()
        if (typeof bridge.hpkeEncap === 'function' && typeof bridge.hpkeDecap === 'function') {
          return bridge
        }
      } catch {
        // fall through to JS fallback
      }
      return null
    })()
  }
  return hpkeBridgePromise
}

async function dhkemSharedSecret(
  dh: Uint8Array,
  enc: Uint8Array,
  recipientPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const kemContext = concatBytes(enc, recipientPublicKey)
  const eaePrk = await labeledExtractWithSuite(KEM_SUITE_ID, null, 'eae_prk', dh)
  try {
    return await labeledExpandWithSuite(KEM_SUITE_ID, eaePrk, 'shared_secret', kemContext, KEY_LENGTH)
  } finally {
    zeroBytes(eaePrk)
  }
}

async function keySchedule(sharedSecret: Uint8Array, info: Uint8Array): Promise<{
  key: Uint8Array
  baseNonce: Uint8Array
}> {
  let pskIdHash: Uint8Array | undefined
  let infoHash: Uint8Array | undefined
  let keyScheduleContext: Uint8Array = new Uint8Array(0)
  try {
    pskIdHash = await labeledExtract(null, 'psk_id_hash', EMPTY_BYTES)
    infoHash = await labeledExtract(null, 'info_hash', info)
    keyScheduleContext = concatBytes(new Uint8Array([MODE_BASE]), pskIdHash, infoHash)
  } finally {
    zeroBytes(pskIdHash)
    zeroBytes(infoHash)
  }

  let secret: Uint8Array | undefined
  try {
    secret = await labeledExtract(sharedSecret, 'secret', EMPTY_BYTES)
    const key = await labeledExpand(secret, 'key', keyScheduleContext, KEY_LENGTH)
    try {
      const baseNonce = await labeledExpand(secret, 'base_nonce', keyScheduleContext, NONCE_LENGTH)
      return { key, baseNonce }
    } catch (error) {
      zeroBytes(key)
      throw error
    }
  } finally {
    zeroBytes(secret)
    zeroBytes(keyScheduleContext)
  }
}

async function labeledExtract(
  salt: Uint8Array | null,
  label: string,
  ikm: Uint8Array,
): Promise<Uint8Array> {
  return labeledExtractWithSuite(SUITE_ID, salt, label, ikm)
}

async function labeledExpand(
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  return labeledExpandWithSuite(SUITE_ID, prk, label, info, length)
}

async function labeledExtractWithSuite(
  suiteId: Uint8Array,
  salt: Uint8Array | null,
  label: string,
  ikm: Uint8Array,
): Promise<Uint8Array> {
  const labeledIkm = concatBytes(LABEL_PREFIX, suiteId, textEncoder.encode(label), ikm)
  try {
    return await hkdfExtract(salt, labeledIkm)
  } finally {
    zeroBytes(labeledIkm)
  }
}

async function labeledExpandWithSuite(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const labeledInfo = concatBytes(
    i2osp(length, 2),
    LABEL_PREFIX,
    suiteId,
    textEncoder.encode(label),
    info,
  )
  try {
    return await hkdfExpand(prk, labeledInfo, length)
  } finally {
    zeroBytes(labeledInfo)
  }
}

async function hkdfExtract(salt: Uint8Array | null, ikm: Uint8Array): Promise<Uint8Array> {
  const keyMaterial = salt && salt.length > 0 ? salt : new Uint8Array(HASH_LENGTH)
  const subtle = getSubtle()
  const hmacKey = await subtle.importKey(
    'raw',
    toArrayBuffer(keyMaterial),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign'],
  )
  const digest = await subtle.sign('HMAC', hmacKey, toArrayBuffer(ikm))
  return new Uint8Array(digest)
}

async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const subtle = getSubtle()
  const hmacKey = await subtle.importKey(
    'raw',
    toArrayBuffer(prk),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign'],
  )

  const blocks = Math.ceil(length / HASH_LENGTH)
  const result = new Uint8Array(blocks * HASH_LENGTH)
  let previous: Uint8Array = new Uint8Array(0)

  try {
    for (let counter = 1; counter <= blocks; counter += 1) {
      const buffer = new Uint8Array(previous.length + info.length + 1)
      buffer.set(previous, 0)
      buffer.set(info, previous.length)
      buffer[buffer.length - 1] = counter

      let block: Uint8Array
      try {
        block = new Uint8Array(await subtle.sign('HMAC', hmacKey, toArrayBuffer(buffer)))
      } finally {
        zeroBytes(buffer)
      }
      result.set(block, (counter - 1) * HASH_LENGTH)
      zeroBytes(previous)
      previous = block
    }

    return result.slice(0, length)
  } finally {
    zeroBytes(previous)
    zeroBytes(result)
  }
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const subtle = getSubtle()
  const digest = await subtle.digest('SHA-256', toArrayBuffer(data))
  return new Uint8Array(digest)
}

function getSubtle(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('WebCrypto subtle API is unavailable for HPKE.')
  }
  return subtle
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

function i2osp(value: number, length: number): Uint8Array {
  if (value < 0 || value >= 1 << (length * 8)) {
    throw new Error(`Value ${value} does not fit in ${length} bytes.`)
  }
  const bytes = new Uint8Array(length)
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = value & 0xff
    value >>>= 8
  }
  return bytes
}

function zeroBytes(bytes: Uint8Array | undefined) {
  bytes?.fill(0)
}

function zeroWords(words: Uint32Array | undefined) {
  words?.fill(0)
}

function ensureUint8Array(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value
  }
  if (Array.isArray(value)) {
    return Uint8Array.from(value)
  }
  throw new Error(`HPKE envelope ${field} must be a byte array.`)
}

function normalizeHpkeEnvelope(envelope: HpkeEnvelope | Partial<HpkeEnvelope>): HpkeEnvelope {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('HPKE envelope is malformed.')
  }
  const { version, suite } = envelope
  if (version !== 1) {
    throw new Error(`Unsupported HPKE envelope version: ${String(version)}`)
  }
  if (!suite) {
    throw new Error('HPKE envelope missing suite definition.')
  }
  if (!isSupportedOpenHpkeSuite(suite)) {
    throw new Error('HPKE envelope uses an unsupported ciphersuite.')
  }
  return {
    version,
    suite,
    enc: ensureUint8Array(envelope.enc, 'enc'),
    ciphertext: ensureUint8Array(envelope.ciphertext, 'ciphertext'),
  }
}

function isSupportedOpenHpkeSuite(suite: HpkeEnvelope['suite']): boolean {
  return isCurrentHpkeSuite(suite) || isLegacyHpkeSuite(suite)
}

function isCurrentHpkeSuite(suite: HpkeEnvelope['suite']): boolean {
  return suite.kem === KEM_ID && suite.kdf === KDF_ID && suite.aead === AEAD_ID && suite.mode === MODE_BASE
}

function isLegacyHpkeSuite(suite: HpkeEnvelope['suite']): boolean {
  return suite.kem === LEGACY_KEM_ID && suite.kdf === KDF_ID && suite.aead === AEAD_ID && suite.mode === MODE_BASE
}

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  if (
    view.byteOffset === 0 &&
    view.byteLength === view.buffer.byteLength &&
    view.buffer instanceof ArrayBuffer
  ) {
    return view.buffer
  }
  const copy = view.slice()
  return copy.buffer
}

function chacha20Poly1305Seal(params: {
  key: Uint8Array
  nonce: Uint8Array
  aad: Uint8Array
  plaintext: Uint8Array
}): Uint8Array {
  const { key, nonce, aad, plaintext } = params
  if (key.length !== KEY_LENGTH) {
    throw new Error('ChaCha20-Poly1305 key must be 32 bytes.')
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error('ChaCha20-Poly1305 nonce must be 12 bytes.')
  }

  let firstBlock: Uint8Array | undefined
  let polyKey: Uint8Array | undefined
  let ciphertext: Uint8Array | undefined
  let tag: Uint8Array | undefined
  try {
    firstBlock = chacha20Block(key, 0, nonce)
    polyKey = firstBlock.slice(0, 32)
    ciphertext = chacha20Xor(key, nonce, 1, plaintext)
    tag = poly1305Authenticate(polyKey, aad, ciphertext)

    const sealed = new Uint8Array(ciphertext.length + tag.length)
    sealed.set(ciphertext, 0)
    sealed.set(tag, ciphertext.length)
    return sealed
  } finally {
    zeroBytes(firstBlock)
    zeroBytes(polyKey)
    zeroBytes(ciphertext)
    zeroBytes(tag)
  }
}

function chacha20Poly1305Open(params: {
  key: Uint8Array
  nonce: Uint8Array
  aad: Uint8Array
  ciphertext: Uint8Array
}): Uint8Array {
  const { key, nonce, aad, ciphertext } = params
  if (ciphertext.length < 16) {
    throw new Error('ChaCha20-Poly1305 ciphertext must include an authentication tag.')
  }
  if (key.length !== KEY_LENGTH) {
    throw new Error('ChaCha20-Poly1305 key must be 32 bytes.')
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error('ChaCha20-Poly1305 nonce must be 12 bytes.')
  }

  const tagOffset = ciphertext.length - 16
  let payload: Uint8Array | undefined
  let tag: Uint8Array | undefined
  let firstBlock: Uint8Array | undefined
  let polyKey: Uint8Array | undefined
  let expectedTag: Uint8Array | undefined
  try {
    payload = ciphertext.slice(0, tagOffset)
    tag = ciphertext.slice(tagOffset)
    firstBlock = chacha20Block(key, 0, nonce)
    polyKey = firstBlock.slice(0, 32)
    expectedTag = poly1305Authenticate(polyKey, aad, payload)
    if (!constantTimeEquals(expectedTag, tag)) {
      throw new Error('ChaCha20-Poly1305 authentication failed.')
    }

    return chacha20Xor(key, nonce, 1, payload)
  } finally {
    zeroBytes(payload)
    zeroBytes(tag)
    zeroBytes(firstBlock)
    zeroBytes(polyKey)
    zeroBytes(expectedTag)
  }
}

function chacha20Xor(
  key: Uint8Array,
  nonce: Uint8Array,
  counter: number,
  plaintext: Uint8Array,
): Uint8Array {
  const output = new Uint8Array(plaintext.length)
  const block = new Uint8Array(64)
  let ctr = counter >>> 0
  let completed = false

  try {
    for (let offset = 0; offset < plaintext.length; offset += 64) {
      const keystream = chacha20Block(key, ctr, nonce, block)
      ctr = (ctr + 1) >>> 0
      const chunk = Math.min(64, plaintext.length - offset)
      for (let i = 0; i < chunk; i += 1) {
        output[offset + i] = plaintext[offset + i] ^ keystream[i]
      }
    }

    completed = true
    return output
  } finally {
    zeroBytes(block)
    if (!completed) {
      zeroBytes(output)
    }
  }
}

function chacha20Block(
  key: Uint8Array,
  counter: number,
  nonce: Uint8Array,
  buffer?: Uint8Array,
): Uint8Array {
  const state = new Uint32Array(16)
  let working: Uint32Array | undefined
  try {
    state[0] = 0x61707865
    state[1] = 0x3320646e
    state[2] = 0x79622d32
    state[3] = 0x6b206574

    for (let i = 0; i < 8; i += 1) {
      state[4 + i] = readUint32LE(key, i * 4)
    }

    state[12] = counter >>> 0
    state[13] = readUint32LE(nonce, 0)
    state[14] = readUint32LE(nonce, 4)
    state[15] = readUint32LE(nonce, 8)

    working = state.slice()

    for (let round = 0; round < 10; round += 1) {
      quarterRound(working, 0, 4, 8, 12)
      quarterRound(working, 1, 5, 9, 13)
      quarterRound(working, 2, 6, 10, 14)
      quarterRound(working, 3, 7, 11, 15)
      quarterRound(working, 0, 5, 10, 15)
      quarterRound(working, 1, 6, 11, 12)
      quarterRound(working, 2, 7, 8, 13)
      quarterRound(working, 3, 4, 9, 14)
    }

    for (let i = 0; i < 16; i += 1) {
      working[i] = (working[i] + state[i]) >>> 0
    }

    const output = buffer ?? new Uint8Array(64)
    for (let i = 0; i < 16; i += 1) {
      writeUint32LE(output, i * 4, working[i])
    }
    return output
  } finally {
    zeroWords(state)
    zeroWords(working)
  }
}

function quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number) {
  state[a] = (state[a] + state[b]) >>> 0
  state[d] ^= state[a]
  state[d] = rotateLeft(state[d], 16)

  state[c] = (state[c] + state[d]) >>> 0
  state[b] ^= state[c]
  state[b] = rotateLeft(state[b], 12)

  state[a] = (state[a] + state[b]) >>> 0
  state[d] ^= state[a]
  state[d] = rotateLeft(state[d], 8)

  state[c] = (state[c] + state[d]) >>> 0
  state[b] ^= state[c]
  state[b] = rotateLeft(state[b], 7)
}

function rotateLeft(value: number, count: number): number {
  return ((value << count) | (value >>> (32 - count))) >>> 0
}

function readUint32LE(bytes: Uint8Array, offset: number): number {
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)
  ) >>> 0
}

function writeUint32LE(target: Uint8Array, offset: number, value: number) {
  target[offset] = value & 0xff
  target[offset + 1] = (value >>> 8) & 0xff
  target[offset + 2] = (value >>> 16) & 0xff
  target[offset + 3] = (value >>> 24) & 0xff
}

function constantTimeEquals(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  let result = 0
  for (let index = 0; index < left.length; index += 1) {
    result |= left[index] ^ right[index]
  }
  return result === 0
}

function poly1305Authenticate(key: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (key.length !== 32) {
    throw new Error('Poly1305 key must be 32 bytes.')
  }
  const r = clampPolyKey(leBytesToBigInt(key, 0, 16))
  const s = leBytesToBigInt(key, 16, 16)
  const prime = (1n << 130n) - 5n
  let acc = 0n

  const lengthBlock = new Uint8Array(16)
  let macData: Uint8Array | undefined
  try {
    writeUint64LE(lengthBlock, 0, BigInt(aad.length))
    writeUint64LE(lengthBlock, 8, BigInt(ciphertext.length))
    macData = concatBytes(
      aad,
      poly1305Padding(aad.length),
      ciphertext,
      poly1305Padding(ciphertext.length),
      lengthBlock,
    )
    acc = poly1305Accumulate(acc, r, macData, prime)

    const tagValue = (acc + s) % (1n << 128n)
    return bigIntToBytes(tagValue, 16)
  } finally {
    zeroBytes(lengthBlock)
    zeroBytes(macData)
  }
}

function clampPolyKey(value: bigint): bigint {
  const mask = BigInt('0x0ffffffc0ffffffc0ffffffc0fffffff')
  return value & mask
}

function poly1305Accumulate(
  acc: bigint,
  r: bigint,
  data: Uint8Array,
  prime: bigint,
): bigint {
  for (let offset = 0; offset < data.length; offset += 16) {
    const chunk = Math.min(16, data.length - offset)
    const blockValue = leBytesToBigInt(data, offset, chunk) + (1n << BigInt(8 * chunk))
    acc = (acc + blockValue) % prime
    acc = (acc * r) % prime
  }
  return acc
}

function poly1305Padding(length: number): Uint8Array {
  const remainder = length % 16
  if (remainder === 0) {
    return new Uint8Array(0)
  }
  return new Uint8Array(16 - remainder)
}

function leBytesToBigInt(bytes: Uint8Array, offset: number, length: number): bigint {
  let value = 0n
  for (let i = 0; i < length; i += 1) {
    value += BigInt(bytes[offset + i] ?? 0) << BigInt(8 * i)
  }
  return value
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const result = new Uint8Array(length)
  for (let i = 0; i < length; i += 1) {
    result[i] = Number((value >> BigInt(8 * i)) & 0xffn)
  }
  return result
}

function writeUint64LE(target: Uint8Array, offset: number, value: bigint) {
  for (let i = 0; i < 8; i += 1) {
    target[offset + i] = Number((value >> BigInt(8 * i)) & 0xffn)
  }
}
