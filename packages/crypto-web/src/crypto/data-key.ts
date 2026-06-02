import { encode as cborEncode } from 'cbor-x'

import { deriveKeyFromPassword } from './argon2'
import { decodeBase64, encodeBase64 } from './base64'
import { KEY_SIZE_BYTES } from './constants'
import { hkdfExpand } from './hkdf'
import { randomBytes } from './random'
import {
  parseSealedPayload,
  serializeSealedPayloadBase64,
  type SealedPayload,
} from './sealed-payload'
import { getStrongBoxBridge, type StrongBoxBridge } from './strong-box'

const encoder = new TextEncoder()

const DATA_KEY_CONTEXT_LABEL = 'worklist.user.data_key'
const DATA_KEY_CONTEXT = encoder.encode(DATA_KEY_CONTEXT_LABEL)
const OPAQUE_EXPORT_KEY_INFO = 'worklist.opaque.export_key.data_key.v1'
const LEGACY_PASSWORD_ARGON2_PAYLOAD_VERSION = 1
const OPAQUE_EXPORT_KEY_PAYLOAD_VERSION = 2
export const DATA_KEY_SALT_BYTES = 32
export const OPAQUE_EXPORT_KEY_REQUIRED_CODE = 'OPAQUE_EXPORT_KEY_REQUIRED'

export class OpaqueExportKeyRequiredError extends Error {
  readonly code = OPAQUE_EXPORT_KEY_REQUIRED_CODE

  constructor() {
    super('OPAQUE export key is required to decrypt this data key payload')
    this.name = 'OpaqueExportKeyRequiredError'
  }
}

export function isOpaqueExportKeyRequiredError(error: unknown): error is OpaqueExportKeyRequiredError {
  return (
    error instanceof OpaqueExportKeyRequiredError ||
    (error instanceof Error && 'code' in error && error.code === OPAQUE_EXPORT_KEY_REQUIRED_CODE)
  )
}

type KeyDeriver = (password: string, salt: Uint8Array) => Promise<Uint8Array>
type OpaqueExportKeyDeriver = (exportKey: string) => Promise<Uint8Array>

type CreateCiphertextParams = {
  password: string
  /**
   * Provide an existing data key for deterministic tests; otherwise a random key is generated.
   */
  dataKey?: Uint8Array
  /**
   * Provide a fixed salt for deterministic tests; otherwise a random salt is generated.
   */
  salt?: Uint8Array
  strongBox?: StrongBoxBridge
  deriveKey?: KeyDeriver
}

type CreateOpaqueCiphertextParams = {
  opaqueExportKey: string
  /**
   * Provide an existing data key for deterministic tests; otherwise a random key is generated.
   */
  dataKey?: Uint8Array
  strongBox?: StrongBoxBridge
  deriveOpaqueExportKey?: OpaqueExportKeyDeriver
}

export type CreateCiphertextResult = {
  ciphertext: string
  dataKey: Uint8Array
  salt?: Uint8Array
}

type DecryptCiphertextParams = {
  /**
   * Required for legacy Argon2-wrapped data-key ciphertexts.
   */
  password?: string
  /**
   * Required for current OPAQUE-export-key-wrapped data-key ciphertexts.
   */
  opaqueExportKey?: string
  ciphertext: string
  strongBox?: StrongBoxBridge
  deriveKey?: KeyDeriver
  deriveOpaqueExportKey?: OpaqueExportKeyDeriver
}

export type DecryptCiphertextResult =
  | {
      dataKey: Uint8Array
      salt: Uint8Array
      format: 'legacy_password_argon2'
    }
  | {
      dataKey: Uint8Array
      salt?: undefined
      format: 'opaque_export_key'
    }

export async function createDataKeyCiphertext(
  params: CreateCiphertextParams,
): Promise<CreateCiphertextResult> {
  const {
    password,
    salt = randomBytes(DATA_KEY_SALT_BYTES),
    dataKey = randomBytes(KEY_SIZE_BYTES),
    strongBox,
    deriveKey = deriveKeyFromPassword,
  } = params

  assertSaltLength(salt)
  const saltCopy = copyBytes(salt)
  const dataKeyCopy = copyBytes(dataKey)

  const wrappingKey = await deriveKey(password, saltCopy)
  const bridge = strongBox ?? (await getStrongBoxBridge())
  const sealed = await bridge.encrypt({
    key: wrappingKey,
    context: DATA_KEY_CONTEXT,
    plaintext: dataKeyCopy,
  })

  const payload: SealedPayload = {
    version: LEGACY_PASSWORD_ARGON2_PAYLOAD_VERSION,
    ciphertext: concatBytes(saltCopy, sealed),
  }

  return {
    ciphertext: serializeSealedPayloadBase64(payload),
    dataKey: dataKeyCopy,
    salt: saltCopy,
  }
}

export async function createDataKeyCiphertextFromOpaqueExportKey(
  params: CreateOpaqueCiphertextParams,
): Promise<CreateCiphertextResult> {
  const {
    opaqueExportKey,
    dataKey = randomBytes(KEY_SIZE_BYTES),
    strongBox,
    deriveOpaqueExportKey = deriveDataKeyWrappingKeyFromOpaqueExportKey,
  } = params

  const dataKeyCopy = copyBytes(dataKey)
  const wrappingKey = await deriveOpaqueExportKey(opaqueExportKey)
  const bridge = strongBox ?? (await getStrongBoxBridge())
  const sealed = await bridge.encrypt({
    key: wrappingKey,
    context: DATA_KEY_CONTEXT,
    plaintext: dataKeyCopy,
  })

  const payload: SealedPayload = {
    version: OPAQUE_EXPORT_KEY_PAYLOAD_VERSION,
    ciphertext: sealed,
  }

  return {
    ciphertext: serializeDataKeySealedPayloadBase64(payload),
    dataKey: dataKeyCopy,
  }
}

export async function decryptDataKeyCiphertext(
  params: DecryptCiphertextParams,
): Promise<DecryptCiphertextResult> {
  const {
    password,
    opaqueExportKey,
    ciphertext,
    strongBox,
    deriveKey = deriveKeyFromPassword,
    deriveOpaqueExportKey = deriveDataKeyWrappingKeyFromOpaqueExportKey,
  } = params
  const payload = parseSealedPayload(ciphertext)
  if (payload.version === OPAQUE_EXPORT_KEY_PAYLOAD_VERSION) {
    if (!opaqueExportKey) {
      throw new OpaqueExportKeyRequiredError()
    }
    const wrappingKey = await deriveOpaqueExportKey(opaqueExportKey)
    const bridge = strongBox ?? (await getStrongBoxBridge())
    const dataKey = await bridge.decrypt({
      key: wrappingKey,
      context: DATA_KEY_CONTEXT,
      ciphertext: payload.ciphertext,
    })

    assertDataKeyLength(dataKey)
    return {
      dataKey: copyBytes(dataKey),
      format: 'opaque_export_key',
    }
  }

  if (payload.version !== LEGACY_PASSWORD_ARGON2_PAYLOAD_VERSION) {
    throw new Error(`Unsupported data key payload version: ${payload.version}`)
  }

  if (!password) {
    throw new Error('password is required to decrypt legacy data key payloads')
  }
  if (payload.ciphertext.length <= DATA_KEY_SALT_BYTES) {
    throw new Error('data key payload is truncated')
  }

  const salt = payload.ciphertext.slice(0, DATA_KEY_SALT_BYTES)
  const sealed = payload.ciphertext.slice(DATA_KEY_SALT_BYTES)
  assertSaltLength(salt)

  const wrappingKey = await deriveKey(password, salt)
  const bridge = strongBox ?? (await getStrongBoxBridge())
  const dataKey = await bridge.decrypt({
    key: wrappingKey,
    context: DATA_KEY_CONTEXT,
    ciphertext: sealed,
  })

  assertDataKeyLength(dataKey)

  return {
    dataKey: copyBytes(dataKey),
    salt: copyBytes(salt),
    format: 'legacy_password_argon2',
  }
}

function concatBytes(...chunks: Uint8Array[]) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}

function copyBytes(source: Uint8Array) {
  const copy = new Uint8Array(source.length)
  copy.set(source)
  return copy
}

function assertSaltLength(salt: Uint8Array) {
  if (salt.length !== DATA_KEY_SALT_BYTES) {
    throw new Error(`data key salt must be ${DATA_KEY_SALT_BYTES} bytes`)
  }
}

function serializeDataKeySealedPayloadBase64(payload: SealedPayload): string {
  if (
    payload.version !== LEGACY_PASSWORD_ARGON2_PAYLOAD_VERSION &&
    payload.version !== OPAQUE_EXPORT_KEY_PAYLOAD_VERSION
  ) {
    throw new Error(`Unsupported data key payload version: ${payload.version}`)
  }
  if (!(payload.ciphertext instanceof Uint8Array) || payload.ciphertext.length === 0) {
    throw new Error('Ciphertext must be a non-empty Uint8Array')
  }
  return encodeBase64(cborEncode(payload))
}

type RewrapDataKeyCiphertextParams = {
  oldPassword?: string
  oldOpaqueExportKey?: string
  newPassword?: string
  newOpaqueExportKey?: string
  oldCiphertext: string
  strongBox?: StrongBoxBridge
  deriveKey?: KeyDeriver
  deriveOpaqueExportKey?: OpaqueExportKeyDeriver
}

export type RewrapDataKeyCiphertextResult = {
  newCiphertext: string
  dataKey: Uint8Array
  oldSalt?: Uint8Array
  newSalt?: Uint8Array
}

/**
 * Rewrap a data key ciphertext from old password to new password.
 * This unwraps the data key with the old password and rewraps it with the new password.
 * The actual data key remains unchanged, only the encryption wrapper changes.
 */
export async function rewrapDataKeyCiphertext(
  params: RewrapDataKeyCiphertextParams,
): Promise<RewrapDataKeyCiphertextResult> {
  const {
    oldPassword,
    oldOpaqueExportKey,
    newPassword,
    newOpaqueExportKey,
    oldCiphertext,
    strongBox,
    deriveKey,
    deriveOpaqueExportKey,
  } = params

  // Unwrap with current material. Legacy payloads need the old password;
  // current payloads need the OPAQUE export key.
  const { dataKey, salt: oldSalt } = await decryptDataKeyCiphertext({
    password: oldPassword,
    opaqueExportKey: oldOpaqueExportKey,
    ciphertext: oldCiphertext,
    strongBox,
    deriveKey,
    deriveOpaqueExportKey,
  })

  const { ciphertext: newCiphertext, salt: newSalt } = newOpaqueExportKey
    ? await createDataKeyCiphertextFromOpaqueExportKey({
        opaqueExportKey: newOpaqueExportKey,
        dataKey,
        strongBox,
        deriveOpaqueExportKey,
      })
    : await createDataKeyCiphertext({
        password: requirePassword(newPassword, 'new password is required to rewrap legacy data key payloads'),
        dataKey,
        strongBox,
        deriveKey,
      })

  return {
    newCiphertext,
    dataKey: copyBytes(dataKey),
    oldSalt: oldSalt ? copyBytes(oldSalt) : undefined,
    newSalt,
  }
}

export async function deriveDataKeyWrappingKeyFromOpaqueExportKey(exportKey: string): Promise<Uint8Array> {
  const exportKeyBytes = decodeBase64(exportKey)
  if (exportKeyBytes.length === 0) {
    throw new Error('OPAQUE export key cannot be empty')
  }
  return hkdfExpand({
    parent: exportKeyBytes,
    info: OPAQUE_EXPORT_KEY_INFO,
    length: KEY_SIZE_BYTES,
  })
}

function assertDataKeyLength(dataKey: Uint8Array) {
  if (dataKey.length !== KEY_SIZE_BYTES) {
    throw new Error('data key must be 32 bytes')
  }
}

function requirePassword(password: string | undefined, message: string): string {
  if (!password) {
    throw new Error(message)
  }
  return password
}
