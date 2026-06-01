import { deriveKeyFromPassword } from './argon2'
import { KEY_SIZE_BYTES } from './constants'
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
export const DATA_KEY_SALT_BYTES = 32

type KeyDeriver = (password: string, salt: Uint8Array) => Promise<Uint8Array>

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

export type CreateCiphertextResult = {
  ciphertext: string
  dataKey: Uint8Array
  salt: Uint8Array
}

type DecryptCiphertextParams = {
  password: string
  ciphertext: string
  strongBox?: StrongBoxBridge
  deriveKey?: KeyDeriver
}

export type DecryptCiphertextResult = {
  dataKey: Uint8Array
  salt: Uint8Array
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
    version: 1,
    ciphertext: concatBytes(saltCopy, sealed),
  }

  return {
    ciphertext: serializeSealedPayloadBase64(payload),
    dataKey: dataKeyCopy,
    salt: saltCopy,
  }
}

export async function decryptDataKeyCiphertext(
  params: DecryptCiphertextParams,
): Promise<DecryptCiphertextResult> {
  const { password, ciphertext, strongBox, deriveKey = deriveKeyFromPassword } = params
  const payload = parseSealedPayload(ciphertext)
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

  if (dataKey.length !== KEY_SIZE_BYTES) {
    throw new Error('data key must be 32 bytes')
  }

  return {
    dataKey: copyBytes(dataKey),
    salt: copyBytes(salt),
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

type RewrapDataKeyCiphertextParams = {
  oldPassword: string
  newPassword: string
  oldCiphertext: string
  strongBox?: StrongBoxBridge
  deriveKey?: KeyDeriver
}

export type RewrapDataKeyCiphertextResult = {
  newCiphertext: string
  dataKey: Uint8Array
  oldSalt: Uint8Array
  newSalt: Uint8Array
}

/**
 * Rewrap a data key ciphertext from old password to new password.
 * This unwraps the data key with the old password and rewraps it with the new password.
 * The actual data key remains unchanged, only the encryption wrapper changes.
 */
export async function rewrapDataKeyCiphertext(
  params: RewrapDataKeyCiphertextParams,
): Promise<RewrapDataKeyCiphertextResult> {
  const { oldPassword, newPassword, oldCiphertext, strongBox, deriveKey } = params

  // Unwrap with old password
  const { dataKey, salt: oldSalt } = await decryptDataKeyCiphertext({
    password: oldPassword,
    ciphertext: oldCiphertext,
    strongBox,
    deriveKey,
  })

  // Rewrap with new password (generate new salt for security)
  const { ciphertext: newCiphertext, salt: newSalt } = await createDataKeyCiphertext({
    password: newPassword,
    dataKey,
    strongBox,
    deriveKey,
  })

  return {
    newCiphertext,
    dataKey: copyBytes(dataKey),
    oldSalt: copyBytes(oldSalt),
    newSalt,
  }
}
