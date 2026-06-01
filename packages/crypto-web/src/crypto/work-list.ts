import { encode as cborEncode, decode as cborDecode } from 'cbor-x'

import { SEALED_PAYLOAD_VERSION } from './constants'
import { decodeBase64, encodeBase64 } from './base64'
import { hkdfExpand } from './hkdf'
import { parseSealedPayload, serializeSealedPayload, type SealedPayload } from './sealed-payload'
import { getStrongBoxBridge } from './strong-box'
import { validatePayloadBytes, computeSchemaHash } from './payload-validation'
import type { SealedBlobPayload, ValidatedSealedBlobPayload } from './types'

const encoder = new TextEncoder()
const WORK_LIST_PAYLOAD_CONTEXT = encoder.encode('worklist.work_list.v1')
const WORK_LIST_MEMBERSHIP_CONTEXT = encoder.encode('worklist.membership')
const TEXT_VALUE_CONTEXT_LABELS = {
  workListTitle: 'worklist.work_list.title.v1',
  workListDescription: 'worklist.work_list.description.v1',
  taskTitle: 'worklist.task.title.v1',
  noteTitle: 'worklist.note.title.v1',
} as const
const TEXT_VALUE_CONTEXTS = {
  workListTitle: encoder.encode(TEXT_VALUE_CONTEXT_LABELS.workListTitle),
  workListDescription: encoder.encode(TEXT_VALUE_CONTEXT_LABELS.workListDescription),
  taskTitle: encoder.encode(TEXT_VALUE_CONTEXT_LABELS.taskTitle),
  noteTitle: encoder.encode(TEXT_VALUE_CONTEXT_LABELS.noteTitle),
} as const

export type TextValueContext = keyof typeof TEXT_VALUE_CONTEXTS

export type WorkListPayloadEnvelope = {
  kind: 'work_list'
  version: number
  body: Record<string, unknown>
}

export async function deriveWorkListKey(params: {
  dataKey: Uint8Array
  workListId: string
}): Promise<Uint8Array> {
  return hkdfExpand({
    parent: params.dataKey,
    info: `worklist:${params.workListId}`,
  })
}

export async function derivePayloadBindingKey(params: { listKey: Uint8Array }): Promise<Uint8Array> {
  return hkdfExpand({
    parent: params.listKey,
    info: 'member:payload-binding',
  })
}

export async function decryptWorkListPayload(params: {
  ciphertext: string
  listKey: Uint8Array
}): Promise<WorkListPayloadEnvelope> {
  const sealed = parseSealedPayload(params.ciphertext)
  const bridge = await getStrongBoxBridge()
  const plaintext = await bridge.decrypt({
    key: params.listKey,
    context: WORK_LIST_PAYLOAD_CONTEXT,
    ciphertext: sealed.ciphertext,
  })
  const envelope = cborDecode(plaintext) as unknown
  if (
    !isRecord(envelope) ||
    envelope.kind !== 'work_list' ||
    typeof envelope.version !== 'number' ||
    !isRecord(envelope.body)
  ) {
    throw new Error('Invalid work list payload envelope')
  }
  return {
    kind: envelope.kind,
    version: envelope.version,
    body: envelope.body,
  }
}

export async function encryptWorkListPayload(params: {
  envelope: WorkListPayloadEnvelope
  listKey: Uint8Array
}): Promise<ValidatedSealedBlobPayload> {
  const bridge = await getStrongBoxBridge()
  const plaintext = toUint8Array(cborEncode(params.envelope))
  validatePayloadBytes(plaintext, 'work_list')
  const [schemaHash, ciphertext] = await Promise.all([
    computeSchemaHash(plaintext),
    bridge.encrypt({
      key: params.listKey,
      context: WORK_LIST_PAYLOAD_CONTEXT,
      plaintext,
    }),
  ])
  const sealed = toSealedBlob({ version: SEALED_PAYLOAD_VERSION, ciphertext })
  return {
    ...sealed,
    schemaHash,
  }
}

export async function sealWorkListKeyForOwner(params: {
  listKey: Uint8Array
  dataKey: Uint8Array
}): Promise<SealedBlobPayload> {
  const bridge = await getStrongBoxBridge()
  const ciphertext = await bridge.encrypt({
    key: params.dataKey,
    context: WORK_LIST_MEMBERSHIP_CONTEXT,
    plaintext: toUint8Array(params.listKey),
  })
  return toSealedBlob({
    version: SEALED_PAYLOAD_VERSION,
    ciphertext,
  })
}

export async function decryptWorkListKeyCiphertext(params: {
  ciphertext: string
  dataKey: Uint8Array
}): Promise<Uint8Array> {
  if (!params.ciphertext) {
    throw new Error('Work list key ciphertext is required')
  }
  const sealed = parseSealedPayload(params.ciphertext)
  const bridge = await getStrongBoxBridge()
  const plaintext = await bridge.decrypt({
    key: params.dataKey,
    context: WORK_LIST_MEMBERSHIP_CONTEXT,
    ciphertext: sealed.ciphertext,
  })
  return extractWorkListKeyFromPlaintext(plaintext)
}

export async function sealTextValue(params: {
  value: string
  key: Uint8Array
  context: TextValueContext
  entityId?: string
}): Promise<SealedBlobPayload> {
  const bridge = await getStrongBoxBridge()
  const plaintext = toUint8Array(cborEncode({ value: params.value }))
  const ciphertext = await bridge.encrypt({
    key: params.key,
    context: textValueContextBytes(params.context, params.entityId),
    plaintext,
  })
  return toSealedBlob({
    version: SEALED_PAYLOAD_VERSION,
    ciphertext,
  })
}

export async function decryptTextValue(params: {
  ciphertext: string
  key: Uint8Array
  context: TextValueContext
  entityId?: string
}): Promise<string> {
  const sealed = parseSealedPayload(params.ciphertext)
  const bridge = await getStrongBoxBridge()
  let plaintext: Uint8Array
  try {
    plaintext = await bridge.decrypt({
      key: params.key,
      context: textValueContextBytes(params.context, params.entityId),
      ciphertext: sealed.ciphertext,
    })
  } catch (error) {
    if (!params.entityId) {
      throw error
    }
    try {
      // Older stored text fields used only the base context. Keep the read path
      // tolerant during migration, but preserve the entity-bound error if both
      // attempts fail because it reflects the preferred encoding.
      plaintext = await bridge.decrypt({
        key: params.key,
        context: TEXT_VALUE_CONTEXTS[params.context],
        ciphertext: sealed.ciphertext,
      })
    } catch {
      throw error
    }
  }
  const decoded = cborDecode(plaintext) as unknown
  if (!isRecord(decoded) || !hasOnlyKeys(decoded, ['value']) || typeof decoded.value !== 'string') {
    throw new Error('Invalid text value payload')
  }
  return decoded.value
}

export async function decryptTaskTitleCompatibleTextValueSafe(
  ciphertext: string | null | undefined,
  listKey: Uint8Array,
): Promise<string | null> {
  if (!ciphertext || typeof ciphertext !== 'string' || ciphertext.trim().length === 0) {
    return null
  }
  try {
    parseSealedPayload(ciphertext)
  } catch {
    return null
  }
  try {
    return await decryptTextValue({
      ciphertext,
      key: listKey,
      context: 'taskTitle',
    })
  } catch {
    return null
  }
}

export async function sealOptionalText(params: {
  value: string | null | undefined
  key: Uint8Array
  context: TextValueContext
  entityId?: string
}): Promise<SealedBlobPayload | null> {
  const { value } = params
  if (value === null || value === undefined) {
    return null
  }
  if (value.trim().length === 0) {
    return null
  }
  return sealTextValue({
    value,
    key: params.key,
    context: params.context,
    entityId: params.entityId,
  })
}

function textValueContextBytes(context: TextValueContext, entityId?: string): Uint8Array {
  const base = TEXT_VALUE_CONTEXTS[context]
  if (!entityId) {
    return base
  }
  return encoder.encode(`${TEXT_VALUE_CONTEXT_LABELS[context]}:${entityId}`)
}

export function isLegacyCborTextValue(ciphertext: string | null | undefined): boolean {
  return decodeLegacyCborTextValue(ciphertext) !== null
}

export function decodeLegacyCborTextValue(ciphertext: string | null | undefined): string | null {
  if (!ciphertext) {
    return null
  }
  try {
    const sealed = parseSealedPayload(ciphertext)
    const decoded = cborDecode(sealed.ciphertext) as unknown
    // Keep this aligned with the Rust detector's deny_unknown_fields shape:
    // only canonical `{ value: string }` legacy text payloads are eligible.
    return isRecord(decoded) &&
      hasOnlyKeys(decoded, ['value']) &&
      typeof decoded.value === 'string'
      ? decoded.value
      : null
  } catch {
    return null
  }
}

export function decodeLegacyCborRecurrenceTemplateText(
  ciphertext: string | null | undefined,
  kind: 'recurrence-title' | 'recurrence-body',
): string | null {
  if (!ciphertext) {
    return null
  }
  try {
    const sealed = parseSealedPayload(ciphertext)
    const decoded = cborDecode(sealed.ciphertext) as unknown
    if (
      !isRecord(decoded) ||
      !hasOnlyKeys(decoded, ['body', 'kind', 'version']) ||
      !isRecord(decoded.body) ||
      !hasOnlyKeys(decoded.body, ['text'])
    ) {
      return null
    }
    // Intentional: only the shipped v1 recurrence-template CBOR bug is in
    // scope for this detector. Future legacy shapes should add explicit
    // migration logic instead of being accepted implicitly here.
    return (
      decoded.kind === kind &&
      decoded.version === 1 &&
      typeof decoded.body.text === 'string'
    )
      ? decoded.body.text
      : null
  } catch {
    return null
  }
}

export async function computePayloadProof({
  ciphertext,
  bindingKey,
  schemaHash,
}: {
  ciphertext: Uint8Array
  bindingKey: Uint8Array
  schemaHash?: Uint8Array | null
}): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto HMAC is unavailable')
  }
  const normalizedKey = toUint8Array(bindingKey)
  const normalizedCiphertext = toUint8Array(ciphertext)
  const message = schemaHash && schemaHash.length > 0
    ? concatBytes(normalizedCiphertext, toUint8Array(schemaHash))
    : normalizedCiphertext
  const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(normalizedKey), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ])
  const mac = await crypto.subtle.sign('HMAC', cryptoKey, toArrayBuffer(message))
  return encodeBase64(new Uint8Array(mac))
}

export function clonePayloadBody(envelope: WorkListPayloadEnvelope): Record<string, unknown> {
  const body = envelope?.body
  if (!isRecord(body)) {
    return {}
  }
  return structuredClone(body)
}

export function rebuildEnvelope(body: Record<string, unknown>, version = 1): WorkListPayloadEnvelope {
  return {
    kind: 'work_list',
    version,
    body,
  }
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0)
  const combined = new Uint8Array(total)
  let offset = 0
  arrays.forEach((arr) => {
    combined.set(arr, offset)
    offset += arr.length
  })
  return combined
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const { buffer, byteOffset, byteLength } = bytes
  if (buffer instanceof ArrayBuffer) {
    if (byteOffset === 0 && byteLength === buffer.byteLength) {
      return buffer.slice(0)
    }
    return buffer.slice(byteOffset, byteOffset + byteLength)
  }
  const copied = bytes.slice()
  return copied.buffer
}

function toSealedBlob(payload: SealedPayload): SealedBlobPayload {
  const bytes = serializeSealedPayload(payload)
  return {
    bytes,
    base64: encodeBase64(bytes),
  }
}

function toUint8Array(value: Uint8Array | ArrayBuffer | ArrayBufferLike): Uint8Array {
  const source = value instanceof Uint8Array ? value : new Uint8Array(value as ArrayBufferLike)
  const copy = new Uint8Array(source.length)
  copy.set(source)
  return copy
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasOnlyKeys(value: Record<string, unknown>, allowedKeys: string[]): boolean {
  const allowed = new Set(allowedKeys)
  return Object.keys(value).every((key) => allowed.has(key))
}

function extractWorkListKeyFromPlaintext(plaintext: Uint8Array): Uint8Array {
  const envelopeKey = tryDecodeWorkListKeyEnvelope(plaintext)
  if (envelopeKey) {
    return envelopeKey
  }
  if (plaintext.length === 0) {
    throw new Error('Decrypted work list key is empty')
  }
  return toUint8Array(plaintext)
}

function tryDecodeWorkListKeyEnvelope(plaintext: Uint8Array): Uint8Array | null {
  try {
    const decoded = cborDecode(plaintext) as unknown
    if (!decoded) {
      return null
    }
    if (decoded instanceof Uint8Array) {
      return toUint8Array(decoded)
    }
    if (!isRecord(decoded)) {
      return null
    }
    const key = decoded.key
    if (typeof key === 'string') {
      return toUint8Array(decodeMembershipKeyString(key))
    }
    if (key instanceof Uint8Array) {
      return toUint8Array(key)
    }
    if (key instanceof ArrayBuffer) {
      return toUint8Array(new Uint8Array(key))
    }
    return null
  } catch {
    return null
  }
}

function decodeMembershipKeyString(value: string): Uint8Array {
  const normalized = value.trim().replace(/-/g, '+').replace(/_/g, '/')
  const bytes = decodeBase64(normalized)
  if (bytes.length === 0) {
    throw new Error('Work list key string cannot be empty')
  }
  return bytes
}
