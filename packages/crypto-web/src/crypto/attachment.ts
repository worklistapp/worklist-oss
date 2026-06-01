import { decode as cborDecode, encode as cborEncode } from 'cbor-x'

import { SEALED_PAYLOAD_VERSION } from './constants'
import { randomBytes } from './random'
import { parseSealedPayloadBytes, serializeSealedPayload, type SealedPayload } from './sealed-payload'
import { getStrongBoxBridge, type StrongBoxBridge } from './strong-box'

const encoder = new TextEncoder()
const ATTACHMENT_BLOB_CONTEXT_LABEL = 'worklist.attachment.blob.v1'
const ATTACHMENT_REF_CONTEXT_LABEL = 'worklist.attachment.ref.v1'
const ATTACHMENT_KEY_BYTES = 32
const ATTACHMENT_BLOB_REF_VERSION = 1
const STRONG_BOX_MAGIC_BYTES = 3
const STRONG_BOX_ARRAY_HEADER_BYTES = 1
const STRONG_BOX_KEY_ID_BYTES = 16
const STRONG_BOX_NONCE_BYTES = 12
const STRONG_BOX_TAG_BYTES = 16

export const MAX_ATTACHMENT_CIPHERTEXT_BYTES = 10 * 1024 * 1024
export const MAX_ATTACHMENT_PLAINTEXT_BYTES =
  maxPlaintextBytesForCiphertextLimit(MAX_ATTACHMENT_CIPHERTEXT_BYTES)

export const ATTACHMENT_BLOB_CONTEXT = encoder.encode(ATTACHMENT_BLOB_CONTEXT_LABEL)
const ATTACHMENT_REF_CONTEXT = encoder.encode(ATTACHMENT_REF_CONTEXT_LABEL)

export type AttachmentBlobRef = {
  version: 1
  object_key: string
  ciphertext_bytes: number
  file_key: Uint8Array
  enc_context: string
}

export type AttachmentRef = {
  id: string
  file_name: string
  content_type: string
  size_bytes: number
  blob_key: Uint8Array
}

export type AttachmentEncryptionResult = {
  ciphertext: Uint8Array
  file_key: Uint8Array
  enc_context: string
}

function generateAttachmentKey(): Uint8Array {
  return randomBytes(ATTACHMENT_KEY_BYTES)
}

export async function encryptAttachmentBytes(params: {
  plaintext: Uint8Array
  fileKey?: Uint8Array
  strongBox?: StrongBoxBridge
}): Promise<AttachmentEncryptionResult> {
  const bridge = params.strongBox ?? (await getStrongBoxBridge())
  const fileKey = params.fileKey ?? generateAttachmentKey()
  const ciphertext = await bridge.encrypt({
    key: fileKey,
    context: ATTACHMENT_BLOB_CONTEXT,
    plaintext: toUint8Array(params.plaintext),
  })
  return {
    ciphertext,
    file_key: toUint8Array(fileKey),
    enc_context: ATTACHMENT_BLOB_CONTEXT_LABEL,
  }
}

export async function encodeAttachmentBlobKey(params: {
  listKey: Uint8Array
  blobRef: AttachmentBlobRef
  strongBox?: StrongBoxBridge
}): Promise<Uint8Array> {
  const bridge = params.strongBox ?? (await getStrongBoxBridge())
  const plaintext = toUint8Array(cborEncode(params.blobRef))
  const ciphertext = await bridge.encrypt({
    key: params.listKey,
    context: ATTACHMENT_REF_CONTEXT,
    plaintext,
  })
  return toSealedBlobBytes({ version: SEALED_PAYLOAD_VERSION, ciphertext })
}

export async function decodeAttachmentBlobKey(params: {
  listKey: Uint8Array
  blobKey: Uint8Array
  strongBox?: StrongBoxBridge
}): Promise<AttachmentBlobRef> {
  const bridge = params.strongBox ?? (await getStrongBoxBridge())
  const sealed = parseSealedPayloadBytes(toUint8Array(params.blobKey))
  if (sealed.version !== SEALED_PAYLOAD_VERSION) {
    throw new Error(`Unsupported sealed payload version: ${sealed.version}`)
  }
  const plaintext = await bridge.decrypt({
    key: params.listKey,
    context: ATTACHMENT_REF_CONTEXT,
    ciphertext: sealed.ciphertext,
  })
  const decoded = cborDecode(plaintext) as Partial<AttachmentBlobRef>
  if (!decoded || typeof decoded !== 'object') {
    throw new Error('Attachment blob key is invalid')
  }
  const ciphertextBytes = Number(decoded.ciphertext_bytes)
  if (
    decoded.version !== ATTACHMENT_BLOB_REF_VERSION ||
    typeof decoded.object_key !== 'string' ||
    !Number.isFinite(ciphertextBytes) ||
    ciphertextBytes <= 0 ||
    !decoded.file_key
  ) {
    throw new Error('Attachment blob key is invalid')
  }
  return {
    version: ATTACHMENT_BLOB_REF_VERSION,
    object_key: decoded.object_key,
    ciphertext_bytes: ciphertextBytes,
    file_key: toUint8Array(decoded.file_key),
    enc_context:
      typeof decoded.enc_context === 'string'
        ? decoded.enc_context
        : ATTACHMENT_BLOB_CONTEXT_LABEL,
  }
}

export async function decryptAttachmentBytes(params: {
  ciphertext: Uint8Array
  fileKey: Uint8Array
  encContext?: string
  strongBox?: StrongBoxBridge
}): Promise<Uint8Array> {
  const bridge = params.strongBox ?? (await getStrongBoxBridge())
  const contextLabel = params.encContext ?? ATTACHMENT_BLOB_CONTEXT_LABEL
  const plaintext = await bridge.decrypt({
    key: params.fileKey,
    context: encoder.encode(contextLabel),
    ciphertext: toUint8Array(params.ciphertext),
  })
  return toUint8Array(plaintext)
}

export function buildAttachmentBlobRef(params: {
  objectKey: string
  ciphertextBytes: number
  fileKey: Uint8Array
  encContext?: string
}): AttachmentBlobRef {
  return {
    version: ATTACHMENT_BLOB_REF_VERSION,
    object_key: params.objectKey,
    ciphertext_bytes: params.ciphertextBytes,
    file_key: toUint8Array(params.fileKey),
    enc_context: params.encContext ?? ATTACHMENT_BLOB_CONTEXT_LABEL,
  }
}

function maxPlaintextBytesForCiphertextLimit(ciphertextLimit: number): number {
  let estimate = Math.max(0, ciphertextLimit)
  while (true) {
    const overhead = strongBoxOverheadForPlaintext(estimate)
    const next = Math.max(0, ciphertextLimit - overhead)
    if (next === estimate) {
      return next
    }
    estimate = next
  }
}

function strongBoxOverheadForPlaintext(plaintextBytes: number): number {
  const ciphertextLen = plaintextBytes + STRONG_BOX_TAG_BYTES
  return (
    STRONG_BOX_MAGIC_BYTES +
    STRONG_BOX_ARRAY_HEADER_BYTES +
    cborBytesHeaderLength(STRONG_BOX_KEY_ID_BYTES) +
    STRONG_BOX_KEY_ID_BYTES +
    cborBytesHeaderLength(STRONG_BOX_NONCE_BYTES) +
    STRONG_BOX_NONCE_BYTES +
    cborBytesHeaderLength(ciphertextLen) +
    STRONG_BOX_TAG_BYTES
  )
}

function cborBytesHeaderLength(len: number): number {
  if (len <= 23) {
    return 1
  }
  if (len <= 0xff) {
    return 2
  }
  if (len <= 0xffff) {
    return 3
  }
  if (len <= 0xffffffff) {
    return 5
  }
  return 9
}

function toSealedBlobBytes(payload: SealedPayload): Uint8Array {
  return serializeSealedPayload(payload)
}

function toUint8Array(value: Uint8Array | ArrayBuffer | ArrayBufferLike): Uint8Array {
  const source = value instanceof Uint8Array ? value : new Uint8Array(value as ArrayBufferLike)
  const copy = new Uint8Array(source.length)
  copy.set(source)
  return copy
}
