import { encode as cborEncode, decode as cborDecode } from 'cbor-x'

import { SEALED_PAYLOAD_VERSION } from './constants'
import { encodeBase64 } from './base64'
import { parseSealedPayload, serializeSealedPayload, type SealedPayload } from './sealed-payload'
import { getStrongBoxBridge } from './strong-box'
import { computeSchemaHash, validatePayloadBytes } from './payload-validation'
import type { TaskPayloadRichText } from './task'
import type { SealedBlobPayload, ValidatedSealedBlobPayload } from './types'

const encoder = new TextEncoder()
const COMMENT_PAYLOAD_CONTEXT = encoder.encode('worklist.comment.v1')

export type CommentPayloadBody = {
  content: TaskPayloadRichText
  mentions?: string[]
  attachments?: unknown[]
  client_meta?: Record<string, unknown>
}

export type CommentPayloadEnvelope = {
  kind: 'comment'
  version: number
  body: CommentPayloadBody
}

export function buildCommentPayloadEnvelope(body: CommentPayloadBody, version = 1): CommentPayloadEnvelope {
  return {
    kind: 'comment',
    version,
    body,
  }
}

export async function encryptCommentPayload(params: {
  envelope: CommentPayloadEnvelope
  listKey: Uint8Array
}): Promise<ValidatedSealedBlobPayload> {
  const bridge = await getStrongBoxBridge()
  const plaintext = toUint8Array(cborEncode(params.envelope))
  validatePayloadBytes(plaintext, 'comment')
  const [schemaHash, ciphertext] = await Promise.all([
    computeSchemaHash(plaintext),
    bridge.encrypt({
      key: params.listKey,
      context: COMMENT_PAYLOAD_CONTEXT,
      plaintext,
    }),
  ])
  const sealed = toSealedBlob({ version: SEALED_PAYLOAD_VERSION, ciphertext })
  return {
    ...sealed,
    schemaHash,
  }
}

export async function decryptCommentPayload(params: {
  ciphertext: string
  listKey: Uint8Array
}): Promise<CommentPayloadEnvelope> {
  const sealed = parseSealedPayload(params.ciphertext)
  const bridge = await getStrongBoxBridge()
  const plaintext = await bridge.decrypt({
    key: params.listKey,
    context: COMMENT_PAYLOAD_CONTEXT,
    ciphertext: sealed.ciphertext,
  })
  const envelope = cborDecode(plaintext) as CommentPayloadEnvelope
  if (!envelope || envelope.kind !== 'comment') {
    throw new Error('Invalid comment payload envelope')
  }
  return envelope
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
