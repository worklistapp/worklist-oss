import { encode as cborEncode, decode as cborDecode } from 'cbor-x'

import { SEALED_PAYLOAD_VERSION } from './constants'
import { encodeBase64 } from './base64'
import { getStrongBoxBridge } from './strong-box'
import {
  parseSealedPayload,
  serializeSealedPayload,
  serializeSealedPayloadBase64,
  type SealedPayload,
} from './sealed-payload'
import { validatePayloadBytes, computeSchemaHash } from './payload-validation'
import { randomBytes } from './random'
import type { SealedBlobPayload, ValidatedSealedBlobPayload } from './types'

const encoder = new TextEncoder()
const NOTE_PAYLOAD_CONTEXT = encoder.encode('worklist.note.v1')
const NOTE_KEY_CONTEXT = encoder.encode('worklist.note.key.v1')
const NOTE_KEY_BYTES = 32

type TextMarkType = 'bold' | 'italic' | 'strike' | 'code' | 'link' | 'mention'

export type TextMark = {
  type: TextMarkType
  attrs?: Record<string, unknown>
}

export type TextSpan = {
  text: string
  marks?: TextMark[]
}

export type RichTextBlock = {
  type: 'paragraph' | 'heading' | 'blockquote' | 'code_block' | 'bullet_item' | 'ordered_item'
  text: string // Plain text for backwards compat and search
  content?: TextSpan[] // Rich content with inline marks
  attrs?: Record<string, unknown> // Block-level attrs (e.g., heading level, code language)
}

export type NotePayloadRichText = {
  format: 'plaintext' | 'markdown' | 'prosemirror'
  version: number
  blocks: RichTextBlock[]
}

type AttachmentRef = {
  id: string
  name: string
  size: number
  mime_type?: string
}

export type NotePayloadBody = {
  title: string
  content: NotePayloadRichText
  mentions?: string[]
  attachments?: AttachmentRef[]
  client_meta?: Record<string, unknown>
}

export type NotePayloadEnvelope = {
  kind: 'note'
  version: number
  body: NotePayloadBody
}

export function buildNotePayloadEnvelope(body: NotePayloadBody, version = 1): NotePayloadEnvelope {
  return {
    kind: 'note',
    version,
    body,
  }
}

export async function encryptNotePayload(params: {
  envelope: NotePayloadEnvelope
  noteKey: Uint8Array
}): Promise<ValidatedSealedBlobPayload> {
  const bridge = await getStrongBoxBridge()
  const plaintext = toUint8Array(cborEncode(params.envelope))
  validatePayloadBytes(plaintext, 'note')
  const [schemaHash, ciphertext] = await Promise.all([
    computeSchemaHash(plaintext),
    bridge.encrypt({
      key: params.noteKey,
      context: NOTE_PAYLOAD_CONTEXT,
      plaintext,
    }),
  ])
  const sealed = toSealedBlob({ version: SEALED_PAYLOAD_VERSION, ciphertext })
  return {
    ...sealed,
    schemaHash,
  }
}

export async function decryptNotePayload(params: {
  ciphertext: string
  noteKey: Uint8Array
}): Promise<NotePayloadEnvelope> {
  const sealed = parseSealedPayload(params.ciphertext)
  const bridge = await getStrongBoxBridge()
  const plaintext = await bridge.decrypt({
    key: params.noteKey,
    context: NOTE_PAYLOAD_CONTEXT,
    ciphertext: sealed.ciphertext,
  })
  const envelope = cborDecode(plaintext) as NotePayloadEnvelope
  if (!envelope || envelope.kind !== 'note') {
    throw new Error('Invalid note payload envelope')
  }
  return envelope
}

export async function decryptNoteKey(params: {
  noteKeyCiphertext: string
  dataKey: Uint8Array
}): Promise<Uint8Array> {
  const sealed = parseSealedPayload(params.noteKeyCiphertext)
  const bridge = await getStrongBoxBridge()
  return bridge.decrypt({
    key: params.dataKey,
    context: NOTE_KEY_CONTEXT,
    ciphertext: sealed.ciphertext,
  })
}

export async function encryptNoteKey(params: {
  noteKey: Uint8Array
  dataKey: Uint8Array
}): Promise<string> {
  const bridge = await getStrongBoxBridge()
  const ciphertext = await bridge.encrypt({
    key: params.dataKey,
    context: NOTE_KEY_CONTEXT,
    plaintext: toUint8Array(params.noteKey),
  })
  return serializeSealedPayloadBase64({
    version: SEALED_PAYLOAD_VERSION,
    ciphertext,
  })
}

export function generateNoteKey(): Uint8Array {
  return randomBytes(NOTE_KEY_BYTES)
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
