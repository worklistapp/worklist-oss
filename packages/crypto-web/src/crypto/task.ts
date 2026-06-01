import { encode as cborEncode, decode as cborDecode } from 'cbor-x'

import { SEALED_PAYLOAD_VERSION } from './constants'
import { encodeBase64 } from './base64'
import { getStrongBoxBridge } from './strong-box'
import { parseSealedPayload, serializeSealedPayload, type SealedPayload } from './sealed-payload'
import { validatePayloadBytes, computeSchemaHash } from './payload-validation'
import type { SealedBlobPayload, ValidatedSealedBlobPayload } from './types'
import type { AttachmentRef } from './attachment'

const encoder = new TextEncoder()
const TASK_PAYLOAD_CONTEXT = encoder.encode('worklist.task.v1')

export type TextMarkType = 'bold' | 'italic' | 'strike' | 'code' | 'link' | 'mention'

export type TextMark = {
  type: TextMarkType
  attrs?: Record<string, unknown>
}

export type TextSpan = {
  text: string
  marks?: TextMark[]
}

export type RichTextBlock = {
  // Note: 'list_item' is legacy - kept for backwards compat (treated as bullet_item)
  type: 'paragraph' | 'heading' | 'blockquote' | 'code_block' | 'list_item' | 'bullet_item' | 'ordered_item'
  text: string // Plain text for backwards compat and search
  content?: TextSpan[] // Rich content with inline marks
  attrs?: Record<string, unknown> // Block-level attrs (e.g., heading level, code language)
}

export type TaskPayloadRichText = {
  format: 'plaintext' | 'markdown' | 'prosemirror'
  version: number
  blocks: RichTextBlock[]
}

export type ChecklistItemPayload = {
  id: string
  title: string
  is_done: boolean
  completed_at?: number | null
  assignee_user_ids?: string[]
}

export type TaskPayloadBody = {
  title: string
  rich_text?: TaskPayloadRichText | null
  checklist?: ChecklistItemPayload[]
  attachments?: AttachmentRef[]
  references?: unknown[]
  mentions?: string[]
  client_meta?: Record<string, unknown>
  recurrence_state?: Record<string, unknown> | null
}

export type TaskPayloadEnvelope = {
  kind: 'task'
  version: number
  body: TaskPayloadBody
}

export function buildTaskPayloadEnvelope(body: TaskPayloadBody, version = 1): TaskPayloadEnvelope {
  return {
    kind: 'task',
    version,
    body,
  }
}

export async function encryptTaskPayload(params: {
  envelope: TaskPayloadEnvelope
  listKey: Uint8Array
}): Promise<ValidatedSealedBlobPayload> {
  const bridge = await getStrongBoxBridge()
  const plaintext = toUint8Array(cborEncode(params.envelope))
  validatePayloadBytes(plaintext, 'task')
  const [schemaHash, ciphertext] = await Promise.all([
    computeSchemaHash(plaintext),
    bridge.encrypt({
      key: params.listKey,
      context: TASK_PAYLOAD_CONTEXT,
      plaintext,
    }),
  ])
  const sealed = toSealedBlob({ version: SEALED_PAYLOAD_VERSION, ciphertext })
  return {
    ...sealed,
    schemaHash,
  }
}

export async function decryptTaskPayload(params: {
  ciphertext: string
  listKey: Uint8Array
}): Promise<TaskPayloadEnvelope> {
  const sealed = parseSealedPayload(params.ciphertext)
  const bridge = await getStrongBoxBridge()
  const plaintext = await bridge.decrypt({
    key: params.listKey,
    context: TASK_PAYLOAD_CONTEXT,
    ciphertext: sealed.ciphertext,
  })
  const envelope = cborDecode(plaintext) as TaskPayloadEnvelope
  if (!envelope || envelope.kind !== 'task') {
    throw new Error('Invalid task payload envelope')
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
