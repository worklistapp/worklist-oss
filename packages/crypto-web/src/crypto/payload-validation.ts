import { decode as cborDecode } from 'cbor-x'

import { MAX_ATTACHMENT_PLAINTEXT_BYTES } from './attachment'

export type PayloadKind = 'work_list' | 'task' | 'comment' | 'recurrence-title' | 'recurrence-body' | 'note'

export class PayloadValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PayloadValidationError'
    Object.setPrototypeOf(this, PayloadValidationError.prototype)
  }
}

const WORK_LIST_SCHEMA_VERSION = 1
const TASK_SCHEMA_VERSION = 1
const COMMENT_SCHEMA_VERSION = 1
const RECURRENCE_TITLE_SCHEMA_VERSION = 1
const RECURRENCE_BODY_SCHEMA_VERSION = 1
const NOTE_SCHEMA_VERSION = 1

const MAX_TITLE_LEN = 256
const MAX_DESCRIPTION_LEN = 2048
const MAX_SECTION_COUNT = 32
const MAX_CHECKLIST_ITEMS = 200
const MAX_ATTACHMENTS = 50
const MAX_REFERENCES = 50
const MAX_MENTIONS = 50
const MAX_RICH_TEXT_BLOCKS = 500
const MAX_RICH_TEXT_TEXT_LEN = 8192
const MAX_ATTACHMENT_NAME_LEN = 255
const MAX_URI_LEN = 2048
const MAX_SECTION_NAME_LEN = 80
export const MAX_CHECKLIST_TITLE_LEN = 1024
const MAX_REFERENCE_LABEL_LEN = 128
const MAX_EMOJI_LEN = 8
const MAX_BLOB_KEY_LEN = 1024
const MAX_MARKS_PER_BLOCK = 16
const MAX_ASSIGNEES_PER_CHECKLIST = 16

export function validatePayloadBytes(
  input: Uint8Array | ArrayBuffer | ArrayLike<number>,
  expected: PayloadKind,
): void {
  const bytes = toUint8Array(input)
  const envelope = decodeEnvelope(bytes)

  if (envelope.kind !== expected) {
    throw new PayloadValidationError(
      `payload kind mismatch: expected ${expected}, got ${String(envelope.kind)}`,
    )
  }

  const expectedVersion = schemaVersionFor(expected)
  if (!isSupportedVersion(envelope.version, expectedVersion)) {
    throw new PayloadValidationError(
      `${expected} payload version ${String(envelope.version)} is not supported (expected ${expectedVersion})`,
    )
  }

  switch (expected) {
    case 'work_list':
      validateWorkListPayload(envelope.body)
      break
    case 'task':
      validateTaskPayload(envelope.body)
      break
    case 'comment':
      validateCommentPayload(envelope.body)
      break
    case 'recurrence-title':
      validateRecurrenceTitlePayload(envelope.body)
      break
    case 'recurrence-body':
      validateRecurrenceBodyPayload(envelope.body)
      break
    case 'note':
      validateNotePayload(envelope.body)
      break
  }
}

function decodeEnvelope(bytes: Uint8Array): {
  kind: unknown
  version: unknown
  body: unknown
} {
  let decoded: unknown
  try {
    decoded = cborDecode(bytes)
  } catch {
    throw new PayloadValidationError('payload is not valid CBOR')
  }

  const envelope = toRecord(decoded, 'payload envelope')
  const kind = envelope.kind
  const version = envelope.version
  const body = envelope.body

  if (body === undefined) {
    throw new PayloadValidationError('payload envelope is missing body')
  }

  return { kind, version, body }
}

function schemaVersionFor(kind: PayloadKind): number {
  switch (kind) {
    case 'work_list':
      return WORK_LIST_SCHEMA_VERSION
    case 'task':
      return TASK_SCHEMA_VERSION
    case 'comment':
      return COMMENT_SCHEMA_VERSION
    case 'recurrence-title':
      return RECURRENCE_TITLE_SCHEMA_VERSION
    case 'recurrence-body':
      return RECURRENCE_BODY_SCHEMA_VERSION
    case 'note':
      return NOTE_SCHEMA_VERSION
  }
}

function isSupportedVersion(value: unknown, expected: number): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value === expected
}

function validateWorkListPayload(value: unknown): void {
  const body = toRecord(value, 'work_list.body')

  ensureString(body.title, 'title', 1, MAX_TITLE_LEN)
  ensureOptionalString(body.description, 'description', 0, MAX_DESCRIPTION_LEN)

  if (body.theme !== undefined && body.theme !== null) {
    const theme = toRecord(body.theme, 'theme')
    const color = theme.color
    if (typeof color !== 'string' || !/^#[0-9a-fA-F]{6}$/.test(color)) {
      throw new PayloadValidationError('theme.color must be a #RRGGBB hex value')
    }
    ensureOptionalString(theme.emoji, 'theme.emoji', 1, MAX_EMOJI_LEN)
  }

  const sections = toArray(body.sections, 'sections')
  if (sections.length > MAX_SECTION_COUNT) {
    throw new PayloadValidationError(`sections cannot exceed ${MAX_SECTION_COUNT} entries`)
  }
  sections.forEach((section, index) => validateSection(section, index))

  const clientMeta = body.client_meta
  if (clientMeta !== undefined && clientMeta !== null) {
    toRecord(clientMeta, 'client_meta')
  }
}

function validateSection(value: unknown, index: number): void {
  const section = toRecord(value, `sections[${index}]`)
  ensureUuid(section.id, `sections[${index}].id`)
  ensureString(section.name, `sections[${index}].name`, 1, MAX_SECTION_NAME_LEN)
  if (section.wip_limit !== undefined && section.wip_limit !== null) {
    if (typeof section.wip_limit !== 'number' || !Number.isInteger(section.wip_limit)) {
      throw new PayloadValidationError('sections.wip_limit must be an integer value')
    }
    if (section.wip_limit <= 0) {
      throw new PayloadValidationError('sections.wip_limit must be > 0')
    }
  }
}

function validateTaskPayload(value: unknown): void {
  const body = toRecord(value, 'task.body')

  ensureString(body.title, 'title', 1, MAX_TITLE_LEN)

  if (body.rich_text !== undefined && body.rich_text !== null) {
    validateRichTextDocument(body.rich_text)
  }

  const checklist = toArray(body.checklist, 'checklist')
  if (checklist.length > MAX_CHECKLIST_ITEMS) {
    throw new PayloadValidationError(`checklist cannot exceed ${MAX_CHECKLIST_ITEMS} entries`)
  }
  checklist.forEach((item, index) => validateChecklistItem(item, index))

  const attachments = toArray(body.attachments, 'attachments')
  ensureCollectionLimit('attachments', attachments, MAX_ATTACHMENTS)
  attachments.forEach((attachment, index) => validateAttachment(attachment, index))

  const references = toArray(body.references, 'references')
  ensureCollectionLimit('references', references, MAX_REFERENCES)
  references.forEach((reference, index) => validateReference(reference, index))

  if (body.recurrence_state !== undefined && body.recurrence_state !== null) {
    validateRecurrenceState(body.recurrence_state)
  }

  const clientMeta = body.client_meta
  if (clientMeta !== undefined && clientMeta !== null) {
    toRecord(clientMeta, 'client_meta')
  }
}

function validateChecklistItem(value: unknown, index: number): void {
  const item = toRecord(value, `checklist[${index}]`)
  ensureUuid(item.id, `checklist[${index}].id`)
  ensureString(item.title, `checklist[${index}].title`, 1, MAX_CHECKLIST_TITLE_LEN)
  if (typeof item.is_done !== 'boolean') {
    throw new PayloadValidationError('checklist.is_done must be a boolean')
  }
  if (item.completed_at !== undefined && item.completed_at !== null) {
    if (typeof item.completed_at !== 'number' || !Number.isFinite(item.completed_at)) {
      throw new PayloadValidationError('checklist.completed_at must be a unix timestamp')
    }
  }
  const assignees = toArray(item.assignee_user_ids, `checklist[${index}].assignee_user_ids`)
  if (assignees.length > MAX_ASSIGNEES_PER_CHECKLIST) {
    throw new PayloadValidationError(
      `checklist.assignee_user_ids cannot exceed ${MAX_ASSIGNEES_PER_CHECKLIST} entries`,
    )
  }
  assignees.forEach((assignee, assigneeIdx) =>
    ensureUuid(assignee, `checklist[${index}].assignee_user_ids[${assigneeIdx}]`),
  )
}

function validateAttachment(value: unknown, index: number): void {
  const attachment = toRecord(value, `attachments[${index}]`)
  ensureUuid(attachment.id, `attachments[${index}].id`)
  ensureString(
    attachment.file_name,
    `attachments[${index}].file_name`,
    1,
    MAX_ATTACHMENT_NAME_LEN,
  )
  ensureString(
    attachment.content_type,
    `attachments[${index}].content_type`,
    1,
    MAX_TITLE_LEN,
  )
  if (
    typeof attachment.size_bytes !== 'number' ||
    !Number.isFinite(attachment.size_bytes) ||
    attachment.size_bytes <= 0 ||
    attachment.size_bytes > MAX_ATTACHMENT_PLAINTEXT_BYTES
  ) {
    throw new PayloadValidationError(
      `attachments.size_bytes must be between 1 and ${MAX_ATTACHMENT_PLAINTEXT_BYTES}`,
    )
  }
  const blobKey = toByteArray(attachment.blob_key, `attachments[${index}].blob_key`)
  if (blobKey.length === 0 || blobKey.length > MAX_BLOB_KEY_LEN) {
    throw new PayloadValidationError('attachments.blob_key must be a sealed reference')
  }
}

function validateReference(value: unknown, index: number): void {
  const reference = toRecord(value, `references[${index}]`)
  ensureString(reference.label, `references[${index}].label`, 1, MAX_REFERENCE_LABEL_LEN)
  ensureString(reference.uri, `references[${index}].uri`, 1, MAX_URI_LEN)
  if (!['url', 'task', 'doc'].includes(String(reference.kind ?? '').toLowerCase())) {
    throw new PayloadValidationError('references.kind must be url, task, or doc')
  }
}

function validateRecurrenceState(value: unknown): void {
  const state = toRecord(value, 'recurrence_state')
  ensureUuid(state.template_id, 'recurrence_state.template_id')
  ensureString(state.occurrence, 'recurrence_state.occurrence', 1, MAX_TITLE_LEN)
}

function validateCommentPayload(value: unknown): void {
  const body = toRecord(value, 'comment.body')
  validateRichTextDocument(body.content)

  const mentions = toArray(body.mentions, 'mentions')
  ensureCollectionLimit('mentions', mentions, MAX_MENTIONS)
  mentions.forEach((mention, index) => ensureUuid(mention, `mentions[${index}]`))

  const attachments = toArray(body.attachments, 'attachments')
  ensureCollectionLimit('attachments', attachments, MAX_ATTACHMENTS)
  attachments.forEach((attachment, index) => validateAttachment(attachment, index))

  if (body.client_meta !== undefined && body.client_meta !== null) {
    toRecord(body.client_meta, 'client_meta')
  }
}

function validateNotePayload(value: unknown): void {
  const body = toRecord(value, 'note.body')

  ensureString(body.title, 'title', 1, MAX_TITLE_LEN)
  validateNoteRichTextContent(body.content)

  const mentions = toArray(body.mentions, 'mentions')
  ensureCollectionLimit('mentions', mentions, MAX_MENTIONS)
  mentions.forEach((mention, index) => ensureUuid(mention, `mentions[${index}]`))

  const attachments = toArray(body.attachments, 'attachments')
  ensureCollectionLimit('attachments', attachments, MAX_ATTACHMENTS)
  attachments.forEach((attachment, index) => validateNoteAttachment(attachment, index))

  if (body.client_meta !== undefined && body.client_meta !== null) {
    toRecord(body.client_meta, 'client_meta')
  }
}

function validateNoteRichTextContent(value: unknown): void {
  const content = toRecord(value, 'content')

  const format = content.format
  if (typeof format !== 'string' || !['plaintext', 'markdown', 'prosemirror'].includes(format)) {
    throw new PayloadValidationError('content.format must be plaintext, markdown, or prosemirror')
  }

  if (content.version !== 1) {
    throw new PayloadValidationError('content.version must be 1')
  }

  const blocks = toArray(content.blocks, 'content.blocks')
  // Empty blocks array is allowed for notes (unlike comments/rich_text)
  ensureCollectionLimit('content.blocks', blocks, MAX_RICH_TEXT_BLOCKS)
  blocks.forEach((block, index) => validateRichTextBlock(block, index))
}

function validateNoteAttachment(value: unknown, index: number): void {
  const attachment = toRecord(value, `attachments[${index}]`)

  // Note attachments use string UUIDs
  const id = attachment.id
  if (typeof id !== 'string') {
    ensureUuid(id, `attachments[${index}].id`)
  } else {
    // Validate string UUID format
    const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
    if (!uuidPattern.test(id)) {
      throw new PayloadValidationError(`attachments[${index}].id must be a valid UUID`)
    }
  }

  ensureString(attachment.name, `attachments[${index}].name`, 1, MAX_ATTACHMENT_NAME_LEN)

  if (
    typeof attachment.size !== 'number' ||
    !Number.isFinite(attachment.size) ||
    attachment.size <= 0 ||
    attachment.size > MAX_ATTACHMENT_PLAINTEXT_BYTES
  ) {
    throw new PayloadValidationError(
      `attachments[${index}].size must be between 1 and ${MAX_ATTACHMENT_PLAINTEXT_BYTES}`,
    )
  }

  // mime_type is optional
  if (attachment.mime_type !== undefined && attachment.mime_type !== null) {
    ensureString(attachment.mime_type, `attachments[${index}].mime_type`, 1, MAX_TITLE_LEN)
  }
}

function validateRecurrenceTitlePayload(value: unknown): void {
  const body = toRecord(value, 'recurrence-title.body')
  ensureString(body.text, 'text', 1, MAX_TITLE_LEN)
}

function validateRecurrenceBodyPayload(value: unknown): void {
  const body = toRecord(value, 'recurrence-body.body')
  ensureString(body.text, 'text', 0, MAX_DESCRIPTION_LEN)
}

function validateRichTextDocument(value: unknown): void {
  const doc = toRecord(value, 'rich_text')
  if (doc.version !== 1) {
    throw new PayloadValidationError('rich_text.version must be 1')
  }
  const blocks = toArray(doc.blocks, 'rich_text.blocks')
  if (blocks.length === 0) {
    throw new PayloadValidationError('rich_text.blocks must not be empty')
  }
  ensureCollectionLimit('rich_text.blocks', blocks, MAX_RICH_TEXT_BLOCKS)
  blocks.forEach((block, index) => validateRichTextBlock(block, index))
}

function validateRichTextBlock(value: unknown, index: number): void {
  const block = toRecord(value, `rich_text.blocks[${index}]`)
  const kind = String(block.type ?? block.kind ?? '').toLowerCase()
  const allowedTypes = [
    'paragraph',
    'heading',
    'blockquote',
    'code_block',
    'list_item',    // legacy
    'bullet_item',
    'ordered_item',
  ]
  if (!allowedTypes.includes(kind)) {
    throw new PayloadValidationError('rich_text.blocks.type is not supported')
  }
  ensureString(block.text, `rich_text.blocks[${index}].text`, 0, MAX_RICH_TEXT_TEXT_LEN)
  const marks = toArray(block.marks, `rich_text.blocks[${index}].marks`)
  ensureCollectionLimit('rich_text.blocks.marks', marks, MAX_MARKS_PER_BLOCK)
  marks.forEach((mark, markIndex) => validateTextMark(mark, index, markIndex))
}

function validateTextMark(value: unknown, blockIndex: number, markIndex: number): void {
  const mark = toRecord(value, `rich_text.blocks[${blockIndex}].marks[${markIndex}]`)
  const kind = String(mark.type ?? mark.kind ?? '').toLowerCase()
  if (!['bold', 'italic', 'code', 'link'].includes(kind)) {
    throw new PayloadValidationError('rich_text mark kind is not supported')
  }
  if (kind === 'link') {
    const attrs = toRecord(mark.attrs ?? {}, 'rich_text.mark.attrs')
    const href = attrs.href
    if (typeof href !== 'string' || href.trim().length === 0) {
      throw new PayloadValidationError('link mark requires attrs.href')
    }
  }
}

function ensureCollectionLimit(field: string, items: unknown[], max: number): void {
  if (items.length > max) {
    throw new PayloadValidationError(`${field} cannot exceed ${max} entries`)
  }
}

function ensureString(
  value: unknown,
  field: string,
  min: number,
  max: number,
): string {
  if (typeof value !== 'string') {
    throw new PayloadValidationError(`${field} must be a string`)
  }
  const length = [...value].length
  if (length < min) {
    throw new PayloadValidationError(`${field} must have at least ${min} characters`)
  }
  if (length > max) {
    throw new PayloadValidationError(`${field} cannot exceed ${max} characters`)
  }
  return value
}

function ensureOptionalString(
  value: unknown,
  field: string,
  min: number,
  max: number,
): string | null {
  if (value === undefined || value === null) {
    return null
  }
  return ensureString(value, field, min, max)
}

function toArray(value: unknown, field: string): unknown[] {
  if (value === undefined || value === null) {
    return []
  }
  if (!Array.isArray(value)) {
    throw new PayloadValidationError(`${field} must be an array`)
  }
  return value
}

function toRecord(value: unknown, field: string): Record<string, unknown> {
  if (value === null || value === undefined) {
    throw new PayloadValidationError(`${field} must be an object`)
  }
  if (value instanceof Map) {
    return Object.fromEntries(value.entries())
  }
  if (typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  throw new PayloadValidationError(`${field} must be an object`)
}

function ensureUuid(value: unknown, field: string): void {
  if (value === undefined || value === null) {
    throw new PayloadValidationError(`${field} is required`)
  }
  if (value instanceof Uint8Array) {
    if (value.length !== 16) {
      throw new PayloadValidationError(`${field} must be 16 bytes`)
    }
    return
  }
  if (value instanceof ArrayBuffer) {
    if (value.byteLength !== 16) {
      throw new PayloadValidationError(`${field} must be 16 bytes`)
    }
    return
  }
  if (Array.isArray(value)) {
    if (value.length !== 16 || value.some((entry) => typeof entry !== 'number')) {
      throw new PayloadValidationError(`${field} must be 16 bytes`)
    }
    return
  }
  if (typeof value === 'string') {
    const normalized = value.trim()
    const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
    if (!uuidPattern.test(normalized)) {
      throw new PayloadValidationError(`${field} must be a UUID or 16-byte array`)
    }
    return
  }
  throw new PayloadValidationError(`${field} must be a UUID or 16-byte array`)
}

function toByteArray(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value)
  }
  if (Array.isArray(value) && value.every((entry) => typeof entry === 'number')) {
    return Uint8Array.from(value)
  }
  throw new PayloadValidationError(`${field} must be a byte array`)
}

function toUint8Array(value: Uint8Array | ArrayBuffer | ArrayLike<number>): Uint8Array {
  if (value instanceof Uint8Array) {
    return value.slice()
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value)
  }
  if (typeof value === 'object' && value !== null && 'length' in value) {
    return Uint8Array.from(value as ArrayLike<number>)
  }
  throw new PayloadValidationError('payload must be provided as bytes')
}

export async function computeSchemaHash(bytes: Uint8Array): Promise<Uint8Array> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto digest is unavailable')
  }
  const buffer = sliceArrayBuffer(bytes)
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  return new Uint8Array(digest)
}

function sliceArrayBuffer(bytes: Uint8Array): ArrayBuffer {
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
