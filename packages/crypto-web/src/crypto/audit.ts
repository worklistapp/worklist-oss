import { decode as cborDecode, encode as cborEncode } from 'cbor-x'

import { SEALED_PAYLOAD_VERSION } from './constants'
import { encodeBase64 } from './base64'
import { parseSealedPayload, serializeSealedPayload, type SealedPayload } from './sealed-payload'
import { getStrongBoxBridge } from './strong-box'
import { computePayloadProof } from './work-list'
import type { SealedBlobPayload } from './types'

const encoder = new TextEncoder()
const AUDIT_PAYLOAD_CONTEXT = encoder.encode('audit-patch')

export type AuditPayloadBody = Record<string, unknown> & {
  narrativeKey?: string | null
  narrativeOptions?: Record<string, unknown> | null
  narrative?: string | null
  summary?: string | null
  message?: string | null
  description?: string | null
  text?: string | null
}

export type AuditPayloadEnvelope = {
  kind: string
  version: number
  body: AuditPayloadBody
}

export type AuditEnvelope = AuditPayloadEnvelope

export async function encryptAuditEnvelope(params: {
  envelope: AuditEnvelope
  listKey: Uint8Array
  bindingKey: Uint8Array
}): Promise<{
  payloadCiphertext: string
  payloadCiphertextProof: string
}> {
  const plaintext = toUint8Array(cborEncode(params.envelope))
  const bridge = await getStrongBoxBridge()
  const ciphertext = await bridge.encrypt({
    key: params.listKey,
    context: AUDIT_PAYLOAD_CONTEXT,
    plaintext,
  })
  const sealed = toSealedBlob({ version: SEALED_PAYLOAD_VERSION, ciphertext })
  const proof = await computePayloadProof({
    ciphertext: sealed.bytes,
    bindingKey: params.bindingKey,
  })

  return {
    payloadCiphertext: sealed.base64,
    payloadCiphertextProof: proof,
  }
}

export async function decryptAuditPayload(params: {
  ciphertext: string
  listKey: Uint8Array
}): Promise<AuditPayloadEnvelope> {
  const sealed = parseSealedPayload(params.ciphertext)
  const bridge = await getStrongBoxBridge()
  const plaintext = await bridge.decrypt({
    key: params.listKey,
    context: AUDIT_PAYLOAD_CONTEXT,
    ciphertext: sealed.ciphertext,
  })
  const envelope = cborDecode(plaintext) as Partial<AuditPayloadEnvelope> | null
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('Invalid audit payload envelope')
  }
  const { kind, version, body } = envelope
  if (typeof kind !== 'string' || kind.length === 0) {
    throw new Error('Audit payload kind must be a string')
  }
  if (typeof version !== 'number' || !Number.isFinite(version)) {
    throw new Error('Audit payload version must be numeric')
  }
  if (!body || typeof body !== 'object') {
    throw new Error('Audit payload body must be an object')
  }
  return {
    kind,
    version,
    body: body as AuditPayloadBody,
  }
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
