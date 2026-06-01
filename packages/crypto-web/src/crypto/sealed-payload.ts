import { decode as cborDecode, encode as cborEncode } from 'cbor-x'

import { SEALED_PAYLOAD_VERSION } from './constants'
import { decodeBase64, encodeBase64 } from './base64'

export type SealedPayload = {
  version: number
  ciphertext: Uint8Array
}

type SealedPayloadRecord = {
  version: number
  ciphertext: Uint8Array
}

function assertSealedPayload(value: unknown): asserts value is SealedPayloadRecord {
  if (
    !value ||
    typeof value !== 'object' ||
    typeof (value as SealedPayloadRecord).version !== 'number' ||
    !(value as SealedPayloadRecord).ciphertext
  ) {
    throw new Error('Invalid sealed payload structure')
  }
}

export function parseSealedPayloadBytes(bytes: Uint8Array): SealedPayload {
  const decoded = cborDecode(bytes) as unknown
  assertSealedPayload(decoded)

  // Convert Array to Uint8Array if needed
  let ciphertext = decoded.ciphertext
  if (Array.isArray(ciphertext)) {
    ciphertext = new Uint8Array(ciphertext)
  } else if (!(ciphertext instanceof Uint8Array)) {
    throw new Error('Ciphertext must be an Array or Uint8Array')
  }

  return {
    version: decoded.version,
    ciphertext,
  }
}

export function parseSealedPayload(base64Value: string): SealedPayload {
  const bytes = decodeBase64(base64Value)
  return parseSealedPayloadBytes(bytes)
}

export function validateSealedPayload(payload: SealedPayload): void {
  if (payload.version !== SEALED_PAYLOAD_VERSION) {
    throw new Error(`Unsupported sealed payload version: ${payload.version}`)
  }
  if (!(payload.ciphertext instanceof Uint8Array) || payload.ciphertext.length === 0) {
    throw new Error('Ciphertext must be a non-empty Uint8Array')
  }
}

export function serializeSealedPayload(payload: SealedPayload): Uint8Array {
  validateSealedPayload(payload)
  return cborEncode(payload)
}

export function serializeSealedPayloadBase64(payload: SealedPayload): string {
  const bytes = serializeSealedPayload(payload)
  return encodeBase64(bytes)
}
