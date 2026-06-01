import { Buffer } from 'node:buffer'
import { encode as cborEncode } from 'cbor-x'
import { describe, expect, it } from 'vitest'

import {
  parseSealedPayload,
  parseSealedPayloadBytes,
  serializeSealedPayload,
  serializeSealedPayloadBase64,
  validateSealedPayload,
} from '../sealed-payload'

describe('sealed payload helpers', () => {
  it('parses base64 encoded payloads', () => {
    const payload = { version: 1, ciphertext: new Uint8Array([1, 2, 3]) }
    const encoded = Buffer.from(cborEncode(payload)).toString('base64')

    const parsed = parseSealedPayload(encoded)
    expect(parsed.version).toBe(1)
    expect(Array.from(parsed.ciphertext)).toEqual([1, 2, 3])
  })

  it('serializes and re-parses payloads', () => {
    const payload = { version: 1, ciphertext: new Uint8Array([9, 8, 7]) }
    validateSealedPayload(payload)

    const bytes = serializeSealedPayload(payload)
    const reparsed = parseSealedPayloadBytes(bytes)

    expect(reparsed.version).toBe(1)
    expect(Array.from(reparsed.ciphertext)).toEqual([9, 8, 7])
  })

  it('serializes to base64 form', () => {
    const payload = { version: 1, ciphertext: new Uint8Array([42]) }
    const encoded = serializeSealedPayloadBase64(payload)
    const reparsed = parseSealedPayload(encoded)
    expect(Array.from(reparsed.ciphertext)).toEqual([42])
  })
})
