import { beforeEach, describe, expect, it, vi } from 'vitest'
import { encode as cborEncode } from 'cbor-x'

const encryptSpy = vi.fn()
const decryptSpy = vi.fn()

vi.mock('../strong-box', () => ({
  getStrongBoxBridge: () => Promise.resolve({ encrypt: encryptSpy, decrypt: decryptSpy }),
}))

import { SEALED_PAYLOAD_VERSION } from '../constants'
import {
  buildNotePayloadEnvelope,
  decryptNoteKey,
  decryptNotePayload,
  encryptNoteKey,
  encryptNotePayload,
  generateNoteKey,
  type NotePayloadRichText,
} from '../note'
import { parseSealedPayload, serializeSealedPayloadBase64 } from '../sealed-payload'

const textDecoder = new TextDecoder()

const sampleContent: NotePayloadRichText = {
  format: 'plaintext',
  version: 1,
  blocks: [{ type: 'paragraph', text: 'Hello note' }],
}

describe('note payload and key crypto', () => {
  beforeEach(() => {
    encryptSpy.mockReset()
    decryptSpy.mockReset()
  })

  it('uses the note payload context when encrypting payloads', async () => {
    encryptSpy.mockResolvedValue(new Uint8Array([1, 2, 3, 4]))

    const envelope = buildNotePayloadEnvelope({ title: 'Note', content: sampleContent })
    await encryptNotePayload({ envelope, noteKey: new Uint8Array(32).fill(7) })

    expect(encryptSpy).toHaveBeenCalledOnce()
    const { context } = encryptSpy.mock.calls[0][0]
    expect(textDecoder.decode(context)).toBe('worklist.note.v1')
  })

  it('uses the note payload context when decrypting payloads', async () => {
    const envelope = buildNotePayloadEnvelope({ title: 'Note', content: sampleContent })
    decryptSpy.mockImplementation(async ({ context }) => {
      expect(textDecoder.decode(context)).toBe('worklist.note.v1')
      return new Uint8Array(cborEncode(envelope))
    })

    const sealed = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array([9, 8, 7]),
    })

    const result = await decryptNotePayload({
      ciphertext: sealed,
      noteKey: new Uint8Array(32).fill(9),
    })

    expect(result).toEqual(envelope)
    expect(decryptSpy).toHaveBeenCalledOnce()
  })

  it('uses the note key context when encrypting note keys', async () => {
    encryptSpy.mockResolvedValue(new Uint8Array([4, 3, 2, 1]))

    const result = await encryptNoteKey({
      noteKey: new Uint8Array(32).fill(1),
      dataKey: new Uint8Array(32).fill(2),
    })

    expect(encryptSpy).toHaveBeenCalledOnce()
    const { context } = encryptSpy.mock.calls[0][0]
    expect(textDecoder.decode(context)).toBe('worklist.note.key.v1')
    expect(Array.from(parseSealedPayload(result).ciphertext)).toEqual([4, 3, 2, 1])
  })

  it('uses the note key context when decrypting note keys', async () => {
    decryptSpy.mockImplementation(async ({ context }) => {
      expect(textDecoder.decode(context)).toBe('worklist.note.key.v1')
      return new Uint8Array(32).fill(5)
    })

    const sealed = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array([1, 2, 3]),
    })

    const result = await decryptNoteKey({
      noteKeyCiphertext: sealed,
      dataKey: new Uint8Array(32).fill(6),
    })

    expect(Array.from(result)).toEqual(Array.from(new Uint8Array(32).fill(5)))
    expect(decryptSpy).toHaveBeenCalledOnce()
  })

  it('generates 32-byte note keys', () => {
    expect(generateNoteKey()).toHaveLength(32)
  })
})
