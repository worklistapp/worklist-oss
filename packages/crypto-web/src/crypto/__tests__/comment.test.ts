import { beforeEach, describe, expect, it, vi } from 'vitest'
import { encode as cborEncode } from 'cbor-x'

const encryptSpy = vi.fn()
const decryptSpy = vi.fn()

vi.mock('../strong-box', () => ({
  getStrongBoxBridge: () => Promise.resolve({ encrypt: encryptSpy, decrypt: decryptSpy }),
}))

import { SEALED_PAYLOAD_VERSION } from '../constants'
import { buildCommentPayloadEnvelope, decryptCommentPayload, encryptCommentPayload } from '../comment'
import { serializeSealedPayloadBase64 } from '../sealed-payload'
import type { TaskPayloadRichText } from '../task'

const textDecoder = new TextDecoder()

const sampleContent: TaskPayloadRichText = {
  format: 'plaintext',
  version: 1,
  blocks: [{ type: 'paragraph', text: 'Hello world' }],
}

describe('comment payload StrongBox context', () => {
  beforeEach(() => {
    encryptSpy.mockReset()
    decryptSpy.mockReset()
  })

  it('uses the comment context when encrypting payloads', async () => {
    encryptSpy.mockResolvedValue(new Uint8Array([1, 2, 3, 4]))

    const envelope = buildCommentPayloadEnvelope({ content: sampleContent })
    await encryptCommentPayload({ envelope, listKey: new Uint8Array(32).fill(7) })

    expect(encryptSpy).toHaveBeenCalledOnce()
    const { context } = encryptSpy.mock.calls[0][0]
    expect(textDecoder.decode(context)).toBe('worklist.comment.v1')
  })

  it('passes the comment context when decrypting payloads', async () => {
    const envelope = buildCommentPayloadEnvelope({ content: sampleContent })
    decryptSpy.mockImplementation(async ({ context }) => {
      expect(textDecoder.decode(context)).toBe('worklist.comment.v1')
      return new Uint8Array(cborEncode(envelope))
    })

    const sealed = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array([9, 8, 7]),
    })

    const result = await decryptCommentPayload({
      ciphertext: sealed,
      listKey: new Uint8Array(32).fill(9),
    })

    expect(result).toEqual(envelope)
    expect(decryptSpy).toHaveBeenCalledOnce()
  })
})
