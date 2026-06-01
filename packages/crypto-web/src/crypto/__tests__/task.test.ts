import { beforeEach, describe, expect, it, vi } from 'vitest'
import { encode as cborEncode } from 'cbor-x'

const encryptSpy = vi.fn()
const decryptSpy = vi.fn()

vi.mock('../strong-box', () => ({
  getStrongBoxBridge: () => Promise.resolve({ encrypt: encryptSpy, decrypt: decryptSpy }),
}))

import { SEALED_PAYLOAD_VERSION } from '../constants'
import { buildTaskPayloadEnvelope, decryptTaskPayload, encryptTaskPayload } from '../task'
import { serializeSealedPayloadBase64 } from '../sealed-payload'

const textDecoder = new TextDecoder()

describe('task payload StrongBox context', () => {
  beforeEach(() => {
    encryptSpy.mockReset()
    decryptSpy.mockReset()
  })

  it('uses the task context when encrypting payloads', async () => {
    encryptSpy.mockResolvedValue(new Uint8Array([1, 2, 3, 4]))

    const envelope = buildTaskPayloadEnvelope({ title: 'Ship release' })
    await encryptTaskPayload({ envelope, listKey: new Uint8Array(32).fill(7) })

    expect(encryptSpy).toHaveBeenCalledOnce()
    const { context } = encryptSpy.mock.calls[0][0]
    expect(textDecoder.decode(context)).toBe('worklist.task.v1')
  })

  it('passes the task context when decrypting payloads', async () => {
    const envelope = buildTaskPayloadEnvelope({ title: 'Decrypt me' })
    decryptSpy.mockImplementation(async ({ context }) => {
      expect(textDecoder.decode(context)).toBe('worklist.task.v1')
      return new Uint8Array(cborEncode(envelope))
    })

    const sealed = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array([9, 8, 7]),
    })

    const result = await decryptTaskPayload({
      ciphertext: sealed,
      listKey: new Uint8Array(32).fill(9),
    })

    expect(result).toEqual(envelope)
    expect(decryptSpy).toHaveBeenCalledOnce()
  })
})
