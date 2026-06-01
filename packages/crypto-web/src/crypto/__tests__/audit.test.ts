import { beforeEach, describe, expect, it, vi } from 'vitest'
import { encode as cborEncode } from 'cbor-x'

const encryptSpy = vi.fn()
const decryptSpy = vi.fn()

vi.mock('../strong-box', () => ({
  getStrongBoxBridge: () => Promise.resolve({ encrypt: encryptSpy, decrypt: decryptSpy }),
}))

import { decryptAuditPayload, encryptAuditEnvelope, type AuditEnvelope } from '../audit'
import { parseSealedPayload, serializeSealedPayloadBase64 } from '../sealed-payload'
import { SEALED_PAYLOAD_VERSION } from '../constants'

const textDecoder = new TextDecoder()

const sampleEnvelope: AuditEnvelope = {
  kind: 'audit.task_created',
  version: 2,
  body: {
    narrativeKey: 'features.audit.narratives.taskCreated',
    narrativeOptions: { title: 'Ship OSS crypto' },
  },
}

describe('audit payload crypto', () => {
  beforeEach(() => {
    encryptSpy.mockReset()
    decryptSpy.mockReset()
  })

  it('uses the audit context when encrypting payloads', async () => {
    encryptSpy.mockResolvedValue(new Uint8Array([1, 2, 3, 4]))

    const result = await encryptAuditEnvelope({
      envelope: sampleEnvelope,
      listKey: new Uint8Array(32).fill(7),
      bindingKey: new Uint8Array(32).fill(8),
    })

    expect(encryptSpy).toHaveBeenCalledOnce()
    const { context } = encryptSpy.mock.calls[0][0]
    expect(textDecoder.decode(context)).toBe('audit-patch')
    expect(Array.from(parseSealedPayload(result.payloadCiphertext).ciphertext)).toEqual([1, 2, 3, 4])
    expect(result.payloadCiphertextProof).toMatch(/^[A-Za-z0-9+/]+=*$/)
  })

  it('uses the audit context when decrypting payloads', async () => {
    decryptSpy.mockImplementation(async ({ context }) => {
      expect(textDecoder.decode(context)).toBe('audit-patch')
      return new Uint8Array(cborEncode(sampleEnvelope))
    })

    const sealed = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array([9, 8, 7]),
    })

    const result = await decryptAuditPayload({
      ciphertext: sealed,
      listKey: new Uint8Array(32).fill(9),
    })

    expect(result).toEqual(sampleEnvelope)
    expect(decryptSpy).toHaveBeenCalledOnce()
  })

  it('rejects malformed audit envelopes after decryption', async () => {
    decryptSpy.mockResolvedValue(new Uint8Array(cborEncode({ kind: '', version: 2, body: {} })))

    const sealed = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array([1]),
    })

    await expect(
      decryptAuditPayload({
        ciphertext: sealed,
        listKey: new Uint8Array(32).fill(1),
      }),
    ).rejects.toThrow('Audit payload kind must be a string')
  })
})
