import { beforeEach, describe, expect, it, vi } from 'vitest'
import { decode as cborDecode, encode as cborEncode } from 'cbor-x'

const encryptSpy = vi.fn()

vi.mock('../strong-box', () => ({
  getStrongBoxBridge: () => Promise.resolve({ encrypt: encryptSpy }),
}))

import { SEALED_PAYLOAD_VERSION } from '../constants'
import { parseSealedPayload, serializeSealedPayloadBase64 } from '../sealed-payload'
import {
  decodeLegacyCborRecurrenceTemplateText,
  decodeLegacyCborTextValue,
  decryptTaskTitleCompatibleTextValueSafe,
  isLegacyCborTextValue,
  sealTextValue,
} from '../work-list'

const textDecoder = new TextDecoder()

describe('StrongBox text value sealing', () => {
  beforeEach(() => {
    encryptSpy.mockReset()
  })

  it('encrypts text values instead of storing plaintext CBOR in the sealed payload', async () => {
    encryptSpy.mockResolvedValue(new Uint8Array([0xff, 0xff, 0xff]))

    const sealed = await sealTextValue({
      value: 'PT secret: Project Apollo',
      key: new Uint8Array(32).fill(1),
      context: 'workListTitle',
    })

    const inner = parseSealedPayload(sealed.base64).ciphertext
    expect(inner).toEqual(new Uint8Array([0xff, 0xff, 0xff]))
    expect(decodeLegacyCborTextValue(sealed.base64)).toBeNull()
    expect(() => cborDecode(inner)).toThrow()
    expect(textDecoder.decode(encryptSpy.mock.calls[0][0].context)).toBe(
      'worklist.work_list.title.v1',
    )
  })

  it('binds text values to their entity id when provided', async () => {
    encryptSpy.mockResolvedValue(new Uint8Array([0xee]))

    await sealTextValue({
      value: 'Entity-bound title',
      key: new Uint8Array(32).fill(1),
      context: 'taskTitle',
      entityId: '018f2c69-1ebd-7d6d-b46b-0890173329af',
    })

    expect(textDecoder.decode(encryptSpy.mock.calls[0][0].context)).toBe(
      'worklist.task.title.v1:018f2c69-1ebd-7d6d-b46b-0890173329af',
    )
  })

  it('detects legacy CBOR-wrapped text values', () => {
    const legacy = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array(cborEncode({ value: 'Legacy title' })),
    })

    expect(isLegacyCborTextValue(legacy)).toBe(true)
    expect(decodeLegacyCborTextValue(legacy)).toBe('Legacy title')
  })

  it('rejects legacy CBOR-wrapped text values with unknown fields', () => {
    const legacy = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array(cborEncode({ value: 'Legacy title', extra: true })),
    })

    expect(isLegacyCborTextValue(legacy)).toBe(false)
    expect(decodeLegacyCborTextValue(legacy)).toBeNull()
  })

  it('detects legacy CBOR-wrapped recurrence template envelopes', () => {
    const legacy = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array(
        cborEncode({
          kind: 'recurrence-title',
          version: 1,
          body: { text: 'Legacy recurring task' },
        }),
      ),
    })

    expect(decodeLegacyCborRecurrenceTemplateText(legacy, 'recurrence-title')).toBe(
      'Legacy recurring task',
    )
    expect(decodeLegacyCborRecurrenceTemplateText(legacy, 'recurrence-body')).toBeNull()
    expect(isLegacyCborTextValue(legacy)).toBe(false)
  })

  it('rejects recurrence template envelopes with unknown fields', () => {
    const legacy = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array(
        cborEncode({
          kind: 'recurrence-title',
          version: 1,
          body: { text: 'Legacy recurring task' },
          extra: true,
        }),
      ),
    })

    expect(decodeLegacyCborRecurrenceTemplateText(legacy, 'recurrence-title')).toBeNull()
  })

  it('silently ignores speculative task title decrypt failures', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const sealed = serializeSealedPayloadBase64({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array([0xff]),
    })

    await expect(
      decryptTaskTitleCompatibleTextValueSafe(sealed, new Uint8Array(32).fill(1)),
    ).resolves.toBeNull()
    expect(warnSpy).not.toHaveBeenCalled()

    warnSpy.mockRestore()
  })
})
