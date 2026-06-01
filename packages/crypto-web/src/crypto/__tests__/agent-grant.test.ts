import { beforeEach, describe, expect, it, vi } from 'vitest'

const { encodeHpkeEnvelopeSpy, hpkeSealSpy } = vi.hoisted(() => ({
  encodeHpkeEnvelopeSpy: vi.fn(),
  hpkeSealSpy: vi.fn(),
}))

vi.mock('../hpke', () => ({
  encodeHpkeEnvelope: encodeHpkeEnvelopeSpy,
  hpkeSeal: hpkeSealSpy,
}))

import { encodeBase64 } from '../base64'
import { buildAgentGrantCiphertext } from '../agent-grant'

describe('agent grant crypto', () => {
  beforeEach(() => {
    encodeHpkeEnvelopeSpy.mockReset()
    hpkeSealSpy.mockReset()
    hpkeSealSpy.mockImplementation(
      async ({ recipientPublicKey }: { recipientPublicKey: Uint8Array }) => ({
        recipientPublicKey,
      }),
    )
    encodeHpkeEnvelopeSpy.mockImplementation(
      ({ recipientPublicKey }: { recipientPublicKey: Uint8Array }) => recipientPublicKey,
    )
  })

  it('seals list keys to the agent recipient key with a work-list context', async () => {
    const recipientPublicKey = new Uint8Array(32).fill(7)
    const listKey = new Uint8Array([9, 8, 7])

    const ciphertext = await buildAgentGrantCiphertext({
      recipientPublicKey: encodeBase64(recipientPublicKey),
      workListId: 'work-list-123',
      listKey,
    })

    expect(ciphertext).toBe(encodeBase64(recipientPublicKey))
    expect(hpkeSealSpy).toHaveBeenCalledOnce()
    expect(hpkeSealSpy.mock.calls[0][0].recipientPublicKey).toEqual(recipientPublicKey)
    expect(hpkeSealSpy.mock.calls[0][0].plaintext).toEqual(listKey)
    expect(new TextDecoder().decode(hpkeSealSpy.mock.calls[0][0].info)).toBe(
      'worklist.agent.grant:work-list-123',
    )
    expect(hpkeSealSpy.mock.calls[0][0].aad).toEqual(hpkeSealSpy.mock.calls[0][0].info)
  })

  it('rejects malformed recipient keys before sealing', async () => {
    await expect(
      buildAgentGrantCiphertext({
        recipientPublicKey: 'AQ',
        workListId: 'work-list-123',
        listKey: new Uint8Array([1, 2, 3]),
      }),
    ).rejects.toThrow('Agent recipient public key must decode to 32 bytes.')
    expect(hpkeSealSpy).not.toHaveBeenCalled()
  })
})
