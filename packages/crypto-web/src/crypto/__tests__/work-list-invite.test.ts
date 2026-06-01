import { beforeEach, describe, expect, it, vi } from 'vitest'

const { decryptSpy, encryptSpy, randomBytesSpy } = vi.hoisted(() => ({
  encryptSpy: vi.fn(),
  decryptSpy: vi.fn(),
  randomBytesSpy: vi.fn(),
}))
const { computeKeyFingerprintSpy, hpkeOpenSpy, hpkeSealSpy } = vi.hoisted(() => ({
  computeKeyFingerprintSpy: vi.fn(),
  hpkeOpenSpy: vi.fn(),
  hpkeSealSpy: vi.fn(),
}))

vi.mock('../strong-box', () => ({
  getStrongBoxBridge: () => Promise.resolve({ encrypt: encryptSpy, decrypt: decryptSpy }),
}))

vi.mock('../random', () => ({
  randomBytes: randomBytesSpy,
}))

vi.mock('../hpke', () => ({
  computeKeyFingerprint: computeKeyFingerprintSpy,
  encodeHpkeEnvelope: ({ ciphertext }: { ciphertext: Uint8Array }) => ciphertext,
  hpkeOpen: hpkeOpenSpy,
  hpkeSeal: hpkeSealSpy,
}))

import { decodeBase64, encodeBase64 } from '../base64'
import { parseSealedPayload } from '../sealed-payload'
import {
  buildWorkListInviteAcceptancePayload,
  computeMembershipProof,
  createWorkListInvitePayload,
  deriveMemberEnvelopeKey,
} from '../work-list-invite'

const decoder = new TextDecoder()

describe('work-list invite crypto', () => {
  beforeEach(() => {
    encryptSpy.mockReset()
    decryptSpy.mockReset()
    randomBytesSpy.mockReset()
    computeKeyFingerprintSpy.mockReset()
    hpkeOpenSpy.mockReset()
    hpkeSealSpy.mockReset()
    encryptSpy.mockImplementation(async ({ plaintext }: { plaintext: Uint8Array }) => new Uint8Array(plaintext))
    decryptSpy.mockImplementation(async ({ ciphertext }: { ciphertext: Uint8Array }) => new Uint8Array(ciphertext))
    randomBytesSpy.mockImplementation(() => new Uint8Array(32).fill(9))
    computeKeyFingerprintSpy.mockResolvedValue(new Uint8Array(32).fill(222))
    hpkeSealSpy.mockImplementation(async ({ plaintext }: { plaintext: Uint8Array }) => ({
      enc: new Uint8Array([1, 2, 3]),
      ciphertext: new Uint8Array(plaintext),
    }))
    hpkeOpenSpy.mockImplementation(async ({ envelope }: { envelope: Uint8Array }) => new Uint8Array(envelope))
  })

  it('creates and accepts an invite payload with HPKE binding inputs', async () => {
    const dataKey = new Uint8Array(32).fill(3)
    const listKey = new Uint8Array(32).fill(4)
    const bindingKey = new Uint8Array(32).fill(5)
    const membershipId = '018f2c69-1ebd-7d6d-b46b-0890173329af'
    const userId = 'user-123'
    const publicKey = new Uint8Array(32).fill(6)

    const invite = await createWorkListInvitePayload({
      workListId: 'list-123',
      listKey,
      bindingKey,
      recipientPublicKey: publicKey,
      target: {
        userId,
        email: 'aria@example.com',
        name: 'Aria Patel',
        membershipRole: 'member',
      },
      listTitle: 'Launch Readiness',
      membershipId,
      inviter: { id: 'owner', name: 'Owner', email: 'owner@example.com' },
      expiresAt: '2026-06-09T00:00:00.000Z',
      inviteKeyProof: { proof: true },
    })

    const accepted = await buildWorkListInviteAcceptancePayload({
      invitation: {
        workListId: 'list-123',
        membershipId,
        recipientCiphertext: invite.recipientCiphertext,
        saltMember: invite.saltMember,
        role: 'member',
        workListKeyCiphertext: invite.workListKeyCiphertext,
      },
      dataKey,
      userId,
    })

    const memberEnvelopeKey = await deriveMemberEnvelopeKey({
      listKey,
      userId,
      salt: decodeBase64(invite.saltMember),
    })
    await expect(computeMembershipProof(memberEnvelopeKey, membershipId)).resolves.toBe(
      accepted.membershipProof,
    )
    expect(parseSealedPayload(accepted.workListKeyCiphertext).ciphertext.length).toBeGreaterThan(0)
    expect(invite.payloadBindingKey).toBe(encodeBase64(bindingKey))
    expect(invite.inviteKeyProof).toEqual({ proof: true })
    expect(hpkeSealSpy).toHaveBeenCalledOnce()
    expect(hpkeSealSpy.mock.calls[0][0].info).toEqual(hpkeSealSpy.mock.calls[0][0].aad)
    expect(hpkeSealSpy.mock.calls[0][0].recipientPublicKey).toEqual(publicKey)
    expect(hpkeOpenSpy).toHaveBeenCalledOnce()
    expect(hpkeOpenSpy.mock.calls[0][0].info).toEqual(hpkeOpenSpy.mock.calls[0][0].aad)

    const encryptContexts = encryptSpy.mock.calls.map((call) => decoder.decode(call[0].context))
    expect(encryptContexts).toContain('worklist.invite.member')
    expect(encryptContexts).toContain('worklist.invite.package')
    expect(encryptContexts).toContain('worklist.membership')
  })

  it('rejects recipient payloads bound to a different role', async () => {
    const dataKey = new Uint8Array(32).fill(7)
    const listKey = new Uint8Array(32).fill(8)
    const userId = 'user-456'
    const membershipId = '018f2c69-1ebd-7d6d-b46b-0890173329b0'
    const publicKey = new Uint8Array(32).fill(6)
    const invite = await createWorkListInvitePayload({
      workListId: 'list-456',
      listKey,
      bindingKey: new Uint8Array(32).fill(6),
      recipientPublicKey: publicKey,
      target: {
        userId,
        email: 'mina@example.com',
        name: 'Mina Solano',
        membershipRole: 'member',
      },
      listTitle: 'Ops',
      membershipId,
      expiresAt: '2026-06-09T00:00:00.000Z',
      inviteKeyProof: null,
    })

    await expect(
      buildWorkListInviteAcceptancePayload({
        invitation: {
          workListId: 'list-456',
          membershipId,
          recipientCiphertext: invite.recipientCiphertext,
          saltMember: invite.saltMember,
          role: 'admin',
          workListKeyCiphertext: invite.workListKeyCiphertext,
        },
        dataKey,
        userId,
      }),
    ).rejects.toThrow('Recipient HPKE payload role mismatch')
  })
})
