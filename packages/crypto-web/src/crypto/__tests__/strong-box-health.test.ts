import { describe, expect, it, vi } from 'vitest'

import { verifyStrongBoxLocalHealth } from '../strong-box-health'

describe('StrongBox local health check', () => {
  it('returns true when the bridge decrypts the healthcheck plaintext', async () => {
    const bridge = {
      encrypt: vi.fn(async ({ plaintext }: { plaintext: Uint8Array }) => new Uint8Array(plaintext)),
      decrypt: vi.fn(async ({ ciphertext }: { ciphertext: Uint8Array }) => new Uint8Array(ciphertext)),
    }

    await expect(verifyStrongBoxLocalHealth(bridge)).resolves.toBe(true)
    expect(bridge.encrypt).toHaveBeenCalledOnce()
    expect(bridge.decrypt).toHaveBeenCalledOnce()
  })

  it('returns false when the round trip changes bytes', async () => {
    const bridge = {
      encrypt: vi.fn(async () => new Uint8Array([1, 2, 3])),
      decrypt: vi.fn(async () => new Uint8Array([4, 5, 6])),
    }

    await expect(verifyStrongBoxLocalHealth(bridge)).resolves.toBe(false)
  })
})
