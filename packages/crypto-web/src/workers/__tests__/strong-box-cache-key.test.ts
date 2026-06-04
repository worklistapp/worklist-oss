import { describe, expect, it } from 'vitest'

import { computeStrongBoxDecryptCacheKey } from '../strong-box-cache-key'

describe('StrongBox decrypt cache keys', () => {
  it('frames context and payload lengths so split-equivalent inputs do not collide', async () => {
    const key = new Uint8Array([0xaa])
    const first = await computeStrongBoxDecryptCacheKey(
      key,
      new Uint8Array([0x01]),
      new Uint8Array([0x02, 0x03]),
    )
    const second = await computeStrongBoxDecryptCacheKey(
      key,
      new Uint8Array([0x01, 0x02]),
      new Uint8Array([0x03]),
    )

    expect(first).not.toBe(second)
  })
})
