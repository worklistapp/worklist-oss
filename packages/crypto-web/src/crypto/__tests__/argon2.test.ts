import { afterEach, describe, expect, it, vi } from 'vitest'

const mockHash = vi.fn()

vi.mock('argon2-browser', () => {
  return {
    default: {
      ArgonType: {
        Argon2id: 2,
      },
      hash: (...args: unknown[]) => mockHash(...(args as [unknown])),
    },
  }
})

mockHash.mockImplementation(async (options: { salt: Uint8Array; hashLen: number }) => {
  const result = new Uint8Array(options.hashLen)
  result.set(options.salt.slice(0, options.hashLen), 0)
  return {
    hash: result,
    hashHex: '',
    encoded: '',
  }
})

import { deriveKeyFromPassword } from '../argon2'

describe('deriveKeyFromPassword', () => {
  afterEach(() => {
    mockHash.mockClear()
  })

  it('passes the correct parameters to argon2-browser', async () => {
    const salt = new Uint8Array(16).fill(1)
    await deriveKeyFromPassword('hunter2', salt, {
      memoryKiB: 1024,
      iterations: 3,
      parallelism: 2,
    })

    expect(mockHash).toHaveBeenCalledWith(
      expect.objectContaining({
        pass: 'hunter2',
        salt,
        hashLen: 32,
        type: 2,
        time: 3,
        mem: 1024,
        parallelism: 2,
        raw: true,
      }),
    )
  })

  it('returns derived bytes from the underlying hash result', async () => {
    const salt = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2])
    const key = await deriveKeyFromPassword('password', salt, {
      memoryKiB: 1024,
      iterations: 1,
      parallelism: 1,
    })

    expect(key).toHaveLength(32)
    expect(Array.from(key.slice(0, 4))).toEqual([9, 8, 7, 6])
  })

  it('rejects salts shorter than the minimum size', async () => {
    const salt = new Uint8Array([1, 2, 3])
    await expect(
      deriveKeyFromPassword('password', salt, {
        memoryKiB: 1024,
        iterations: 1,
        parallelism: 1,
      }),
    ).rejects.toThrow(/Salt must be at least/i)
  })
})
