import { describe, expect, it, vi, afterEach } from 'vitest'

import { clampScalar, derivePublicKey, deriveSharedSecret, __resetX25519ImplementationForTesting } from './x25519'
import { x25519ScalarMult, x25519ScalarMultBase } from './x25519-fallback'

const ALICE_SCALAR = hexToBytes('a546e36b389a1a706c147f1bf9d53e9798d7051fa25610c7d11d69860e652720')
const BOB_SCALAR = hexToBytes('4b66e9d4d1b40b172b928b2cc76c32101cf71f0f2c1942b47eb18ae0428d4230')
const ALICE_PUBLIC = hexToBytes('c0be51d006467bc40bf2d1f6fb9fa7e75b8a79e6ad741f096079b6abcc8ca676')
const BOB_PUBLIC = hexToBytes('a29ed84b9258f532dad080e90bab35643350970db7fbcf84557265b8d2af4e19')
const SHARED_SECRET = hexToBytes('2acc94fb2a20e487d2b253a0e7075c27e30250ec294900f8760ab515f805250e')

describe('x25519 fallback', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    __resetX25519ImplementationForTesting()
  })

  it('matches the reference vector when using the software fallback directly', () => {
    const aliceKey = clampScalar(ALICE_SCALAR)
    const bobKey = clampScalar(BOB_SCALAR)

    expect(x25519ScalarMultBase(aliceKey)).toEqual(ALICE_PUBLIC)
    expect(x25519ScalarMultBase(bobKey)).toEqual(BOB_PUBLIC)
    expect(x25519ScalarMult(aliceKey, BOB_PUBLIC)).toEqual(SHARED_SECRET)
    expect(x25519ScalarMult(bobKey, ALICE_PUBLIC)).toEqual(SHARED_SECRET)
  })

  it('falls back to the software path when WebCrypto rejects X25519', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const unsupportedError = () =>
      typeof DOMException !== 'undefined'
        ? new DOMException('X25519 not supported', 'NotSupportedError')
        : Object.assign(new Error('X25519 not supported'), { name: 'NotSupportedError' })

    const importKeyMock = vi
      .fn<SubtleCrypto['importKey']>()
      .mockImplementation(() => Promise.reject(unsupportedError()))
    const deriveBitsMock = vi.fn<SubtleCrypto['deriveBits']>()

    const subtle = {
      importKey: importKeyMock as unknown as SubtleCrypto['importKey'],
      deriveBits: deriveBitsMock as unknown as SubtleCrypto['deriveBits'],
    } as unknown as SubtleCrypto

    vi.stubGlobal('crypto', { subtle } as Crypto)

    const aliceKey = clampScalar(ALICE_SCALAR)
    const expectedPublic = x25519ScalarMultBase(aliceKey)

    const derivedPublic = await derivePublicKey(aliceKey)
    expect(derivedPublic).toEqual(expectedPublic)
    expect(importKeyMock).toHaveBeenCalledTimes(1)

    importKeyMock.mockClear()

    const shared = await deriveSharedSecret({ privateKey: aliceKey, peerPublicKey: BOB_PUBLIC })
    expect(shared).toEqual(x25519ScalarMult(aliceKey, BOB_PUBLIC))
    expect(importKeyMock).not.toHaveBeenCalled()
    expect(warnSpy).toHaveBeenCalled()
  })
})

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex input must be even length')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    const offset = i * 2
    bytes[i] = Number.parseInt(hex.slice(offset, offset + 2), 16)
  }
  return bytes
}
