import { describe, expect, it } from 'vitest'

import { decodeBase64, encodeBase64 } from '../base64'

describe('base64 helpers', () => {
  it('encodes and decodes round trips', () => {
    const input = new TextEncoder().encode('sealed payload data')
    const encoded = encodeBase64(input)
    const decoded = decodeBase64(encoded)

    expect(Array.from(decoded)).toEqual(Array.from(input))
  })

  it('accepts unpadded strings', () => {
    const encoded = 'c2VjcmV0LXRva2Vu' // "secret-token" without padding
    const decoded = decodeBase64(encoded)
    expect(new TextDecoder().decode(decoded)).toBe('secret-token')
  })

  it('accepts URL-safe strings', () => {
    const decoded = decodeBase64('-_8')
    expect(Array.from(decoded)).toEqual([251, 255])
  })
})
