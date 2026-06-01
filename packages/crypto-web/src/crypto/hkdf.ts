const encoder = new TextEncoder()

type KeyMaterial = ArrayBuffer | Uint8Array

function getSubtleCrypto(): SubtleCrypto {
  if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) {
    throw new Error('WebCrypto subtle API is not available in this environment')
  }
  return globalThis.crypto.subtle
}

function toArrayBuffer(input: KeyMaterial): ArrayBuffer {
  if (input instanceof ArrayBuffer) {
    return input.slice(0)
  }
  const copy = new Uint8Array(input.byteLength)
  copy.set(input)
  return copy.buffer
}

type HkdfInfo = string | Uint8Array

export async function hkdfExpand(params: {
  parent: KeyMaterial
  info: HkdfInfo
  length?: number
  salt?: KeyMaterial
}): Promise<Uint8Array> {
  const { parent, info, length = 32, salt } = params
  const subtle = getSubtleCrypto()
  const parentBits = toArrayBuffer(parent)
  const saltBytes = (salt ? toArrayBuffer(salt) : new ArrayBuffer(0)) as ArrayBuffer
  const infoBytes = typeof info === 'string' ? encoder.encode(info) : info
  if (infoBytes.length === 0) {
    throw new Error('HKDF info label is required')
  }
  const infoBuffer = infoBytes.buffer
    .slice(infoBytes.byteOffset, infoBytes.byteOffset + infoBytes.byteLength) as ArrayBuffer
  const importKey = await subtle.importKey('raw', parentBits, 'HKDF', false, ['deriveBits'])
  const derivedBits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBytes,
      info: infoBuffer,
    },
    importKey,
    length * 8,
  )

  return new Uint8Array(derivedBits)
}
