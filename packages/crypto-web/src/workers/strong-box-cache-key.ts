const CACHE_KEY_DOMAIN = new TextEncoder().encode('worklist.strong_box.decrypt_cache.v1')
const LENGTH_PREFIX_BYTES = 4
const MAX_FIELD_BYTES = 0xffff_ffff

export async function computeStrongBoxDecryptCacheKey(
  key: Uint8Array,
  context: Uint8Array,
  payload: Uint8Array,
): Promise<string> {
  const subtle = crypto.subtle
  if (!subtle) {
    throw new Error('crypto.subtle is required to compute StrongBox decrypt cache keys')
  }

  const framed = frameCacheKeyFields([CACHE_KEY_DOMAIN, key, context, payload])
  let digestInput: Uint8Array | null = null
  try {
    digestInput = new Uint8Array(framed.byteLength)
    digestInput.set(framed)
    const digest = await subtle.digest('SHA-256', digestInput.buffer as ArrayBuffer)
    return bytesToHex(new Uint8Array(digest))
  } finally {
    digestInput?.fill(0)
    framed.fill(0)
  }
}

function frameCacheKeyFields(fields: Uint8Array[]): Uint8Array {
  let totalLength = 0
  for (const field of fields) {
    if (field.byteLength > MAX_FIELD_BYTES) {
      throw new Error('StrongBox decrypt cache key field is too large')
    }
    totalLength += LENGTH_PREFIX_BYTES + field.byteLength
  }

  const framed = new Uint8Array(totalLength)
  const view = new DataView(framed.buffer)
  let offset = 0
  for (const field of fields) {
    view.setUint32(offset, field.byteLength, true)
    offset += LENGTH_PREFIX_BYTES
    framed.set(field, offset)
    offset += field.byteLength
  }
  return framed
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
