function normalizeBase64(input: string): string {
  const sanitized = input.trim().replace(/\s+/g, '')
  if (sanitized.length === 0) {
    throw new Error('base64 input cannot be empty')
  }

  const remainder = sanitized.length % 4
  if (remainder === 0) {
    return sanitized
  }

  return sanitized.padEnd(sanitized.length + (4 - remainder), '=')
}

function decodeWithAtob(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function encodeWithBtoa(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

export function decodeBase64(value: string): Uint8Array {
  const normalized = normalizeBase64(value)
  if (typeof atob !== 'function') {
    throw new Error('Base64 decoding requires atob support')
  }
  return decodeWithAtob(normalized)
}

export function encodeBase64(bytes: Uint8Array): string {
  if (typeof btoa !== 'function') {
    throw new Error('Base64 encoding requires btoa support')
  }
  return encodeWithBtoa(bytes).replace(/=+$/, '')
}
