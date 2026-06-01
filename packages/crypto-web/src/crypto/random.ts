function getCrypto():
  | Crypto
  | (Crypto & {
      msCrypto?: Crypto
    })
  | undefined {
  return (
    (globalThis.crypto as Crypto | undefined) ??
    ((globalThis as unknown as { msCrypto?: Crypto }).msCrypto as Crypto | undefined)
  )
}

export function randomBytes(length: number): Uint8Array {
  if (length <= 0) {
    throw new Error('Length must be greater than zero')
  }
  const crypto = getCrypto()
  if (!crypto || typeof crypto.getRandomValues !== 'function') {
    throw new Error('WebCrypto random generator is not available')
  }
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}
