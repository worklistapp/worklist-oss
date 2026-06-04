import { STRONG_BOX_WASM_SHA256 } from '../crypto/wasm/strong_box_wasm_hash'

export async function verifyStrongBoxWasmBytes(
  bytes: Uint8Array,
  expectedSha256: string = STRONG_BOX_WASM_SHA256,
): Promise<void> {
  const actualSha256 = await sha256Hex(bytes)
  if (actualSha256 !== expectedSha256) {
    throw new Error(
      `StrongBox WASM hash mismatch: expected ${expectedSha256}, received ${actualSha256}`,
    )
  }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const subtle = crypto.subtle
  if (!subtle) {
    throw new Error('crypto.subtle is required to verify StrongBox WASM integrity')
  }

  const digestInput = new Uint8Array(bytes.byteLength)
  digestInput.set(bytes)
  try {
    const digest = await subtle.digest('SHA-256', digestInput.buffer as ArrayBuffer)
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
  } finally {
    digestInput.fill(0)
  }
}
