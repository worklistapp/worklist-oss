import { KEY_SIZE_BYTES } from './constants'
import type { StrongBoxBridge } from './strong-box'

const encoder = new TextEncoder()
const HEALTHCHECK_CONTEXT = encoder.encode('worklist.crypto.local_healthcheck')
const HEALTHCHECK_PLAINTEXT = encoder.encode('local_crypto_ready')
const HEALTHCHECK_KEY = (() => {
  const key = new Uint8Array(KEY_SIZE_BYTES)
  for (let index = 0; index < key.length; index += 1) {
    key[index] = (index * 29 + 11) & 0xff
  }
  return key
})()

export async function verifyStrongBoxLocalHealth(bridge: StrongBoxBridge): Promise<boolean> {
  const ciphertext = await bridge.encrypt({
    key: copyBytes(HEALTHCHECK_KEY),
    context: copyBytes(HEALTHCHECK_CONTEXT),
    plaintext: copyBytes(HEALTHCHECK_PLAINTEXT),
  })

  const decrypted = await bridge.decrypt({
    key: copyBytes(HEALTHCHECK_KEY),
    context: copyBytes(HEALTHCHECK_CONTEXT),
    ciphertext,
  })

  return buffersEqual(decrypted, HEALTHCHECK_PLAINTEXT)
}

function copyBytes(source: Uint8Array) {
  const copy = new Uint8Array(source.length)
  copy.set(source)
  return copy
}

function buffersEqual(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) {
    return false
  }

  let difference = 0
  for (let index = 0; index < a.length; index += 1) {
    difference |= a[index] ^ b[index]
  }

  return difference === 0
}
