import { describe, expect, it } from 'vitest'
import { client as opaqueClient, ready as opaqueReady, server as opaqueServer } from '@serenity-kit/opaque'

import { KEY_SIZE_BYTES } from '../constants'
import {
  createDataKeyCiphertext,
  createDataKeyCiphertextFromOpaqueExportKey,
  DATA_KEY_SALT_BYTES,
  decryptDataKeyCiphertext,
  deriveDataKeyWrappingKeyFromOpaqueExportKey,
  OpaqueExportKeyRequiredError,
  rewrapDataKeyCiphertext,
} from '../data-key'
import { parseSealedPayload, serializeSealedPayloadBase64 } from '../sealed-payload'
import type { StrongBoxBridge } from '../strong-box'
import { createStrongBoxWasmTestBridge } from '../../test/strong-box-wasm-test-bridge'

const deterministicBox: StrongBoxBridge = {
  async encrypt({ key, context, plaintext }) {
    const normalizedKey = normalize(key)
    const normalizedContext = normalize(context)
    const tag = computeTag(normalizedKey, normalizedContext)
    const body = xorWithKey(normalize(plaintext), normalizedKey)
    return concat(tag, body)
  },
  async decrypt({ key, context, ciphertext }) {
    const normalizedKey = normalize(key)
    const normalizedContext = normalize(context)
    if (ciphertext.length <= TAG_LENGTH) {
      throw new Error('ciphertext too short')
    }
    const tag = ciphertext.slice(0, TAG_LENGTH)
    const body = ciphertext.slice(TAG_LENGTH)
    const expectedTag = computeTag(normalizedKey, normalizedContext)
    for (let i = 0; i < TAG_LENGTH; i += 1) {
      if (tag[i] !== expectedTag[i]) {
        throw new Error('authentication failed')
      }
    }
    return xorWithKey(body, normalizedKey)
  },
}

const TAG_LENGTH = 16
const OPAQUE_EXPORT_KEY_VECTOR =
  'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw'
const OPAQUE_DATA_KEY_VECTOR = Uint8Array.from({ length: KEY_SIZE_BYTES }, (_, index) => 0xa0 + index)
const OPAQUE_BROWSER_NONCE_VECTOR = Uint8Array.from({ length: 12 }, (_, index) => 0x90 + index)
const BROWSER_PRODUCED_OPAQUE_DATA_KEY_CIPHERTEXT =
  'uQACZ3ZlcnNpb24CamNpcGhlcnRleHTYQFhUsbj1g1ASAyVSxOht8es25TKWnoYATJCRkpOUlZaXmJmam1gwO1DSTcsSYAhB/HTiL6uF9RyJkn2wF1suIqrKn5oJOOYXf8Y9ntSemXs3WD7Uevil'
const RUST_PRODUCED_OPAQUE_DATA_KEY_CIPHERTEXT =
  'omd2ZXJzaW9uAmpjaXBoZXJ0ZXh0mFQYsRi4GPUYgxhQEgMYJRhSGMQY6BhtGPEY6xg2GOUYMhiWGJ4YhgAYTBjcGJ8YSBhrAhifGKsY5BjrGOQY4RjDGFgYMBh6GCUY1xjYGGMYqhhKBBjoBBh5GOYY7hjIGNYYrhj/Bhj3GGoYwBj+GIYYehjPGG8YdhhbGK0YfRi1BxiFGJwYwRheGN4YfxjuGIkYgBhcGCQYhxhzGPIYbRji'

const deriveKeyStub = async (password: string, salt: Uint8Array) => {
  const key = new Uint8Array(KEY_SIZE_BYTES)
  for (let i = 0; i < key.length; i += 1) {
    const saltByte = salt[i % salt.length]
    const pwdByte = password.charCodeAt(i % password.length)
    key[i] = saltByte ^ (pwdByte & 0xff)
  }
  return key
}

const deriveOpaqueKeyStub = async (exportKey: string) => {
  const key = new Uint8Array(KEY_SIZE_BYTES)
  for (let i = 0; i < key.length; i += 1) {
    key[i] = (exportKey.charCodeAt(i % exportKey.length) ^ 0x5a) & 0xff
  }
  return key
}

describe('data key ciphertext helpers', () => {
  it('round-trips a legacy Argon2-wrapped data key via sealed payload', async () => {
    const salt = new Uint8Array(DATA_KEY_SALT_BYTES).fill(7)
    const dataKey = new Uint8Array(KEY_SIZE_BYTES).fill(3)

    const { ciphertext } = await createDataKeyCiphertext({
      password: 'correct horse battery staple',
      salt,
      dataKey,
      strongBox: deterministicBox,
      deriveKey: deriveKeyStub,
    })

    const decrypted = await decryptDataKeyCiphertext({
      password: 'correct horse battery staple',
      ciphertext,
      strongBox: deterministicBox,
      deriveKey: deriveKeyStub,
    })

    expect(decrypted.format).toBe('legacy_password_argon2')
    if (decrypted.format !== 'legacy_password_argon2') {
      throw new Error('expected legacy data key result')
    }
    expect(Array.from(decrypted.dataKey)).toEqual(Array.from(dataKey))
    expect(Array.from(decrypted.salt)).toEqual(Array.from(salt))
  })

  it('round-trips a data key wrapped by an OPAQUE export key', async () => {
    const dataKey = new Uint8Array(KEY_SIZE_BYTES).fill(6)

    const { ciphertext, salt } = await createDataKeyCiphertextFromOpaqueExportKey({
      opaqueExportKey: 'opaque-export-key',
      dataKey,
      strongBox: deterministicBox,
      deriveOpaqueExportKey: deriveOpaqueKeyStub,
    })

    expect(salt).toBeUndefined()
    expect(parseSealedPayload(ciphertext).version).toBe(2)

    const decrypted = await decryptDataKeyCiphertext({
      opaqueExportKey: 'opaque-export-key',
      ciphertext,
      strongBox: deterministicBox,
      deriveOpaqueExportKey: deriveOpaqueKeyStub,
    })

    expect(Array.from(decrypted.dataKey)).toEqual(Array.from(dataKey))
    expect(decrypted.salt).toBeUndefined()
    expect(decrypted.format).toBe('opaque_export_key')
  })

  it('round-trips a data key with a real OPAQUE base64url export key', async () => {
    const password = 'correct horse battery staple'
    const email = 'user@example.com'
    const identifiers = { client: email, server: 'worklist.api' }
    await opaqueReady

    const serverSetup = opaqueServer.createSetup()
    const registrationStart = opaqueClient.startRegistration({ password })
    const registrationResponse = opaqueServer.createRegistrationResponse({
      serverSetup,
      userIdentifier: email,
      registrationRequest: registrationStart.registrationRequest,
    })
    const registrationFinish = opaqueClient.finishRegistration({
      password,
      clientRegistrationState: registrationStart.clientRegistrationState,
      registrationResponse: registrationResponse.registrationResponse,
      identifiers,
    })

    expect(registrationFinish.exportKey).toMatch(/^[A-Za-z0-9_-]+$/)

    const loginStart = opaqueClient.startLogin({ password })
    const serverLogin = opaqueServer.startLogin({
      serverSetup,
      registrationRecord: registrationFinish.registrationRecord,
      startLoginRequest: loginStart.startLoginRequest,
      userIdentifier: email,
      identifiers,
    })
    const loginFinish = opaqueClient.finishLogin({
      password,
      clientLoginState: loginStart.clientLoginState,
      loginResponse: serverLogin.loginResponse,
      identifiers,
    })

    expect(loginFinish).toBeDefined()
    if (!loginFinish) {
      throw new Error('expected OPAQUE login to finish')
    }
    expect(loginFinish?.exportKey).toBe(registrationFinish.exportKey)

    const dataKey = new Uint8Array(KEY_SIZE_BYTES).fill(10)
    const { ciphertext } = await createDataKeyCiphertextFromOpaqueExportKey({
      opaqueExportKey: registrationFinish.exportKey,
      dataKey,
      strongBox: deterministicBox,
    })

    const decrypted = await decryptDataKeyCiphertext({
      opaqueExportKey: loginFinish.exportKey,
      ciphertext,
      strongBox: deterministicBox,
    })

    expect(Array.from(decrypted.dataKey)).toEqual(Array.from(dataKey))
    expect(decrypted.format).toBe('opaque_export_key')
  })

  it('matches a frozen browser-produced OPAQUE export-key data-key vector with real StrongBox WASM', async () => {
    const strongBox = await createStrongBoxWasmTestBridge()
    const restoreRandom = stubCryptoRandom(OPAQUE_BROWSER_NONCE_VECTOR)

    try {
      const { ciphertext } = await createDataKeyCiphertextFromOpaqueExportKey({
        opaqueExportKey: OPAQUE_EXPORT_KEY_VECTOR,
        dataKey: OPAQUE_DATA_KEY_VECTOR,
        strongBox,
      })

      expect(ciphertext).toBe(BROWSER_PRODUCED_OPAQUE_DATA_KEY_CIPHERTEXT)

      const decrypted = await decryptDataKeyCiphertext({
        opaqueExportKey: OPAQUE_EXPORT_KEY_VECTOR,
        ciphertext,
        strongBox,
      })

      expect(decrypted.format).toBe('opaque_export_key')
      expect(Array.from(decrypted.dataKey)).toEqual(Array.from(OPAQUE_DATA_KEY_VECTOR))
    } finally {
      restoreRandom()
    }
  })

  it('decrypts a frozen Rust-produced OPAQUE export-key data-key vector with real StrongBox WASM', async () => {
    const strongBox = await createStrongBoxWasmTestBridge()

    const decrypted = await decryptDataKeyCiphertext({
      opaqueExportKey: OPAQUE_EXPORT_KEY_VECTOR,
      ciphertext: RUST_PRODUCED_OPAQUE_DATA_KEY_CIPHERTEXT,
      strongBox,
    })

    expect(decrypted.format).toBe('opaque_export_key')
    expect(Array.from(decrypted.dataKey)).toEqual(Array.from(OPAQUE_DATA_KEY_VECTOR))
  })

  it('requires an OPAQUE export key for current data-key payloads', async () => {
    const { ciphertext } = await createDataKeyCiphertextFromOpaqueExportKey({
      opaqueExportKey: 'opaque-export-key',
      dataKey: new Uint8Array(KEY_SIZE_BYTES).fill(4),
      strongBox: deterministicBox,
      deriveOpaqueExportKey: deriveOpaqueKeyStub,
    })

    await expect(
      decryptDataKeyCiphertext({
        password: 'legacy-password',
        ciphertext,
        strongBox: deterministicBox,
        deriveOpaqueExportKey: deriveOpaqueKeyStub,
      }),
    ).rejects.toBeInstanceOf(OpaqueExportKeyRequiredError)
  })

  it('does not misclassify legacy salts that start with the old opaque marker bytes', async () => {
    const salt = new Uint8Array(DATA_KEY_SALT_BYTES).fill(8)
    salt.set(new TextEncoder().encode('wkdk2'))
    const dataKey = new Uint8Array(KEY_SIZE_BYTES).fill(5)

    const { ciphertext } = await createDataKeyCiphertext({
      password: 'legacy-password',
      salt,
      dataKey,
      strongBox: deterministicBox,
      deriveKey: deriveKeyStub,
    })

    const decrypted = await decryptDataKeyCiphertext({
      password: 'legacy-password',
      ciphertext,
      strongBox: deterministicBox,
      deriveKey: deriveKeyStub,
    })

    expect(decrypted.format).toBe('legacy_password_argon2')
    expect(Array.from(decrypted.dataKey)).toEqual(Array.from(dataKey))
  })

  it('migrates legacy password-wrapped payloads to OPAQUE export-key wrapping during rewrap', async () => {
    const salt = new Uint8Array(DATA_KEY_SALT_BYTES).fill(8)
    const dataKey = new Uint8Array(KEY_SIZE_BYTES).fill(9)
    const { ciphertext } = await createDataKeyCiphertext({
      password: 'old-password',
      salt,
      dataKey,
      strongBox: deterministicBox,
      deriveKey: deriveKeyStub,
    })

    const rewrapped = await rewrapDataKeyCiphertext({
      oldPassword: 'old-password',
      newOpaqueExportKey: 'new-export-key',
      oldCiphertext: ciphertext,
      strongBox: deterministicBox,
      deriveKey: deriveKeyStub,
      deriveOpaqueExportKey: deriveOpaqueKeyStub,
    })

    const decrypted = await decryptDataKeyCiphertext({
      opaqueExportKey: 'new-export-key',
      ciphertext: rewrapped.newCiphertext,
      strongBox: deterministicBox,
      deriveOpaqueExportKey: deriveOpaqueKeyStub,
    })

    expect(Array.from(decrypted.dataKey)).toEqual(Array.from(dataKey))
    expect(decrypted.format).toBe('opaque_export_key')
  })

  it('rejects truncated payloads', async () => {
    const payload = {
      version: 1,
      ciphertext: new Uint8Array(DATA_KEY_SALT_BYTES - 4),
    }
    const encoded = serializeSealedPayloadBase64(payload)

    await expect(
      decryptDataKeyCiphertext({
        password: 'hunter2',
        ciphertext: encoded,
        strongBox: deterministicBox,
        deriveKey: deriveKeyStub,
      }),
    ).rejects.toThrow(/truncated/i)
  })

  it('rejects invalid passwords', async () => {
    const salt = new Uint8Array(DATA_KEY_SALT_BYTES).fill(1)
    const dataKey = new Uint8Array(KEY_SIZE_BYTES).fill(2)
    const { ciphertext } = await createDataKeyCiphertext({
      password: 'right',
      salt,
      dataKey,
      strongBox: deterministicBox,
      deriveKey: deriveKeyStub,
    })

    await expect(
      decryptDataKeyCiphertext({
        password: 'wrong',
        ciphertext,
        strongBox: deterministicBox,
        deriveKey: deriveKeyStub,
      }),
    ).rejects.toThrow()
  })

  it('derives a fixed-size wrapping key from a base64 OPAQUE export key', async () => {
    const exportKey = btoa('opaque-export-key-material')
    await expect(deriveDataKeyWrappingKeyFromOpaqueExportKey(exportKey)).resolves.toHaveLength(KEY_SIZE_BYTES)
  })
})

function concat(a: Uint8Array, b: Uint8Array) {
  const merged = new Uint8Array(a.length + b.length)
  merged.set(a, 0)
  merged.set(b, a.length)
  return merged
}

function normalize(value: Uint8Array) {
  const copy = new Uint8Array(value.length)
  copy.set(value)
  return copy
}

function xorWithKey(data: Uint8Array, key: Uint8Array) {
  const out = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i += 1) {
    out[i] = data[i] ^ key[i % key.length]
  }
  return out
}

function computeTag(key: Uint8Array, context: Uint8Array) {
  const tag = new Uint8Array(TAG_LENGTH)
  for (let i = 0; i < TAG_LENGTH; i += 1) {
    const keyByte = key[i % key.length]
    const ctxByte = context[i % context.length]
    tag[i] = keyByte ^ ctxByte ^ 0xa5
  }
  return tag
}

function stubCryptoRandom(bytes: Uint8Array) {
  const original = globalThis.crypto.getRandomValues.bind(globalThis.crypto)
  Object.defineProperty(globalThis.crypto, 'getRandomValues', {
    configurable: true,
    value<T extends ArrayBufferView | null>(array: T): T {
      if (!array) {
        return array
      }
      const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength)
      if (view.byteLength !== bytes.byteLength) {
        throw new Error(`unexpected random length ${view.byteLength}`)
      }
      view.set(bytes)
      return array
    },
  })

  return () => {
    Object.defineProperty(globalThis.crypto, 'getRandomValues', {
      configurable: true,
      value: original,
    })
  }
}
