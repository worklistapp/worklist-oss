import { describe, expect, it } from 'vitest'

import { KEY_SIZE_BYTES } from '../constants'
import {
  createDataKeyCiphertext,
  DATA_KEY_SALT_BYTES,
  decryptDataKeyCiphertext,
} from '../data-key'
import { serializeSealedPayloadBase64 } from '../sealed-payload'
import type { StrongBoxBridge } from '../strong-box'

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

const deriveKeyStub = async (password: string, salt: Uint8Array) => {
  const key = new Uint8Array(KEY_SIZE_BYTES)
  for (let i = 0; i < key.length; i += 1) {
    const saltByte = salt[i % salt.length]
    const pwdByte = password.charCodeAt(i % password.length)
    key[i] = saltByte ^ (pwdByte & 0xff)
  }
  return key
}

describe('data key ciphertext helpers', () => {
  it('round-trips a data key via sealed payload', async () => {
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

    expect(Array.from(decrypted.dataKey)).toEqual(Array.from(dataKey))
    expect(Array.from(decrypted.salt)).toEqual(Array.from(salt))
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
