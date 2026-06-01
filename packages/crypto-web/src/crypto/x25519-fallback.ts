const BASE_POINT = (() => {
  const bytes = new Uint8Array(32)
  bytes[0] = 9
  return bytes
})()

// Use BigInt arithmetic to avoid external dependencies when WebCrypto lacks X25519.
const MODULUS = (1n << 255n) - 19n
const A24 = 121665n

export function x25519ScalarMultBase(privateKey: Uint8Array): Uint8Array {
  assertKeyLength(privateKey, 'Private key')
  return montgomeryLadder(privateKey, BASE_POINT)
}

export function x25519ScalarMult(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  assertKeyLength(privateKey, 'Private key')
  assertKeyLength(peerPublicKey, 'Peer public key')
  return montgomeryLadder(privateKey, peerPublicKey)
}

function assertKeyLength(key: Uint8Array, label: string) {
  if (key.length !== 32) {
    throw new Error(`${label} must be 32 bytes for X25519.`)
  }
}

function montgomeryLadder(scalar: Uint8Array, uCoordinate: Uint8Array): Uint8Array {
  const k = bytesToBigInt(scalar)
  const x1 = normalize(bytesToBigInt(uCoordinate))
  let x2 = 1n
  let z2 = 0n
  let x3 = x1
  let z3 = 1n
  let swap = 0

  for (let bitIndex = 254; bitIndex >= 0; bitIndex--) {
    const kBit = Number((k >> BigInt(bitIndex)) & 1n)
    if (kBit !== swap) {
      ;[x2, x3] = [x3, x2]
      ;[z2, z3] = [z3, z2]
      swap = kBit
    }

    const a = modAdd(x2, z2)
    const aa = modSquare(a)
    const b = modSub(x2, z2)
    const bb = modSquare(b)
    const e = modSub(aa, bb)
    const c = modAdd(x3, z3)
    const d = modSub(x3, z3)
    const da = modMul(d, a)
    const cb = modMul(c, b)
    x3 = modSquare(modAdd(da, cb))
    z3 = modMul(x1, modSquare(modSub(da, cb)))
    x2 = modMul(aa, bb)
    z2 = modMul(e, modAdd(aa, modMul(A24, e)))
  }

  if (swap) {
    ;[x2, x3] = [x3, x2]
    ;[z2, z3] = [z3, z2]
  }

  const inverse = modInverse(z2)
  const result = modMul(x2, inverse)
  return bigintToBytes(result)
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i])
  }
  return value
}

function bigintToBytes(value: bigint): Uint8Array {
  let remaining = normalize(value)
  const out = new Uint8Array(32)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
  return out
}

function normalize(value: bigint): bigint {
  const reduced = value % MODULUS
  return reduced >= 0n ? reduced : reduced + MODULUS
}

function modAdd(a: bigint, b: bigint): bigint {
  return normalize(a + b)
}

function modSub(a: bigint, b: bigint): bigint {
  return normalize(a - b)
}

function modMul(a: bigint, b: bigint): bigint {
  return normalize(a * b)
}

function modSquare(a: bigint): bigint {
  return modMul(a, a)
}

function modInverse(value: bigint): bigint {
  if (value === 0n) {
    throw new Error('Cannot invert zero in the X25519 field.')
  }
  return modPow(value, MODULUS - 2n)
}

function modPow(base: bigint, exponent: bigint): bigint {
  let result = 1n
  let factor = normalize(base)
  let remaining = exponent
  while (remaining > 0n) {
    if (remaining & 1n) {
      result = modMul(result, factor)
    }
    factor = modSquare(factor)
    remaining >>= 1n
  }
  return result
}
