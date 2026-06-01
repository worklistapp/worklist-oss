export const KEY_SIZE_BYTES = 32
export const SEALED_PAYLOAD_VERSION = 1
export const MIN_SALT_BYTES = 8

export type Argon2Params = {
  memoryKiB: number
  iterations: number
  parallelism: number
}

const E2E_ARGON2_PARAMS: Argon2Params = Object.freeze({
  memoryKiB: 1024,
  iterations: 1,
  parallelism: 1,
})

const PRODUCTION_ARGON2_PARAMS: Argon2Params = Object.freeze({
  memoryKiB: 64 * 1024,
  iterations: 3,
  parallelism: 1,
})

const isE2eFastCryptoRequested = import.meta.env.VITE_E2E_FAST_CRYPTO === '1'

if (isE2eFastCryptoRequested && import.meta.env.PROD) {
  throw new Error('VITE_E2E_FAST_CRYPTO must not be enabled in production builds')
}

export const DEFAULT_ARGON2_PARAMS: Argon2Params =
  isE2eFastCryptoRequested && !import.meta.env.PROD
    ? E2E_ARGON2_PARAMS
    : PRODUCTION_ARGON2_PARAMS
