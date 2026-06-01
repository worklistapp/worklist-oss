import { StrongBoxWorkerClient } from './strong-box-worker-client'

export type StrongBoxEncryptInput = {
  key: Uint8Array
  context: Uint8Array
  plaintext: Uint8Array
}

export type StrongBoxDecryptInput = {
  key: Uint8Array
  context: Uint8Array
  ciphertext: Uint8Array
}

export type HpkeEncapInput = {
  recipientPublicKey: Uint8Array
  info: Uint8Array
  aad: Uint8Array
  plaintext: Uint8Array
}

export type HpkeEncapResult = {
  enc: Uint8Array
  nonce: Uint8Array
  ciphertext: Uint8Array
}

export type HpkeDecapInput = {
  recipientPrivateKey: Uint8Array
  info: Uint8Array
  aad: Uint8Array
  enc: Uint8Array
  ciphertext: Uint8Array
}

export interface StrongBoxBridge {
  encrypt(input: StrongBoxEncryptInput): Promise<Uint8Array>
  decrypt(input: StrongBoxDecryptInput): Promise<Uint8Array>
  hpkeEncap?(input: HpkeEncapInput): Promise<HpkeEncapResult>
  hpkeDecap?(input: HpkeDecapInput): Promise<Uint8Array>
}

let bridgePromise: Promise<StrongBoxBridge> | null = null

export async function getStrongBoxBridge(): Promise<StrongBoxBridge> {
  if (!bridgePromise) {
    bridgePromise = createBridge()
  }
  return bridgePromise
}

async function createBridge(): Promise<StrongBoxBridge> {
  assertWorkerBridgeSupport()
  return StrongBoxWorkerClient.create()
}

function assertWorkerBridgeSupport() {
  const hasWorker = typeof Worker !== 'undefined'
  const hasWasm = typeof WebAssembly !== 'undefined'
  const hasCrypto = typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function'

  if (!hasWorker || !hasWasm || !hasCrypto) {
    throw new Error(
      'StrongBox WASM bridge is required but this environment lacks WebWorker, WebAssembly, or secure randomness support.',
    )
  }
}
