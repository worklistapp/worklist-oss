/// <reference path="../types/argon2-browser.d.ts" />

import * as argon2Import from 'argon2-browser'
import wasmUrl from 'argon2-browser/dist/argon2.wasm?url'

import { DEFAULT_ARGON2_PARAMS, KEY_SIZE_BYTES, MIN_SALT_BYTES, type Argon2Params } from './constants'

type Argon2Module = typeof import('argon2-browser').default
type Argon2ImportShape = Partial<Argon2Module> & {
  default?: Argon2Module
}

type Argon2Global = typeof globalThis & {
  argon2?: Argon2Module
  argon2WasmPath?: string
  loadArgon2WasmBinary?: () => Promise<Uint8Array>
  process?: typeof process
}

const globalWithArgon2 = globalThis as Argon2Global
const isServerRuntime = import.meta.env.SSR
const hasWindow = typeof window !== 'undefined'
const isBrowserEnvironment = !isServerRuntime && hasWindow && typeof window.document !== 'undefined'
const isNodeProcess = typeof process !== 'undefined' && !!(process.versions && process.versions.node)

if (isServerRuntime) {
  if (hasWindow && isNodeProcess) {
    ;(window as Argon2Global).process = process
  }
  if (!globalWithArgon2.loadArgon2WasmBinary) {
    const loader = async () => {
      const nodeFsModuleId = 'node:fs/promises'
      const nodeModuleId = 'node:module'
      const { readFile } = await import(/* @vite-ignore */ nodeFsModuleId)
      const { createRequire } = await import(/* @vite-ignore */ nodeModuleId)
      const require = createRequire(import.meta.url)
      const buffer = await readFile(require.resolve('argon2-browser/dist/argon2.wasm'))
      return new Uint8Array(buffer)
    }
    globalWithArgon2.loadArgon2WasmBinary = loader
    if (hasWindow) {
      ;(window as Argon2Global).loadArgon2WasmBinary = loader
    }
  }
} else if (isBrowserEnvironment) {
  if (!globalWithArgon2.argon2WasmPath) {
    globalWithArgon2.argon2WasmPath = wasmUrl
    if (typeof window !== 'undefined') {
      ;(window as Argon2Global).argon2WasmPath = wasmUrl
    }
  }
  if (!globalWithArgon2.loadArgon2WasmBinary) {
    let wasmPromise: Promise<Uint8Array> | null = null
    const loader = () => {
      if (!wasmPromise) {
        wasmPromise = fetch(wasmUrl).then(async (response) => {
          if (!response.ok) {
            throw new Error(`Failed to load Argon2 WASM from ${wasmUrl}`)
          }
          const buffer = await response.arrayBuffer()
          return new Uint8Array(buffer)
        })
      }
      return wasmPromise
    }
    globalWithArgon2.loadArgon2WasmBinary = loader
    if (typeof window !== 'undefined') {
      ;(window as Argon2Global).loadArgon2WasmBinary = loader
    }
  }
}

function resolveArgon2Module(): Argon2Module {
  const imported = argon2Import as Argon2ImportShape
  const module =
    imported.default ??
    (imported.hash && imported.ArgonType ? imported : undefined) ??
    globalWithArgon2.argon2
  if (!module?.hash || !module.ArgonType) {
    throw new Error('argon2-browser did not expose a usable module')
  }
  return module as Argon2Module
}

const { hash, ArgonType } = resolveArgon2Module()

export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<Uint8Array> {
  if (salt.byteLength < MIN_SALT_BYTES) {
    throw new Error(`Salt must be at least ${MIN_SALT_BYTES} bytes`)
  }

  const result = await hash({
    pass: password,
    salt,
    hashLen: KEY_SIZE_BYTES,
    type: ArgonType.Argon2id,
    time: params.iterations,
    mem: params.memoryKiB,
    parallelism: params.parallelism,
    raw: true,
  })

  return new Uint8Array(result.hash)
}
