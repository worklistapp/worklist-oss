import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

// Vitest only includes src/**/* tests; this intentionally covers script utilities.
import {
  HOST_SPECIFIC_WASM_UPDATE_ENV,
  canUpdateCommittedWasm,
  deterministicWasmBuildEnv,
  repoRoot,
  resolveRepositoryRoot,
  sourceRoot,
  targetRoot,
} from '../../../scripts/wasm-utils'

const originalCargoTargetDir = process.env.CARGO_TARGET_DIR
const originalCargoBuildTargetDir = process.env.CARGO_BUILD_TARGET_DIR
const expectedDefaultTargetRoot = path.join(repoRoot, 'target')

describe('StrongBox WASM build utilities', () => {
  afterEach(() => {
    restoreEnv('CARGO_TARGET_DIR', originalCargoTargetDir)
    restoreEnv('CARGO_BUILD_TARGET_DIR', originalCargoBuildTargetDir)
  })

  it('defaults to the repository target directory', () => {
    delete process.env.CARGO_TARGET_DIR
    delete process.env.CARGO_BUILD_TARGET_DIR

    expect(targetRoot()).toBe(expectedDefaultTargetRoot)
  })

  it('resolves relative target directories from the repository root', () => {
    process.env.CARGO_TARGET_DIR = 'target'
    delete process.env.CARGO_BUILD_TARGET_DIR

    expect(targetRoot()).toBe(expectedDefaultTargetRoot)
  })

  it('uses CARGO_BUILD_TARGET_DIR as the fallback target directory', () => {
    delete process.env.CARGO_TARGET_DIR
    process.env.CARGO_BUILD_TARGET_DIR = 'fallback-target'

    expect(targetRoot()).toBe(path.join(repoRoot, 'fallback-target'))
  })

  it('passes absolute target directories through unchanged', () => {
    const absoluteTargetRoot = path.join(repoRoot, 'absolute-target')
    process.env.CARGO_TARGET_DIR = absoluteTargetRoot
    delete process.env.CARGO_BUILD_TARGET_DIR

    expect(targetRoot()).toBe(absoluteTargetRoot)
  })

  it('passes the canonical target directory through the deterministic build environment', () => {
    delete process.env.CARGO_TARGET_DIR
    delete process.env.CARGO_BUILD_TARGET_DIR

    const env = deterministicWasmBuildEnv(() => null)

    expect(env.CARGO_TARGET_DIR).toBe(expectedDefaultTargetRoot)
    expect(env.CARGO_ENCODED_RUSTFLAGS).toContain(
      `--remap-path-prefix=${expectedDefaultTargetRoot}=/workspace/target`,
    )
    expect(env.CARGO_ENCODED_RUSTFLAGS).toContain(`--remap-path-prefix=${sourceRoot}=/workspace`)
  })

  it('resolves the parent root for the monorepo oss directory', () => {
    const monorepoRoot = path.join('/tmp', 'worklist')
    const monorepoOssRoot = path.join(monorepoRoot, 'oss')
    const existingPaths = new Set([
      path.join(monorepoRoot, 'Cargo.toml'),
      path.join(monorepoRoot, 'oss', 'Cargo.toml'),
      path.join(monorepoRoot, 'crates', 'strong-box-wasm', 'Cargo.toml'),
      path.join(monorepoRoot, 'oss', 'crates', 'strong-box-wasm', 'Cargo.toml'),
    ])

    expect(resolveRepositoryRoot(monorepoOssRoot, (filePath) => existingPaths.has(filePath))).toBe(monorepoRoot)
  })

  it('keeps the OSS root for the published subtree layout', () => {
    const standaloneOssRoot = path.join('/tmp', 'oss')

    expect(resolveRepositoryRoot(standaloneOssRoot, () => false)).toBe(standaloneOssRoot)
  })

  it('allows committed WASM updates only on linux/x64 unless explicitly overridden', () => {
    expect(canUpdateCommittedWasm('linux', 'x64', {})).toBe(true)
    expect(canUpdateCommittedWasm('darwin', 'arm64', {})).toBe(false)
    expect(canUpdateCommittedWasm('darwin', 'arm64', { [HOST_SPECIFIC_WASM_UPDATE_ENV]: '1' })).toBe(true)
  })
})

function restoreEnv(name: 'CARGO_TARGET_DIR' | 'CARGO_BUILD_TARGET_DIR', value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name]
    return
  }

  process.env[name] = value
}
