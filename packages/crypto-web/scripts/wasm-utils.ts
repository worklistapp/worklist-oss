import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readFile, rm, copyFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
export const packageDir = path.resolve(scriptDir, '..')
export const ossRoot = path.resolve(packageDir, '../..')
export const packageWasmPath = path.join(packageDir, 'src/crypto/wasm/strong_box_wasm_bg.wasm')

export function targetRoot(): string {
  const configured = process.env.CARGO_TARGET_DIR || process.env.CARGO_BUILD_TARGET_DIR
  if (!configured) {
    return path.join(ossRoot, 'target')
  }
  return path.isAbsolute(configured) ? configured : path.join(ossRoot, configured)
}

export function builtWasmPath(): string {
  return path.join(targetRoot(), 'wasm32-unknown-unknown/wasm-release/strong_box_wasm.wasm')
}

function builtDepsWasmPath(): string {
  return path.join(targetRoot(), 'wasm32-unknown-unknown/wasm-release/deps/strong_box_wasm.wasm')
}

export async function buildWasm(): Promise<string> {
  const output = builtWasmPath()
  await rm(output, { force: true })
  await rm(builtDepsWasmPath(), { force: true })

  const result = spawnSync(
    'cargo',
    ['build', '-p', 'strong-box-wasm', '--profile', 'wasm-release', '--target', 'wasm32-unknown-unknown'],
    {
      cwd: ossRoot,
      env: process.env,
      stdio: 'inherit',
    },
  )

  if (result.status !== 0) {
    throw new Error(`cargo build failed with status ${result.status ?? 'unknown'}`)
  }

  return output
}

export async function copyBuiltWasm(): Promise<void> {
  const output = await buildWasm()
  await mkdir(path.dirname(packageWasmPath), { recursive: true })
  await copyFile(output, packageWasmPath)
}

export async function sha256File(filePath: string): Promise<string> {
  const bytes = await readFile(filePath)
  return createHash('sha256').update(bytes).digest('hex')
}
