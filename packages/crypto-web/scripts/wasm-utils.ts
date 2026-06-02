import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readFile, rm, copyFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
export const packageDir = path.resolve(scriptDir, '..')
export const ossRoot = path.resolve(packageDir, '../..')
const repoRoot = path.resolve(ossRoot, '..')
export const packageWasmPath = path.join(packageDir, 'src/crypto/wasm/strong_box_wasm_bg.wasm')
const rustflagsSeparator = '\x1f'

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

function rustSysroot(): string | null {
  const result = spawnSync('rustc', ['--print', 'sysroot'], {
    cwd: ossRoot,
    encoding: 'utf8',
  })
  if (result.status !== 0) {
    return null
  }
  return result.stdout.trim() || null
}

export function deterministicWasmBuildEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env }
  const cargoHome = env.CARGO_HOME
    ? path.resolve(env.CARGO_HOME)
    : path.join(homedir(), '.cargo')
  const remapFlags = [
    `--remap-path-prefix=${repoRoot}=/workspace`,
    `--remap-path-prefix=${targetRoot()}=/workspace/target`,
    `--remap-path-prefix=${cargoHome}=/cargo`,
  ]

  const sysroot = rustSysroot()
  if (sysroot) {
    remapFlags.push(`--remap-path-prefix=${sysroot}=/rust`)
  }

  delete env.RUSTFLAGS
  env.CARGO_ENCODED_RUSTFLAGS = remapFlags.join(rustflagsSeparator)
  return env
}

export async function buildWasm(): Promise<string> {
  const output = builtWasmPath()
  await rm(output, { force: true })
  await rm(builtDepsWasmPath(), { force: true })

  const result = spawnSync(
    'cargo',
    [
      'build',
      '-p',
      'strong-box-wasm',
      '--profile',
      'wasm-release',
      '--locked',
      '--target',
      'wasm32-unknown-unknown',
    ],
    {
      cwd: ossRoot,
      env: deterministicWasmBuildEnv(),
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
