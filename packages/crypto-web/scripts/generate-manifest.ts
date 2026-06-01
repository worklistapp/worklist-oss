import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'

import { ossRoot, packageDir, packageWasmPath, sha256File } from './wasm-utils'

type PackageJson = {
  name: string
  version: string
  license: string
}

function argValue(name: string): string | null {
  const index = process.argv.indexOf(name)
  if (index === -1) {
    return null
  }
  return process.argv[index + 1] ?? null
}

async function optionalSha256(filePath: string): Promise<string | null> {
  try {
    const bytes = await readFile(filePath)
    return createHash('sha256').update(bytes).digest('hex')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null
    }
    throw error
  }
}

function gitCommit(): string {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: ossRoot,
    encoding: 'utf8',
  })
  if (result.status !== 0) {
    return 'unknown'
  }
  return result.stdout.trim() || 'unknown'
}

const packageJson = JSON.parse(
  await readFile(path.join(packageDir, 'package.json'), 'utf8'),
) as PackageJson

const manifest = {
  packageName: packageJson.name,
  packageVersion: packageJson.version,
  gitCommit: gitCommit(),
  bunLockSha256: await optionalSha256(path.join(ossRoot, 'bun.lock')),
  cargoLockSha256: await optionalSha256(path.join(ossRoot, 'Cargo.lock')),
  wasmSha256: await sha256File(packageWasmPath),
  buildCommand:
    'cargo build -p strong-box-wasm --profile wasm-release --target wasm32-unknown-unknown',
  license: packageJson.license,
}

const outputDir = path.join(packageDir, 'dist')
await mkdir(outputDir, { recursive: true })
const json = `${JSON.stringify(manifest, null, 2)}\n`
await writeFile(path.join(outputDir, 'crypto-manifest.json'), json)

const frontendPublic = argValue('--frontend-public')
if (frontendPublic) {
  const resolved = path.resolve(packageDir, frontendPublic)
  await mkdir(resolved, { recursive: true })
  await writeFile(path.join(resolved, 'crypto-manifest.json'), json)
}

console.log(json)
