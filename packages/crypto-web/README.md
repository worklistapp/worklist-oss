# @worklist/crypto-web

Auditable browser encryption implementation for Worklist.

This package contains the browser-side cryptographic primitives used by the production frontend: OPAQUE-export-key data-key wrapping, legacy Argon2 data-key unwrap compatibility, sealed payload encryption, payload validation, private note-key wrapping, audit payload sealing, HPKE invite and agent-grant helpers, OPAQUE browser helpers, and the StrongBox WASM worker bridge plus health check.

## Commands

Install Bun dependencies first. `bun run test` launches Vitest through Node 26 so the browser-crypto test runtime matches CI. The script fails fast if `node` on `PATH` is not Node 26.

```bash
bun run typecheck
bun run test
bun run build:wasm
bun run verify:wasm
bun run generate:manifest
```

Run these from `oss/packages/crypto-web`. From the OSS workspace root, `bun run test` runs the crypto-web typecheck, tests, and WASM verification.

## Audit Scope

The current public package is the source of truth for the browser crypto modules imported by the private Worklist frontend through `@worklist/crypto-web/crypto/*`. Product-specific API clients, React components, TanStack Query wiring, and localization remain private adapters.
