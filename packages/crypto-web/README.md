# @worklist/crypto-web

Auditable browser encryption implementation for Worklist.

This package contains the browser-side cryptographic primitives used by the production frontend: password-export-key based data-key wrapping, sealed payload encryption, payload validation, HPKE invite envelopes, OPAQUE browser helpers, and the StrongBox WASM worker bridge.

## Commands

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
