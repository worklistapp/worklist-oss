# StrongBox WASM Build

The StrongBox WASM bridge source lives in `oss/crates/strong-box-wasm` and builds from the public OSS workspace.

The workspace currently includes `oss/crates/strong-box` because the first spike against the published `strong-box = 0.5.1` crate failed for `wasm32-unknown-unknown`: that published dependency graph pulls `getrandom 0.3` without a supported backend for this target. Keep the fork public until the needed WASM target support is released upstream.

```bash
cd oss
../scripts/build-strong-box-wasm.sh
```

The package script `bun run build:wasm` rebuilds the artifact with deterministic `CARGO_ENCODED_RUSTFLAGS` path remapping, copies it to `src/crypto/wasm/strong_box_wasm_bg.wasm`, and updates the adjacent `src/crypto/wasm/strong_box_wasm_hash.ts` runtime integrity constant. The root `scripts/build-strong-box-wasm.sh` script applies the same remapping. Both update entrypoints refuse to rewrite committed artifacts outside Linux x64 unless `STRONG_BOX_WASM_UPDATE_HOST_SPECIFIC=1` is set for an explicitly host-specific local rebuild. The script `bun run verify:wasm` rebuilds the artifact, compares SHA256 hashes against the checked-in browser artifact, and checks that the committed runtime hash constant still matches the artifact.

Exact byte-for-byte verification is enforced by default on every host. Set `STRONG_BOX_WASM_ALLOW_HOST_SPECIFIC_HASH=1` only for local non-Linux-x64 diagnosis when a host-specific rebuild is expected; CI and release builds must not use that override.

Runtime hash verification catches accidental corruption, partial deploys, cache-poisoned subresource mismatches, and build/deploy drift between the JavaScript bundle and the WASM artifact. It is not a defense against full origin or JavaScript bundle compromise because the expected hash constant is served with the same application bundle.

The private monorepo and public OSS workspaces intentionally have different `Cargo.lock` files because the OSS workspace includes the public CLI/client crates while the private root includes backend crates. The shipped browser artifact is built from the OSS workspace with `--locked`, and `verify:wasm` is the lockfile gate for that public build input. The monorepo sync check still compares the shared StrongBox source trees, shared crate manifests, and the `wasm-release` profile so private and public StrongBox build configuration does not silently drift.

Docker frontend builds must run on Linux x64 so the committed browser artifact is compared byte-for-byte against the canonical rebuild. Use a native or otherwise reliable `linux/amd64` builder for release images; non-x64 Docker builds fail before shipping an unverifiable artifact.

When recommitting `src/crypto/wasm/strong_box_wasm_bg.wasm` without a Rust source diff, record the artifact SHA256 and the Linux x64 CI run that produced or verified it in the PR description.
