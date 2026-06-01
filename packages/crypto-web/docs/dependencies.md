# Dependencies

- `@serenity-kit/opaque`: browser OPAQUE client helpers.
- `argon2-browser`: Argon2id WASM implementation for password export-key derivation.
- `cbor-x`: CBOR serialization for sealed payloads and HPKE envelopes.
- `strong-box`: Rust AEAD helper consumed by the public `strong-box-wasm` bridge through the OSS Cargo workspace. The source is currently vendored in `oss/crates/strong-box` for WASM target compatibility.
