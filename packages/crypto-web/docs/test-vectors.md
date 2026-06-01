# Test Vectors

The package currently carries browser unit and integration coverage for sealed payloads, task/comment/note/work-list payloads, data-key wrapping, X25519, HPKE legacy/current envelopes, attachments, and the StrongBox bridge.

Shared Rust-vs-web vectors should live under `oss/test-vectors/crypto` so `oss/crates/client-crypto` and this package can verify the same fixtures.
