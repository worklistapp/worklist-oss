# Browser Crypto Audit Scope

The public browser crypto package includes:

- key derivation helpers for OPAQUE-export-key data-key wrapping and legacy Argon2 data-key unwrap compatibility;
- OPAQUE browser start/finish helpers;
- sealed payload serialization, parsing, validation, and StrongBox encryption;
- task, comment, note, attachment, and work-list payload helpers;
- private note-key generation and data-key wrapping;
- audit payload sealing/opening and payload proof generation;
- HPKE invite issuance/acceptance, member-envelope key derivation, membership proof generation, envelope sealing/opening, and invite-key derivation;
- HPKE agent-grant ciphertext generation;
- X25519 fallback code used when native browser support is unavailable;
- StrongBox WASM worker client, worker bridge, and local health check.

The private frontend still owns API transport, React state, query invalidation, UI text, and session stores. Those adapters may hold key material, but cryptographic transformations should be imported from this package.
