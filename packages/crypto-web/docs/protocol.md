# Browser Crypto Protocol Notes

Payloads are encoded with CBOR, validated against package-local limits, and sealed with StrongBox AEAD using explicit context labels. Work-list payload proofs use HMAC binding keys derived from the work-list key.

HPKE invite envelopes use:

- mode: base mode (`0x00`);
- KEM: DHKEM(X25519, HKDF-SHA256), encoded as `0x0020`;
- KDF: HKDF-SHA256 (`0x0001`);
- AEAD: ChaCha20-Poly1305 (`0x0003`).

The opener still accepts legacy Worklist envelopes that stored `0x0010` while using X25519 key material. That compatibility path is accept-on-read only; new browser seals use `0x0020`.
