# Browser Crypto Protocol Notes

Payloads are encoded with CBOR, validated against package-local limits, and sealed with StrongBox AEAD using explicit context labels. Work-list payload proofs use HMAC binding keys derived from the work-list key.

Current user data-key payloads are sealed under `worklist.user.data_key` with a wrapping key derived from the OPAQUE `exportKey` using HKDF-SHA256 and the info label `worklist.opaque.export_key.data_key.v1`. They use sealed payload version `2` so the browser can distinguish current OPAQUE-export-key payloads from legacy payloads without sniffing random legacy salt bytes.

Legacy user data-key payloads remain accept-on-read for existing accounts. They store a 32-byte random salt followed by the StrongBox ciphertext and derive the wrapping key from the password with Argon2id. Password change rewraps successfully decrypted legacy payloads into the current OPAQUE-export-key format.

Private note keys are generated as 32 random bytes and wrapped with the user's data key under `worklist.note.key.v1`. Audit payloads are sealed under `audit-patch` and bind their ciphertext to the work-list payload proof mechanism.

HPKE invite envelopes use:

- mode: base mode (`0x00`);
- KEM: DHKEM(X25519, HKDF-SHA256), encoded as `0x0020`;
- KDF: HKDF-SHA256 (`0x0001`);
- AEAD: ChaCha20-Poly1305 (`0x0003`).

The opener still accepts legacy Worklist envelopes that stored `0x0010` while using X25519 key material. That compatibility path is accept-on-read only; new browser seals use `0x0020`.

Work-list invites bind the HPKE recipient payload to CBOR-encoded `work_list_id`, `membership_id`, `role`, and invite-key fingerprint context. Member envelopes are sealed with StrongBox under `worklist.invite.member`; invite metadata packages use `worklist.invite.package`; accepted memberships seal the recovered work-list key for the owner under `worklist.membership`.

Agent grants seal work-list keys to 32-byte agent recipient public keys with HPKE using `worklist.agent.grant:<workListId>` as both `info` and `aad`.

The StrongBox health check performs a fixed-key local round trip under `worklist.crypto.local_healthcheck` and returns a boolean so private UI code can localize the failure text without owning the crypto check.
