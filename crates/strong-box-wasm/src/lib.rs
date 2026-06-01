#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::{mem, ptr, ptr::NonNull, slice};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use strong_box::{Key, StaticStrongBox, StrongBox};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

// Use wee_alloc as the global allocator for smaller WASM binary size
#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(all(test, miri))]
mod result_tracker {
    use std::{
        collections::HashMap,
        sync::{Mutex, OnceLock},
    };

    #[derive(Clone, Copy)]
    struct Entry {
        ptr: *mut u8,
        capacity: usize,
    }

    unsafe impl Send for Entry {}
    unsafe impl Sync for Entry {}

    fn registry() -> &'static Mutex<HashMap<usize, Entry>> {
        static REGISTRY: OnceLock<Mutex<HashMap<usize, Entry>>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(super) fn remember(addr: usize, ptr: *mut u8, capacity: usize) {
        if addr == 0 || capacity == 0 {
            return;
        }

        let mut guard = registry().lock().unwrap();
        guard.insert(addr, Entry { ptr, capacity });
    }

    pub(super) fn take(addr: usize) -> Option<(*mut u8, usize)> {
        if addr == 0 {
            return None;
        }

        let mut guard = registry().lock().unwrap();
        guard.remove(&addr).map(|entry| (entry.ptr, entry.capacity))
    }
}

#[cfg(target_arch = "wasm32")]
mod rand_bridge {
    use getrandom_02 as getrandom;

    #[link(wasm_import_module = "strong_box")]
    unsafe extern "C" {
        fn strong_box_random(ptr: *mut u8, len: usize) -> i32;
    }

    getrandom::register_custom_getrandom!(fill_random);

    fn fill_random(dest: &mut [u8]) -> Result<(), getrandom::Error> {
        if dest.is_empty() {
            return Ok(());
        }

        let status = unsafe { strong_box_random(dest.as_mut_ptr(), dest.len()) };
        if status == 0 {
            Ok(())
        } else {
            Err(getrandom::Error::UNEXPECTED)
        }
    }
}

const KEY_SIZE_BYTES: usize = 32;
const HPKE_NONCE_LEN: usize = 12;
const HPKE_ENC_LEN: usize = 32;
const ERR_INVALID_KEY: u32 = 1;
const ERR_NULL_POINTER: u32 = 2;
const ERR_ENCRYPT_FAILED: u32 = 10;
const ERR_DECRYPT_FAILED: u32 = 11;
const ERR_HPKE_ENCAP_FAILED: u32 = 20;
const ERR_HPKE_DECAP_FAILED: u32 = 21;
const ERR_HPKE_DERIVE_FAILED: u32 = 22;

const HPKE_MODE_BASE: u8 = 0x00;
const HPKE_KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const HPKE_KDF_ID: u16 = 0x0001; // HKDF-SHA256
const HPKE_AEAD_ID: u16 = 0x0003; // ChaCha20-Poly1305
const HPKE_LABEL_PREFIX: &[u8] = b"HPKE-v1";
type HmacSha256 = Hmac<Sha256>;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StrongBoxResult {
    pub ptr: usize,
    pub len: usize,
    pub capacity: usize,
    pub error_code: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Encrypt,
    Decrypt,
    HpkeEncap,
    HpkeDecap,
}

#[derive(Debug)]
enum BridgeError {
    InvalidKeyLength,
    NullPointer(&'static str),
    StrongBox(strong_box::Error),
    Hpke(&'static str),
}

impl BridgeError {
    fn code(&self, op: Operation) -> u32 {
        match self {
            BridgeError::InvalidKeyLength => ERR_INVALID_KEY,
            BridgeError::NullPointer(_) => ERR_NULL_POINTER,
            BridgeError::StrongBox(_) => match op {
                Operation::Encrypt => ERR_ENCRYPT_FAILED,
                Operation::Decrypt => ERR_DECRYPT_FAILED,
                Operation::HpkeEncap => ERR_HPKE_ENCAP_FAILED,
                Operation::HpkeDecap => ERR_HPKE_DECAP_FAILED,
            },
            BridgeError::Hpke(_) => match op {
                Operation::HpkeEncap => ERR_HPKE_ENCAP_FAILED,
                Operation::HpkeDecap => ERR_HPKE_DECAP_FAILED,
                _ => ERR_HPKE_DERIVE_FAILED,
            },
        }
    }

    fn message(&self) -> String {
        match self {
            BridgeError::InvalidKeyLength => format!("key must be {KEY_SIZE_BYTES} bytes"),
            BridgeError::NullPointer(field) => format!("{field} pointer was null"),
            BridgeError::StrongBox(err) => err.to_string(),
            BridgeError::Hpke(msg) => msg.to_string(),
        }
    }
}

impl From<strong_box::Error> for BridgeError {
    fn from(value: strong_box::Error) -> Self {
        Self::StrongBox(value)
    }
}

#[derive(Clone, Copy)]
struct WasmSlice {
    ptr: *const u8,
    len: usize,
}

impl WasmSlice {
    const fn new(ptr: *const u8, len: usize) -> Self {
        Self { ptr, len }
    }

    unsafe fn read<'a>(self, field_name: &'static str) -> Result<&'a [u8], BridgeError> {
        unsafe { read_slice(self.ptr, self.len, field_name) }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn strong_box_result_size() -> usize {
    mem::size_of::<StrongBoxResult>()
}

#[unsafe(no_mangle)]
pub extern "C" fn strong_box_alloc(size: usize) -> *mut u8 {
    let mut buffer = Vec::<u8>::with_capacity(size);
    let ptr = buffer.as_mut_ptr();
    mem::forget(buffer);
    ptr
}

/// Releases a buffer previously allocated by [`strong_box_alloc`].
///
/// # Safety
/// - `ptr` must come from `strong_box_alloc` and still own the allocation.
/// - `capacity` must match the capacity that was originally requested.
/// - Callers must ensure no other references access the buffer while it is freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strong_box_free(ptr: *mut u8, capacity: usize) {
    if capacity == 0 || ptr.is_null() {
        return;
    }

    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, capacity);
    }
}

/// Encrypts `plaintext` with the provided `key` and context bytes.
///
/// # Safety
/// - All pointer/length pairs must describe valid readable memory for the entire call.
/// - `result_ptr` must be a valid, writable pointer to a `StrongBoxResult`.
/// - Callers are responsible for ensuring the key length matches the expected 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strong_box_encrypt(
    key_ptr: *const u8,
    key_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    result_ptr: *mut StrongBoxResult,
) {
    let result = match unsafe {
        encrypt_bytes(
            key_ptr,
            key_len,
            context_ptr,
            context_len,
            plaintext_ptr,
            plaintext_len,
        )
    } {
        Ok(bytes) => StrongBoxResult::success(bytes),
        Err(err) => StrongBoxResult::error(err.code(Operation::Encrypt), err.message()),
    };

    unsafe { write_result(result_ptr, result) };
}

/// Decrypts `ciphertext` with the provided `key` and context bytes.
///
/// # Safety
/// - All pointer/length pairs must describe valid readable memory for the entire call.
/// - `result_ptr` must be a valid, writable pointer to a `StrongBoxResult`.
/// - The key must match the one used during encryption and be 32 bytes long.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strong_box_decrypt(
    key_ptr: *const u8,
    key_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
    result_ptr: *mut StrongBoxResult,
) {
    let result = match unsafe {
        decrypt_bytes(
            key_ptr,
            key_len,
            context_ptr,
            context_len,
            ciphertext_ptr,
            ciphertext_len,
        )
    } {
        Ok(bytes) => StrongBoxResult::success(bytes),
        Err(err) => StrongBoxResult::error(err.code(Operation::Decrypt), err.message()),
    };

    unsafe { write_result(result_ptr, result) };
}

/// HPKE encap (Base mode, X25519 + HKDF-SHA256 + ChaCha20-Poly1305)
///
/// # Safety
/// - All pointer/length pairs must be valid for the duration of the call.
/// - `result_ptr` must be a valid, writable pointer to a `StrongBoxResult`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strong_box_hpke_encap(
    recipient_pub_ptr: *const u8,
    recipient_pub_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    result_ptr: *mut StrongBoxResult,
) {
    let result = match unsafe {
        hpke_encap_bytes(
            WasmSlice::new(recipient_pub_ptr, recipient_pub_len),
            WasmSlice::new(info_ptr, info_len),
            WasmSlice::new(aad_ptr, aad_len),
            WasmSlice::new(plaintext_ptr, plaintext_len),
        )
    } {
        Ok(bytes) => StrongBoxResult::success(bytes),
        Err(err) => StrongBoxResult::error(err.code(Operation::HpkeEncap), err.message()),
    };

    unsafe { write_result(result_ptr, result) };
}

/// HPKE decap (Base mode, X25519 + HKDF-SHA256 + ChaCha20-Poly1305)
///
/// # Safety
/// - All pointer/length pairs must be valid for the duration of the call.
/// - `result_ptr` must be a valid, writable pointer to a `StrongBoxResult`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strong_box_hpke_decap(
    recipient_priv_ptr: *const u8,
    recipient_priv_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    enc_ptr: *const u8,
    enc_len: usize,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
    result_ptr: *mut StrongBoxResult,
) {
    let result = match unsafe {
        hpke_decap_bytes(
            WasmSlice::new(recipient_priv_ptr, recipient_priv_len),
            WasmSlice::new(info_ptr, info_len),
            WasmSlice::new(aad_ptr, aad_len),
            WasmSlice::new(enc_ptr, enc_len),
            WasmSlice::new(ciphertext_ptr, ciphertext_len),
        )
    } {
        Ok(bytes) => StrongBoxResult::success(bytes),
        Err(err) => StrongBoxResult::error(err.code(Operation::HpkeDecap), err.message()),
    };

    unsafe { write_result(result_ptr, result) };
}

unsafe fn encrypt_bytes(
    key_ptr: *const u8,
    key_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
) -> Result<Vec<u8>, BridgeError> {
    let plaintext = unsafe { read_slice(plaintext_ptr, plaintext_len, "plaintext") }?;
    let key = unsafe { read_slice(key_ptr, key_len, "key") }?;
    let context = unsafe { read_slice(context_ptr, context_len, "context") }?;

    encrypt_with_key(key, context, plaintext)
}

unsafe fn decrypt_bytes(
    key_ptr: *const u8,
    key_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
) -> Result<Vec<u8>, BridgeError> {
    let ciphertext = unsafe { read_slice(ciphertext_ptr, ciphertext_len, "ciphertext") }?;
    let key = unsafe { read_slice(key_ptr, key_len, "key") }?;
    let context = unsafe { read_slice(context_ptr, context_len, "context") }?;

    decrypt_with_key(key, context, ciphertext)
}

fn encrypt_with_key(key: &[u8], context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BridgeError> {
    let strong_box = build_strong_box(key)?;
    strong_box.encrypt(plaintext, context).map_err(Into::into)
}

fn decrypt_with_key(key: &[u8], context: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, BridgeError> {
    let strong_box = build_strong_box(key)?;
    strong_box.decrypt(ciphertext, context).map_err(Into::into)
}

fn hpke_encap(
    recipient_pub: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, BridgeError> {
    if recipient_pub.len() != HPKE_ENC_LEN {
        return Err(BridgeError::InvalidKeyLength);
    }

    let mut sk_bytes = [0u8; KEY_SIZE_BYTES];
    if getrandom_02::getrandom(&mut sk_bytes).is_err() {
        sk_bytes.zeroize();
        return Err(BridgeError::Hpke("failed to generate ephemeral key"));
    }
    let sk = StaticSecret::from(sk_bytes);
    let enc = PublicKey::from(&sk).to_bytes();
    sk_bytes.zeroize();

    let recipient_pub_bytes =
        <[u8; HPKE_ENC_LEN]>::try_from(recipient_pub).map_err(|_| BridgeError::InvalidKeyLength)?;
    let recipient_key = PublicKey::from(recipient_pub_bytes);
    let mut dh = sk.diffie_hellman(&recipient_key).to_bytes();
    if dh.iter().all(|b| *b == 0) {
        dh.zeroize();
        return Err(BridgeError::Hpke("derived shared secret is invalid"));
    }

    let shared_secret_result = dhkem_shared_secret(&dh, &enc, &recipient_pub_bytes);
    dh.zeroize();
    let mut shared_secret = shared_secret_result?;
    let keys_result = derive_hpke_keys(info, &shared_secret);
    shared_secret.zeroize();
    let (mut aead_key, mut base_nonce) = keys_result?;

    let cipher = match ChaCha20Poly1305::new_from_slice(&aead_key) {
        Ok(cipher) => cipher,
        Err(_) => {
            aead_key.zeroize();
            base_nonce.zeroize();
            return Err(BridgeError::Hpke("invalid HPKE AEAD key"));
        }
    };

    let ciphertext = match cipher.encrypt(
        Nonce::from_slice(&base_nonce),
        Payload {
            msg: plaintext,
            aad,
        },
    ) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            aead_key.zeroize();
            base_nonce.zeroize();
            return Err(BridgeError::Hpke("HPKE encryption failed"));
        }
    };

    let packed = pack_hpke_result(&base_nonce, &enc, &ciphertext);
    aead_key.zeroize();
    base_nonce.zeroize();
    Ok(packed)
}

fn hpke_decap(
    recipient_priv: &[u8],
    info: &[u8],
    aad: &[u8],
    enc: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, BridgeError> {
    if recipient_priv.len() != KEY_SIZE_BYTES || enc.len() != HPKE_ENC_LEN {
        return Err(BridgeError::InvalidKeyLength);
    }

    let mut priv_bytes = [0u8; KEY_SIZE_BYTES];
    priv_bytes.copy_from_slice(recipient_priv);
    let sk = StaticSecret::from(priv_bytes);
    priv_bytes.zeroize();

    let enc_bytes =
        <[u8; HPKE_ENC_LEN]>::try_from(enc).map_err(|_| BridgeError::InvalidKeyLength)?;
    let peer_pub = PublicKey::from(enc_bytes);
    let mut dh = sk.diffie_hellman(&peer_pub).to_bytes();
    if dh.iter().all(|b| *b == 0) {
        dh.zeroize();
        return Err(BridgeError::Hpke("derived shared secret is invalid"));
    }

    let recipient_pub_bytes = PublicKey::from(&sk).to_bytes();
    let shared_secret_result = dhkem_shared_secret(&dh, &enc_bytes, &recipient_pub_bytes);
    dh.zeroize();
    let mut shared_secret = shared_secret_result?;
    let keys_result = derive_hpke_keys(info, &shared_secret);
    shared_secret.zeroize();
    let (mut aead_key, mut base_nonce) = keys_result?;

    let cipher = match ChaCha20Poly1305::new_from_slice(&aead_key) {
        Ok(cipher) => cipher,
        Err(_) => {
            aead_key.zeroize();
            base_nonce.zeroize();
            return Err(BridgeError::Hpke("invalid HPKE AEAD key"));
        }
    };

    let plaintext = match cipher.decrypt(
        Nonce::from_slice(&base_nonce),
        Payload {
            msg: ciphertext,
            aad,
        },
    ) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            aead_key.zeroize();
            base_nonce.zeroize();
            return Err(BridgeError::Hpke("HPKE decryption failed"));
        }
    };

    let packed = pack_hpke_result(&base_nonce, enc, &plaintext);
    aead_key.zeroize();
    base_nonce.zeroize();
    Ok(packed)
}

fn dhkem_shared_secret(
    dh: &[u8; KEY_SIZE_BYTES],
    enc: &[u8; HPKE_ENC_LEN],
    recipient_pub: &[u8; HPKE_ENC_LEN],
) -> Result<[u8; KEY_SIZE_BYTES], BridgeError> {
    let kem_context = [enc.as_slice(), recipient_pub.as_slice()].concat();
    let suite_id = kem_suite_id();
    let mut eae_prk = labeled_extract_with_suite(&suite_id, None, b"eae_prk", dh)?;
    let shared_secret_bytes_result = labeled_expand_with_suite(
        &suite_id,
        &eae_prk,
        b"shared_secret",
        &kem_context,
        KEY_SIZE_BYTES,
    );
    eae_prk.zeroize();
    let mut shared_secret_bytes = shared_secret_bytes_result?;
    let shared_secret = match <[u8; KEY_SIZE_BYTES]>::try_from(shared_secret_bytes.as_slice()) {
        Ok(bytes) => bytes,
        Err(_) => {
            shared_secret_bytes.zeroize();
            return Err(BridgeError::Hpke("failed to derive HPKE shared secret"));
        }
    };
    shared_secret_bytes.zeroize();
    Ok(shared_secret)
}

fn derive_hpke_keys(
    info: &[u8],
    shared_secret: &[u8],
) -> Result<([u8; KEY_SIZE_BYTES], [u8; HPKE_NONCE_LEN]), BridgeError> {
    let mut psk_id_hash = labeled_extract(None, b"psk_id_hash", &[])?;
    let info_hash_result = labeled_extract(None, b"info_hash", info);
    if info_hash_result.is_err() {
        psk_id_hash.zeroize();
    }
    let mut info_hash = info_hash_result?;
    let mut key_schedule_context = [
        &[HPKE_MODE_BASE],
        psk_id_hash.as_slice(),
        info_hash.as_slice(),
    ]
    .concat();
    psk_id_hash.zeroize();
    info_hash.zeroize();

    let secret_result = labeled_extract(Some(shared_secret), b"secret", &[]);
    if secret_result.is_err() {
        key_schedule_context.zeroize();
    }
    let mut secret = secret_result?;

    let key_bytes_result = labeled_expand(&secret, b"key", &key_schedule_context, KEY_SIZE_BYTES);
    if key_bytes_result.is_err() {
        secret.zeroize();
        key_schedule_context.zeroize();
    }
    let mut key_bytes = key_bytes_result?;

    let nonce_bytes_result = labeled_expand(
        &secret,
        b"base_nonce",
        &key_schedule_context,
        HPKE_NONCE_LEN,
    );
    secret.zeroize();
    key_schedule_context.zeroize();

    let mut nonce_bytes = match nonce_bytes_result {
        Ok(bytes) => bytes,
        Err(err) => {
            key_bytes.zeroize();
            return Err(err);
        }
    };

    let mut key = match <[u8; KEY_SIZE_BYTES]>::try_from(key_bytes.as_slice()) {
        Ok(key) => key,
        Err(_) => {
            key_bytes.zeroize();
            nonce_bytes.zeroize();
            return Err(BridgeError::Hpke("failed to derive HPKE key"));
        }
    };
    key_bytes.zeroize();

    let nonce = match <[u8; HPKE_NONCE_LEN]>::try_from(nonce_bytes.as_slice()) {
        Ok(nonce) => nonce,
        Err(_) => {
            key.zeroize();
            nonce_bytes.zeroize();
            return Err(BridgeError::Hpke("failed to derive HPKE nonce"));
        }
    };
    nonce_bytes.zeroize();

    Ok((key, nonce))
}

fn labeled_extract(
    salt: Option<&[u8]>,
    label: &[u8],
    ikm: &[u8],
) -> Result<[u8; KEY_SIZE_BYTES], BridgeError> {
    labeled_extract_with_suite(&suite_id(), salt, label, ikm)
}

fn labeled_extract_with_suite(
    suite_id: &[u8],
    salt: Option<&[u8]>,
    label: &[u8],
    ikm: &[u8],
) -> Result<[u8; KEY_SIZE_BYTES], BridgeError> {
    let mut labeled =
        Vec::with_capacity(HPKE_LABEL_PREFIX.len() + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(HPKE_LABEL_PREFIX);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);

    let default_salt = [0u8; KEY_SIZE_BYTES];
    let salt = salt.unwrap_or(&default_salt);
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(salt) {
        Ok(mac) => mac,
        Err(_) => {
            labeled.zeroize();
            return Err(BridgeError::Hpke("HKDF extract init failed"));
        }
    };
    mac.update(&labeled);
    labeled.zeroize();

    let mut prk = mac.finalize().into_bytes();
    let mut okm = [0u8; KEY_SIZE_BYTES];
    okm.copy_from_slice(&prk);
    prk.zeroize();
    Ok(okm)
}

fn labeled_expand(
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, BridgeError> {
    labeled_expand_with_suite(&suite_id(), prk, label, info, length)
}

fn labeled_expand_with_suite(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, BridgeError> {
    let mut labeled =
        Vec::with_capacity(2 + HPKE_LABEL_PREFIX.len() + suite_id.len() + label.len() + info.len());
    labeled.extend_from_slice(&(length as u16).to_be_bytes());
    labeled.extend_from_slice(HPKE_LABEL_PREFIX);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);

    let hkdf = match Hkdf::<Sha256>::from_prk(prk) {
        Ok(hkdf) => hkdf,
        Err(_) => {
            labeled.zeroize();
            return Err(BridgeError::Hpke("HKDF expand init failed"));
        }
    };
    let mut okm = vec![0u8; length];
    let expand_result = hkdf.expand(&labeled, &mut okm);
    labeled.zeroize();
    if expand_result.is_err() {
        okm.zeroize();
        return Err(BridgeError::Hpke("HKDF expand failed"));
    }
    Ok(okm)
}

fn kem_suite_id() -> [u8; 5] {
    let mut out = [0u8; 5];
    out[0..3].copy_from_slice(b"KEM");
    out[3..5].copy_from_slice(&HPKE_KEM_ID.to_be_bytes());
    out
}

fn suite_id() -> [u8; 10] {
    let mut out = [0u8; 10];
    out[0..4].copy_from_slice(b"HPKE");
    out[4..6].copy_from_slice(&HPKE_KEM_ID.to_be_bytes());
    out[6..8].copy_from_slice(&HPKE_KDF_ID.to_be_bytes());
    out[8..10].copy_from_slice(&HPKE_AEAD_ID.to_be_bytes());
    out
}

fn pack_hpke_result(nonce: &[u8], enc: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + nonce.len() + enc.len() + payload.len());
    out.extend_from_slice(&(nonce.len() as u32).to_le_bytes());
    out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(enc);
    out.extend_from_slice(payload);
    out
}

#[allow(clippy::too_many_arguments)]
unsafe fn hpke_encap_bytes(
    recipient_pub: WasmSlice,
    info: WasmSlice,
    aad: WasmSlice,
    plaintext: WasmSlice,
) -> Result<Vec<u8>, BridgeError> {
    let recipient_pub = unsafe { recipient_pub.read("recipient_public_key") }?;
    let info = unsafe { info.read("info") }?;
    let aad = unsafe { aad.read("aad") }?;
    let plaintext = unsafe { plaintext.read("plaintext") }?;

    hpke_encap(recipient_pub, info, aad, plaintext)
}

#[allow(clippy::too_many_arguments)]
unsafe fn hpke_decap_bytes(
    recipient_priv: WasmSlice,
    info: WasmSlice,
    aad: WasmSlice,
    enc: WasmSlice,
    ciphertext: WasmSlice,
) -> Result<Vec<u8>, BridgeError> {
    let recipient_priv = unsafe { recipient_priv.read("recipient_private_key") }?;
    let info = unsafe { info.read("info") }?;
    let aad = unsafe { aad.read("aad") }?;
    let enc = unsafe { enc.read("enc") }?;
    let ciphertext = unsafe { ciphertext.read("ciphertext") }?;

    hpke_decap(recipient_priv, info, aad, enc, ciphertext)
}

unsafe fn read_slice<'a>(
    ptr: *const u8,
    len: usize,
    label: &'static str,
) -> Result<&'a [u8], BridgeError> {
    if len == 0 {
        return Ok(&[]);
    }

    let Some(_) = NonNull::new(ptr as *mut u8) else {
        return Err(BridgeError::NullPointer(label));
    };

    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

fn build_strong_box(key_bytes: &[u8]) -> Result<StaticStrongBox, BridgeError> {
    if key_bytes.len() != KEY_SIZE_BYTES {
        return Err(BridgeError::InvalidKeyLength);
    }

    let mut key_material = [0u8; KEY_SIZE_BYTES];
    key_material.copy_from_slice(key_bytes);

    let key = Key::from(Box::new(key_material));
    let decrypt_key = key.clone();

    Ok(StaticStrongBox::new(key, [decrypt_key]))
}

impl StrongBoxResult {
    fn success(bytes: Vec<u8>) -> Self {
        Self::from_vec(bytes, 0)
    }

    fn error(code: u32, message: String) -> Self {
        Self::from_vec(message.into_bytes(), code)
    }

    fn from_vec(mut data: Vec<u8>, error_code: u32) -> Self {
        let raw_ptr = data.as_mut_ptr();
        let ptr = raw_ptr as usize;
        let len = data.len();
        let capacity = data.capacity();
        mem::forget(data);

        #[cfg(all(test, miri))]
        result_tracker::remember(ptr, raw_ptr, capacity);

        Self {
            ptr,
            len,
            capacity,
            error_code,
        }
    }
}

unsafe fn write_result(target: *mut StrongBoxResult, value: StrongBoxResult) {
    if target.is_null() {
        return;
    }

    unsafe {
        ptr::write_unaligned(target, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(miri)]
    const MISALIGN_SHIFT: usize = 1;

    #[cfg(miri)]
    struct MisalignedResultBuffer {
        base: *mut u8,
        capacity: usize,
        ptr: *mut StrongBoxResult,
    }

    #[cfg(miri)]
    impl MisalignedResultBuffer {
        fn new(bytes: usize) -> Self {
            let total = bytes
                .checked_add(MISALIGN_SHIFT)
                .expect("result buffer size overflow");
            let mut buffer = Vec::<u8>::with_capacity(total);
            let base = buffer.as_mut_ptr();
            let capacity = buffer.capacity();
            mem::forget(buffer);
            let ptr = unsafe { base.add(MISALIGN_SHIFT) as *mut StrongBoxResult };

            Self {
                base,
                capacity,
                ptr,
            }
        }

        fn as_mut_ptr(&self) -> *mut StrongBoxResult {
            self.ptr
        }
    }

    #[cfg(miri)]
    fn free_result_buffer(result: &StrongBoxResult) {
        if result.capacity == 0 || result.ptr == 0 {
            return;
        }

        if let Some((ptr, capacity)) = super::result_tracker::take(result.ptr) {
            unsafe {
                let _ = Vec::from_raw_parts(ptr, 0, capacity);
            }
        }
    }

    #[cfg(miri)]
    impl Drop for MisalignedResultBuffer {
        fn drop(&mut self) {
            if self.base.is_null() || self.capacity == 0 {
                return;
            }

            unsafe {
                let _ = Vec::from_raw_parts(self.base, 0, self.capacity);
            }
        }
    }

    #[test]
    fn encrypt_and_decrypt_round_trip() {
        let key = [1u8; KEY_SIZE_BYTES];
        let context = b"ctx".as_ref();
        let plaintext = b"secret".as_ref();

        let ciphertext = encrypt_with_key(&key, context, plaintext).unwrap();
        let recovered = decrypt_with_key(&key, context, &ciphertext).unwrap();

        assert_eq!(plaintext, recovered.as_slice());
    }

    #[test]
    fn rejects_invalid_key_size() {
        let key = [0u8; KEY_SIZE_BYTES - 1];
        let context = b"ctx".as_ref();
        let plaintext = b"secret".as_ref();

        let err = encrypt_with_key(&key, context, plaintext).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidKeyLength));
    }

    #[test]
    fn hpke_labeled_extract_returns_raw_hkdf_extract_prk() {
        let suite_id = suite_id();
        let salt = [0xa0; KEY_SIZE_BYTES];
        let ikm = [0xb1; KEY_SIZE_BYTES];
        let labeled_ikm = [
            HPKE_LABEL_PREFIX,
            suite_id.as_slice(),
            b"secret".as_slice(),
            ikm.as_slice(),
        ]
        .concat();
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&salt).expect("hmac should accept sha256 salt");
        mac.update(&labeled_ikm);
        let expected = mac.finalize().into_bytes();

        let actual = labeled_extract_with_suite(&suite_id, Some(&salt), b"secret", &ikm)
            .expect("labeled extract");

        assert_eq!(actual.as_slice(), &expected[..]);
    }

    #[cfg(miri)]
    #[test]
    fn encrypt_respects_byte_aligned_result_buffers() {
        let key = [2u8; KEY_SIZE_BYTES];
        let context = b"ctx";
        let plaintext = b"demo";

        let buffer = MisalignedResultBuffer::new(strong_box_result_size());
        let result_ptr = buffer.as_mut_ptr();
        assert!(
            !result_ptr.is_null(),
            "result buffer should provide a valid pointer"
        );

        unsafe {
            strong_box_encrypt(
                key.as_ptr(),
                key.len(),
                context.as_ptr(),
                context.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                result_ptr,
            );
        }

        let result = unsafe { std::ptr::read_unaligned(result_ptr) };
        assert_eq!(result.error_code, 0, "encryption should succeed");

        free_result_buffer(&result);
    }
}
