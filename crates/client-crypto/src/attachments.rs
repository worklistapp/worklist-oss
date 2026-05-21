use worklist_client_core::{PublicError, PublicResult};

use crate::{
    ATTACHMENT_BLOB_CONTEXT_LABEL, ATTACHMENT_BLOB_REF_VERSION, ATTACHMENT_REF_CONTEXT,
    AttachmentBlobRef, FlexibleValue, SymmetricKey,
    cbor::{deserialize_from_cbor, flexible_value_to_json},
    decode_base64, decrypt_raw_attachment_bytes, decrypt_sealed_bytes,
    keys::symmetric_key_from_bytes,
};

fn default_attachment_blob_context_label() -> String {
    ATTACHMENT_BLOB_CONTEXT_LABEL.to_string()
}

pub fn decode_attachment_blob_key(
    list_key: &SymmetricKey,
    blob_key: &[u8],
) -> PublicResult<AttachmentBlobRef> {
    let plaintext = decrypt_sealed_bytes(
        list_key,
        blob_key,
        ATTACHMENT_REF_CONTEXT,
        "failed to decrypt attachment reference",
    )?;
    let blob_ref_value: FlexibleValue = deserialize_from_cbor(&plaintext).map_err(|err| {
        PublicError::validation(format!(
            "failed to deserialize attachment reference payload: {err}"
        ))
    })?;
    validate_attachment_blob_ref(parse_attachment_blob_ref(blob_ref_value)?)
}

pub fn decrypt_attachment_bytes(
    ciphertext: &[u8],
    file_key: &[u8],
    enc_context: Option<&str>,
) -> PublicResult<Vec<u8>> {
    let file_key = symmetric_key_from_bytes(file_key)?;
    let context = enc_context.unwrap_or(ATTACHMENT_BLOB_CONTEXT_LABEL);
    decrypt_raw_attachment_bytes(&file_key, ciphertext, context.as_bytes()).or_else(|raw_err| {
        decrypt_sealed_bytes(
            &file_key,
            ciphertext,
            context.as_bytes(),
            "failed to decrypt attachment bytes",
        )
        .map_err(|sealed_err| {
            PublicError::crypto(format!(
                "failed to decrypt attachment bytes as raw StrongBox ciphertext ({raw_err}); also failed wrapped payload fallback ({sealed_err})"
            ))
        })
    })
}
fn parse_attachment_blob_ref(value: FlexibleValue) -> PublicResult<AttachmentBlobRef> {
    let json = flexible_value_to_json(value);
    let version = parse_attachment_blob_ref_version(&json)?;
    let object_key = parse_attachment_blob_ref_object_key(&json)?;
    let ciphertext_bytes =
        parse_required_attachment_blob_ref_u64(&json, &["ciphertext_bytes", "ciphertextBytes"])?;
    let file_key = parse_attachment_blob_ref_file_key(&json)?;
    let enc_context =
        parse_optional_attachment_blob_ref_text(&json, &["enc_context", "encContext"])
            .unwrap_or_else(default_attachment_blob_context_label);

    Ok(AttachmentBlobRef {
        version,
        object_key,
        ciphertext_bytes,
        file_key,
        enc_context,
    })
}

fn parse_attachment_blob_ref_version(value: &serde_json::Value) -> PublicResult<u8> {
    let version = parse_required_attachment_blob_ref_u64(value, &["version"])?;
    u8::try_from(version).map_err(|_| {
        PublicError::validation(format!(
            "attachment reference version {version} does not fit in u8"
        ))
    })
}

fn parse_attachment_blob_ref_object_key(value: &serde_json::Value) -> PublicResult<String> {
    parse_required_attachment_blob_ref_text(value, &["object_key", "objectKey"]).or_else(|_| {
        extract_attachment_blob_ref_nested_object_key(value)
            .ok_or_else(|| PublicError::validation("attachment reference object key is required"))
    })
}

fn parse_attachment_blob_ref_file_key(value: &serde_json::Value) -> PublicResult<Vec<u8>> {
    parse_required_attachment_blob_ref_bytes(value, &["file_key", "fileKey"]).or_else(|_| {
        find_attachment_blob_ref_value(value, &["file_key", "fileKey"])
            .and_then(extract_attachment_blob_ref_nested_file_key)
            .ok_or_else(|| PublicError::validation("attachment reference file key is required"))
    })
}

fn parse_required_attachment_blob_ref_text(
    value: &serde_json::Value,
    field_names: &[&str],
) -> PublicResult<String> {
    find_attachment_blob_ref_value(value, field_names)
        .and_then(extract_attachment_blob_ref_text)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            PublicError::validation(format!(
                "attachment reference {} is required",
                field_names[0]
            ))
        })
}

fn parse_optional_attachment_blob_ref_text(
    value: &serde_json::Value,
    field_names: &[&str],
) -> Option<String> {
    find_attachment_blob_ref_value(value, field_names)
        .and_then(extract_attachment_blob_ref_text)
        .filter(|value| !value.trim().is_empty())
}

fn parse_required_attachment_blob_ref_u64(
    value: &serde_json::Value,
    field_names: &[&str],
) -> PublicResult<u64> {
    find_attachment_blob_ref_value(value, field_names)
        .and_then(extract_attachment_blob_ref_u64)
        .ok_or_else(|| {
            PublicError::validation(format!(
                "attachment reference {} is required",
                field_names[0]
            ))
        })
}

fn parse_required_attachment_blob_ref_bytes(
    value: &serde_json::Value,
    field_names: &[&str],
) -> PublicResult<Vec<u8>> {
    find_attachment_blob_ref_value(value, field_names)
        .and_then(extract_attachment_blob_ref_bytes)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            PublicError::validation(format!(
                "attachment reference {} is required",
                field_names[0]
            ))
        })
}

fn find_attachment_blob_ref_value<'a>(
    value: &'a serde_json::Value,
    field_names: &[&str],
) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Object(entries) => {
            for field_name in field_names {
                if let Some(value) = entries.get(*field_name) {
                    return Some(value);
                }
            }
            entries
                .values()
                .find_map(|value| find_attachment_blob_ref_value(value, field_names))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|value| find_attachment_blob_ref_value(value, field_names)),
        _ => None,
    }
}

fn extract_attachment_blob_ref_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Array(values) => {
            let bytes = json_array_to_bytes(values)?;
            String::from_utf8(bytes).ok()
        }
        serde_json::Value::Object(_) => extract_attachment_blob_ref_nested_object_key(value),
        _ => None,
    }
}

fn extract_attachment_blob_ref_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(value) => value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok())),
        serde_json::Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn extract_attachment_blob_ref_bytes(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Array(values) => json_array_to_bytes(values),
        serde_json::Value::String(value) => decode_base64(value).ok(),
        serde_json::Value::Object(_) => extract_attachment_blob_ref_nested_file_key(value),
        _ => None,
    }
}

fn extract_attachment_blob_ref_nested_object_key(value: &serde_json::Value) -> Option<String> {
    find_attachment_blob_ref_value(value, &["object_key", "objectKey", "key", "path", "value"])
        .and_then(extract_attachment_blob_ref_text)
}

fn extract_attachment_blob_ref_nested_file_key(value: &serde_json::Value) -> Option<Vec<u8>> {
    find_attachment_blob_ref_value(value, &["file_key", "fileKey", "bytes", "data", "value"])
        .and_then(extract_attachment_blob_ref_bytes)
}

fn json_array_to_bytes(values: &[serde_json::Value]) -> Option<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect()
}

fn validate_attachment_blob_ref(blob_ref: AttachmentBlobRef) -> PublicResult<AttachmentBlobRef> {
    if blob_ref.version != ATTACHMENT_BLOB_REF_VERSION {
        return Err(PublicError::validation(format!(
            "unsupported attachment reference version {}",
            blob_ref.version
        )));
    }
    if blob_ref.object_key.trim().is_empty() {
        return Err(PublicError::validation(
            "attachment reference object key cannot be empty",
        ));
    }
    if blob_ref.ciphertext_bytes == 0 {
        return Err(PublicError::validation(
            "attachment reference ciphertext bytes must be positive",
        ));
    }
    symmetric_key_from_bytes(&blob_ref.file_key)?;
    if blob_ref.enc_context.trim().is_empty() {
        return Err(PublicError::validation(
            "attachment reference encryption context cannot be empty",
        ));
    }
    Ok(blob_ref)
}
