use std::io::Cursor;

use serde::{Serialize, de::DeserializeOwned};
use worklist_client_core::{PublicError, PublicResult};

use crate::payloads::FlexibleValue;

pub fn flexible_value_to_json(value: FlexibleValue) -> serde_json::Value {
    match value {
        FlexibleValue::Integer(value) => integer_to_json_value(value),
        FlexibleValue::Bytes(bytes) => {
            serde_json::Value::Array(bytes.into_iter().map(serde_json::Value::from).collect())
        }
        FlexibleValue::Float(value) => serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .unwrap_or_else(|| serde_json::Value::String(value.to_string())),
        FlexibleValue::Text(value) => serde_json::Value::String(value),
        FlexibleValue::Bool(value) => serde_json::Value::Bool(value),
        FlexibleValue::Null => serde_json::Value::Null,
        FlexibleValue::Tag(tag, value) => serde_json::json!({
            "tag": tag,
            "value": flexible_value_to_json(*value),
        }),
        FlexibleValue::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(flexible_value_to_json).collect())
        }
        FlexibleValue::Map(entries) => serde_json::Value::Object(
            entries
                .into_iter()
                .map(|(key, value)| {
                    (
                        flexible_map_key_to_string(key),
                        flexible_value_to_json(value),
                    )
                })
                .collect(),
        ),
        other => serde_json::Value::String(format!("{other:?}")),
    }
}

pub fn json_value_to_flexible(value: serde_json::Value) -> FlexibleValue {
    match value {
        serde_json::Value::Null => FlexibleValue::Null,
        serde_json::Value::Bool(value) => FlexibleValue::Bool(value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                FlexibleValue::Integer(value.into())
            } else if let Some(value) = value.as_u64() {
                FlexibleValue::Integer(value.into())
            } else {
                FlexibleValue::Float(
                    value
                        .as_f64()
                        .expect("serde_json number should deserialize as f64"),
                )
            }
        }
        serde_json::Value::String(value) => FlexibleValue::Text(value),
        serde_json::Value::Array(values) => {
            FlexibleValue::Array(values.into_iter().map(json_value_to_flexible).collect())
        }
        serde_json::Value::Object(values) => FlexibleValue::Map(
            values
                .into_iter()
                .map(|(key, value)| (FlexibleValue::Text(key), json_value_to_flexible(value)))
                .collect(),
        ),
    }
}
fn integer_to_json_value(value: strong_box::ciborium::value::Integer) -> serde_json::Value {
    let value = i128::from(value);
    if let Ok(value) = i64::try_from(value) {
        return serde_json::Value::from(value);
    }
    if let Ok(value) = u64::try_from(value) {
        return serde_json::Value::from(value);
    }

    serde_json::Value::String(value.to_string())
}

fn flexible_map_key_to_string(value: FlexibleValue) -> String {
    match value {
        FlexibleValue::Text(value) => value,
        other => flexible_value_to_json(other).to_string(),
    }
}
pub fn deserialize_from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> PublicResult<T> {
    let mut cursor = Cursor::new(bytes);
    strong_box::ciborium::de::from_reader(&mut cursor)
        .map_err(|err| PublicError::crypto(format!("failed to deserialize payload: {err}")))
}

pub fn serialize_to_cbor<T: Serialize + ?Sized>(value: &T) -> PublicResult<Vec<u8>> {
    let mut buffer = Vec::new();
    strong_box::ciborium::ser::into_writer(value, &mut buffer)
        .map_err(|err| PublicError::crypto(format!("failed to serialize payload: {err}")))?;
    Ok(buffer)
}
pub(crate) fn deserialize_complete_from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> PublicResult<T> {
    let mut cursor = Cursor::new(bytes);
    let decoded = strong_box::ciborium::de::from_reader(&mut cursor)
        .map_err(|err| PublicError::crypto(format!("failed to deserialize payload: {err}")))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(PublicError::validation(
            "CBOR payload contains trailing bytes",
        ));
    }
    Ok(decoded)
}
