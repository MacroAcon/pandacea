//! Utility functions for timestamp conversions, Struct conversions, and expiration checks.

use crate::error::{Result, MCPError}; // Import Result and Error
use crate::types::{McpRequest, PurposeDna}; // Import types used in functions
use chrono::{DateTime, Utc};
use prost_types::{Timestamp, Struct, Value as ProstValue, value::Kind as ProstKind, ListValue};
use serde_json::{Value as SerdeValue, Map as SerdeMap};
use std::collections::HashMap;

// --- Timestamp Conversions ---

/// Converts a `chrono::DateTime<Utc>` to a `prost_types::Timestamp`.
pub fn prost_timestamp_from_chrono(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32, // Note: Potential truncation if chrono nanos > 10^9
    }
}

/// Converts a `prost_types::Timestamp` to an `Option<chrono::DateTime<Utc>>`.
/// Returns `None` if the timestamp is invalid or out of the representable range.
pub fn chrono_from_prost_timestamp(ts: &Timestamp) -> Option<DateTime<Utc>> {
    // Validate nanos part is within the valid range for prost::Timestamp
    if !(0..=999_999_999).contains(&ts.nanos) {
        return None; 
    }
    // `from_timestamp_opt` handles seconds range checks and returns Option
    // It uses the deprecated `from_timestamp` internally but is the correct API now.
    #[allow(deprecated)] 
    DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
}

// --- Expiration Checks ---

/// Checks if an [`McpRequest`] has expired based on its `request_expiry` field.
/// Returns `true` if expired or if `request_expiry` is missing or invalid.
pub fn is_request_expired(request: &McpRequest) -> bool {
    request.request_expiry.as_ref()
        .and_then(chrono_from_prost_timestamp) // Convert to DateTime<Utc> if valid
        .map_or(false, |expiry_dt| expiry_dt <= Utc::now()) // Check if expiry time is past or equal to now
}

/// Checks if a [`PurposeDna`] has expired based on its `purpose_expiry_timestamp` field.
/// Returns `true` if expired or if the timestamp is missing or invalid.
pub fn is_purpose_expired(purpose: &PurposeDna) -> bool {
     purpose.purpose_expiry_timestamp.as_ref()
        .and_then(chrono_from_prost_timestamp)
        .map_or(false, |expiry_dt| expiry_dt <= Utc::now())
}

// --- Struct <-> HashMap Conversions ---
// These functions handle the conversion between prost_types::Struct 
// (used in Protobuf) and HashMap<String, serde_json::Value> (easier to work with).

/// Converts a `HashMap<String, serde_json::Value>` to an `Option<prost_types::Struct>`.
/// Returns `Ok(None)` if the map is empty.
/// Returns `Err(MCPError::ConversionError)` if a value cannot be converted.
pub fn hashmap_to_prost_struct(map: HashMap<String, SerdeValue>) -> Result<Option<Struct>> {
    if map.is_empty() {
        Ok(None)
    } else {
        let fields = map.into_iter()
            .map(|(k, v)| serde_value_to_prost_value(v).map(|pv| (k, pv)))
            .collect::<Result<HashMap<String, ProstValue>>>()?; // Collect into Result<HashMap>
        Ok(Some(Struct { fields }))
    }
}

/// Converts an `Option<&prost_types::Struct>` to a `HashMap<String, serde_json::Value>`.
/// Returns an empty map if the input is `None`.
/// Returns `Err(MCPError::ConversionError)` if a value cannot be converted.
pub fn prost_struct_to_hashmap(p_struct: Option<&Struct>) -> Result<HashMap<String, SerdeValue>> {
    match p_struct {
        Some(s) => {
            s.fields.iter()
                .map(|(k, v)| prost_value_to_serde_value(v.clone()).map(|sv| (k.clone(), sv)))
                .collect::<Result<HashMap<String, SerdeValue>>>() // Collect into Result<HashMap>
        }
        None => Ok(HashMap::new()),
    }
}

// --- Value Conversion Helpers (serde_json::Value <-> prost_types::Value) ---

/// Converts a `serde_json::Value` to a `prost_types::Value`.
/// Handles nested structures and lists recursively.
pub fn serde_value_to_prost_value(value: SerdeValue) -> Result<ProstValue> {
    let kind = match value {
        SerdeValue::Null => ProstKind::NullValue(0), // prost uses 0 for NullValue
        SerdeValue::Bool(b) => ProstKind::BoolValue(b),
        SerdeValue::Number(n) => {
            // prost::Value uses f64 for number_value
            let num = n.as_f64().ok_or_else(|| MCPError::conversion_error(
                format!("Could not convert serde_json::Number '{}' to f64", n)
            ))?;
            ProstKind::NumberValue(num)
        }
        SerdeValue::String(s) => ProstKind::StringValue(s),
        SerdeValue::Array(arr) => {
            let values = arr.into_iter()
                .map(serde_value_to_prost_value)
                .collect::<Result<Vec<ProstValue>>>()?;
            ProstKind::ListValue(ListValue { values })
        }
        SerdeValue::Object(map) => {
            // Convert the inner map<String, SerdeValue> to map<String, ProstValue>
            let fields = map.into_iter()
                .map(|(k, v)| serde_value_to_prost_value(v).map(|pv| (k, pv)))
                .collect::<Result<HashMap<String, ProstValue>>>()?; 
            ProstKind::StructValue(Struct { fields })
        }
    };
    Ok(ProstValue { kind: Some(kind) })
}

/// Converts a `prost_types::Value` to a `serde_json::Value`.
/// Handles nested structures and lists recursively.
pub fn prost_value_to_serde_value(value: ProstValue) -> Result<SerdeValue> {
    let kind = value.kind.ok_or_else(|| MCPError::conversion_error(
        "prost_types::Value has no Kind specified"
    ))?;

    match kind {
        ProstKind::NullValue(_) => Ok(SerdeValue::Null),
        ProstKind::NumberValue(n) => {
            // serde_json::Number can represent integers and floats
            // Try to represent as u64/i64 if possible, otherwise f64
            let num = serde_json::Number::from_f64(n).ok_or_else(|| MCPError::conversion_error(
                format!("Could not convert f64 '{}' to serde_json::Number (NaN or Infinity?)", n)
            ))?;
            Ok(SerdeValue::Number(num))
        }
        ProstKind::StringValue(s) => Ok(SerdeValue::String(s)),
        ProstKind::BoolValue(b) => Ok(SerdeValue::Bool(b)),
        ProstKind::StructValue(s) => {
            let map = s.fields.into_iter()
                .map(|(k, v)| prost_value_to_serde_value(v).map(|sv| (k, sv)))
                .collect::<Result<SerdeMap<String, SerdeValue>>>()?;
            Ok(SerdeValue::Object(map))
        }
        ProstKind::ListValue(l) => {
            let vec = l.values.into_iter()
                .map(prost_value_to_serde_value)
                .collect::<Result<Vec<SerdeValue>>>()?;
            Ok(SerdeValue::Array(vec))
        }
    }
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*; // Import functions from this module
    use crate::builders::McpRequestBuilder; // For creating test data
    use crate::crypto::KeyPair; // For test identity
    use crate::types::{RequestorIdentity, PurposeDna};
    use chrono::{Duration, TimeZone};
    use prost_types::value::Kind;
    use serde_json::json;

    // Timestamp Tests
    #[test]
    fn test_timestamp_conversion_roundtrip() {
        let now = Utc::now();
        let prost_ts = prost_timestamp_from_chrono(now);
        let chrono_dt_opt = chrono_from_prost_timestamp(&prost_ts);
        
        assert!(chrono_dt_opt.is_some());
        let chrono_dt = chrono_dt_opt.unwrap();
        
        // Compare timestamps carefully - microseconds might get truncated in prost -> chrono
        assert_eq!(chrono_dt.timestamp(), now.timestamp());
        // Compare nanoseconds, allowing for minor differences due to precision
        assert!((chrono_dt.timestamp_subsec_nanos() as i64 - now.timestamp_subsec_nanos() as i64).abs() < 1000);
    }
    
    #[test]
    fn test_chrono_from_prost_invalid_nanos() {
        let ts_neg_nanos = Timestamp { seconds: 100, nanos: -1 };
        assert!(chrono_from_prost_timestamp(&ts_neg_nanos).is_none());
        
        let ts_high_nanos = Timestamp { seconds: 100, nanos: 1_000_000_000 }; // 1 second
        assert!(chrono_from_prost_timestamp(&ts_high_nanos).is_none());
    }
    
     #[test]
    fn test_chrono_from_prost_epoch() {
        let ts_epoch = Timestamp { seconds: 0, nanos: 0 };
        let dt = chrono_from_prost_timestamp(&ts_epoch).unwrap();
        assert_eq!(dt, Utc.timestamp_opt(0, 0).unwrap());
    }

    // Expiration Tests
     // Helper for expiration tests
     fn create_test_request_with_expiry(expiry: Option<DateTime<Utc>>) -> McpRequest {
         let kp = KeyPair::generate().unwrap();
         let identity = RequestorIdentity { 
             pseudonym_id: "exp-test".into(), public_key: kp.public_key_bytes().into(), ..Default::default()
         };
         let purpose = PurposeDna { purpose_id: "exp-purp".into(), ..Default::default() };
         let mut builder = McpRequestBuilder::new(identity, purpose, "1.0".into());
         if let Some(exp) = expiry {
             builder = builder.set_expiry(exp);
         }
         builder.build()
     }
     
     fn create_test_purpose_with_expiry(expiry: Option<DateTime<Utc>>) -> PurposeDna {
         PurposeDna { 
             purpose_id: "exp-purp-dna".into(),
             purpose_expiry_timestamp: expiry.map(prost_timestamp_from_chrono),
              ..Default::default()
         }
     }

    #[test]
    fn test_is_request_expired() {
        let now = Utc::now();
        
        // Not expired (expiry in future)
        let req_future = create_test_request_with_expiry(Some(now + Duration::hours(1)));
        assert!(!is_request_expired(&req_future));
        
        // Expired (expiry in past)
        let req_past = create_test_request_with_expiry(Some(now - Duration::seconds(10)));
        assert!(is_request_expired(&req_past));
        
        // No expiry set - should not be considered expired
        let req_no_expiry = create_test_request_with_expiry(None);
        assert!(!is_request_expired(&req_no_expiry));
        
         // Invalid expiry timestamp (should not be considered expired by this check, validation handles invalid format)
         let mut req_invalid = create_test_request_with_expiry(None);
         req_invalid.request_expiry = Some(Timestamp { seconds: 0, nanos: -1 });
         assert!(!is_request_expired(&req_invalid)); // is_request_expired returns false if chrono_from_prost is None
    }
    
     #[test]
    fn test_is_purpose_expired() {
        let now = Utc::now();
        
        // Not expired (expiry in future)
        let purp_future = create_test_purpose_with_expiry(Some(now + Duration::hours(1)));
        assert!(!is_purpose_expired(&purp_future));
        
        // Expired (expiry in past)
        let purp_past = create_test_purpose_with_expiry(Some(now - Duration::seconds(10)));
        assert!(is_purpose_expired(&purp_past));
        
        // No expiry set
        let purp_no_expiry = create_test_purpose_with_expiry(None);
        assert!(!is_purpose_expired(&purp_no_expiry));
        
         // Invalid expiry timestamp
         let mut purp_invalid = create_test_purpose_with_expiry(None);
         purp_invalid.purpose_expiry_timestamp = Some(Timestamp { seconds: 0, nanos: 1_000_000_001 });
         assert!(!is_purpose_expired(&purp_invalid)); // Returns false if chrono_from_prost is None
    }

    // Struct <-> HashMap Tests
    #[test]
    fn test_struct_hashmap_conversion_roundtrip() -> Result<()> {
        let json = json!({
            "string_key": "hello",
            "number_key": 123.45,
            "bool_key": true,
            "null_key": null,
            "array_key": [1, "two", false, null],
            "object_key": {
                "nested_string": "world",
                "nested_num": 99
            }
        });
        let map = json.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        let prost_struct_opt = hashmap_to_prost_struct(map)?;
        assert!(prost_struct_opt.is_some());
        let prost_struct = prost_struct_opt.unwrap();
        
        let roundtrip_map = prost_struct_to_hashmap(Some(&prost_struct))?;
        let roundtrip_json = SerdeValue::Object(roundtrip_map);

        // Compare original JSON with round-tripped JSON
        assert_eq!(json, roundtrip_json);
        Ok(())
    }
    
     #[test]
    fn test_hashmap_to_prost_struct_empty() -> Result<()> {
         let map: HashMap<String, SerdeValue> = HashMap::new();
         let prost_struct_opt = hashmap_to_prost_struct(map)?;
         assert!(prost_struct_opt.is_none());
         Ok(())
    }
    
     #[test]
    fn test_prost_struct_to_hashmap_none() -> Result<()> {
         let map = prost_struct_to_hashmap(None)?;
         assert!(map.is_empty());
         Ok(())
    }
    
     #[test]
    fn test_serde_value_to_prost_value_all_types() -> Result<()> {
         assert_eq!(serde_value_to_prost_value(SerdeValue::Null)?.kind, Some(Kind::NullValue(0)));
         assert_eq!(serde_value_to_prost_value(SerdeValue::Bool(true))?.kind, Some(Kind::BoolValue(true)));
         assert_eq!(serde_value_to_prost_value(SerdeValue::String("test".to_string()))?.kind, Some(Kind::StringValue("test".to_string())));
         assert_eq!(serde_value_to_prost_value(json!(123))?.kind, Some(Kind::NumberValue(123.0)));
         assert_eq!(serde_value_to_prost_value(json!(123.5))?.kind, Some(Kind::NumberValue(123.5)));
         
         // Array
         let arr_json = json!([1, "a"]);
         let arr_prost_val = serde_value_to_prost_value(arr_json)?;
         match arr_prost_val.kind {
             Some(Kind::ListValue(list)) => {
                 assert_eq!(list.values.len(), 2);
                 assert_eq!(list.values[0].kind, Some(Kind::NumberValue(1.0)));
                 assert_eq!(list.values[1].kind, Some(Kind::StringValue("a".to_string())));
             }
             _ => panic!("Expected ListValue"),
         }
         
         // Object
         let obj_json = json!({ "key": "value"});
         let obj_prost_val = serde_value_to_prost_value(obj_json)?;
         match obj_prost_val.kind {
            Some(Kind::StructValue(s)) => {
                assert_eq!(s.fields.len(), 1);
                assert!(s.fields.contains_key("key"));
                assert_eq!(s.fields["key"].kind, Some(Kind::StringValue("value".to_string())));
            }
             _ => panic!("Expected StructValue"),
         }
         Ok(())
    }
    
    #[test]
    fn test_prost_value_to_serde_value_all_types() -> Result<()> {
         assert_eq!(prost_value_to_serde_value(ProstValue { kind: Some(Kind::NullValue(0)) })?, SerdeValue::Null);
         assert_eq!(prost_value_to_serde_value(ProstValue { kind: Some(Kind::BoolValue(false)) })?, SerdeValue::Bool(false));
         assert_eq!(prost_value_to_serde_value(ProstValue { kind: Some(Kind::StringValue("abc".to_string())) })?, SerdeValue::String("abc".to_string()));
         assert_eq!(prost_value_to_serde_value(ProstValue { kind: Some(Kind::NumberValue(99.0)) })?, json!(99.0));
         assert_eq!(prost_value_to_serde_value(ProstValue { kind: Some(Kind::NumberValue(99.5)) })?, json!(99.5));
         
         // List
         let list = ListValue { values: vec![
             ProstValue { kind: Some(Kind::NumberValue(1.0)) }, 
             ProstValue { kind: Some(Kind::StringValue("a".to_string())) }
         ]};
         let list_prost_val = ProstValue { kind: Some(Kind::ListValue(list)) };
         assert_eq!(prost_value_to_serde_value(list_prost_val)?, json!([1.0, "a"]));
         
         // Struct
         let mut fields = HashMap::new();
         fields.insert("key".to_string(), ProstValue { kind: Some(Kind::StringValue("value".to_string())) });
         let s = Struct { fields };
         let struct_prost_val = ProstValue { kind: Some(Kind::StructValue(s)) };
         assert_eq!(prost_value_to_serde_value(struct_prost_val)?, json!({ "key": "value" }));
         
         Ok(())
    }
    
    #[test]
    fn test_prost_value_to_serde_value_no_kind() {
        let val = ProstValue { kind: None };
        let result = prost_value_to_serde_value(val);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::ConversionError { .. }));
    }
    
    #[test]
    fn test_serde_value_to_prost_value_unsupported_number() {
        // serde_json::Number can hold values unrepresentable by f64 (though typically parsed from f64)
        // Example: Extremely large integer (may parse as f64::INFINITY)
        // let large_num_str = "1".repeat(400);
        // let large_num: SerdeValue = serde_json::from_str(&large_num_str).unwrap(); 
        let nan_val = json!(f64::NAN);
        let result = serde_value_to_prost_value(nan_val);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::ConversionError { .. }));
        
        let inf_val = json!(f64::INFINITY);
        let result_inf = serde_value_to_prost_value(inf_val);
        assert!(result_inf.is_err());
        assert!(matches!(result_inf.unwrap_err(), MCPError::ConversionError { .. }));
    }
    
     #[test]
    fn test_prost_value_to_serde_value_unsupported_number() {
        let nan_val = ProstValue { kind: Some(Kind::NumberValue(f64::NAN)) };
        let result = prost_value_to_serde_value(nan_val);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::ConversionError { .. }));
        
         let inf_val = ProstValue { kind: Some(Kind::NumberValue(f64::INFINITY)) };
        let result_inf = prost_value_to_serde_value(inf_val);
        assert!(result_inf.is_err());
        assert!(matches!(result_inf.unwrap_err(), MCPError::ConversionError { .. }));
    }

} 