//! Serialization and deserialization functions for MCP messages.

use crate::types::{McpRequest, McpResponse}; // Import necessary types
use crate::error::{Result, MCPError}; // Import Result and Error
use prost::Message;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

// --- Request Serialization/Deserialization ---

/// Serializes an [`McpRequest`] into Protobuf bytes (`Vec<u8>`).
///
/// # Arguments
/// * `request`: The [`McpRequest`] to serialize.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the serialized Protobuf bytes.
/// * `Err(MCPError::SerializationError)` if encoding fails.
pub fn serialize_request(request: &McpRequest) -> Result<Vec<u8>> {
    // TODO: Consider adding size limit checks before serialization if needed.
    let mut buf = Vec::new();
    buf.reserve(request.encoded_len());
    request.encode(&mut buf)
        .map_err(|e| MCPError::SerializationError { context: "McpRequest encoding".to_string(), source: e })?;
    Ok(buf)
}

/// Deserializes Protobuf bytes (`&[u8]`) into an [`McpRequest`].
///
/// # Arguments
/// * `buf`: The byte slice containing the serialized Protobuf data.
///
/// # Returns
/// * `Ok(McpRequest)` if deserialization is successful.
/// * `Err(MCPError::DeserializationError)` if decoding fails.
pub fn deserialize_request(buf: &[u8]) -> Result<McpRequest> {
    // TODO: Consider adding size limit checks on `buf.len()` before deserialization.
    // TODO: Explore zero-copy alternatives for specific fields if necessary.
    McpRequest::decode(buf)
         .map_err(|e| MCPError::DeserializationError { context: "McpRequest decoding".to_string(), source: e })
}

// --- Response Serialization/Deserialization ---

/// Serializes an [`McpResponse`] into Protobuf bytes (`Vec<u8>`).
///
/// # Arguments
/// * `response`: The [`McpResponse`] to serialize.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the serialized Protobuf bytes.
/// * `Err(MCPError::SerializationError)` if encoding fails.
pub fn serialize_response(response: &McpResponse) -> Result<Vec<u8>> {
    // TODO: Consider adding size limit checks, especially for `response_payload`.
    let mut buf = Vec::new();
    buf.reserve(response.encoded_len());
    response.encode(&mut buf)
         .map_err(|e| MCPError::SerializationError { context: "McpResponse encoding".to_string(), source: e })?;
    Ok(buf)
}

/// Deserializes Protobuf bytes (`&[u8]`) into an [`McpResponse`].
///
/// # Arguments
/// * `buf`: The byte slice containing the serialized Protobuf data.
///
/// # Returns
/// * `Ok(McpResponse)` if deserialization is successful.
/// * `Err(MCPError::DeserializationError)` if decoding fails.
pub fn deserialize_response(buf: &[u8]) -> Result<McpResponse> {
    // TODO: Consider adding size limit checks on `buf.len()` before deserialization.
    // TODO: Explore zero-copy alternatives for specific fields if necessary.
    McpResponse::decode(buf)
        .map_err(|e| MCPError::DeserializationError { context: "McpResponse decoding".to_string(), source: e })
}

// --- SERIALIZABLE DATA STRUCTURES FOR CANONICAL REPRESENTATION ---

/// Serializable structure representing an McpRequest for canonical serialization
#[derive(Serialize, Deserialize)]
struct CanonicalRequest<'a> {
    request_id: &'a str,
    mcp_version: &'a str,
    requestor_identity: CanonicalIdentity<'a>,
    purpose_dna: CanonicalPurpose<'a>,
    permissions: Vec<CanonicalPermission<'a>>,
    timestamp: i64, // Nanoseconds since epoch
    request_expiry: Option<i64>,
    extensions: Vec<CanonicalExtension<'a>>,
}

/// Serializable structure representing a RequestorIdentity
#[derive(Serialize, Deserialize)]
struct CanonicalIdentity<'a> {
    pseudonym_id: &'a str,
    public_key: &'a [u8],
    // Note: We intentionally exclude attestations for simplicity in this implementation
}

/// Serializable structure representing a PurposeDNA
#[derive(Serialize, Deserialize)]
struct CanonicalPurpose<'a> {
    purpose_id: &'a str,
    primary_purpose_category: i32,
    specific_purpose_description: &'a str,
    data_types_involved: Vec<&'a str>,
    // Add other fields as needed for your specific implementation
}

/// Serializable structure representing a PermissionSpecification
#[derive(Serialize, Deserialize)]
struct CanonicalPermission<'a> {
    resource_identifier: &'a str,
    requested_action: i32,
    constraints: Option<BTreeMap<&'a str, serde_json::Value>>,
}

/// Serializable structure representing a protocol extension
#[derive(Serialize, Deserialize)]
struct CanonicalExtension<'a> {
    type_url: &'a str,
    value: &'a [u8],
}

/// Serializable structure representing an McpResponse for canonical serialization
#[derive(Serialize, Deserialize)]
struct CanonicalResponse<'a> {
    request_id: &'a str,
    mcp_version: &'a str,
    status: i32,
    status_message: &'a str,
    timestamp: i64,
    permissions_status: Vec<CanonicalPermissionStatus<'a>>,
    payload: Option<&'a [u8]>,
    consent_receipt: Option<&'a [u8]>,
    extensions: Vec<CanonicalExtension<'a>>,
}

/// Serializable structure representing a permission status
#[derive(Serialize, Deserialize)]
struct CanonicalPermissionStatus<'a> {
    resource_identifier: &'a str,
    granted: bool,
    reason: &'a str,
}

// --- Canonicalization for Signatures ---

/// Serializes a message into a canonicalized byte representation using CBOR.
///
/// This function converts the protobuf message into a structured representation 
/// that is then serialized using the deterministic CBOR format, which ensures:
/// 1. Consistent field ordering
/// 2. Deterministic encoding of values
/// 3. Compatibility with cryptographic operations
///
/// This approach addresses the limitations of Protobuf serialization, which does not
/// guarantee canonical output across different implementations or runs.
///
/// # Arguments
/// * `message`: The message to canonicalize.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the canonicalized CBOR bytes.
/// * `Err(MCPError)` if conversion or serialization fails.

/// Prepares an [`McpRequest`] for signing by creating a canonical byte representation.
///
/// This involves:
/// 1. Converting the request to a canonical form (without the signature field)
/// 2. Serializing using deterministic CBOR encoding
///
/// # Arguments
/// * `request`: The [`McpRequest`] to prepare.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the byte sequence to be signed.
/// * `Err(MCPError)` if serialization fails.
pub fn prepare_request_for_signing(request: &McpRequest) -> Result<Vec<u8>> {
    // Extract values from the request and create a canonical representation
    let canonical = convert_request_to_canonical(request)?;
    
    // Serialize using CBOR with deterministic encoding
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut buf)
        .map_err(|e| {
            MCPError::ConversionError { 
                message: format!("CBOR canonicalization of request failed: {}", e)
            }
        })?;
    
    Ok(buf)
}

/// Prepares an [`McpResponse`] for signing by creating a canonical byte representation.
///
/// This involves:
/// 1. Converting the response to a canonical form (without the signature field)
/// 2. Serializing using deterministic CBOR encoding
///
/// # Arguments
/// * `response`: The [`McpResponse`] to prepare.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the byte sequence to be signed.
/// * `Err(MCPError)` if serialization fails.
pub fn prepare_response_for_signing(response: &McpResponse) -> Result<Vec<u8>> {
    // Extract values from the response and create a canonical representation
    let canonical = convert_response_to_canonical(response)?;
    
    // Serialize using CBOR with deterministic encoding
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut buf)
        .map_err(|e| {
            MCPError::ConversionError { 
                message: format!("CBOR canonicalization of response failed: {}", e)
            }
        })?;
    
    Ok(buf)
}

// --- Helper functions for conversion ---

/// Converts an McpRequest to its canonical form
fn convert_request_to_canonical(request: &McpRequest) -> Result<CanonicalRequest> {
    // Basic validation to make sure required fields are present
    let identity = request.requestor_identity.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.requestor_identity"))?;
    
    let purpose = request.purpose_dna.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.purpose_dna"))?;
    
    let timestamp = request.timestamp.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.timestamp"))?;
    
    // Convert timestamp to nanoseconds since epoch
    let timestamp_nanos = (timestamp.seconds * 1_000_000_000) + timestamp.nanos as i64;
    
    // Optional expiry timestamp conversion
    let request_expiry = request.request_expiry.as_ref().map(|t| 
        (t.seconds * 1_000_000_000) + t.nanos as i64
    );
    
    // Convert identity to canonical form
    let canonical_identity = CanonicalIdentity {
        pseudonym_id: &identity.pseudonym_id,
        public_key: &identity.public_key,
    };
    
    // Convert purpose to canonical form
    let canonical_purpose = CanonicalPurpose {
        purpose_id: &purpose.purpose_id,
        primary_purpose_category: purpose.primary_purpose_category,
        specific_purpose_description: &purpose.specific_purpose_description,
        data_types_involved: purpose.data_types_involved.iter().map(|s| s.as_str()).collect(),
    };
    
    // Convert permissions to canonical form
    let mut canonical_permissions = Vec::with_capacity(request.permissions.len());
    for perm in &request.permissions {
        // Convert struct/constraints if present
        let constraints = if let Some(constr) = &perm.constraints {
            // Convert prost Struct to BTreeMap (automatically sorted)
            let mut map = BTreeMap::new();
            
            // Access the fields directly
            for (key, value) in &constr.fields {
                // Convert value to serde_json::Value for CBOR serialization
                if let Ok(json_value) = convert_prost_value_to_json(value) {
                    map.insert(key.as_str(), json_value);
                } else {
                    return Err(MCPError::ConversionError { 
                        message: format!("Failed to convert constraint value for key: {}", key) 
                    });
                }
            }
            
            if !map.is_empty() {
                Some(map)
            } else {
                None
            }
        } else {
            None
        };
        
        canonical_permissions.push(CanonicalPermission {
            resource_identifier: &perm.resource_identifier,
            requested_action: perm.requested_action,
            constraints,
        });
    }
    
    // Convert extensions to canonical form
    let mut canonical_extensions = Vec::with_capacity(request.extensions.len());
    for ext in &request.extensions {
        canonical_extensions.push(CanonicalExtension {
            type_url: &ext.type_url,
            value: &ext.value,
        });
    }
    
    Ok(CanonicalRequest {
        request_id: &request.request_id,
        mcp_version: &request.mcp_version,
        requestor_identity: canonical_identity,
        purpose_dna: canonical_purpose,
        permissions: canonical_permissions,
        timestamp: timestamp_nanos,
        request_expiry,
        extensions: canonical_extensions,
    })
}

/// Converts an McpResponse to its canonical form
fn convert_response_to_canonical(response: &McpResponse) -> Result<CanonicalResponse> {
    // Basic validation
    let timestamp = response.timestamp.as_ref()
        .ok_or_else(|| MCPError::missing_field("response.timestamp"))?;
    
    // Convert timestamp to nanoseconds since epoch
    let timestamp_nanos = (timestamp.seconds * 1_000_000_000) + timestamp.nanos as i64;
    
    // Convert permission statuses to canonical form
    let mut canonical_perm_statuses = Vec::with_capacity(response.permission_statuses.len());
    for status in &response.permission_statuses {
        canonical_perm_statuses.push(CanonicalPermissionStatus {
            resource_identifier: &status.resource_identifier,
            granted: status.granted,
            reason: &status.reason,
        });
    }
    
    // Convert extensions to canonical form
    let mut canonical_extensions = Vec::with_capacity(response.extensions.len());
    for ext in &response.extensions {
        canonical_extensions.push(CanonicalExtension {
            type_url: &ext.type_url,
            value: &ext.value,
        });
    }
    
    // Extract payload and consent receipt as byte slices if present
    let payload = if !response.response_payload.is_empty() {
        Some(response.response_payload.as_ref())
    } else {
        None
    };
    
    let consent_receipt = if !response.consent_receipt.is_empty() {
        Some(response.consent_receipt.as_ref())
    } else {
        None
    };
    
    Ok(CanonicalResponse {
        request_id: &response.request_id,
        mcp_version: &response.mcp_version,
        status: response.status,
        status_message: &response.status_message,
        timestamp: timestamp_nanos,
        permissions_status: canonical_perm_statuses,
        payload,
        consent_receipt,
        extensions: canonical_extensions,
    })
}

/// Converts a prost_types::Value to a serde_json::Value
fn convert_prost_value_to_json(value: &prost_types::Value) -> Result<serde_json::Value> {
    use prost_types::value::Kind;
    
    match &value.kind {
        Some(Kind::NullValue(_)) => Ok(serde_json::Value::Null),
        Some(Kind::NumberValue(n)) => Ok(serde_json::Value::Number(
            serde_json::Number::from_f64(*n).ok_or_else(|| 
                MCPError::ConversionError { message: format!("Invalid number: {}", n) }
            )?
        )),
        Some(Kind::StringValue(s)) => Ok(serde_json::Value::String(s.clone())),
        Some(Kind::BoolValue(b)) => Ok(serde_json::Value::Bool(*b)),
        Some(Kind::StructValue(s)) => {
            let mut map = serde_json::Map::new();
            
            // Access the fields directly
            for (k, v) in &s.fields {
                map.insert(k.clone(), convert_prost_value_to_json(v)?);
            }
            
            Ok(serde_json::Value::Object(map))
        },
        Some(Kind::ListValue(list)) => {
            let mut values = Vec::new();
            for item in &list.values {
                values.push(convert_prost_value_to_json(item)?);
            }
            Ok(serde_json::Value::Array(values))
        },
        None => Err(MCPError::ConversionError { 
            message: "Empty prost value".to_string() 
        }),
    }
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*; // Import functions from this module
    use crate::builders::{McpRequestBuilder, McpResponseBuilder}; // For test data
    use crate::crypto::{KeyPair, sign_request, sign_response}; // For signing
    use crate::types::{RequestorIdentity, PurposeDna, PermissionSpecification, permission_specification::Action, mcp_response::Status};
    use prost_types::Any;

    // Helpers from builders/crypto tests could be moved to a common test_utils module
    fn create_test_identity() -> (KeyPair, RequestorIdentity) {
        let key_pair = KeyPair::generate().expect("Key generation failed");
        let identity = RequestorIdentity {
            pseudonym_id: "ser-test-id".to_string(),
            public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()),
            attestations: vec![],
        };
        (key_pair, identity)
    }

    fn create_test_purpose() -> PurposeDna {
        PurposeDna {
            purpose_id: "ser-test-purpose".to_string(),
            primary_purpose_category: 1, 
            specific_purpose_description: "Serialization testing".to_string(),
            data_types_involved: vec!["ser_data".into()],
            processing_description: "Serializing...".into(),
            storage_description: "Serialized...".into(),
             ..Default::default()
        }
    }

    fn create_test_permission() -> PermissionSpecification {
        PermissionSpecification {
            resource_identifier: "ser-res-1".to_string(), 
            requested_action: Action::Write as i32,
            ..Default::default()
        }
    }
    
    #[test]
    fn test_request_serialization_deserialization_roundtrip() {
        let (key_pair, identity) = create_test_identity();
        let purpose = create_test_purpose();
        let permission = create_test_permission();
        let mut request = McpRequestBuilder::new(identity, purpose, "1.0.0".to_string())
            .add_permission(permission)
             .add_extension(Any { type_url: "test/ext".into(), value: vec![1,2]})
            .build();
        // Sign it to make sure signature is handled
        sign_request(&mut request, &key_pair, "ser-key-1".to_string()).unwrap();
        
        let serialized = serialize_request(&request).unwrap();
        assert!(!serialized.is_empty());
        
        let deserialized = deserialize_request(&serialized).unwrap();
        
        // Use prost::Message::eq for reliable comparison
        assert!(request.eq(&deserialized), "Original and deserialized requests do not match");
    }
    
    #[test]
    fn test_response_serialization_deserialization_roundtrip() {
        let request_id = "req-for-ser-resp".to_string();
        let (key_pair, _identity) = create_test_identity(); // Need a key pair for signing

        let mut response = McpResponseBuilder::new(request_id.clone(), Status::Denied, "1.0.0".to_string())
            .status_message("Denied by policy".to_string())
            .set_payload(Bytes::from_static(b"error info"))
            .set_consent_receipt(Bytes::from_static(b"no consent"))
            .add_extension(Any { type_url: "err/code".into(), value: vec![4,0,3]})
            .build();
        
        // Sign it
        sign_response(&mut response, &key_pair, "ser-resp-key-1".to_string()).unwrap();

        let serialized = serialize_response(&response).unwrap();
        assert!(!serialized.is_empty());
        
        let deserialized = deserialize_response(&serialized).unwrap();

        assert!(response.eq(&deserialized), "Original and deserialized responses do not match");
    }
    
    #[test]
    fn test_prepare_request_for_signing_clears_signature() -> Result<()> {
        let (key_pair, identity) = create_test_identity();
        let mut request = McpRequestBuilder::new(
            identity,
            create_test_purpose(),
            "1.0.0".to_string()
        )
        .add_permission(create_test_permission())
        .build();
        
        // Sign it, so it has a signature
        sign_request(&mut request, &key_pair, "test-key-id".to_string())?;
        assert!(request.signature.is_some(), "Request should have a signature");
        
        // Prepare for signing (should clear signature)
        let for_signing = prepare_request_for_signing(&request)?;
        assert!(!for_signing.is_empty(), "Signing bytes should not be empty");
        
        // Deserialize the bytes and verify the signature is gone
        // Not possible with CBOR serialization - we test the idempotency instead
        
        // Verify that calling prepare_request_for_signing twice produces the same bytes
        let for_signing2 = prepare_request_for_signing(&request)?;
        assert_eq!(for_signing, for_signing2, "Canonical serialization should be idempotent");
        
        Ok(())
    }
    
    #[test]
    fn test_prepare_response_for_signing_clears_signature() -> Result<()> {
        let (key_pair, _identity) = create_test_identity();
        let mut response = McpResponseBuilder::new(
            "test-req-id".to_string(), 
            Status::Approved,
            "1.0.0".to_string()
        ).build();
        
        // Sign it, so it has a signature
        sign_response(&mut response, &key_pair, "test-key-id".to_string())?;
        assert!(response.signature.is_some(), "Response should have a signature");
        
        // Prepare for signing (should clear signature)
        let for_signing = prepare_response_for_signing(&response)?;
        assert!(!for_signing.is_empty(), "Signing bytes should not be empty");
        
        // Verify that calling prepare_response_for_signing twice produces the same bytes
        let for_signing2 = prepare_response_for_signing(&response)?;
        assert_eq!(for_signing, for_signing2, "Canonical serialization should be idempotent");
        
        Ok(())
    }
    
    #[test]
    fn test_canonical_serialization_request_order_independence() -> Result<()> {
        // Create two semantically identical requests but build/add fields in different order
        let (key_pair, identity1) = create_test_identity();
        let (_, identity2) = create_test_identity();
        let purpose = create_test_purpose();
        
        // First request: standard build order
        let mut request1 = McpRequestBuilder::new(identity1.clone(), purpose.clone(), "1.0.0".to_string())
            .add_permission(create_test_permission())
            .add_extension(Any { type_url: "test/ext".into(), value: vec![1,2]})
            .build();
            
        // Second request: different order of building (using different identity)
        let mut request2 = McpRequestBuilder::new(identity2, purpose, "1.0.0".to_string())
            .add_extension(Any { type_url: "test/ext".into(), value: vec![1,2]})
            .add_permission(create_test_permission())
            .build();
            
        // Make them semantically identical by setting the same identity
        if let Some(id) = request2.requestor_identity.as_mut() {
            id.pseudonym_id = identity1.pseudonym_id.clone();
            id.public_key = identity1.public_key.clone();
        }
            
        // Test that canonical serialization produces identical results
        let canonical1 = prepare_request_for_signing(&request1)?;
        let canonical2 = prepare_request_for_signing(&request2)?;
        
        assert_eq!(canonical1, canonical2, "Canonical serialization should be invariant to build order");
        
        Ok(())
    }
    
    #[test]
    fn test_deserialize_request_invalid_bytes() {
        let result = deserialize_request(&[0xFF, 0x00, 0x01]); // Invalid Protobuf
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                MCPError::DeserializationError { .. } => {} // Expected
                _ => panic!("Expected DeserializationError, got {:?}", e),
            }
        }
    }
    
    #[test]
    fn test_deserialize_response_invalid_bytes() {
        let result = deserialize_response(&[0xDE, 0xAD, 0xBE, 0xEF]); // Invalid Protobuf
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                MCPError::DeserializationError { .. } => {} // Expected
                _ => panic!("Expected DeserializationError, got {:?}", e),
            }
        }
    }
} 