//! Serialization and deserialization functions for MCP messages.

use crate::types::{McpRequest, McpResponse}; // Import necessary types
use crate::error::{Result, MCPError}; // Import Result and Error
use prost::Message;
use bytes::Bytes;

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


// --- Canonicalization for Signatures (Placeholders) ---
// Achieving truly canonical Protobuf serialization is complex. These functions
// currently just serialize the message after clearing the signature field, 
// which is *not* guaranteed to be canonical across different Protobuf implementations
// or even different runs with the same implementation if map field ordering changes.
// A robust solution might require a custom serialization format or library.

/// Serializes a Protobuf message into a byte vector using standard encoding.
///
/// This function provides a basic mechanism for serialization. However, standard
/// Protocol Buffers encoding does *not* guarantee canonical output across different
/// implementations or even different runs with the same implementation, especially
/// concerning map field ordering and potential encoding variations for default values.
///
/// **Importance for Signatures:** For cryptographic signatures to be verifiable,
/// the exact same byte sequence must be produced by both the signer and the verifier
/// when preparing the message content. Non-canonical serialization breaks this.
///
/// **TODO:** Implement a truly canonical serialization scheme.
/// Possible approaches:
///    1.  Define a strict field ordering and serialization format (e.g., lexicographical
///        ordering of fields by tag number or name, consistent encoding of primitives).
///    2.  Use a serialization format designed for canonical output (e.g., JSON Canonicalization Scheme (JCS)
///        after converting the proto to a defined JSON structure, though this adds overhead).
///    3.  Specify and enforce rules for map key ordering during serialization.
///
/// For now, we rely on `prost`'s default `encode_to_vec`, accepting its limitations.
///
/// # Arguments
/// * `message`: The Protobuf message to serialize.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the serialized bytes.
/// * `Err(MCPError::SerializationError)` if encoding fails.
fn canonical_serialize<T: Message>(message: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    // encode_to_vec is generally preferred over encode as it handles buffer growth.
    message.encode(&mut buf).map_err(|e| MCPError::SerializationError { 
        message: format!("Failed to encode protobuf message: {}", e),
        source: Some(Box::new(e)), 
    })?;
    Ok(buf)
}

/// Prepares an [`McpRequest`] for signing by creating a canonical byte representation.
///
/// This involves:
/// 1. Cloning the original request to avoid modifying it.
/// 2. Clearing the `signature` field in the clone, as the signature is calculated over
///    the message *without* the signature field itself.
/// 3. Serializing the modified clone using `canonical_serialize`.
///
/// **Note on Canonicality:** Relies on `canonical_serialize`, which currently uses
/// standard Protobuf encoding and is *not* guaranteed to be fully canonical (see
/// `canonical_serialize` documentation). This is a known limitation.
///
/// # Arguments
/// * `request`: The [`McpRequest`] to prepare.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the byte sequence to be signed.
/// * `Err(MCPError)` if serialization fails.
pub fn prepare_request_for_signing(request: &McpRequest) -> Result<Vec<u8>> {
    let mut request_clone = request.clone();
    request_clone.signature = None; // Clear the signature field
    canonical_serialize(&request_clone)
}

/// Prepares an [`McpResponse`] for signing by creating a canonical byte representation.
///
/// This involves:
/// 1. Cloning the original response to avoid modifying it.
/// 2. Clearing the `signature` field in the clone.
/// 3. Serializing the modified clone using `canonical_serialize`.
///
/// **Note on Canonicality:** Relies on `canonical_serialize` and its current limitations
/// regarding true canonical output (see `canonical_serialize` documentation).
///
/// # Arguments
/// * `response`: The [`McpResponse`] to prepare.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the byte sequence to be signed.
/// * `Err(MCPError)` if serialization fails.
pub fn prepare_response_for_signing(response: &McpResponse) -> Result<Vec<u8>> {
    let mut response_clone = response.clone();
    response_clone.signature = None; // Clear the signature field
    canonical_serialize(&response_clone)
}


// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*; // Import functions from this module
    use crate::builders::{McpRequestBuilder, McpResponseBuilder}; // For test data
    use crate::crypto::{KeyPair, sign_request, sign_response}; // For signing
    use crate::types::{RequestorIdentity, PurposeDna, PermissionSpecification, Action, Status};
    use bytes::Bytes;
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
        let purpose = create_test_purpose();
        let mut request = McpRequestBuilder::new(identity, purpose, "1.0.0".to_string()).build();
        // Give it a dummy signature first
        request.signature = Some(crate::types::CryptoSignature { 
            key_id: "dummy".into(), algorithm: "dummy".into(), signature: Bytes::from_static(b"dummy") 
        });
        
        // Prepare for signing
        let bytes_to_sign = prepare_request_for_signing(&request)?;
        
        // Deserialize the bytes meant for signing and check the signature field IS None
        let request_from_bytes = deserialize_request(&bytes_to_sign)?;
        assert!(request_from_bytes.signature.is_none(), "Signature should be None in bytes prepared for signing");
        // Ensure other fields are preserved
        assert_eq!(request.request_id, request_from_bytes.request_id);
        Ok(())
    }
    
    #[test]
    fn test_prepare_response_for_signing_clears_signature() -> Result<()> {
        let (key_pair, _identity) = create_test_identity();
        let mut response = McpResponseBuilder::new("req-prep-resp".into(), Status::Approved, "1.0.0".into()).build();
        // Give it a dummy signature first
        response.signature = Some(crate::types::CryptoSignature { 
            key_id: "dummy".into(), algorithm: "dummy".into(), signature: Bytes::from_static(b"dummy") 
        });
        
        // Prepare for signing
        let bytes_to_sign = prepare_response_for_signing(&response)?;
        
        // Deserialize the bytes meant for signing and check the signature field IS None
        let response_from_bytes = deserialize_response(&bytes_to_sign)?;
        assert!(response_from_bytes.signature.is_none(), "Signature should be None in bytes prepared for signing");
        // Ensure other fields are preserved
        assert_eq!(response.response_id, response_from_bytes.response_id);
        Ok(())
    }
    
    // Add tests for error cases if needed (e.g., invalid byte streams for deserialization)
    #[test]
    fn test_deserialize_request_invalid_bytes() {
        let invalid_bytes = b"this is not a valid protobuf message";
        let result = deserialize_request(invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::DeserializationError { .. }));
    }
    
     #[test]
    fn test_deserialize_response_invalid_bytes() {
        let invalid_bytes = b"\x01\x02\x03\x04";
        let result = deserialize_response(invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::DeserializationError { .. }));
    }
} 