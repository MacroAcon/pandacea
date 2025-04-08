use prost::Message;
use uuid::Uuid;
use chrono::{Utc, DateTime};
use prost_types::{Timestamp, Struct, Value as ProstValue, value::Kind as ProstKind, ListValue};
use serde_json::{Value as SerdeValue, Map};
use std::collections::HashMap;
use bytes::Bytes;
use ring::signature::KeyPair as _; // Import KeyPair trait for public_key() method

// Include the generated Protobuf structures. 
// The actual filename (e.g., `pandacea.mcp.rs`) is determined by prost-build based on the package name in the .proto file.
// We use a module to encapsulate it.
pub mod mcp {
    // Add the prost_wkt_types dependency to handle well-known types like Timestamp and Struct
    // This needs to be done because the build.rs script adds serde attributes that use prost_wkt_types
    // Note: This dependency needs to be added to Cargo.toml as well.
    pub use prost_wkt_types; 
    include!(concat!(env!("OUT_DIR"), "/pandacea.mcp.rs"));
}

// Re-export core types for easier use
pub use mcp::{
    McpRequest,
    McpResponse,
    PurposeDna,
    RequestorIdentity,
    PermissionSpecification,
    permission_specification::Action,
    mcp_response::Status,
    mcp_response::PermissionStatus,
    CryptoSignature
};

// --- Error Handling ---
#[derive(Debug, thiserror::Error)]
pub enum MCPError {
    #[error("Protobuf encoding error: {0}")]
    EncodeError(#[from] prost::EncodeError),
    #[error("Protobuf decoding error: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid field value: {0}")]
    InvalidField(String),
    #[error("Signature verification failed: {0}")]
    SignatureError(String),
    #[error("Cryptography error: {0}")]
    CryptoError(String),
    #[error("Invalid cryptographic key: {0}")]
    InvalidKey(#[from] ring::error::KeyRejected),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Type conversion error: {0}")]
    ConversionError(String),
}

pub type Result<T> = std::result::Result<T, MCPError>;

// --- Serialization / Deserialization ---

pub fn serialize_request(request: &McpRequest) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.reserve(request.encoded_len());
    request.encode(&mut buf)?;
    Ok(buf)
}

pub fn deserialize_request(buf: &[u8]) -> Result<McpRequest> {
    McpRequest::decode(buf).map_err(MCPError::from)
}

pub fn serialize_response(response: &McpResponse) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.reserve(response.encoded_len());
    response.encode(&mut buf)?;
    Ok(buf)
}

pub fn deserialize_response(buf: &[u8]) -> Result<McpResponse> {
    McpResponse::decode(buf).map_err(MCPError::from)
}

// --- Basic Validation ---
// Placeholder for more sophisticated validation logic
pub fn validate_request(request: &McpRequest) -> Result<()> {
    if request.request_id.is_empty() {
        return Err(MCPError::MissingField("request_id".to_string()));
    }
    if request.requestor_identity.is_none() {
        return Err(MCPError::MissingField("requestor_identity".to_string()));
    }
    if request.requestor_identity.as_ref().map_or(true, |id| id.pseudonym_id.is_empty() || id.public_key.is_empty()) {
        return Err(MCPError::InvalidField("requestor_identity requires non-empty pseudonym_id and public_key".to_string()));
    }
     if request.purpose_dna.is_none() {
        return Err(MCPError::MissingField("purpose_dna".to_string()));
    }
    if request.permissions.is_empty() {
        return Err(MCPError::InvalidField("permissions list cannot be empty".to_string()));
    }
    if request.signature.is_none() {
         return Err(MCPError::MissingField("signature".to_string()));
    }
    // TODO: Add more checks (e.g., timestamp validity, purpose DNA content, signature verification)
    Ok(())
}

// --- Request Builder Helper --- (Simplified example)

pub struct McpRequestBuilder {
    request: McpRequest,
}

impl McpRequestBuilder {
    pub fn new(requestor_identity: RequestorIdentity, purpose_dna: PurposeDna, mcp_version: String) -> Self {
        Self {
            request: McpRequest {
                request_id: Uuid::new_v4().to_string(), // Generate a unique ID
                timestamp: Some(prost_timestamp_from_chrono(Utc::now())),
                requestor_identity: Some(requestor_identity),
                purpose_dna: Some(purpose_dna),
                permissions: vec![],
                request_expiry: None, // Optional
                signature: None, // Signature added separately
                mcp_version,
                related_request_id: String::new(), // Optional
            },
        }
    }

    pub fn add_permission(mut self, permission: PermissionSpecification) -> Self {
        self.request.permissions.push(permission);
        self
    }

    pub fn set_expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.request.request_expiry = Some(prost_timestamp_from_chrono(expiry));
        self
    }

    pub fn set_related_request_id(mut self, related_id: String) -> Self {
        self.request.related_request_id = related_id;
        self
    }

    // Consumes the builder and returns the request
    // Signing should happen *after* this, on the finalized, serialized request body (excluding the signature field itself).
    pub fn build(self) -> McpRequest {
        self.request
    }
}

// --- Utility Functions ---

pub fn prost_timestamp_from_chrono(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

pub fn chrono_from_prost_timestamp(ts: &Timestamp) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
}

// Helper function to convert serde_json::Value to prost_types::Value
fn serde_value_to_prost_value(value: SerdeValue) -> Result<ProstValue> {
    let kind = match value {
        SerdeValue::Null => ProstKind::NullValue(0), // Assuming 0 maps to NullValue::NULL_VALUE
        SerdeValue::Bool(b) => ProstKind::BoolValue(b),
        SerdeValue::Number(n) => {
            if let Some(f) = n.as_f64() {
                ProstKind::NumberValue(f)
            } else {
                return Err(MCPError::ConversionError("Unsupported number type in JSON".to_string()));
            }
        }
        SerdeValue::String(s) => ProstKind::StringValue(s),
        SerdeValue::Array(a) => {
            let values = a.into_iter()
                .map(serde_value_to_prost_value)
                .collect::<Result<Vec<ProstValue>>>()?;
            ProstKind::ListValue(ListValue { values })
        }
        SerdeValue::Object(o) => {
            let fields = o.into_iter()
                .map(|(k, v)| serde_value_to_prost_value(v).map(|pv| (k, pv)))
                .collect::<Result<HashMap<String, ProstValue>>>()?;
            ProstKind::StructValue(Struct { fields })
        }
    };
    Ok(ProstValue { kind: Some(kind) })
}

// Helper function to convert prost_types::Value to serde_json::Value
fn prost_value_to_serde_value(value: ProstValue) -> Result<SerdeValue> {
    match value.kind {
        Some(ProstKind::NullValue(_)) => Ok(SerdeValue::Null),
        Some(ProstKind::NumberValue(n)) => Ok(SerdeValue::from(n)),
        Some(ProstKind::StringValue(s)) => Ok(SerdeValue::String(s)),
        Some(ProstKind::BoolValue(b)) => Ok(SerdeValue::Bool(b)),
        Some(ProstKind::StructValue(s)) => {
            let map = s.fields.into_iter()
                .map(|(k, v)| prost_value_to_serde_value(v).map(|sv| (k, sv)))
                .collect::<Result<Map<String, SerdeValue>>>()?;
            Ok(SerdeValue::Object(map))
        }
        Some(ProstKind::ListValue(l)) => {
            let vec = l.values.into_iter()
                .map(prost_value_to_serde_value)
                .collect::<Result<Vec<SerdeValue>>>()?;
            Ok(SerdeValue::Array(vec))
        }
        None => Ok(SerdeValue::Null), // Treat None kind as Null
    }
}

// Helper to convert HashMap<String, SerdeValue> to Option<Struct>
pub fn hashmap_to_prost_struct(map: HashMap<String, SerdeValue>) -> Result<Option<Struct>> {
    if map.is_empty() {
        Ok(None)
    } else {
        let fields = map.into_iter()
            .map(|(k, v)| serde_value_to_prost_value(v).map(|pv| (k, pv)))
            .collect::<Result<HashMap<String, ProstValue>>>()?;
        Ok(Some(Struct { fields }))
    }
}

// Helper to convert Option<Struct> to HashMap<String, SerdeValue>
pub fn prost_struct_to_hashmap(p_struct: Option<&Struct>) -> Result<HashMap<String, SerdeValue>> {
    match p_struct {
        Some(s) => {
            s.fields.iter()
                .map(|(k, v)| prost_value_to_serde_value(v.clone()).map(|sv| (k.clone(), sv)))
                .collect::<Result<HashMap<String, SerdeValue>>>()
        }
        None => Ok(HashMap::new()),
    }
}

// --- Cryptographic Utilities (Placeholders) ---

// Placeholder structure for key pairs - replace with actual key management
pub struct KeyPair {
    pub public_key_bytes: Vec<u8>,
    // In a real implementation, the private key would be handled securely,
    // possibly stored separately or managed by a hardware module.
    // For this example, we might just hold it directly (NOT FOR PRODUCTION).
    signing_key: ring::signature::Ed25519KeyPair, // Example using Ed25519
}

impl KeyPair {
    // Generates a new key pair (for demonstration)
    pub fn new_random() -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| MCPError::CryptoError(e.to_string()))?;
        let signing_key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        let public_key_bytes = signing_key.public_key().as_ref().to_vec();
        Ok(KeyPair { public_key_bytes, signing_key })
    }

    // Creates a KeyPair from existing PKCS8 bytes (e.g., loaded from storage)
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self> {
         let signing_key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes)?;
         let public_key_bytes = signing_key.public_key().as_ref().to_vec();
         Ok(KeyPair { public_key_bytes, signing_key })
    }

    pub fn sign(&self, message: &[u8]) -> CryptoSignature {
        let signature_bytes = self.signing_key.sign(message);
        CryptoSignature {
            key_id: self.get_key_id(), // Simple key ID generation (e.g., hash of pub key)
            algorithm: "Ed25519".to_string(),
            signature: Bytes::copy_from_slice(signature_bytes.as_ref()),
        }
    }

    // Example key ID generation - replace with a proper method
    pub fn get_key_id(&self) -> String {
        // Using a simple SHA256 hash of the public key as an example ID
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.public_key_bytes);
        hex::encode(digest.as_ref()) // Add `hex` crate to Cargo.toml
    }

    pub fn get_public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }
}

// Verifies a signature against a message and public key
pub fn verify_signature(
    public_key_bytes: &[u8],
    signature: &CryptoSignature,
    message: &[u8],
) -> Result<()> {
    // Basic algorithm check (extend for more algorithms)
    if signature.algorithm != "Ed25519" {
        return Err(MCPError::SignatureError(format!("Unsupported signature algorithm: {}", signature.algorithm)));
    }

    let public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        public_key_bytes
    );

    public_key.verify(message, &signature.signature)
        .map_err(|e| MCPError::SignatureError(format!("Ring verification error: {}", e)))
}

// Function to prepare the message data for signing/verification
// Excludes the signature field itself.
fn prepare_request_for_signing(request: &McpRequest) -> Result<Vec<u8>> {
    let mut request_to_sign = request.clone();
    request_to_sign.signature = None; // Exclude signature field
    serialize_request(&request_to_sign)
}

fn prepare_response_for_signing(response: &McpResponse) -> Result<Vec<u8>> {
    let mut response_to_sign = response.clone();
    response_to_sign.signature = None; // Exclude signature field
    serialize_response(&response_to_sign)
}

// --- Signing and Verification Functions ---

pub fn sign_request(request: &mut McpRequest, key_pair: &KeyPair) -> Result<()> {
    let message_bytes = prepare_request_for_signing(request)?;
    request.signature = Some(key_pair.sign(&message_bytes));
    Ok(())
}

pub fn verify_request_signature(request: &McpRequest) -> Result<()> {
    let signature = request.signature.as_ref()
        .ok_or_else(|| MCPError::MissingField("signature".to_string()))?;
    let identity = request.requestor_identity.as_ref()
        .ok_or_else(|| MCPError::MissingField("requestor_identity".to_string()))?;

    // Optional: Verify key_id matches the public key if needed, e.g.:
    // let expected_key_id = calculate_key_id(&identity.public_key);
    // if signature.key_id != expected_key_id {
    //     return Err(MCPError::SignatureError("Key ID mismatch".to_string()));
    // }

    let message_bytes = prepare_request_for_signing(request)?;
    verify_signature(&identity.public_key, signature, &message_bytes)
}

// TODO: Implement sign_response and verify_response_signature similarly


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use serde_json::json;

    // Helper to create a basic valid request for testing
    fn create_test_request(key_pair: &KeyPair) -> McpRequest {
        let requestor_identity = RequestorIdentity {
            pseudonym_id: "requester-123".to_string(),
            public_key: Bytes::copy_from_slice(key_pair.get_public_key_bytes()),
            attestations: vec!["https://example.com/attestation/1".to_string()],
        };

        let purpose_dna = PurposeDna {
            purpose_id: "purpose-abc".to_string(),
            primary_purpose_category: "Analytics".to_string(),
            specific_purpose_description: "Collect usage data to improve service".to_string(),
            data_types_involved: vec!["user.action".to_string(), "device.info".to_string()],
            processing_description: "Aggregate metrics, no PII extraction".to_string(),
            storage_description: "Encrypted storage, retention 30 days".to_string(),
            intended_recipients: vec!["internal-analytics-team".to_string()],
            purpose_expiry_timestamp: Some(prost_timestamp_from_chrono(Utc::now() + chrono::Duration::days(30))),
            legal_context_url: "https://example.com/privacy".to_string(),
        };

        let mut constraints_map = HashMap::new();
        constraints_map.insert("max_frequency_per_hour".to_string(), json!(10));
        let constraints_struct = hashmap_to_prost_struct(constraints_map).unwrap().unwrap();

        let permission = PermissionSpecification {
            resource_identifier: "/api/v1/user/action".to_string(),
            requested_action: Action::Write as i32,
            constraints: constraints_struct,
        };

        let mut request = McpRequestBuilder::new(
                requestor_identity,
                purpose_dna,
                "1.0.0".to_string()
            )
            .add_permission(permission)
            .build();

        // Sign the request
        sign_request(&mut request, key_pair).expect("Signing failed");
        request
    }

    #[test]
    fn test_request_serialization_deserialization() {
        let key_pair = KeyPair::new_random().unwrap();
        let original_request = create_test_request(&key_pair);

        let serialized = serialize_request(&original_request).expect("Serialization failed");
        let deserialized_request = deserialize_request(&serialized).expect("Deserialization failed");

        assert_eq!(original_request, deserialized_request);
    }

    #[test]
    fn test_basic_validation_ok() {
        let key_pair = KeyPair::new_random().unwrap();
        let request = create_test_request(&key_pair);
        assert!(validate_request(&request).is_ok());
    }

     #[test]
    fn test_basic_validation_fails_missing_fields() {
        let key_pair = KeyPair::new_random().unwrap();
        let mut request = create_test_request(&key_pair);
        request.request_id = "".to_string(); // Make invalid
        assert!(validate_request(&request).is_err());

        // Reset and try another field
        request = create_test_request(&key_pair);
        request.signature = None;
        assert!(validate_request(&request).is_err());

        request = create_test_request(&key_pair);
        request.permissions = vec![];
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn test_signature_verification_ok() {
        let key_pair = KeyPair::new_random().unwrap();
        let request = create_test_request(&key_pair);
        assert!(verify_request_signature(&request).is_ok());
    }

    #[test]
    fn test_signature_verification_tampered_data() {
        let key_pair = KeyPair::new_random().unwrap();
        let mut request = create_test_request(&key_pair);

        // Tamper with data *after* signing
        request.mcp_version = "1.1.0".to_string();

        let verification_result = verify_request_signature(&request);
        assert!(verification_result.is_err());
        assert!(matches!(verification_result.unwrap_err(), MCPError::SignatureError(_)));
    }

    #[test]
    fn test_signature_verification_wrong_key() {
        let key_pair1 = KeyPair::new_random().unwrap();
        let key_pair2 = KeyPair::new_random().unwrap(); // Different key pair
        let request = create_test_request(&key_pair1);

        // Try to verify with key_pair2's public key
        let identity_with_wrong_key = RequestorIdentity {
             public_key: Bytes::copy_from_slice(key_pair2.get_public_key_bytes()),
             ..request.requestor_identity.clone().unwrap()
        };
        let mut request_with_wrong_key_in_identity = request.clone();
        request_with_wrong_key_in_identity.requestor_identity = Some(identity_with_wrong_key);

        // Note: The signature was created with key_pair1, but the identity field now contains key_pair2's public key.
        // The verification should use the public key *from the identity field* to check the signature.
        let verification_result = verify_request_signature(&request_with_wrong_key_in_identity);

        assert!(verification_result.is_err());
        assert!(matches!(verification_result.unwrap_err(), MCPError::SignatureError(_)));
    }

     #[test]
     fn test_struct_conversion() {
        let mut map = HashMap::new();
        map.insert("string_val".to_string(), json!("hello"));
        map.insert("number_val".to_string(), json!(123));
        map.insert("bool_val".to_string(), json!(true));
        map.insert("nested_obj".to_string(), json!({ "a": 1 }));
        map.insert("array_val".to_string(), json!([1, 2, 3]));

        let prost_struct = hashmap_to_prost_struct(map.clone()).unwrap().unwrap();
        let converted_map = prost_struct_to_hashmap(Some(&prost_struct)).unwrap();

        assert_eq!(map.len(), converted_map.len());
        for (k, v) in map.iter() {
            assert_eq!(v, converted_map.get(k).unwrap());
        }
     }
} 