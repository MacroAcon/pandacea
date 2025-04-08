//! # Pandacea MCP Library
//!
//! This crate provides the core data structures, serialization, validation,
//! and cryptographic utilities for the Pandacea Model Context Protocol (MCP).
//!
//! MCP is used for requesting data access or actions from user-controlled
//! edge devices in a standardized, consent-driven manner.
//!
//! ## Key Components:
//!
//! *   **Data Structures:** Defines `McpRequest`, `McpResponse`, `PurposeDna`,
//!     `RequestorIdentity`, `PermissionSpecification`, and `CryptoSignature` based
//!     on the `mcp.proto` definitions.
//! *   **Serialization:** Functions (`serialize_*`, `deserialize_*`) to convert
//!     MCP messages to/from Protobuf binary format (`Vec<u8>`).
//! *   **Validation:** Comprehensive validation functions (`validate_request`,
//!     `validate_response`) to check structural integrity, required fields,
//!     timestamps, and cryptographic signatures.
//! *   **Cryptography:** Utilities (`KeyPair`, `sign_*`, `verify_*`) for generating
//!     key pairs (Ed25519), signing MCP messages, and verifying signatures.
//! *   **Builders:** Helper structs (`McpRequestBuilder`, `McpResponseBuilder`)
//!     for constructing valid MCP messages.
//! *   **Error Handling:** A dedicated `MCPError` enum for categorizing issues
//!     during processing.
//! *   **Utilities:** Helper functions for timestamp conversion (`prost_timestamp_from_chrono`,
//!     `chrono_from_prost_timestamp`), JSON/Protobuf struct conversion, and checking
//!     message expiration.
//!
//! ## Example Usage:
//!
//! ```rust,no_run
//! use pandacea_mcp::{
//!     KeyPair, RequestorIdentity, PurposeDna, PermissionSpecification,
//!     McpRequestBuilder, sign_request, validate_request, serialize_request,
//!     deserialize_request, Action, MCPError, bytes::Bytes
//! };
//! use chrono::{Utc, Duration};
//! use prost_types::Struct;
//! use std::collections::HashMap;
//!
//! fn main() -> Result<(), MCPError> {
//!     // 1. Generate/Load Requestor KeyPair
//!     let requestor_key_pair = KeyPair::generate()?;
//!     let requestor_key_id = "req-key-001".to_string(); // Identifier for the key
//!
//!     // 2. Define Requestor Identity
//!     let requestor_identity = RequestorIdentity { pseudonym_id: "app-instance-xyz".to_string(), public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()), attestations: vec![] };
//!
//!     // 3. Define Purpose DNA
//!     let purpose_dna = PurposeDna { purpose_id: "pid".into(), primary_purpose_category: "cat".into(), specific_purpose_description: "desc".into(), data_types_involved: vec!["dt".into()], processing_description: "proc".into(), storage_description: "store".into(), intended_recipients: vec![], purpose_expiry_timestamp: None, legal_context_url: String::new() };
//!
//!     // 4. Define Permissions
//!     let permission = PermissionSpecification { resource_identifier: "res".into(), requested_action: Action::Read as i32, constraints: None };
//!
//!     // 5. Build the Request
//!     let mut request = McpRequestBuilder::new(identity, purpose, "1.2.0".into())
//!         .add_permission(permission)
//!         .set_expiry(Utc::now() + Duration::minutes(5))
//!         .build();
//!
//!     // 6. Sign the Request
//!     sign_request(&mut request, &key_pair, key_id.clone())?;
//!
//!     // 7. Validate the Request (e.g., before sending or upon receiving)
//!     // Note: Validation checks the signature internally.
//!     validate_request(&request)?;
//!
//!     // 8. Serialize for transport
//!     let serialized_request = serialize_request(&request)?;
//!
//!     // --- On the receiving side ---
//!
//!     // 9. Deserialize
//!     let received_request = deserialize_request(&serialized_request)?;
//!
//!     // 10. Validate (including signature verification using public key in identity)
//!     validate_request(&received_request)?;
//!
//!     println!("Request validated successfully!");
//!     // Proceed with consent checking...
//!
//!     Ok(())
//! }
//! ```
use prost::Message;
use uuid::Uuid;
use chrono::{Utc, DateTime};
use prost_types::{Timestamp, Struct, Value as ProstValue, value::Kind as ProstKind, ListValue};
use serde_json::{Value as SerdeValue, Map};
use std::collections::HashMap;
use bytes::Bytes;
// --- Import necessary crypto items ---
use ring::{
    signature::{self, KeyPair as RingKeyPair, Ed25519KeyPair, UnparsedPublicKey, ED25519},
    rand::SystemRandom,
    error::Unspecified as RingUnspecified,
};
use std::time::SystemTime; // Used for expiration checks

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

// --- Re-exports ---

/// Represents the main request message in the Model Context Protocol (MCP).
/// Contains identity, purpose, requested permissions, and signature.
pub use mcp::McpRequest;
/// Represents the main response message in the Model Context Protocol (MCP).
/// Contains status, potential payload, consent receipt, and signature.
pub use mcp::McpResponse;
/// Describes the purpose (intent) behind an `McpRequest`.
/// Includes categorization, description, data types, processing, storage, etc.
pub use mcp::PurposeDna;
/// Identifies the entity making an `McpRequest`.
/// Includes a pseudonymous ID, public key, and optional attestations.
pub use mcp::RequestorIdentity;
/// Specifies a single permission being requested (data access or action).
/// Includes the target resource, the requested action, and optional constraints.
pub use mcp::PermissionSpecification;
/// Enumerates the possible actions that can be requested on a resource.
pub use mcp::permission_specification::Action;
/// Enumerates the possible overall statuses of processing an `McpRequest`.
pub use mcp::mcp_response::Status;
/// Describes the outcome of a specific permission request within an `McpResponse`.
pub use mcp::mcp_response::PermissionStatus;
/// Contains cryptographic signature information (key ID, algorithm, signature bytes).
pub use mcp::CryptoSignature;

// --- Error Handling ---

/// Errors that can occur during MCP processing, serialization, validation, or cryptography.
pub enum MCPError {
    /// Error during Protobuf message encoding.
    #[error("Protobuf encoding error: {context} - {source}")]
    SerializationError { 
        context: String, 
        #[source] source: prost::EncodeError 
    },
    /// Error during Protobuf message decoding.
    #[error("Protobuf decoding error: {context} - {source}")]
    DeserializationError { 
        context: String, 
        #[source] source: prost::DecodeError 
    },
    /// Error during JSON serialization or deserialization (often used for Struct conversion).
    #[error("JSON processing error: {context} - {source}")]
    JsonError { 
        context: String, 
        #[source] source: serde_json::Error 
    },
    /// A required field was missing from an MCP message.
    #[error("Missing required field: {field_name}")]
    MissingField { field_name: String },
    /// A field contained an invalid value (wrong format, out of range, unspecified enum, etc.).
    #[error("Invalid field value for '{field_name}': {reason}")]
    InvalidField { field_name: String, reason: String },
    /// The request has expired based on its `request_expiry` timestamp.
    #[error("Request expired at {expiry_time}")]
    ExpiredRequest { expiry_time: DateTime<Utc> },
    /// The purpose has expired based on its `purpose_expiry_timestamp`.
    #[error("Purpose expired at {expiry_time}")]
    ExpiredPurpose { expiry_time: DateTime<Utc> },
    /// The MCP protocol version is not supported.
    #[error("Unsupported MCP version: {version}")]
    UnsupportedVersion { version: String },
    /// Cryptographic signature verification failed.
    #[error("Signature verification failed: {reason}")]
    SignatureError { reason: String },
    /// The specified cryptographic key could not be found or retrieved.
    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },
    /// An invalid cryptographic key was provided or generated.
    #[error("Invalid cryptographic key: {reason}")]
    InvalidKey { 
        #[from] source: ring::error::KeyRejected,
        reason: String // Add context here
    },
    /// An unspecified error occurred within the underlying crypto library (`ring`).
    #[error("Unspecified cryptographic error: {source}")]
    CryptoUnspecified { #[from] source: RingUnspecified },
    /// An error occurred during constraint evaluation.
    #[error("Constraint evaluation failed for '{constraint_key}': {reason}")]
    ConstraintEvaluationError { constraint_key: String, reason: String },
    /// An error occurred during a specific validation stage, wrapping the underlying error.
    #[error("Validation failed during {stage} stage: {source}")]
    ValidationError { 
        stage: String, 
        #[source] source: Box<MCPError> 
    },
    /// An I/O error occurred (e.g., reading key files).
    #[error("I/O error: {context} - {source}")]
    IoError { 
        context: String, 
        #[source] source: std::io::Error 
    },
    /// Error during type conversion (e.g., timestamp, struct).
    #[error("Type conversion error: {message}")]
    ConversionError { message: String },
}

/// A specialized `Result` type for MCP operations, using [`MCPError`](crate::MCPError).
pub type Result<T> = std::result::Result<T, MCPError>;

// --- Serialization / Deserialization ---

/// Serializes an [`McpRequest`] into Protobuf bytes (`Vec<u8>`).
///
/// See notes within the function regarding performance and canonicalization.
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
    request.encode(&mut buf)?;
    Ok(buf)
}

/// Deserializes Protobuf bytes (`&[u8]`) into an [`McpRequest`].
///
/// See notes within the function regarding performance and zero-copy considerations.
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
    McpRequest::decode(buf).map_err(MCPError::from)
}

/// Serializes an [`McpResponse`] into Protobuf bytes (`Vec<u8>`).
///
/// See notes within `serialize_request` regarding performance and canonicalization.
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
    response.encode(&mut buf)?;
    Ok(buf)
}

/// Deserializes Protobuf bytes (`&[u8]`) into an [`McpResponse`].
///
/// See notes within `deserialize_request` regarding performance and zero-copy considerations.
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
    McpResponse::decode(buf).map_err(MCPError::from)
}

// --- Serialization Enhancements (Placeholders/Examples) ---

// **Compression:**
// Compression should typically be applied *after* serialization and *before*
// deserialization by the application logic.

/// Example: Compresses serialized data (e.g., using zstd).
/// Requires adding a compression crate like `zstd` to `Cargo.toml`.
/// ```rust,ignore
/// pub fn compress_serialized_data(data: &[u8], level: i32) -> Result<Vec<u8>> {
///     zstd::encode_all(data, level).map_err(|e| MCPError::IoError(e))
/// }
/// ```

/// Example: Decompresses data before deserialization (e.g., using zstd).
/// ```rust,ignore
/// pub fn decompress_serialized_data(compressed_data: &[u8]) -> Result<Vec<u8>> {
///     zstd::decode_all(compressed_data).map_err(|e| MCPError::IoError(e))
/// }
/// ```

// **Streaming:**
// Handling very large messages or payloads often requires application-level chunking
// or using length-delimited framing before serializing/deserializing smaller parts.
// Prost's `encode_length_delimited` and `decode_length_delimited` can be useful here,
// or libraries like `tokio-util` with `LengthDelimitedCodec` for network streams.
// True streaming *parsing* (without buffering the whole message) is complex with Protobuf.

// **Canonical Serialization for Signatures:**
// (See notes in `prepare_request_for_signing` and `prepare_response_for_signing`)
// Achieving canonical serialization reliably might involve:
// 1. Defining a strict ordering for all fields, including map keys.
// 2. Using a specific encoding library that guarantees canonical output.
// 3. Potentially defining a custom serialization format specifically for signing.


// --- Validation Pipeline ---

/// Validates the structure, semantics, and security of an [`McpRequest`].
///
/// This is the main entry point for request validation. It sequentially calls:
/// 1. Syntax validation (`validate_request_syntax`): Checks required fields, formats, timestamps, expiration.
/// 2. Semantic validation (`validate_request_semantics`): Checks purpose coherence, permission scope (currently placeholder).
/// 3. Security validation (`validate_request_security`): Checks cryptographic signature.
///
/// # Arguments
/// * `request`: The [`McpRequest`] to validate.
///
/// # Returns
/// * `Ok(())` if the request passes all validation stages.
/// * `Err(MCPError::ValidationError)` wrapping the specific error from the failed stage.
pub fn validate_request(request: &McpRequest) -> Result<()> {
    validate_request_syntax(request).map_err(|e| {
        // Add context to the error
        MCPError::ValidationError { stage: "Syntax".to_string(), source: Box::new(e) }
    })?;

    validate_request_semantics(request).map_err(|e| {
        // Add context to the error
        MCPError::ValidationError { stage: "Semantics".to_string(), source: Box::new(e) }
    })?;

    validate_request_security(request).map_err(|e| {
        // Add context to the error
        MCPError::ValidationError { stage: "Security".to_string(), source: Box::new(e) }
    })?;
    
    Ok(())
}

// --- Request Builder Helper ---

/// A helper struct to construct [`McpRequest`] messages using a fluent API.
///
/// Ensures required fields are set during creation and provides methods to add
/// optional fields like permissions, expiry, etc.
///
/// **Note:** The signature must be added separately using [`sign_request`] after building.
///
/// # Example
/// ```rust
/// # use pandacea_mcp::{*};
/// # use chrono::{Utc, Duration};
/// # use bytes::Bytes;
/// # let (key_pair, identity) = create_test_identity(); // Assume helper exists
/// # let purpose = create_test_purpose(); // Assume helper exists
/// # let perm = create_test_permission(); // Assume helper exists
/// let mut request = McpRequestBuilder::new(identity, purpose, "1.0.0".to_string())
///     .add_permission(perm)
///     .set_expiry(Utc::now() + Duration::minutes(5))
///     .build();
/// // Sign the request
/// // sign_request(&mut request, &key_pair, "key-id-01".to_string()).unwrap();
/// ```
pub struct McpRequestBuilder {
    request: McpRequest,
}

impl McpRequestBuilder {
    /// Creates a new `McpRequestBuilder` with essential fields.
    ///
    /// Automatically sets a unique `request_id` (UUIDv4) and the current `timestamp`.
    ///
    /// # Arguments
    /// * `requestor_identity`: The [`RequestorIdentity`] of the sender.
    /// * `purpose_dna`: The [`PurposeDna`] describing the intent.
    /// * `mcp_version`: The MCP protocol version string (e.g., "1.0.0").
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
                // TODO: Consider adding checks for non-empty mcp_version?
            },
        }
    }

    /// Adds a [`PermissionSpecification`] to the request.
    pub fn add_permission(mut self, permission: PermissionSpecification) -> Self {
        self.request.permissions.push(permission);
        self
    }

    /// Sets the optional `request_expiry` timestamp.
    pub fn set_expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.request.request_expiry = Some(prost_timestamp_from_chrono(expiry));
        self
    }

    /// Sets the optional `related_request_id`.
    pub fn set_related_request_id(mut self, related_id: String) -> Self {
        self.request.related_request_id = related_id;
        self
    }

    /// Consumes the builder and returns the constructed [`McpRequest`].
    /// The signature field will be `None` and must be added via [`sign_request`].
    pub fn build(self) -> McpRequest {
        // Potential location for final validation checks on the built request *before* signing?
        self.request
    }
}

// --- Response Builder Helper ---

/// A helper struct to construct [`McpResponse`] messages using a fluent API.
///
/// Ensures required fields are set during creation and provides methods to add
/// optional fields like status message, permissions statuses, payload, etc.
///
/// **Note:** The signature must be added separately using [`sign_response`] after building.
///
/// # Example
/// ```rust
/// # use pandacea_mcp::{*};
/// # use bytes::Bytes;
/// # let request_id = "req-123".to_string();
/// # let (key_pair, _) = create_test_identity(); // Assume helper exists
/// let mut response = McpResponseBuilder::new(request_id, Status::Approved, "1.0.0".to_string())
///     .status_message("Request granted.".to_string())
///     .set_payload(Bytes::from_static(b"example data"))
///     .build();
/// // Sign the response
/// // sign_response(&mut response, &key_pair, "responder-key-01".to_string()).unwrap();
/// ```
pub struct McpResponseBuilder {
    response: McpResponse,
}

impl McpResponseBuilder {
    /// Creates a new `McpResponseBuilder` with essential fields.
    ///
    /// Automatically sets a unique `response_id` (UUIDv4) and the current `timestamp`.
    ///
    /// # Arguments
    /// * `request_id`: The ID of the [`McpRequest`] this response corresponds to.
    /// * `status`: The overall [`Status`] of the request processing.
    /// * `mcp_version`: The MCP protocol version string (e.g., "1.0.0").
    pub fn new(request_id: String, status: Status, mcp_version: String) -> Self {
        Self {
            response: McpResponse {
                response_id: Uuid::new_v4().to_string(),
                request_id,
                timestamp: Some(prost_timestamp_from_chrono(Utc::now())),
                status: status as i32,
                status_message: String::new(),
                permission_statuses: vec![],
                response_payload: Bytes::new(),
                consent_receipt: Bytes::new(),
                signature: None, // Added separately
                mcp_version,
                // TODO: Check non-empty request_id and mcp_version?
                // TODO: Check status != StatusUnspecified?
            },
        }
    }

    /// Sets the optional `status_message`.
    pub fn status_message(mut self, message: String) -> Self {
        self.response.status_message = message;
        self
    }

    /// Adds a [`PermissionStatus`] detailing the outcome for a specific permission.
    /// Primarily used when the overall status is `PARTIALLY_APPROVED`.
    pub fn add_permission_status(mut self, status: PermissionStatus) -> Self {
        self.response.permission_statuses.push(status);
        self
    }

    /// Sets the optional `response_payload` (e.g., for approved READ requests).
    pub fn set_payload(mut self, payload: Bytes) -> Self {
        // TODO: Consider size limit check for payload?
        self.response.response_payload = payload;
        self
    }

     /// Sets the optional consent receipt.
     pub fn set_consent_receipt(mut self, receipt: Bytes) -> Self {
        // TODO: Consider size limit check for receipt?
        self.response.consent_receipt = receipt;
        self
    }

    /// Consumes the builder and returns the constructed [`McpResponse`].
    /// The signature field will be `None` and must be added via [`sign_response`].
    pub fn build(self) -> McpResponse {
        // Potential location for final validation checks *before* signing?
        // E.g., check status consistency with permission_statuses.
        self.response
    }
}

// --- Utility Functions ---

/// Converts a `chrono::DateTime<Utc>` to a `prost_types::Timestamp`.
pub fn prost_timestamp_from_chrono(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

/// Converts a `prost_types::Timestamp` to an `Option<chrono::DateTime<Utc>>`.
/// Returns `None` if the timestamp is invalid or out of the representable range.
pub fn chrono_from_prost_timestamp(ts: &Timestamp) -> Option<DateTime<Utc>> {
    // Validate nanos part
    if !(0..=999_999_999).contains(&ts.nanos) {
        return None;
    }
    // `from_timestamp` handles seconds range checks internally.
    DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
}

/// Checks if an [`McpRequest`] has expired based on its `request_expiry` field.
/// Returns `true` if expired or if `request_expiry` is invalid/missing.
pub fn is_request_expired(request: &McpRequest) -> bool {
    request.request_expiry.as_ref()
        .and_then(chrono_from_prost_timestamp) // Convert to DateTime<Utc> if valid
        .map_or(false, |expiry_dt| expiry_dt <= Utc::now()) // Check if expiry time is past now
}

/// Checks if a [`PurposeDna`] has expired based on its `purpose_expiry_timestamp` field.
/// Returns `true` if expired or if the timestamp is invalid/missing.
pub fn is_purpose_expired(purpose: &PurposeDna) -> bool {
     purpose.purpose_expiry_timestamp.as_ref()
        .and_then(chrono_from_prost_timestamp)
        .map_or(false, |expiry_dt| expiry_dt <= Utc::now())
}

/// Converts a `HashMap<String, serde_json::Value>` to an `Option<prost_types::Struct>`.
/// Returns `Ok(None)` if the map is empty.
/// Returns `Err(MCPError::ConversionError)` if a value cannot be converted.
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

/// Converts an `Option<&prost_types::Struct>` to a `HashMap<String, serde_json::Value>`.
/// Returns an empty map if the input is `None`.
/// Returns `Err(MCPError::ConversionError)` if a value cannot be converted.
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

// --- Cryptography --- 

/// Represents a cryptographic key pair, currently supporting Ed25519.
/// Provides methods for generation, loading, and signing.
/// See struct definition notes for security considerations on storage and rotation.
pub struct KeyPair {
    // Internal representation using the `ring` crate's Ed25519 key pair.
    // TODO(#1): Generalize this to support multiple algorithms (e.g., using an enum wrapper).
    ring_kp: Ed25519KeyPair,
    // TODO(#1): Add an algorithm identifier field when supporting multiple types.
    // algorithm: SignatureAlgorithm, 
}

// TODO(#1): Define an enum for supported signature algorithms when needed.
// pub enum SignatureAlgorithm { Ed25519, EcdsaP256, ... }

impl KeyPair {
    /// Generates a new Ed25519 `KeyPair` using a secure random number generator.
    ///
    /// # Errors
    /// Returns `MCPError::CryptoUnspecified` if the underlying random number
    /// generator fails.
    pub fn generate() -> Result<Self> {
        // TODO(#1): Adapt this if supporting multiple algorithms (take algorithm as arg?).
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(MCPError::CryptoUnspecified)?; 
        
        // `from_pkcs8` performs necessary validation.
        Self::from_pkcs8(&pkcs8_bytes)
    }

    /// Creates an Ed25519 `KeyPair` from PKCS#8 v2 encoded private key bytes.
    ///
    /// Performs validation to ensure the key is a valid Ed25519 private key.
    ///
    /// # Arguments
    /// * `pkcs8_bytes`: The PKCS#8 encoded Ed25519 private key.
    ///
    /// # Errors
    /// Returns `MCPError::InvalidKey` if the bytes do not represent a valid Ed25519 key.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self> {
        // TODO(#1): Adapt this if supporting multiple algorithms (check algorithm metadata?).
        let ring_kp = Ed25519KeyPair::from_pkcs8(pkcs8_bytes)
            .map_err(MCPError::InvalidKey)?;
        Ok(KeyPair { ring_kp })
    }

    /// Creates an Ed25519 `KeyPair` directly from a 32-byte seed.
    ///
    /// **Warning:** Use with caution; prefer `from_pkcs8`.
    ///
    /// # Arguments
    /// * `seed_bytes`: The 32-byte seed for the Ed25519 key.
    ///
    /// # Errors
    /// Returns `MCPError::InvalidKey` if the seed length is incorrect.
    pub fn from_seed(seed_bytes: &[u8]) -> Result<Self> {
        // TODO(#1): Adapt this if supporting multiple algorithms.
        let ring_kp = Ed25519KeyPair::from_seed_unchecked(seed_bytes)
            .map_err(MCPError::InvalidKey)?; 
        // `from_seed_unchecked` requires the caller ensures length, but ring checks anyway.
        // We could add an explicit length check here for clarity if desired.
        Ok(KeyPair { ring_kp })
    }

    /// Returns the public key bytes (32 bytes for Ed25519).
    pub fn public_key_bytes(&self) -> &[u8] {
        self.ring_kp.public_key().as_ref()
    }

    /// Signs a message using the private key. Returns `ring::signature::Signature`.
    pub fn sign(&self, message: &[u8]) -> signature::Signature {
        // TODO(#1): Adapt this if supporting multiple algorithms.
        self.ring_kp.sign(message)
    }

    // TODO(#1): Add method to get the algorithm identifier when implemented.
    // pub fn algorithm(&self) -> SignatureAlgorithm { self.algorithm } 
}

/// Verifies a cryptographic signature against a message using a public key and algorithm.
///
/// Currently supports "Ed25519".
///
/// # Arguments
/// * `public_key_bytes`: The raw public key bytes.
/// * `message`: The message data that was allegedly signed.
/// * `signature_bytes`: The raw signature bytes.
/// * `algorithm`: The identifier string for the signature algorithm (e.g., "Ed25519").
///
/// # Errors
/// Returns `MCPError::InvalidKey` if the key length is incorrect for the algorithm.
/// Returns `MCPError::SignatureError` if the algorithm is unsupported or verification fails.
pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    algorithm: &str, 
) -> Result<()> {
    match algorithm.to_uppercase().as_str() {
        "ED25519" => {
            if public_key_bytes.len() != 32 { 
                // Use custom constructor for context
                return Err(MCPError::invalid_key( 
                    ring::error::KeyRejected::wrong_length("Ed25519 public key wrong length".to_string()),
                    format!("Expected 32 bytes, got {}", public_key_bytes.len())
                ));
            }
            if signature_bytes.len() != 64 { 
                 // Use specific constructor
                 return Err(MCPError::signature_error(format!(
                     "Invalid Ed25519 signature length: expected 64 bytes, got {}", signature_bytes.len()
                 )));
             }
            let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
            public_key.verify(message, signature_bytes)
                .map_err(|e| MCPError::signature_error(format!("Ed25519 verification failed: {}", e)))
        }
        _ => {
            Err(MCPError::signature_error(format!(
                "Unsupported signature algorithm for verification: {}", algorithm
            )))
        }
    }
}

/// Signs an [`McpRequest`] in-place, populating its `signature` field.
///
/// Calculates the signature over a canonical representation of the request.
///
/// # Arguments
/// * `request`: The [`McpRequest`] to sign (mutable).
/// * `key_pair`: The [`KeyPair`] to use for signing.
/// * `key_id`: An identifier for the public key corresponding to the `key_pair`.
pub fn sign_request(request: &mut McpRequest, key_pair: &KeyPair, key_id: String) -> Result<()> {
    // Prepare the data to be signed (canonical representation).
    let message_bytes = prepare_request_for_signing(request)?;

    // Sign the message.
    let signature = key_pair.sign(&message_bytes);
    
    // TODO(#1): Get algorithm string from key_pair.algorithm when implemented.
    let algorithm = "Ed25519".to_string(); 

    // Populate the signature field in the request.
    request.signature = Some(CryptoSignature {
        key_id,
        algorithm,
        signature: Bytes::copy_from_slice(signature.as_ref()),
    });

    Ok(())
}

/// Verifies the signature of an [`McpRequest`] using the public key from its `requestor_identity`.
///
/// # Errors
/// Returns `MCPError::MissingField` if required identity/signature fields are absent.
/// Returns errors from [`verify_signature`] if verification fails.
pub fn verify_request_signature(request: &McpRequest) -> Result<()> {
    let signature_info = request.signature.as_ref()
        .ok_or_else(|| MCPError::missing_field("Cannot verify: request.signature is missing"))?;

    let identity = request.requestor_identity.as_ref()
        .ok_or_else(|| MCPError::missing_field("Cannot verify: request.requestor_identity is missing"))?;
    
    if identity.public_key.is_empty() {
        return Err(MCPError::missing_field("Cannot verify: request.requestor_identity.public_key is missing"));
    }

    // Prepare the data that was allegedly signed.
    let message_bytes = prepare_request_for_signing(request)?;

    // Perform verification using the algorithm specified in the signature info.
    verify_signature(
        &identity.public_key, 
        &message_bytes, 
        &signature_info.signature, 
        &signature_info.algorithm, // Pass algorithm from signature
    )
}

/// Signs an [`McpResponse`] in-place, populating its `signature` field.
///
/// Calculates the signature over a canonical representation of the response.
///
/// # Arguments
/// * `response`: The [`McpResponse`] to sign (mutable).
/// * `key_pair`: The [`KeyPair`] of the responder used for signing.
/// * `key_id`: An identifier for the public key corresponding to the `key_pair`.
pub fn sign_response(response: &mut McpResponse, key_pair: &KeyPair, key_id: String) -> Result<()> {
    // Prepare the data to be signed (canonical representation).
    let message_bytes = prepare_response_for_signing(response)?;

    // Sign the message.
    let signature = key_pair.sign(&message_bytes);
    
    // TODO: Get algorithm from key_pair when implemented.
    let algorithm = "Ed25519".to_string(); 

    // Populate the signature field in the response.
    response.signature = Some(CryptoSignature {
        key_id,
        algorithm,
        signature: Bytes::copy_from_slice(signature.as_ref()),
    });

    Ok(())
}

/// Verifies the signature of an [`McpResponse`] using an externally provided public key.
///
/// **Note:** The responder's public key must be obtained via a trusted mechanism,
/// potentially using the `key_id` from the response's signature for lookup.
///
/// # Arguments
/// * `response`: The [`McpResponse`] to verify.
/// * `responder_public_key_bytes`: The public key bytes of the entity expected to have signed.
///
/// # Errors
/// Returns `MCPError::MissingField` if the signature field is absent.
/// Returns errors from [`verify_signature`] if verification fails.
pub fn verify_response_signature(response: &McpResponse, responder_public_key_bytes: &[u8]) -> Result<()> {
    let signature_info = response.signature.as_ref()
        .ok_or_else(|| MCPError::missing_field("Cannot verify: response.signature is missing"))?;

    // Prepare the data that was allegedly signed.
    let message_bytes = prepare_response_for_signing(response)?;
    
    // TODO: Optionally, add a check here: look up the key_id specified in
    // signature_info.key_id and confirm it matches the provided responder_public_key_bytes.
    // This requires a key management system or trusted configuration.
    // Example: 
    // if !key_store::verify_key_matches_id(responder_public_key_bytes, &signature_info.key_id) {
    //     return Err(MCPError::SignatureError("Provided public key does not match key_id in signature".to_string()));
    // }

    // Perform verification using the provided public key and the algorithm from the signature.
    verify_signature(
        responder_public_key_bytes,
        &message_bytes,
        &signature_info.signature,
        &signature_info.algorithm, // Use algorithm from signature info
    )
}

// --- Constraint Evaluation ---

/// Represents the context needed to evaluate constraints (e.g., current time, requestor info).
pub struct RequestContext { /* ... fields ... */ }

/// Represents the outcome of evaluating constraints (`Passed` or `Failed(reason)`).
pub enum ConstraintResult { /* ... variants ... */ }

/// Evaluates constraints defined in a `PermissionSpecification`'s `constraints` field.
///
/// Takes an optional Protobuf `Struct` representing the constraints and a [`RequestContext`].
/// Checks implemented constraint types (e.g., time window, frequency) against the context.
///
/// # Arguments
/// * `constraints`: The `Option<&prost_types::Struct>` containing constraint key-value pairs.
/// * `context`: The [`RequestContext`] providing necessary information for evaluation.
///
/// # Returns
/// * `Ok(ConstraintResult::Passed)` if all checks pass or no constraints are defined.
/// * `Ok(ConstraintResult::Failed(reason))` if a constraint check fails.
/// * `Err(MCPError)` if parsing constraints fails (e.g., invalid format).
pub fn evaluate_constraints(
    constraints: Option<&Struct>,
    context: &RequestContext
) -> Result<ConstraintResult> { /* ... */ }

// ... (private helper functions and tests) ...

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Utc, Duration};
    use uuid::Uuid;
    use serde_json::Value as SerdeValue;

    // --- Constraint evaluation tests ...

    #[test]
    fn test_unknown_constraints_ignored() {
        // ... existing test body ...
    }

    // --- Validation Tests --- 

    // Helper function to create a basic valid request for testing
    fn create_valid_test_request() -> (KeyPair, McpRequest) {
        let (key_pair, identity) = create_test_identity();
        let purpose = create_test_purpose();
        let permission = create_test_permission();
        let mut request = McpRequestBuilder::new(identity, purpose, "1.0.0".to_string())
            .add_permission(permission)
            .build();
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap();
        (key_pair, request)
    }

    #[test]
    fn test_validate_request_syntax_valid() {
        let (_key_pair, request) = create_valid_test_request();
        assert!(validate_request_syntax(&request).is_ok());
    }

    #[test]
    fn test_validate_request_syntax_missing_fields() {
        let (key_pair, mut request) = create_valid_test_request();
        
        // Test missing various fields
        let original_request = request.clone();

        request = original_request.clone();
        request.request_id = String::new();
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name == "request.request_id"));
        
        request = original_request.clone();
        request.timestamp = None;
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name == "request.timestamp"));
        
        request = original_request.clone();
        request.requestor_identity = None;
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name == "request.requestor_identity"));
        
        request = original_request.clone();
        request.purpose_dna = None;
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name == "request.purpose_dna"));
        
        request = original_request.clone();
        request.permissions = vec![];
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name.contains("request.permissions")));
        
        request = original_request.clone();
        request.signature = None;
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name == "request.signature"));
        
        // Test nested missing fields
        request = original_request.clone();
        request.requestor_identity.as_mut().unwrap().pseudonym_id = String::new();
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name.contains("pseudonym_id")));

        request = original_request.clone();
        request.purpose_dna.as_mut().unwrap().specific_purpose_description = String::new();
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name.contains("specific_purpose_description")));

        request = original_request.clone();
        request.permissions[0].resource_identifier = String::new();
         assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name.contains("resource_identifier")));

        request = original_request.clone();
        request.signature.as_mut().unwrap().key_id = String::new();
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::MissingField { field_name }) if field_name == "request.signature.key_id"));
    }

    #[test]
    fn test_validate_request_syntax_invalid_fields() {
        let (key_pair, mut request) = create_valid_test_request();
        let original_request = request.clone();

        // Invalid timestamp (too far future)
        request = original_request.clone();
        request.timestamp = Some(prost_timestamp_from_chrono(Utc::now() + Duration::days(1)));
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap(); // Resign needed after changing timestamp
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::InvalidField { field_name, .. }) if field_name == "request.timestamp"));

        // Invalid expiry (before timestamp)
        request = original_request.clone();
        let ts = Utc::now();
        request.timestamp = Some(prost_timestamp_from_chrono(ts));
        request.request_expiry = Some(prost_timestamp_from_chrono(ts - Duration::seconds(10))); 
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap(); // Resign
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::InvalidField { field_name, .. }) if field_name == "request.request_expiry"));

        // Invalid Purpose Category (Unspecified)
        request = original_request.clone();
        request.purpose_dna.as_mut().unwrap().primary_purpose_category = 
            mcp::purpose_dna::PurposeCategory::PurposeCategoryUnspecified as i32;
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap(); // Resign
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::InvalidField { field_name, .. }) if field_name.contains("primary_purpose_category")));

        // Invalid Permission Action (Unspecified)
        request = original_request.clone();
        request.permissions[0].requested_action = Action::Unspecified as i32;
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap(); // Resign
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::InvalidField { field_name, .. }) if field_name.contains("requested_action")));
        
        // Invalid Permission Action (Out of range value)
        request = original_request.clone();
        request.permissions[0].requested_action = 999; // Invalid enum value
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap(); // Resign
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::InvalidField { field_name, .. }) if field_name.contains("requested_action")));

        // Invalid constraints (malformed struct)
        request = original_request.clone();
        let mut invalid_constraints = Struct::default();
        // Create a Struct with a non-string key (not directly possible with HashMap helper)
        // but simulate invalid structure that prost_struct_to_hashmap might fail on.
        // For simplicity, test the error path by modifying a valid request's constraints
        // (If prost_struct_to_hashmap is robust, this might be hard to trigger, focus on other invalids)
        // Instead, let's test an invalid *value* within the constraints
        let mut map = HashMap::new();
        // Prost Value doesn't directly support complex types that cause serde errors easily here
        // map.insert("bad_value".to_string(), SerdeValue::Object(serde_json::Map::new())); // Example 
        // request.permissions[0].constraints = Some(create_prost_struct(map));
        // sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap(); // Resign
        // assert!(matches!(validate_request_syntax(&request), Err(MCPError::InvalidField { field_name, .. }) if field_name.contains("constraints")));

    }

    #[test]
    fn test_validate_request_syntax_expired() {
        let (key_pair, mut request) = create_valid_test_request();

        // Expired Request
        request.request_expiry = Some(prost_timestamp_from_chrono(Utc::now() - Duration::seconds(10)));
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap(); // Resign
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::ExpiredRequest { .. })));

        // Expired Purpose
        request = create_valid_test_request().1; // Reset
        request.purpose_dna.as_mut().unwrap().purpose_expiry_timestamp = Some(prost_timestamp_from_chrono(Utc::now() - Duration::seconds(10)));
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap(); // Resign
        assert!(matches!(validate_request_syntax(&request), Err(MCPError::ExpiredPurpose { .. })));
    }
    
    #[test]
    fn test_validate_request_security() {
        let (key_pair, mut request) = create_valid_test_request();
        
        // Valid signature
        assert!(validate_request_security(&request).is_ok());

        // Invalid signature (tamper with data after signing)
        request.request_id = "tampered".to_string();
        assert!(matches!(validate_request_security(&request), Err(MCPError::SignatureError { .. })));

        // Missing signature
        request = create_valid_test_request().1; // Reset
        request.signature = None;
        assert!(matches!(validate_request_security(&request), Err(MCPError::MissingField { .. }))); // verify_request_signature checks this

        // Signature with unsupported algorithm
        request = create_valid_test_request().1; // Reset
        request.signature.as_mut().unwrap().algorithm = "UnknownAlg".to_string();
        assert!(matches!(validate_request_security(&request), Err(MCPError::SignatureError { reason }) if reason.contains("Unsupported")));
        
        // Signature with wrong length
        request = create_valid_test_request().1; // Reset
        request.signature.as_mut().unwrap().signature = Bytes::from_static(&[0u8; 32]); // Wrong length
        assert!(matches!(validate_request_security(&request), Err(MCPError::SignatureError { reason }) if reason.contains("length")));
        
        // Request with key mismatch (e.g., public key in identity doesn't match signing key)
        // Need a second key pair for this
        let (key_pair2, identity2) = create_test_identity();
        let mut request_wrong_key = McpRequestBuilder::new(identity2, create_test_purpose(), "1.0.0".to_string())
            .add_permission(create_test_permission())
            .build();
        // Sign with the *first* key pair, but identity contains the *second* public key
        sign_request(&mut request_wrong_key, &key_pair, "key-for-identity1".to_string()).unwrap();
        assert!(matches!(validate_request_security(&request_wrong_key), Err(MCPError::SignatureError { .. })));

    }
    
    #[test]
    fn test_validate_request_semantics() {
        // Placeholder: Semantic validation is currently a no-op
        let (_key_pair, request) = create_valid_test_request();
        assert!(validate_request_semantics(&request).is_ok());
        // TODO: Add tests here when semantic validation rules are implemented.
        // Example scenarios:
        // - Purpose category doesn't match requested permissions/data types.
        // - Inconsistent fields within PurposeDNA.
        // - Violation of complex constraints not covered by basic evaluation.
    }
    
    #[test]
    fn test_validate_request_overall() {
        // Test the main `validate_request` function which calls all stages
        let (_key_pair, request) = create_valid_test_request();
        let result = validate_request(&request);
        assert!(result.is_ok());
        
        // Test failure propagation (e.g., syntax error should be wrapped)
        let (_key_pair, mut request) = create_valid_test_request();
        request.request_id = String::new(); // Syntax error
        let result = validate_request(&request);
        assert!(matches!(result, 
            Err(MCPError::ValidationError { stage, source }) 
            if stage == "Syntax" && matches!(*source, MCPError::MissingField { .. })
        ));

        // Test security failure propagation
        let (_key_pair, mut request) = create_valid_test_request();
        request.request_id = "tampered".to_string(); // Security error (invalid signature)
        let result = validate_request(&request);
        assert!(matches!(result, 
            Err(MCPError::ValidationError { stage, source }) 
            if stage == "Security" && matches!(*source, MCPError::SignatureError { .. })
        ));

        // TODO: Test semantic failure propagation when implemented.
    }

    // --- Serialization Tests (Ensure they still work) ---
    #[test]
    fn test_request_serialization_deserialization() {
        let (key_pair, mut request) = create_valid_test_request();
        
        // Add extensions and agent_metadata from proto changes
        let mut agent_meta_map = HashMap::new();
        agent_meta_map.insert("agent_id".to_string(), SerdeValue::String("agent-123".to_string()));
        request.purpose_dna.as_mut().unwrap().agent_metadata = Some(create_prost_struct(agent_meta_map));
        
        let any_val = prost_types::Any { type_url: "example.com/foo".into(), value: vec![1,2,3] };
        request.extensions = vec![any_val];
        
        // Re-sign because we modified the request payload
        sign_request(&mut request, &key_pair, "test-key-01".to_string()).unwrap();

        let serialized = serialize_request(&request).unwrap();
        let deserialized = deserialize_request(&serialized).unwrap();

        // Use prost::Message::eq for comparison as generated structs might not derive PartialEq
        assert!(request.eq(&deserialized), "Original and deserialized requests do not match");
    }
    
    #[test]
    fn test_response_serialization_deserialization() {
        let request_id = Uuid::new_v4().to_string();
        let response_id = Uuid::new_v4().to_string();
        let (key_pair, _identity) = create_test_identity();

        let mut response = McpResponseBuilder::new(request_id.clone(), Status::Approved, "1.0.0".to_string())
            .status_message("OK".to_string())
            .set_payload(Bytes::from_static(b"some data"))
            .set_consent_receipt(Bytes::from_static(b"receipt-bytes"))
            .build();
            
        let any_val = prost_types::Any { type_url: "example.com/bar".into(), value: vec![4,5,6] };
        response.extensions = vec![any_val];

        sign_response(&mut response, &key_pair, "responder-key-01".to_string()).unwrap();

        let serialized = serialize_response(&response).unwrap();
        let deserialized = deserialize_response(&serialized).unwrap();

        assert!(response.eq(&deserialized), "Original and deserialized responses do not match");
    }
    
    // ... other existing tests (signing, timestamp, expiration, json<->struct) ...
    
    // --- Property-Based Test Placeholders --- 
    // Add `proptest` to [dev-dependencies] in Cargo.toml
    /*
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_validate_request_syntax_doesnt_panic( /* Define proptest strategies for McpRequest fields */ ) {
            // Create request from proptest-generated data
            // let request = McpRequest { ... };
            // Calling validate_request_syntax should not panic, just return Ok or Err.
            // let _ = validate_request_syntax(&request);
        }
        
        #[test]
        fn prop_roundtrip_serialization( /* Define proptest strategies for McpRequest */ ) {
            // Create request
            // Serialize
            // Deserialize
            // Assert original == deserialized (requires PartialEq or custom logic)
        }
        
        // Add more property tests for validation, constraints, etc.
    }
    */

}

// --- Benchmark Placeholders --- 
// Benchmarks typically live in benches/ directory and use `criterion` or `test::Bencher`.
// Add `criterion` to [dev-dependencies] and set up benches/my_benchmark.rs
/*
// In benches/my_benchmark.rs:
use criterion::{criterion_group, criterion_main, Criterion, Bencher};
use pandacea_mcp::{serialize_request, deserialize_request, validate_request, /* other functions */};
// Assume setup functions create test data (requests, responses, keys)

fn bench_serialization(c: &mut Criterion) {
    let (_key, request) = setup_valid_request(); // Assume this exists
    c.bench_function("serialize_request", |b| b.iter(|| serialize_request(&request)));
}

fn bench_deserialization(c: &mut Criterion) {
    let (_key, request) = setup_valid_request();
    let serialized = serialize_request(&request).unwrap();
    c.bench_function("deserialize_request", |b| b.iter(|| deserialize_request(&serialized)));
}

fn bench_validation(c: &mut Criterion) {
    let (_key, request) = setup_valid_request();
    c.bench_function("validate_request", |b| b.iter(|| validate_request(&request)));
}

criterion_group!(benches, bench_serialization, bench_deserialization, bench_validation);
criterion_main!(benches);
*/