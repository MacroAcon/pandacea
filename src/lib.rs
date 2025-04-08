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

/// Errors that can occur during MCP processing.
#[derive(Debug, thiserror::Error)]
pub enum MCPError {
    /// Error during Protobuf message encoding.
    #[error("Protobuf encoding error: {0}")]
    EncodeError(#[from] prost::EncodeError),
    /// Error during Protobuf message decoding.
    #[error("Protobuf decoding error: {0}")]
    DecodeError(#[from] prost::DecodeError),
    /// Error during JSON serialization or deserialization (used for Struct conversion).
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    /// A required field was missing from an MCP message.
    #[error("Missing required field: {0}")]
    MissingField(String),
    /// A field contained an invalid value (wrong format, out of range, etc.).
    #[error("Invalid field value: {0}")]
    InvalidField(String),
    /// Cryptographic signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureError(String),
    /// General cryptography error (e.g., during key generation).
    #[error("Cryptography error: {0}")]
    CryptoError(String),
    /// An invalid cryptographic key was provided or generated.
    #[error("Invalid cryptographic key: {0}")]
    InvalidKey(#[from] ring::error::KeyRejected),
    /// An unspecified error occurred within the underlying crypto library (`ring`).
    #[error("Unspecified cryptographic error")]
    CryptoUnspecified(#[from] RingUnspecified),
    /// An I/O error occurred (relevant if loading keys/data from files).
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    /// Error during type conversion (e.g., JSON to Protobuf Value).
    #[error("Type conversion error: {0}")]
    ConversionError(String),
}

/// A specialized `Result` type for MCP operations.
pub type Result<T> = std::result::Result<T, MCPError>;

// --- Serialization / Deserialization ---

/// Serializes an `McpRequest` into Protobuf bytes.
pub fn serialize_request(request: &McpRequest) -> Result<Vec<u8>> {
    // TODO: Consider adding size limit checks before serialization if needed.
    let mut buf = Vec::new();
    buf.reserve(request.encoded_len());
    request.encode(&mut buf)?;
    Ok(buf)
}

/// Deserializes Protobuf bytes into an `McpRequest`.
pub fn deserialize_request(buf: &[u8]) -> Result<McpRequest> {
    // TODO: Consider adding size limit checks on `buf.len()` before deserialization.
    McpRequest::decode(buf).map_err(MCPError::from)
}

/// Serializes an `McpResponse` into Protobuf bytes.
pub fn serialize_response(response: &McpResponse) -> Result<Vec<u8>> {
    // TODO: Consider adding size limit checks, especially for `response_payload`.
    let mut buf = Vec::new();
    buf.reserve(response.encoded_len());
    response.encode(&mut buf)?;
    Ok(buf)
}

/// Deserializes Protobuf bytes into an `McpResponse`.
pub fn deserialize_response(buf: &[u8]) -> Result<McpResponse> {
    // TODO: Consider adding size limit checks on `buf.len()` before deserialization.
    McpResponse::decode(buf).map_err(MCPError::from)
}

// --- Comprehensive Validation ---

/// Validates the structure, content, and signature of an `McpRequest`.
///
/// This function performs a series of checks:
/// *   Presence of required fields (`request_id`, `timestamp`, `requestor_identity`, etc.).
/// *   Validity of timestamp formats and logical constraints (e.g., expiry > timestamp).
/// *   Checks if the request itself has expired based on `request_expiry`.
/// *   Presence and basic format validation of `RequestorIdentity` fields (ID, public key).
/// *   Presence of required `PurposeDNA` fields.
/// *   Ensures the `permissions` list is not empty and contains valid actions.
/// *   Checks the presence and basic validity of `CryptoSignature` fields.
/// *   Performs cryptographic verification of the signature using the public key
///     provided in `requestor_identity`.
///
/// # Arguments
/// * `request`: The `McpRequest` to validate.
///
/// # Returns
/// * `Ok(())` if the request is valid.
/// * `Err(MCPError)` detailing the validation failure reason.
///
/// # Errors
/// Returns `MCPError::MissingField` if required fields are absent.
/// Returns `MCPError::InvalidField` for format errors, logical inconsistencies (e.g., bad timestamps), or expired requests.
/// Returns `MCPError::SignatureError` if the cryptographic signature is invalid or uses an unsupported algorithm.
pub fn validate_request(request: &McpRequest) -> Result<()> {
    // --- Request Level Checks ---
    if request.request_id.is_empty() {
        return Err(MCPError::MissingField("request.request_id".to_string()));
    }
    let request_timestamp = request.timestamp.as_ref()
        .ok_or_else(|| MCPError::MissingField("request.timestamp".to_string()))?;
    let request_dt = chrono_from_prost_timestamp(request_timestamp)
        .ok_or_else(|| MCPError::InvalidField("request.timestamp invalid format or range".to_string()))?;

    // Check for expiration *before* checking timestamp plausibility,
    // as an expired request is definitively invalid regardless of clock skew.
    if is_request_expired(request) {
         return Err(MCPError::InvalidField("request has expired based on request_expiry".to_string()));
    }

    // Timestamp plausibility check (generous window to allow for skew)
    let now = Utc::now();
    let allowed_skew_past = chrono::Duration::hours(1);
    let allowed_skew_future = chrono::Duration::minutes(5); // Shorter window for future timestamps
    if request_dt > now + allowed_skew_future {
         return Err(MCPError::InvalidField(format!("request.timestamp ({}) is too far in the future (current time: {}, allowed skew: {}s)", request_dt, now, allowed_skew_future.num_seconds())));
    }
    if request_dt < now - allowed_skew_past {
        // Less strict about past timestamps, but still useful to flag potentially very old requests.
        // Consider logging a warning instead of returning an error in some contexts.
         return Err(MCPError::InvalidField(format!("request.timestamp ({}) is too far in the past (current time: {}, allowed skew: {}s)", request_dt, now, allowed_skew_past.num_seconds())));
    }

    // Check request_expiry > timestamp (only if expiry exists)
    if let Some(expiry_ts) = &request.request_expiry {
        let expiry_dt = chrono_from_prost_timestamp(expiry_ts)
            .ok_or_else(|| MCPError::InvalidField("request.request_expiry invalid format or range".to_string()))?;
        if expiry_dt <= request_dt {
            return Err(MCPError::InvalidField(format!("request.request_expiry ({}) must be after request.timestamp ({})", expiry_dt, request_dt)));
        }
        // Note: Actual expiration check using `is_request_expired` happened earlier.
    }

    if request.mcp_version.is_empty() {
        return Err(MCPError::MissingField("request.mcp_version".to_string()));
    }
    // TODO: Add semantic version compatibility check if needed, comparing against supported versions.

    // --- Requestor Identity Checks ---
    let identity = request.requestor_identity.as_ref()
        .ok_or_else(|| MCPError::MissingField("request.requestor_identity".to_string()))?;
    if identity.pseudonym_id.trim().is_empty() { // Check trimmed value
        return Err(MCPError::MissingField("requestor_identity.pseudonym_id cannot be empty or whitespace".to_string()));
    }
    if identity.public_key.is_empty() {
        return Err(MCPError::MissingField("requestor_identity.public_key".to_string()));
    }
    // Basic check for public key format (Ed25519 keys are 32 bytes)
    if identity.public_key.len() != 32 {
        return Err(MCPError::InvalidField(format!("requestor_identity.public_key has invalid length ({}) for Ed25519 (expected 32)", identity.public_key.len())));
    }
    // TODO: Consider validating attestation URLs if present (e.g., basic format check).

    // --- Purpose DNA Checks ---
    let purpose = request.purpose_dna.as_ref()
        .ok_or_else(|| MCPError::MissingField("request.purpose_dna".to_string()))?;
    if purpose.purpose_id.trim().is_empty() {
        return Err(MCPError::MissingField("purpose_dna.purpose_id cannot be empty or whitespace".to_string()));
    }
    if purpose.primary_purpose_category.trim().is_empty() {
        return Err(MCPError::MissingField("purpose_dna.primary_purpose_category cannot be empty or whitespace".to_string()));
    }
    if purpose.specific_purpose_description.trim().is_empty() {
        return Err(MCPError::MissingField("purpose_dna.specific_purpose_description cannot be empty or whitespace".to_string()));
    }
    // Check other mandatory fields for clarity/completeness
    if purpose.data_types_involved.is_empty() {
         return Err(MCPError::MissingField("purpose_dna.data_types_involved cannot be empty".to_string()));
    }
    if purpose.data_types_involved.iter().any(|s| s.trim().is_empty()) {
         return Err(MCPError::InvalidField("purpose_dna.data_types_involved contains empty strings".to_string()));
    }
    if purpose.processing_description.trim().is_empty() {
        return Err(MCPError::MissingField("purpose_dna.processing_description cannot be empty or whitespace".to_string()));
    }
     if purpose.storage_description.trim().is_empty() {
        return Err(MCPError::MissingField("purpose_dna.storage_description cannot be empty or whitespace".to_string()));
    }
    // TODO: Add check for purpose_expiry_timestamp validity if present (e.g., not too far past/future)?
    // The `is_purpose_expired` helper can be used separately if needed.

    // --- Permissions Checks ---
    if request.permissions.is_empty() {
        return Err(MCPError::InvalidField("request.permissions list cannot be empty".to_string()));
    }
    for (i, perm) in request.permissions.iter().enumerate() {
        if perm.resource_identifier.trim().is_empty() {
            return Err(MCPError::MissingField(format!("permissions[{}].resource_identifier cannot be empty or whitespace", i)));
        }
        match Action::try_from(perm.requested_action) {
            Ok(Action::ActionUnspecified) | Err(_) => {
                return Err(MCPError::InvalidField(format!("permissions[{}].requested_action has invalid or unspecified value: {}", i, perm.requested_action)));
            }
            Ok(_) => {} // Valid action
        }
        // TODO: Validate constraints Struct based on a schema or known keys if defined.
        // TODO: Check for duplicate resource_identifier + action pairs?
    }

    // --- Signature Presence & Format Checks ---
    let signature_info = request.signature.as_ref()
        .ok_or_else(|| MCPError::MissingField("request.signature".to_string()))?;
    if signature_info.key_id.trim().is_empty() {
        return Err(MCPError::MissingField("signature.key_id cannot be empty or whitespace".to_string()));
    }
    if signature_info.algorithm.trim().is_empty() {
        return Err(MCPError::MissingField("signature.algorithm cannot be empty or whitespace".to_string()));
    }
    // Currently, only Ed25519 is explicitly supported for verification
    if signature_info.algorithm != "Ed25519" {
        return Err(MCPError::SignatureError(format!("Unsupported signature algorithm in request: {}", signature_info.algorithm)));
    }
    if signature_info.signature.is_empty() {
        return Err(MCPError::MissingField("signature.signature cannot be empty".to_string()));
    }

    // --- Cryptographic Signature Verification ---
    // This uses the public key from the requestor_identity field.
    verify_request_signature(request)?;

    Ok(())
}

/// Validates the structure and content of an `McpResponse`.
///
/// This performs checks similar to `validate_request` but for response fields:
/// *   Presence of required fields (`response_id`, `request_id`, `timestamp`, etc.).
/// *   Ensures `request_id` matches the ID of the original request being responded to.
/// *   Validity of timestamp formats.
/// *   Consistency checks for `status` and related fields (e.g., `PARTIALLY_APPROVED`
///     requires `permission_statuses`, `ERROR` requires `status_message`).
/// *   Checks the presence and basic validity of `CryptoSignature` fields.
///
/// **Note:** This function *does not* verify the cryptographic signature itself,
/// as that requires the public key of the *responder* (e.g., Consent Manager),
/// which is not part of the response message. Use `verify_response_signature`
/// separately for that purpose.
///
/// # Arguments
/// * `response`: The `McpResponse` to validate.
/// * `original_request_id`: The `request_id` of the `McpRequest` this response pertains to.
///
/// # Returns
/// * `Ok(())` if the response structure and content are valid.
/// * `Err(MCPError)` detailing the validation failure reason.
///
/// # Errors
/// Returns `MCPError::MissingField` or `MCPError::InvalidField` for structural or content issues.
pub fn validate_response(response: &McpResponse, original_request_id: &str) -> Result<()> {
    // --- Response Level Checks ---
    if response.response_id.is_empty() {
        return Err(MCPError::MissingField("response.response_id".to_string()));
    }
    if response.request_id.is_empty() {
        return Err(MCPError::MissingField("response.request_id".to_string()));
    }
    if response.request_id != original_request_id {
        return Err(MCPError::InvalidField(format!("response.request_id ('{}') does not match expected original request_id ('{}')", response.request_id, original_request_id)));
    }

    let response_timestamp = response.timestamp.as_ref()
        .ok_or_else(|| MCPError::MissingField("response.timestamp".to_string()))?;
    let response_dt = chrono_from_prost_timestamp(response_timestamp)
        .ok_or_else(|| MCPError::InvalidField("response.timestamp invalid format or range".to_string()))?;
    // Basic plausibility check
    let now = Utc::now();
    if response_dt > now + chrono::Duration::minutes(5) || response_dt < now - chrono::Duration::hours(1) {
         // Allow some clock skew
        // return Err(MCPError::InvalidField("response.timestamp is outside acceptable range".to_string()));
    }

    if response.mcp_version.is_empty() {
        return Err(MCPError::MissingField("response.mcp_version".to_string()));
    }

    // --- Status Checks ---
    let status = Status::try_from(response.status)
        .map_err(|_| MCPError::InvalidField(format!("response.status has invalid enum value: {}", response.status)))?;

    match status {
        Status::StatusUnspecified => return Err(MCPError::InvalidField("response.status cannot be UNSPECIFIED".to_string())),
        Status::Error if response.status_message.trim().is_empty() => {
            return Err(MCPError::MissingField("response.status_message required for ERROR status".to_string()))
        },
        Status::Denied if response.status_message.trim().is_empty() => {
             // Optional but recommended
        },
        Status::PartiallyApproved if response.permission_statuses.is_empty() => {
            return Err(MCPError::MissingField("response.permission_statuses required for PARTIALLY_APPROVED status".to_string()))
        },
        Status::Approved | Status::Denied | Status::Error | Status::Pending if !response.permission_statuses.is_empty() => {
             return Err(MCPError::InvalidField(format!("response.permission_statuses must be empty for status {:?}", status)))
        }
        _ => {}
    }

    // --- Permission Status Checks (only if PARTIALLY_APPROVED) ---
    if status == Status::PartiallyApproved {
        // Already checked that the list is not empty above.
        for (i, ps) in response.permission_statuses.iter().enumerate() {
            if ps.resource_identifier.trim().is_empty() {
                 return Err(MCPError::MissingField(format!("permission_statuses[{}].resource_identifier cannot be empty or whitespace", i)));
            }
             let action = Action::try_from(ps.requested_action)
                 .map_err(|_| MCPError::InvalidField(format!("permission_statuses[{}].requested_action has invalid or unspecified value: {}", i, ps.requested_action)));
             if action == Action::ActionUnspecified {
                 return Err(MCPError::InvalidField(format!("permission_statuses[{}].requested_action cannot be UNSPECIFIED", i)));
             }
             if !ps.granted && ps.reason.trim().is_empty() {
                 // Recommended to provide a reason for denial
             }
        }
        // TODO: Optionally check if permission_statuses correspond to the original request permissions
        // (e.g., all original permissions accounted for, no extras). Requires passing original request.
    }

    // --- Signature Presence & Format Checks ---
    // Note: Actual cryptographic verification must be done separately using verify_response_signature.
    let signature_info = response.signature.as_ref()
        .ok_or_else(|| MCPError::MissingField("response.signature".to_string()))?;
    if signature_info.key_id.trim().is_empty() {
        return Err(MCPError::MissingField("signature.key_id cannot be empty or whitespace".to_string()));
    }
    if signature_info.algorithm.trim().is_empty() {
        return Err(MCPError::MissingField("signature.algorithm cannot be empty or whitespace".to_string()));
    }
    if signature_info.algorithm != "Ed25519" {
        return Err(MCPError::InvalidField(format!("Unsupported signature algorithm in response signature block: {}", signature_info.algorithm)));
    }
    if signature_info.signature.is_empty() {
        return Err(MCPError::MissingField("signature.signature cannot be empty".to_string()));
    }

    // --- Other Field Checks ---
    // TODO: Add size limit checks for response_payload and consent_receipt if applicable.

    Ok(())
}

// --- Request Builder Helper ---

/// A helper to construct `McpRequest` messages.
///
/// Provides a fluent API to set fields and add permissions before building
/// the final request object. Signatures must be added separately after building.
///
/// # Example
/// ```rust
/// # use pandacea_mcp::{McpRequestBuilder, RequestorIdentity, PurposeDna, PermissionSpecification, Action, bytes::Bytes, KeyPair, sign_request};
/// # use chrono::Utc;
/// # let key_pair = KeyPair::generate().unwrap();
/// # let identity = RequestorIdentity { pseudonym_id: "id".into(), public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()), attestations: vec![], };
/// # let purpose = PurposeDna { purpose_id: "pid".into(), primary_purpose_category: "cat".into(), specific_purpose_description: "desc".into(), data_types_involved: vec!["dt".into()], processing_description: "proc".into(), storage_description: "store".into(), intended_recipients: vec![], purpose_expiry_timestamp: None, legal_context_url: String::new() };
/// # let perm = PermissionSpecification { resource_identifier: "res".into(), requested_action: Action::Read as i32, constraints: None };
/// let mut request = McpRequestBuilder::new(identity, purpose, "1.2.0".into())
///     .add_permission(perm)
///     .set_expiry(Utc::now() + Duration::minutes(5))
///     .build();
/// // sign_request(&mut request, &key_pair, "key_id".into()).unwrap(); // Sign separately
/// ```
pub struct McpRequestBuilder {
    request: McpRequest,
}

impl McpRequestBuilder {
    /// Creates a new builder with essential request information.
    ///
    /// Automatically generates a unique `request_id` and sets the `timestamp` to now.
    /// The signature must be added later using [`sign_request`].
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

    /// Adds a `PermissionSpecification` to the request.
    pub fn add_permission(mut self, permission: PermissionSpecification) -> Self {
        self.request.permissions.push(permission);
        self
    }

    /// Sets the optional request expiry timestamp.
    pub fn set_expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.request.request_expiry = Some(prost_timestamp_from_chrono(expiry));
        self
    }

    /// Sets the optional related request ID.
    pub fn set_related_request_id(mut self, related_id: String) -> Self {
        self.request.related_request_id = related_id;
        self
    }

    /// Consumes the builder and returns the constructed `McpRequest`.
    ///
    /// Note: The returned request is *unsigned*. Use [`sign_request`] afterwards.
    pub fn build(self) -> McpRequest {
        // Potential location for final validation checks on the built request *before* signing?
        self.request
    }
}

// --- Response Builder Helper ---

/// A helper to construct `McpResponse` messages.
///
/// Provides a fluent API similar to `McpRequestBuilder`. Signatures must be
/// added separately after building using [`sign_response`].
///
/// # Example
/// ```rust
/// # use pandacea_mcp::{McpResponseBuilder, PermissionStatus, Status, Action, bytes::Bytes, KeyPair, sign_response};
/// # let responder_key_pair = KeyPair::generate().unwrap();
/// let mut response = McpResponseBuilder::new("req-123".to_string(), Status::PartiallyApproved, "1.1.0".to_string())
///     .add_permission_status(PermissionStatus {
///         resource_identifier: "res1".into(),
///         requested_action: Action::Read as i32,
///         granted: true,
///         reason: "".into()
///     })
///     .add_permission_status(PermissionStatus {
///         resource_identifier: "res2".into(),
///         requested_action: Action::Write as i32,
///         granted: false,
///         reason: "Policy Denied".into()
///     })
///     .status_message("Partial approval based on policy".into())
///     .build();
/// // sign_response(&mut response, &responder_key_pair, "resp-key-1".to_string()).unwrap(); // Sign separately
/// ```
pub struct McpResponseBuilder {
    response: McpResponse,
}

impl McpResponseBuilder {
    /// Creates a new builder with essential response information.
    ///
    /// Automatically generates a unique `response_id` and sets the `timestamp` to now.
    /// The signature must be added later using [`sign_response`].
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

    /// Sets the optional human-readable status message.
    /// Recommended especially for `Error`, `Denied`, and `PartiallyApproved` statuses.
    pub fn status_message(mut self, message: String) -> Self {
        self.response.status_message = message;
        self
    }

    /// Adds a `PermissionStatus` detailing the outcome for a specific permission.
    /// Required if the overall status is `PartiallyApproved`.
    pub fn add_permission_status(mut self, status: PermissionStatus) -> Self {
        self.response.permission_statuses.push(status);
        self
    }

    /// Sets the optional response payload (e.g., data returned for a READ request).
    pub fn set_payload(mut self, payload: Bytes) -> Self {
        // TODO: Consider size limit check for payload?
        self.response.response_payload = payload;
        self
    }

     /// Sets the optional consent receipt (proof of decision).
     pub fn set_consent_receipt(mut self, receipt: Bytes) -> Self {
        // TODO: Consider size limit check for receipt?
        self.response.consent_receipt = receipt;
        self
    }

    /// Consumes the builder and returns the constructed `McpResponse`.
    ///
    /// Note: The returned response is *unsigned*. Use [`sign_response`] afterwards.
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
/// Returns `None` if the timestamp is invalid (e.g., nanos out of range).
pub fn chrono_from_prost_timestamp(ts: &Timestamp) -> Option<DateTime<Utc>> {
    // Validate nanos part
    if !(0..=999_999_999).contains(&ts.nanos) {
        return None;
    }
    // `from_timestamp` handles seconds range checks internally.
    DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
}

/// Checks if an `McpRequest` has expired based on its `request_expiry` field.
///
/// Returns `true` if `request_expiry` is set and is in the past, `false` otherwise
/// (including if `request_expiry` is not set or invalid).
pub fn is_request_expired(request: &McpRequest) -> bool {
    request.request_expiry.as_ref()
        .and_then(chrono_from_prost_timestamp) // Convert to DateTime<Utc> if valid
        .map_or(false, |expiry_dt| expiry_dt <= Utc::now()) // Check if expiry time is past now
}

/// Checks if a `PurposeDna` has expired based on its `purpose_expiry_timestamp` field.
///
/// Returns `true` if `purpose_expiry_timestamp` is set and is in the past, `false` otherwise.
pub fn is_purpose_expired(purpose: &PurposeDna) -> bool {
     purpose.purpose_expiry_timestamp.as_ref()
        .and_then(chrono_from_prost_timestamp)
        .map_or(false, |expiry_dt| expiry_dt <= Utc::now())
}

// Helper function to convert serde_json::Value to prost_types::Value
// Internal visibility as it's mainly for constraints/payload handling if needed.
fn serde_value_to_prost_value(value: SerdeValue) -> Result<ProstValue> {
    let kind = match value {
        SerdeValue::Null => ProstKind::NullValue(0), // Assuming 0 maps to NullValue::NULL_VALUE
        SerdeValue::Bool(b) => ProstKind::BoolValue(b),
        SerdeValue::Number(n) => {
            if let Some(f) = n.as_f64() {
                // Potential precision loss for large integers
                if !f.is_finite() {
                     return Err(MCPError::ConversionError(format!("Cannot convert non-finite number {} to Protobuf Value", n)));
                }
                ProstKind::NumberValue(f)
            } else {
                // This case might be hit for very large integers or decimals not representable as f64
                return Err(MCPError::ConversionError(format!("Unsupported number type in JSON: {}", n)));
            }
        }
        SerdeValue::String(s) => {
            // TODO: Consider length check?
            ProstKind::StringValue(s)
        },
        SerdeValue::Array(a) => {
            // TODO: Consider depth or element count check?
            let values = a.into_iter()
                .map(serde_value_to_prost_value)
                .collect::<Result<Vec<ProstValue>>>()?;
            ProstKind::ListValue(ListValue { values })
        }
        SerdeValue::Object(o) => {
             // TODO: Consider depth or field count check?
            let fields = o.into_iter()
                .map(|(k, v)| {
                    // TODO: Consider key length/format check?
                    serde_value_to_prost_value(v).map(|pv| (k, pv))
                })
                .collect::<Result<HashMap<String, ProstValue>>>()?;
            ProstKind::StructValue(Struct { fields })
        }
    };
    Ok(ProstValue { kind: Some(kind) })
}

// Helper function to convert prost_types::Value to serde_json::Value
// Internal visibility.
fn prost_value_to_serde_value(value: ProstValue) -> Result<SerdeValue> {
    match value.kind {
        Some(ProstKind::NullValue(_)) => Ok(SerdeValue::Null),
        Some(ProstKind::NumberValue(n)) => {
            // Handle potential precision issues if needed, maybe use serde_json::Number
            serde_json::Number::from_f64(n)
                .map(SerdeValue::Number)
                .ok_or_else(|| MCPError::ConversionError(format!("Cannot convert f64 {} to SerdeValue::Number (NaN or Infinite?)", n)))
        },
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

/// Helper to convert `HashMap<String, SerdeValue>` (like a JSON object) to `Option<prost_types::Struct>`.
/// Returns `Ok(None)` if the input map is empty.
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

/// Helper to convert `Option<&prost_types::Struct>` to `HashMap<String, SerdeValue>`.
/// Returns an empty `HashMap` if the input is `None`.
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

// --- Cryptographic Utilities ---

/// Represents an Ed25519 key pair, wrapping `ring`'s `Ed25519KeyPair`.
/// Provides methods for generation, loading, and signing.
#[derive(Debug)] // Avoid Clone/Copy for keys
pub struct KeyPair {
    ring_kp: Ed25519KeyPair,
}

impl KeyPair {
    /// Generates a new Ed25519 key pair using `ring`'s system random number generator.
    ///
    /// # Errors
    /// Returns `MCPError::CryptoUnspecified` if the RNG fails.
    /// Returns `MCPError::InvalidKey` on internal `ring` errors.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;
        let ring_kp = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        Ok(KeyPair { ring_kp })
    }

    /// Creates a `KeyPair` from existing PKCS#8 encoded private key bytes.
    /// PKCS#8 is a standard format for storing private keys.
    ///
    /// # Arguments
    /// * `pkcs8_bytes`: The raw PKCS#8 bytes of the Ed25519 private key.
    ///
    /// # Errors
    /// Returns `MCPError::InvalidKey` if the bytes are not a valid Ed25519 key in PKCS#8 format.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self> {
        let ring_kp = Ed25519KeyPair::from_pkcs8(pkcs8_bytes)?;
        Ok(KeyPair { ring_kp })
    }

    /// Creates a `KeyPair` from existing Ed25519 seed bytes (32-byte private key).
    /// Use with caution, as this bypasses some `ring` checks compared to `from_pkcs8`.
    ///
    /// # Arguments
    /// * `seed_bytes`: The 32 raw bytes of the Ed25519 private key seed.
    ///
    /// # Errors
    /// Returns `MCPError::InvalidKey` if the seed length is incorrect.
    pub fn from_seed(seed_bytes: &[u8]) -> Result<Self> {
        let ring_kp = Ed25519KeyPair::from_seed_unchecked(seed_bytes)?;
        Ok(KeyPair { ring_kp })
    }

    /// Returns the public key bytes associated with this key pair. (32 bytes for Ed25519)
    pub fn public_key_bytes(&self) -> &[u8] {
        self.ring_kp.public_key().as_ref()
    }

    /// Signs a message using the private key.
    /// Returns a `ring::signature::Signature` object containing the raw signature bytes.
    pub fn sign(&self, message: &[u8]) -> signature::Signature {
        self.ring_kp.sign(message)
    }
}

/// Verifies a signature using a public key.
///
/// # Arguments
/// * `public_key_bytes`: The raw 32 bytes of the Ed25519 public key.
/// * `message`: The message data that was allegedly signed.
/// * `signature_bytes`: The raw bytes of the Ed25519 signature.
///
/// # Returns
/// * `Ok(())` if the signature is valid for the message and public key.
/// * `Err(MCPError::SignatureError)` if verification fails.
///
/// # Errors
/// Can return `MCPError::SignatureError` wrapping `ring::error::Unspecified` if the public key or signature format is invalid.
pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    // Basic length check before passing to ring
    if public_key_bytes.len() != 32 {
         return Err(MCPError::SignatureError(format!("Invalid public key length: {}", public_key_bytes.len())));
    }
    // Ed25519 signatures are typically 64 bytes
    if signature_bytes.len() != 64 {
        return Err(MCPError::SignatureError(format!("Invalid signature length: {}", signature_bytes.len())));
    }

    let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
    public_key.verify(message, signature_bytes)
        .map_err(|e| MCPError::SignatureError(format!("Verification failed: {}", e)))
}

/// Prepares the MCPRequest data for signing by serializing it without the `signature` field.
/// Internal helper function.
fn prepare_request_for_signing(request: &McpRequest) -> Result<Vec<u8>> {
    let mut request_to_sign = request.clone();
    request_to_sign.signature = None; // Remove signature before serializing for signing
    serialize_request(&request_to_sign)
}

/// Signs an McpRequest` using the provided KeyPair and adds the signature to the request.
///
/// This function modifies the `request` object in place, filling the `signature` field.
/// It serializes the request (without the signature field), signs the bytes,
/// and constructs the `CryptoSignature` message.
///
/// # Arguments
/// * `request`: A mutable reference to the `McpRequest` to sign.
/// * `key_pair`: The `KeyPair` to use for signing.
/// * `key_id`: An identifier string for the key being used (e.g., a fingerprint or name).
///
/// # Errors
/// Returns errors from serialization (`MCPError::EncodeError`) or crypto operations.
pub fn sign_request(request: &mut McpRequest, key_pair: &KeyPair, key_id: String) -> Result<()> {
    let data_to_sign = prepare_request_for_signing(request)?;
    let signature = key_pair.sign(&data_to_sign);

    request.signature = Some(CryptoSignature {
        key_id,
        algorithm: "Ed25519".to_string(),
        signature: Bytes::copy_from_slice(signature.as_ref()),
    });
    Ok(())
}

/// Verifies the signature of an McpRequest` using the public key from its `requestor_identity`.
///
/// This extracts the signature, algorithm, and public key from the request,
/// prepares the data that should have been signed (request minus signature field),
/// and calls `verify_signature`.
///
/// # Arguments
/// * `request`: The `McpRequest` whose signature needs verification.
///
/// # Returns
/// * `Ok(())` if the signature is present, correctly formatted, and cryptographically valid.
/// * `Err(MCPError)` otherwise.
///
/// # Errors
/// Returns `MCPError::MissingField` if `signature` or `requestor_identity` is missing.
/// Returns `MCPError::SignatureError` if the algorithm is unsupported or verification fails.
/// Returns `MCPError::EncodeError` if preparing the data for verification fails.
pub fn verify_request_signature(request: &McpRequest) -> Result<()> {
    let signature_info = request.signature.as_ref()
        .ok_or_else(|| MCPError::MissingField("Signature missing for verification".to_string()))?;
    let identity = request.requestor_identity.as_ref()
        .ok_or_else(|| MCPError::MissingField("RequestorIdentity missing for verification".to_string()))?;

    if signature_info.algorithm != "Ed25519" {
        return Err(MCPError::SignatureError(format!("Unsupported signature algorithm: {}", signature_info.algorithm)));
    }

    let data_to_verify = prepare_request_for_signing(request)?;

    verify_signature(
        &identity.public_key,
        &data_to_verify,
        &signature_info.signature,
    )
}

/// Prepares the MCPResponse data for signing by serializing it without the `signature` field.
/// Internal helper function.
fn prepare_response_for_signing(response: &McpResponse) -> Result<Vec<u8>> {
    let mut response_to_sign = response.clone();
    response_to_sign.signature = None; // Remove signature before serializing for signing
    serialize_response(&response_to_sign)
}

/// Signs an McpResponse` using the provided KeyPair and adds the signature to the response.
///
/// This function modifies the `response` object in place, filling the `signature` field.
/// It operates similarly to `sign_request`.
///
/// # Arguments
/// * `response`: A mutable reference to the `McpResponse` to sign.
/// * `key_pair`: The `KeyPair` to use for signing (typically the responder's key).
/// * `key_id`: An identifier string for the key being used.
///
/// # Errors
/// Returns errors from serialization (`MCPError::EncodeError`) or crypto operations.
pub fn sign_response(response: &mut McpResponse, key_pair: &KeyPair, key_id: String) -> Result<()> {
    let data_to_sign = prepare_response_for_signing(response)?;
    let signature = key_pair.sign(&data_to_sign);

    response.signature = Some(CryptoSignature {
        key_id,
        algorithm: "Ed25519".to_string(),
        signature: Bytes::copy_from_slice(signature.as_ref()),
    });
    Ok(())
}

/// Verifies the signature of an McpResponse` using an explicitly provided public key.
///
/// This is necessary because the responder's public key is *not* included within
/// the `McpResponse` message itself. The caller (e.g., the original requestor)
/// must know the expected public key of the responder (e.g., Consent Manager)
/// to verify the response.
///
/// # Arguments
/// * `response`: The `McpResponse` whose signature needs verification.
/// * `responder_public_key_bytes`: The raw bytes of the expected responder's public key.
///
/// # Returns
/// * `Ok(())` if the signature is present, correctly formatted, and cryptographically valid against the provided public key.
/// * `Err(MCPError)` otherwise.
///
/// # Errors
/// Returns `MCPError::MissingField` if `signature` is missing.
/// Returns `MCPError::SignatureError` if the algorithm is unsupported or verification fails.
/// Returns `MCPError::EncodeError` if preparing the data for verification fails.
pub fn verify_response_signature(response: &McpResponse, responder_public_key_bytes: &[u8]) -> Result<()> {
    let signature_info = response.signature.as_ref()
        .ok_or_else(|| MCPError::MissingField("Signature missing for verification".to_string()))?;

    if signature_info.algorithm != "Ed25519" {
        return Err(MCPError::SignatureError(format!("Unsupported signature algorithm: {}", signature_info.algorithm)));
    }

    let data_to_verify = prepare_response_for_signing(response)?;

    verify_signature(
        responder_public_key_bytes,
        &data_to_verify,
        &signature_info.signature,
    )
}


// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*; // Import everything from the parent module
    use prost::Message;
    use mcp::{permission_specification, mcp_response};
    use bytes::Bytes;
    use chrono::Duration; // Use Duration from chrono

    fn create_test_identity() -> (KeyPair, RequestorIdentity) {
        let key_pair = KeyPair::generate().expect("Failed to generate key pair");
        let identity = RequestorIdentity {
            pseudonym_id: "test-requestor-123".to_string(),
            public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()),
            attestations: vec!["http://example.com/attestation/1".to_string()],
        };
        (key_pair, identity)
    }

    fn create_test_purpose() -> PurposeDna {
        PurposeDna {
            purpose_id: "purpose-abc-1".to_string(),
            primary_purpose_category: "Analytics".to_string(),
            specific_purpose_description: "Collect usage data for service improvement".to_string(),
            data_types_involved: vec!["usage.clicks".to_string(), "performance.latency".to_string()],
            processing_description: "Aggregated analysis, anonymized".to_string(),
            storage_description: "Stored securely, encrypted, for 90 days max".to_string(),
            intended_recipients: vec![], // Empty means internal use only
            purpose_expiry_timestamp: Some(prost_timestamp_from_chrono(Utc::now() + Duration::days(90))),
            legal_context_url: "http://example.com/privacy".to_string(),
        }
    }

    fn create_expired_purpose() -> PurposeDna {
        let mut purpose = create_test_purpose();
        purpose.purpose_id = "purpose-expired-1".into();
        purpose.purpose_expiry_timestamp = Some(prost_timestamp_from_chrono(Utc::now() - Duration::days(1)));
        purpose
    }

    fn create_test_permission() -> PermissionSpecification {
        PermissionSpecification {
            resource_identifier: "/data/user/profile".to_string(),
            requested_action: permission_specification::Action::Read as i32,
            constraints: None, // Add constraints test later
        }
    }

    fn create_test_request(identity: RequestorIdentity) -> McpRequest {
         McpRequestBuilder::new(identity, create_test_purpose(), "1.0.0".to_string())
            .add_permission(create_test_permission())
            .build()
    }

    #[test]
    fn test_request_serialization_deserialization() {
        let (_key_pair, identity) = create_test_identity();
        let mut request = create_test_request(identity.clone());
        // Add expiry for more complete serialization test
        request.request_expiry = Some(prost_timestamp_from_chrono(Utc::now() + Duration::hours(1)));

        let serialized = serialize_request(&request).expect("Serialization failed");
        let deserialized = deserialize_request(&serialized).expect("Deserialization failed");

        assert_eq!(request.request_id, deserialized.request_id);
        assert_eq!(request.mcp_version, deserialized.mcp_version);
        assert_eq!(request.requestor_identity, deserialized.requestor_identity);
        assert_eq!(request.purpose_dna, deserialized.purpose_dna);
        assert_eq!(request.permissions, deserialized.permissions);
        assert_eq!(request.request_expiry, deserialized.request_expiry);
        // Signature not checked here as it's added separately
    }

    #[test]
    fn test_response_serialization_deserialization() {
        let response = McpResponseBuilder::new("req-123".to_string(), mcp_response::Status::Approved, "1.0.0".to_string())
            .status_message("All good".to_string())
            .set_payload(Bytes::from("some data"))
            .set_consent_receipt(Bytes::from("receipt-abc"))
            .build();

        let serialized = serialize_response(&response).expect("Serialization failed");
        let deserialized = deserialize_response(&serialized).expect("Deserialization failed");

        assert_eq!(response.response_id, deserialized.response_id);
        assert_eq!(response.request_id, deserialized.request_id);
        assert_eq!(response.status, deserialized.status);
        assert_eq!(response.status_message, deserialized.status_message);
        assert_eq!(response.permission_statuses, deserialized.permission_statuses);
        assert_eq!(response.response_payload, deserialized.response_payload);
        assert_eq!(response.consent_receipt, deserialized.consent_receipt);
        assert_eq!(response.mcp_version, deserialized.mcp_version);
    }

    #[test]
    fn test_request_signing_and_verification() {
        let (key_pair, identity) = create_test_identity();
        let key_id = "test-key-1".to_string();
        let mut request = create_test_request(identity.clone());

        // Sign the request
        sign_request(&mut request, &key_pair, key_id.clone()).expect("Signing failed");

        assert!(request.signature.is_some());
        let sig_info = request.signature.as_ref().unwrap();
        assert_eq!(sig_info.key_id, key_id);
        assert_eq!(sig_info.algorithm, "Ed25519");
        assert!(!sig_info.signature.is_empty());

        // Verify the signature
        verify_request_signature(&request).expect("Verification failed");

        // Test verification failure with tampered data
        let mut tampered_request = request.clone();
        tampered_request.mcp_version = "1.0.1".to_string(); // Change a field
        let verification_result = verify_request_signature(&tampered_request);
        assert!(verification_result.is_err());
        assert!(matches!(verification_result.unwrap_err(), MCPError::SignatureError(_)));

        // Test verification failure with wrong key
        let (other_key_pair, mut other_identity) = create_test_identity();
        other_identity.pseudonym_id = "other-requestor".to_string();
        let mut request_signed_with_other_key = request.clone();
        request_signed_with_other_key.requestor_identity = Some(other_identity);
        let verification_result = verify_request_signature(&request_signed_with_other_key);
        assert!(verification_result.is_err());
        assert!(matches!(verification_result.unwrap_err(), MCPError::SignatureError(_)));

        // Test verification with the correct but externally provided pubkey
        let external_pub_key = key_pair.public_key_bytes();
        let original_sig_bytes = request.signature.as_ref().unwrap().signature.as_ref();
        let data_to_verify = prepare_request_for_signing(&request).unwrap();
        verify_signature(external_pub_key, &data_to_verify, original_sig_bytes).expect("External verification failed");
    }

    #[test]
    fn test_response_signing_and_verification() {
        // Assume the responder (Consent Manager) has its own key pair
        let responder_key_pair = KeyPair::generate().expect("Failed to generate responder key pair");
        let responder_key_id = "consent-manager-key-1".to_string();

        let mut response = McpResponseBuilder::new("req-123".to_string(), Status::Approved, "1.0.0".to_string())
            .status_message("OK".into())
            .set_payload(Bytes::from("some data"))
            .set_consent_receipt(Bytes::from("receipt-abc"))
            .build();
        sign_response(&mut response, &responder_key_pair, responder_key_id.clone()).unwrap();

        // Verify the signature using the correct public key
        verify_response_signature(&response, responder_key_pair.public_key_bytes())
            .expect("Response verification failed");
    }

    #[test]
    fn test_validate_request_valid() {
        let (key_pair, identity) = create_test_identity();
        let mut request = create_test_request(identity.clone());
        sign_request(&mut request, &key_pair, "key-1".to_string()).unwrap();

        let result = validate_request(&request);
        assert!(result.is_ok());
    }

     #[test]
    fn test_validate_request_missing_fields() {
        let (key_pair, identity) = create_test_identity();
        let mut request = create_test_request(identity.clone());
        sign_request(&mut request, &key_pair, "key-1".to_string()).unwrap();

        let mut invalid_req = request.clone(); invalid_req.request_id = "".to_string();
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::MissingField(f) if f == "request.request_id"));

        let mut invalid_req = request.clone(); invalid_req.timestamp = None;
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::MissingField(f) if f == "request.timestamp"));

        let mut invalid_req = request.clone(); invalid_req.requestor_identity = None;
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::MissingField(f) if f == "request.requestor_identity"));

        let mut invalid_req = request.clone(); invalid_req.purpose_dna = None;
        sign_request(&mut invalid_req, &key_pair, "key-1".to_string()).unwrap();
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::MissingField(f) if f == "purpose_dna.purpose_id"));

        let mut invalid_req = request.clone(); invalid_req.permissions = vec![];
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::InvalidField(f) if f == "request.permissions list cannot be empty"));

        let mut invalid_req = request.clone(); invalid_req.signature = None;
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::MissingField(f) if f == "request.signature"));

        let mut invalid_req = request.clone(); invalid_req.mcp_version = "".to_string();
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::MissingField(f) if f == "request.mcp_version"));
    }

    #[test]
    fn test_validate_request_invalid_fields() {
        let (key_pair, identity) = create_test_identity();
        let mut request = create_test_request(identity.clone());
        sign_request(&mut request, &key_pair, "key-1".to_string()).unwrap();

        let mut invalid_req = request.clone(); invalid_req.timestamp = Some(Timestamp { seconds: 1, nanos: 1_000_000_000 });
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::InvalidField(f) if f == "request.timestamp invalid format"));

        let mut invalid_req = request.clone(); invalid_req.request_expiry = Some(prost_timestamp_from_chrono(Utc::now() - Duration::seconds(1)));
        sign_request(&mut invalid_req, &key_pair, "key-1".to_string()).unwrap();
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::InvalidField(f) if f == "request.request_expiry must be after request.timestamp"));

        let mut invalid_req = request.clone(); invalid_req.mcp_version = "".to_string();
        assert!(matches!(validate_request(&invalid_req).unwrap_err(), MCPError::MissingField(f) if f == "request.mcp_version"));
    }

    #[test]
    fn test_validate_request_invalid_signature() {
        let (key_pair, identity) = create_test_identity();
        let mut request = create_test_request(identity.clone());
        sign_request(&mut request, &key_pair, "key-1".to_string()).unwrap();

        let mut invalid_req = request.clone();
        invalid_req.mcp_version = "tampered".to_string();

        let result = validate_request(&invalid_req);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::SignatureError(_)));
    }

    #[test]
    fn test_validate_response_valid() {
        let responder_key_pair = KeyPair::generate().unwrap();
        let req_id = "req-123".to_string();
        let mut response = McpResponseBuilder::new(req_id.clone(), Status::Approved, "1.0.0".to_string())
            .status_message("OK".into())
            .set_payload(Bytes::from("some data"))
            .set_consent_receipt(Bytes::from("receipt-abc"))
            .build();
        sign_response(&mut response, &responder_key_pair, "resp-key-1".to_string()).unwrap();

        let result = validate_response(&response, &req_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_response_missing_fields() {
        let responder_key_pair = KeyPair::generate().unwrap();
        let req_id = "req-123".to_string();
        let mut response = McpResponseBuilder::new(req_id.clone(), Status::Approved, "1.0.0".to_string())
            .status_message("OK".into())
            .set_payload(Bytes::from("some data"))
            .set_consent_receipt(Bytes::from("receipt-abc"))
            .build();
        sign_response(&mut response, &responder_key_pair, "resp-key-1".to_string()).unwrap();

        let mut invalid_resp = response.clone(); invalid_resp.response_id = "".to_string();
        assert!(matches!(validate_response(&invalid_resp, &req_id).unwrap_err(), MCPError::MissingField(f) if f == "response.response_id"));

        let mut invalid_resp = response.clone(); invalid_resp.request_id = "".to_string();
        assert!(matches!(validate_response(&invalid_resp, &req_id).unwrap_err(), MCPError::MissingField(f) if f == "response.request_id"));

        let mut invalid_resp = response.clone(); invalid_resp.signature = None;
        assert!(matches!(validate_response(&invalid_resp, &req_id).unwrap_err(), MCPError::MissingField(f) if f == "response.signature"));
    }

     #[test]
    fn test_validate_response_invalid_fields() {
        let responder_key_pair = KeyPair::generate().unwrap();
        let req_id = "req-123".to_string();
        let mut response = McpResponseBuilder::new(req_id.clone(), Status::Approved, "1.0.0".to_string())
            .status_message("OK".into())
            .set_payload(Bytes::from("some data"))
            .set_consent_receipt(Bytes::from("receipt-abc"))
            .build();
        sign_response(&mut response, &responder_key_pair, "resp-key-1".to_string()).unwrap();

        let mut invalid_resp = response.clone(); invalid_resp.status = 99;
        assert!(matches!(validate_response(&invalid_resp, &req_id).unwrap_err(), MCPError::InvalidField(f) if f == "response.status has invalid enum value"));
    }

    #[test]
    fn test_timestamp_conversion() {
        let now = Utc::now();
        let prost_ts = prost_timestamp_from_chrono(now);
        assert_eq!(prost_ts.seconds, now.timestamp());
        assert_eq!(prost_ts.nanos, now.timestamp_subsec_nanos() as i32);

        let back_to_chrono = chrono_from_prost_timestamp(&prost_ts).expect("Conversion back failed");
        assert_eq!(back_to_chrono, now);

        let invalid_ts_neg = Timestamp { seconds: 0, nanos: -1 };
        assert!(chrono_from_prost_timestamp(&invalid_ts_neg).is_none());
        let invalid_ts_pos = Timestamp { seconds: 0, nanos: 1_000_000_000 };
        assert!(chrono_from_prost_timestamp(&invalid_ts_pos).is_none());
    }

    #[test]
    fn test_expiration_helpers() {
        let (key_pair, identity) = create_test_identity();
        let mut request = create_test_request(identity);

        request.request_expiry = None;
        assert!(!is_request_expired(&request));

        request.request_expiry = Some(prost_timestamp_from_chrono(Utc::now() + Duration::minutes(1)));
        assert!(!is_request_expired(&request));

        request.request_expiry = Some(prost_timestamp_from_chrono(Utc::now() - Duration::seconds(1)));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(is_request_expired(&request));
    }

    #[test]
    fn test_json_struct_conversion() {
        use serde_json::json;
        let json_value = json!({
            "name": "test",
            "value": 42,
            "enabled": true,
            "nested": {
                "key": "nested_value",
                "float_val": 123.456
            },
            "list": [1, "two", null, true],
            "null_val": null,
            "empty_obj": {},
            "empty_list": []
        });

        let serde_map: HashMap<String, SerdeValue> = serde_json::from_value(json_value.clone()).unwrap();

        let prost_struct_opt = hashmap_to_prost_struct(serde_map.clone()).expect("HashMap to Struct failed");
        assert!(prost_struct_opt.is_some());
        let prost_struct = prost_struct_opt.unwrap();

        let back_to_map = prost_struct_to_hashmap(Some(&prost_struct)).expect("Struct to HashMap failed");

        let back_to_json_value: SerdeValue = serde_json::to_value(back_to_map).unwrap();

        assert_eq!(json_value, back_to_json_value);

        let empty_map: HashMap<String, SerdeValue> = HashMap::new();
        let empty_struct = hashmap_to_prost_struct(empty_map.clone()).expect("Empty map to Struct failed");
        assert!(empty_struct.is_none());
        let back_empty_map = prost_struct_to_hashmap(None).expect("None struct to map failed");
        assert!(back_empty_map.is_empty());

        let invalid_map : HashMap<String, SerdeValue> = HashMap::from_iter(vec![
            ("bad_num".to_string(), SerdeValue::Number(serde_json::Number::from_f64(f64::NAN).unwrap()))
        ]);
         assert!(hashmap_to_prost_struct(invalid_map).is_err());
    }
}

</rewritten_file> 