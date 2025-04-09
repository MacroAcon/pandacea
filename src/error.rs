//! Error types for the MCP library.

use chrono::{DateTime, Utc};
use ring::error::Unspecified as RingUnspecified;
use thiserror::Error;

/// Errors that can occur during MCP processing, serialization, validation, or cryptography.
#[derive(Error, Debug)] // Added Debug
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
    #[error("Invalid cryptographic key: {reason} - {source}")] // Show source
    InvalidKey { 
        #[source] source: ring::error::KeyRejected,
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

/// A specialized `Result` type for MCP operations, using [`MCPError`](crate::error::MCPError).
pub type Result<T> = std::result::Result<T, MCPError>;

// --- Implement From traits for convenience (e.g., for `?` operator) ---
// Moved relevant From impls here

impl From<prost::EncodeError> for MCPError {
    fn from(err: prost::EncodeError) -> Self {
        MCPError::SerializationError { context: "Unknown".to_string(), source: err }
        // Consider adding more context where these are generated if possible
    }
}

impl From<prost::DecodeError> for MCPError {
    fn from(err: prost::DecodeError) -> Self {
        MCPError::DeserializationError { context: "Unknown".to_string(), source: err }
         // Consider adding more context
    }
}

implement From<serde_json::Error> for MCPError {
    fn from(err: serde_json::Error) -> Self {
        MCPError::JsonError { context: "Struct/Value conversion".to_string(), source: err }
    }
}

implement From<std::io::Error> for MCPError {
    fn from(err: std::io::Error) -> Self {
        MCPError::IoError { context: "File operation".to_string(), source: err } // Example context
    }
}


// --- Helper constructors for common errors ---
// Add simple constructors for the most common error types

impl MCPError {
    pub fn missing_field(field_name: impl Into<String>) -> Self {
        MCPError::MissingField { field_name: field_name.into() }
    }

    pub fn invalid_field(field_name: impl Into<String>, reason: impl Into<String>) -> Self {
        MCPError::InvalidField { field_name: field_name.into(), reason: reason.into() }
    }
    
    pub fn expired_request(expiry_time: DateTime<Utc>) -> Self {
        MCPError::ExpiredRequest { expiry_time }
    }
    
    pub fn expired_purpose(expiry_time: DateTime<Utc>) -> Self {
        MCPError::ExpiredPurpose { expiry_time }
    }

    pub fn signature_error(reason: impl Into<String>) -> Self {
        MCPError::SignatureError { reason: reason.into() }
    }

     pub fn invalid_key(source: ring::error::KeyRejected, reason: impl Into<String>) -> Self {
        MCPError::InvalidKey { source, reason: reason.into() }
    }
    
    pub fn conversion_error(message: impl Into<String>) -> Self {
        MCPError::ConversionError { message: message.into() }
    }
} 