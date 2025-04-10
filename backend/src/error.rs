//! Error types for the MCP library.

use chrono::{DateTime, Utc};
use thiserror::Error;
use signature::Error as SignatureLibError;
use pkcs8::Error as Pkcs8Error;

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
    /// Cryptographic signature verification failed or a signing error occurred.
    #[error("Signature error: {reason}")]
    SignatureError { reason: String, #[source] source: Option<SignatureLibError> },
    /// The specified cryptographic key could not be found or retrieved.
    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },
    /// An invalid cryptographic key was provided (parsing error, wrong format, etc.).
    #[error("Invalid cryptographic key: {reason}")]
    InvalidKey { reason: String, #[source] source: Option<Box<dyn std::error::Error + Send + Sync + 'static>> },
    /// Error related to PKCS#8 encoding/decoding.
    #[error("PKCS#8 processing error: {context} - {source}")]
    Pkcs8Error { context: String, #[source] source: Pkcs8Error },
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
    /// Error related to Consent Genome operations.
    #[error("Consent Genome error: {context} - {source}")]
    GenomeError {
        context: String,
        #[source] source: Box<dyn std::error::Error + Send + Sync + 'static>
    },
    /// Error related to Audit Log operations.
    #[error("Audit Log error: {context} - {source}")]
    AuditError {
        context: String,
        #[source] source: Box<dyn std::error::Error + Send + Sync + 'static>
    },
    /// Error during communication between agents
    #[error("Communication error: {context} - {source}")]
    CommunicationError {
        /// Context about what operation was being attempted
        context: String,
        /// The underlying error that occurred
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Error related to certificate operations (loading, parsing, validation)
    #[error("Certificate error: {context} - {source}")]
    CertificateError {
        /// Context about what certificate operation was being attempted
        context: String,
        /// The underlying error that occurred
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Error related to PKCS#12 (PFX) format handling
    #[error("PKCS#12 error: {context} - {source}")]
    Pkcs12Error {
        /// Context about what PKCS#12 operation was being attempted
        context: String,
        /// The underlying error that occurred
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Error related to TLS configuration or connection
    #[error("TLS error: {context} - {source}")]
    TlsError {
        /// Context about what TLS operation was being attempted
        context: String,
        /// The underlying error that occurred
        source: Box<dyn std::error::Error + Send + Sync>,
    },
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

impl From<serde_json::Error> for MCPError {
    fn from(err: serde_json::Error) -> Self {
        MCPError::JsonError { context: "Struct/Value conversion".to_string(), source: err }
    }
}

impl From<std::io::Error> for MCPError {
    fn from(err: std::io::Error) -> Self {
        MCPError::IoError { context: "File operation".to_string(), source: err } // Example context
    }
}

// Add From for Pkcs8Error
impl From<Pkcs8Error> for MCPError {
    fn from(err: Pkcs8Error) -> Self {
        MCPError::Pkcs8Error { context: "PKCS#8 operation".to_string(), source: err }
    }
}

// Add From for pkcs12 errors
impl From<pkcs12::Error> for MCPError {
    fn from(err: pkcs12::Error) -> Self {
        MCPError::Pkcs12Error { 
            context: "PKCS#12 parsing operation".to_string(),
            source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
        }
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

    pub fn signature_error(reason: impl Into<String>, source: Option<SignatureLibError>) -> Self {
        MCPError::SignatureError { reason: reason.into(), source }
    }

    pub fn invalid_key(reason: impl Into<String>, source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>) -> Self {
        MCPError::InvalidKey { reason: reason.into(), source }
    }
    
    pub fn pkcs8_error(context: impl Into<String>, source: Pkcs8Error) -> Self {
        MCPError::Pkcs8Error { context: context.into(), source }
    }
    
    pub fn conversion_error(message: impl Into<String>) -> Self {
        MCPError::ConversionError { message: message.into() }
    }
    
    pub fn internal(message: impl Into<String>) -> Self {
        MCPError::ConversionError { message: message.into() }
    }
    
    pub fn constraint_violation(constraint_key: impl Into<String>, reason: impl Into<String>) -> Self {
        MCPError::ConstraintEvaluationError { constraint_key: constraint_key.into(), reason: reason.into() }
    }
    
    pub fn expired_purpose_without_timestamp() -> Self {
        MCPError::ConversionError { message: "Purpose is marked as expired but no expiry timestamp provided".into() }
    }
    
    pub fn genome_error(context: impl Into<String>, source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>) -> Self {
        MCPError::GenomeError { context: context.into(), source: source.into() }
    }
    
    pub fn audit_error(context: impl Into<String>, source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>) -> Self {
        MCPError::AuditError { context: context.into(), source: source.into() }
    }
    
    pub fn certificate_error(context: impl Into<String>, source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        MCPError::CertificateError { context: context.into(), source: source.into() }
    }
    
    pub fn pkcs12_error(context: impl Into<String>, source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        MCPError::Pkcs12Error { context: context.into(), source: source.into() }
    }
    
    pub fn tls_error(context: impl Into<String>, source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        MCPError::TlsError { context: context.into(), source: source.into() }
    }
} 