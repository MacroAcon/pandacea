//! # Pandacea MCP Library
//!
//! This crate provides the core data structures, serialization, validation,
//! and cryptographic utilities for the Pandacea Model Context Protocol (MCP).
//! See individual modules for details.

// Re-export the proto-generated module
// Allow users to access proto definitions directly if needed, e.g., crate::mcp::SomeProtoType
pub mod mcp {
    // Add the prost_wkt_types dependency to handle well-known types like Timestamp and Struct
    // This needs to be done because the build.rs script adds serde attributes that use prost_wkt_types
    // Note: This dependency needs to be added to Cargo.toml as well.
    // We still keep the pub use here, even though it's also in the original `include!` target,
    // to make it explicit and potentially easier for tools to find.
    pub use prost_wkt_types;
    include!(concat!(env!("OUT_DIR"), "/pandacea.mcp.rs"));
}

// Declare the modules
mod types;
mod error;
// mod validation; // Remove old top-level module declaration
mod crypto;
mod builders;
mod serialization;
mod utils;
mod sentinel; // Declare the new sentinel module

// Declare the new validation *directory* as a module
pub mod validation;

// Publicly re-export everything from the modules for easy access
pub use types::*; // Re-exports proto types like McpRequest, McpResponse, enums
pub use error::*; // MCPError enum and Result alias
pub use validation::validate_request; // Only expose the main entry point
// If sub-functions like validate_request_syntax are needed publicly, re-export them too:
// pub use validation::syntax::validate_request_syntax;
pub use crypto::*; // KeyPair, sign_request, verify_request_signature, etc.
pub use builders::*; // McpRequestBuilder, McpResponseBuilder
pub use serialization::*; // serialize_request, deserialize_request, etc.
pub use utils::*; // Timestamp/Struct conversions, expiration checks
pub use sentinel::{SentinelAgent, SentinelConfig, SecurityAlert, AlertType, SensitivityLevel}; // Re-export Sentinel components

// Add module declaration for test_utils (only compiled in test builds)
#[cfg(test)]
mod test_utils;

// --- Remove code that was moved to other modules --- 
// - All `pub use mcp::...` re-exports (moved to types.rs)
// - `MCPError` enum and `Result` type alias (moved to error.rs)
// - `serialize_*`, `deserialize_*`, `prepare_*_for_signing` functions (moved to serialization.rs)
// - Validation functions (`validate_request`, `validate_request_syntax`, etc.) (moved to validation.rs)
// - Builder structs (`McpRequestBuilder`, `McpResponseBuilder`) (moved to builders.rs)
// - Utility functions (`prost_timestamp_from_chrono`, `chrono_from_prost_timestamp`, etc.) (moved to utils.rs)
// - Cryptography structs/functions (`KeyPair`, `sign_*`, `verify_*`) (moved to crypto.rs)
// - `#[cfg(test)] mod tests { ... }` block (tests moved into respective modules)
// - Constraint evaluation placeholders (moved to validation.rs for now)
// - Unused imports (like prost::Message, uuid, etc. if only used in moved code)

// --- Keep top-level documentation and module structure --- 

// Optional: Add top-level examples here if desired, 
// but they might be better placed in README.md or specific module docs.