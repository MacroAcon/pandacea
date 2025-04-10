//! Type definitions and re-exports from the protobuf-generated code.

// --- Re-exports of core MCP types from generated code ---
// This makes them accessible directly via `crate::types::*` or `pandacea_mcp::*`.

/// Represents the main request message in the Model Context Protocol (MCP).
/// Contains identity, purpose, requested permissions, and signature.
pub use crate::mcp::McpRequest;

/// Represents the main response message in the Model Context Protocol (MCP).
/// Contains status, potential payload, consent receipt, and signature.
pub use crate::mcp::McpResponse;

/// Describes the purpose (intent) behind an `McpRequest`.
/// Includes categorization, description, data types, processing, storage, etc.
pub use crate::mcp::PurposeDNA;

/// Identifies the entity making an `McpRequest`.
/// Includes a pseudonymous ID, public key, and optional attestations.
pub use crate::mcp::RequestorIdentity;

/// Specifies a single permission being requested (data access or action).
/// Includes the target resource, the requested action, and optional constraints.
pub use crate::mcp::PermissionSpecification;

/// Contains cryptographic signature information (key ID, algorithm, signature bytes).
pub use crate::mcp::CryptoSignature;

// --- Re-exports of Enums via submodules ---

/// Re-exports from purpose_dna module
pub mod purpose_dna {
    /// Enumerates the possible categories describing the primary purpose of a request.
    pub use crate::mcp::purpose_dna::PurposeCategory;
}

/// Re-exports from permission_specification module
pub mod permission_specification {
    /// Enumerates the possible actions that can be requested on a resource.
    pub use crate::mcp::permission_specification::Action;
}

/// Enumerates the possible overall statuses of processing an `McpRequest`.
pub use crate::mcp::mcp_response::Status;

/// Describes the outcome of a specific permission request within an `McpResponse`.
pub use crate::mcp::mcp_response::PermissionStatus;

// --- Potentially other related types or aliases --- 
// E.g., if you had common internal representations distinct from protos

// Note: `bytes::Bytes` is used directly where needed, but could be re-exported:
// pub use bytes::Bytes; 