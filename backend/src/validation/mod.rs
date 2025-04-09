// src/validation/mod.rs

pub mod syntax;
pub mod semantics;
pub mod security;

use crate::error::{Result, MCPError};
use crate::types::McpRequest;

/// Validates the structure, semantics, and security of an [`McpRequest`].
///
/// This is the main entry point for request validation. It sequentially calls validation
/// checks from the submodules:
/// 1. Syntax validation (`syntax::validate_request_syntax`)
/// 2. Semantic validation (`semantics::validate_request_semantics`)
/// 3. Security validation (`security::validate_request_security`)
///
/// # Arguments
/// * `request`: The [`McpRequest`] to validate.
///
/// # Returns
/// * `Ok(())` if the request passes all validation stages.
/// * `Err(MCPError::ValidationError)` wrapping the specific error from the failed stage.
pub fn validate_request(request: &McpRequest) -> Result<()> {
    // Stage 1: Syntax
    syntax::validate_request_syntax(request).map_err(|e| {
        MCPError::ValidationError {
            stage: "Syntax".to_string(),
            source: Box::new(e),
        }
    })?;

    // Stage 2: Semantics
    semantics::validate_request_semantics(request).map_err(|e| {
        MCPError::ValidationError {
            stage: "Semantics".to_string(),
            source: Box::new(e),
        }
    })?;

    // Stage 3: Security (Signature)
    security::validate_request_security(request).map_err(|e| {
        MCPError::ValidationError {
            stage: "Security".to_string(),
            source: Box::new(e),
        }
    })?;

    Ok(())
}

// TODO: Consider adding validate_response which would call relevant functions
// in syntax, semantics (if needed), and security submodules. 