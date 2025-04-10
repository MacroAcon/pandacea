// src/validation/mod.rs

pub mod syntax;
pub mod semantics;
pub mod security;

use crate::error::{Result, MCPError};
use crate::types::{McpRequest, McpResponse};

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

/// Validates the structure, semantics, and security of an [`McpResponse`].
///
/// This is the main entry point for response validation. It sequentially calls validation
/// checks from the submodules:
/// 1. Syntax validation (`syntax::validate_response_syntax`)
/// 2. Semantic validation (if needed in the future)
/// 3. Security validation (`security::validate_response_security`)
///
/// # Arguments
/// * `response`: The [`McpResponse`] to validate.
///
/// # Returns
/// * `Ok(())` if the response passes all validation stages.
/// * `Err(MCPError::ValidationError)` wrapping the specific error from the failed stage.
pub fn validate_response(response: &McpResponse) -> Result<()> {
    // Stage 1: Syntax
    syntax::validate_response_syntax(response).map_err(|e| {
        MCPError::ValidationError {
            stage: "Syntax".to_string(),
            source: Box::new(e),
        }
    })?;

    // Stage 2: Semantics (if needed in the future)
    // Currently skipped as response semantics are simpler than request semantics
    // But we can add this later if needed

    // Stage 3: Security (Signature)
    security::validate_response_security(response).map_err(|e| {
        MCPError::ValidationError {
            stage: "Security".to_string(),
            source: Box::new(e),
        }
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::*;
    use crate::crypto::KeyPair;
    use crate::types::purpose_dna::PurposeCategory;
    use crate::types::permission_specification::Action;

    #[test]
    fn test_validate_request_valid() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("user.email", Action::Read, None)]
        );

        assert!(validate_request(&request).is_ok());
    }

    #[test]
    fn test_validate_response_valid() {
        let (key_pair, request) = create_valid_signed_request_for_security_tests();
        let response = create_signed_response(
            &key_pair,
            &request,
            McpResponse_Status::APPROVED,
            None
        );

        assert!(validate_response(&response).is_ok());
    }
} 