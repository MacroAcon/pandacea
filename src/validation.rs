//! Validation logic for MCP messages (syntax, semantics, security).

use crate::error::{MCPError, Result};
use crate::types::*; // Import all types
use crate::crypto::{verify_request_signature, verify_response_signature}; // Assuming crypto.rs
use crate::utils::{chrono_from_prost_timestamp, is_request_expired, is_purpose_expired, prost_struct_to_hashmap}; // Assuming utils.rs
use chrono::{Utc, DateTime, Duration};
use prost_types::{Struct, Timestamp}; // Timestamp needed for syntax check comparison
use std::collections::HashMap; // For constraint checking maybe

// --- Main Validation Entry Points ---

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
    // Stage 1: Syntax
    validate_request_syntax(request).map_err(|e| {
        MCPError::ValidationError { stage: "Syntax".to_string(), source: Box::new(e) }
    })?;

    // Stage 2: Semantics (Placeholder)
    validate_request_semantics(request).map_err(|e| {
         MCPError::ValidationError { stage: "Semantics".to_string(), source: Box::new(e) }
    })?;

    // Stage 3: Security (Signature)
    validate_request_security(request).map_err(|e| {
         MCPError::ValidationError { stage: "Security".to_string(), source: Box::new(e) }
    })?;

    Ok(())
}

// TODO: Add `validate_response` function if needed, following a similar pattern.
// pub fn validate_response(response: &McpResponse, responder_public_key: &[u8]) -> Result<()> { ... }


// --- Validation Stages ---

/// Validates the syntax of an [`McpRequest`] without checking signatures or semantics.
///
/// Checks required fields, formats, valid timestamps, non-expiration, etc.
///
/// # Arguments
/// * `request`: The [`McpRequest`] to validate.
///
/// # Returns
/// * `Ok(())` if the request passes syntax validation.
/// * `Err(MCPError)` specific to the validation failure.
pub fn validate_request_syntax(request: &McpRequest) -> Result<()> {
    // 1. Check required string fields are non-empty
    if request.request_id.is_empty() {
        return Err(MCPError::missing_field("request.request_id"));
    }

    // 2. Check timestamp exists and is within reasonable range
    let timestamp = request.timestamp.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.timestamp"))?;

    let request_time = chrono_from_prost_timestamp(timestamp)
        .ok_or_else(|| MCPError::invalid_field(
            "request.timestamp",
            "Invalid timestamp format or value"
        ))?;

    // Check timestamp is not too far in the future or past
    let now = Utc::now();
    if request_time > now + Duration::minutes(5) {
        return Err(MCPError::invalid_field(
            "request.timestamp",
            format!("Timestamp too far in the future: {}", request_time)
        ));
    }

    if request_time < now - Duration::hours(24) {
        return Err(MCPError::invalid_field(
            "request.timestamp",
            format!("Timestamp too far in the past: {}", request_time)
        ));
    }

    // 3. Check requestor_identity exists and has valid fields
    let identity = request.requestor_identity.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.requestor_identity"))?;

    if identity.pseudonym_id.is_empty() {
        return Err(MCPError::missing_field("request.requestor_identity.pseudonym_id"));
    }

    if identity.public_key.is_empty() {
        return Err(MCPError::missing_field("request.requestor_identity.public_key"));
    }

    // 4. Validate purpose_dna
    let purpose = request.purpose_dna.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.purpose_dna"))?;

    if purpose.purpose_id.is_empty() {
        return Err(MCPError::missing_field("request.purpose_dna.purpose_id"));
    }

    if purpose.primary_purpose_category == 0 { // UNSPECIFIED - Assuming 0 maps to UNSPECIFIED
        return Err(MCPError::invalid_field(
            "request.purpose_dna.primary_purpose_category",
            "Primary purpose category must be specified"
        ));
    }

    if purpose.specific_purpose_description.is_empty() {
        return Err(MCPError::missing_field("request.purpose_dna.specific_purpose_description"));
    }

    if purpose.data_types_involved.is_empty() {
        return Err(MCPError::missing_field("request.purpose_dna.data_types_involved"));
    }

    // Check for purpose expiration
    if is_purpose_expired(purpose) {
        if let Some(expiry) = purpose.purpose_expiry_timestamp.as_ref()
            .and_then(chrono_from_prost_timestamp) {
            return Err(MCPError::expired_purpose(expiry));
        } else {
             // This case might indicate an invalid expiry timestamp in an expired purpose,
             // but the primary issue is the expiration itself.
             // Alternatively, could return an invalid_field error for the timestamp.
            return Err(MCPError::expired_purpose_without_timestamp());
        }
    }

    // 5. Check permissions array is not empty and each permission is valid
    if request.permissions.is_empty() {
        return Err(MCPError::missing_field("request.permissions (array cannot be empty)"));
    }

    for (i, permission) in request.permissions.iter().enumerate() {
        if permission.resource_identifier.is_empty() {
            return Err(MCPError::missing_field(
                &format!("request.permissions[{}].resource_identifier", i)
            ));
        }

        // Check action is a valid enum value (assuming 0 is UNSPECIFIED and valid actions are 1-4)
        // This might need adjustment based on the actual proto enum definition
        match permission.requested_action {
            0 => return Err(MCPError::invalid_field(
                &format!("request.permissions[{}].requested_action", i),
                "Action cannot be UNSPECIFIED"
            )),
            action if action < 0 || action > 4 => return Err(MCPError::invalid_field( // Adjust max value if needed
                &format!("request.permissions[{}].requested_action", i),
                &format!("Invalid action value: {}", action)
            )),
            _ => {} // Valid action
        }
    }

    // 6. Check for request expiration
    if let Some(expiry) = request.request_expiry.as_ref() {
        let expiry_time = chrono_from_prost_timestamp(expiry)
            .ok_or_else(|| MCPError::invalid_field(
                "request.request_expiry",
                "Invalid expiry timestamp format or value"
            ))?;

        // Ensure expiry is after the request timestamp
        if expiry_time <= request_time {
            return Err(MCPError::invalid_field(
                "request.request_expiry",
                "Expiry timestamp must be after the request timestamp"
            ));
        }

        // Check if already expired
        if expiry_time <= now {
            return Err(MCPError::expired_request(expiry_time));
        }
    }

    // 7. Validate signature structure (actual verification is done separately)
    let signature = request.signature.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.signature"))?;

    if signature.key_id.is_empty() {
        return Err(MCPError::missing_field("request.signature.key_id"));
    }

    if signature.algorithm.is_empty() {
        return Err(MCPError::missing_field("request.signature.algorithm"));
    }

    if signature.signature.is_empty() {
        return Err(MCPError::missing_field("request.signature.signature"));
    }

    // 8. Check MCP version is specified
    if request.mcp_version.is_empty() {
        return Err(MCPError::missing_field("request.mcp_version"));
    }

    // All validation checks passed
    Ok(())
}


/// Validates the semantic coherence of an [`McpRequest`].
/// (Placeholder - Currently does nothing).
///
/// This stage checks relationships between fields, e.g.:
/// - Does the `purpose_dna.primary_purpose_category` align with the requested `permissions`?
/// - Are the `purpose_dna.data_types_involved` consistent with the resources in `permissions`?
/// - Does the `requestor_identity` meet policy requirements for the requested action/purpose?
/// - Evaluate complex constraints not handled in basic syntax/security checks.
///
/// # Arguments
/// * `request`: The [`McpRequest`] to validate.
///
/// # Returns
/// * `Ok(())` if semantic checks pass.
/// * `Err(MCPError)` if a semantic violation is found (e.g., `InvalidField`, `ConstraintEvaluationError`).
pub fn validate_request_semantics(_request: &McpRequest) -> Result<()> {
    // TODO: Implement semantic validation rules based on MCP specification and policies.
    // Example checks (pseudo-code):
    // - if request.purpose_dna.category == Research && request.permissions.iter().any(|p| p.action == Action::Delete) -> Err(...)
    // - check_data_type_consistency(request.purpose_dna.data_types, request.permissions.resource_ids)?
    // - evaluate_complex_constraints(request.permissions.constraints, context)? // Requires context
    Ok(())
}


/// Validates the security aspects of an [`McpRequest`], primarily its cryptographic signature.
///
/// This is typically the final stage in the validation pipeline, performed after
/// syntax (`validate_request_syntax`) and potentially semantic validation checks
/// have passed.
///
/// It assumes the basic structure of the request, including the presence and format
/// of the `requestor_identity` (containing the public key) and the `signature` fields,
/// have already been validated syntactically. It relies on the `crypto::verify_request_signature`
/// function to perform the actual cryptographic verification, which includes:
///   - Canonical serialization of the request (excluding the signature field).
///   - Checking the signature algorithm against supported types.
///   - Verifying the signature bytes against the serialized data and the requestor's public key.
///
/// # Arguments
/// * `request`: The [`McpRequest`] to validate.
///
/// # Returns
/// * `Ok(())` if the signature is present and cryptographically valid according to
///   the public key in `requestor_identity` and the algorithm specified in the signature.
/// * `Err(MCPError::MissingSignature)` if the `signature` field is absent.
/// * `Err(MCPError::InvalidSignature)` if the signature verification fails (e.g., tampered data, wrong key).
/// * `Err(MCPError::UnsupportedAlgorithm)` if the signature algorithm is not supported by the crypto backend.
/// * `Err(MCPError::CryptoError)` for other cryptographic operation failures during verification.
/// * `Err(MCPError::SerializationError)` if preparing the message for signing verification fails internally.
pub fn validate_request_security(request: &McpRequest) -> Result<()> {
    // 1. Ensure the signature field exists.
    //    Syntax validation should ideally catch missing sub-fields within the signature if it exists,
    //    but this check ensures the entire signature structure is present.
    if request.signature.is_none() {
        return Err(MCPError::MissingSignature);
    }

    // 2. Delegate to the crypto module for actual verification.
    //    This function handles the canonical serialization and crypto checks internally.
    //    It will return Ok(()) on success or map internal errors to appropriate
    //    MCPError variants (InvalidSignature, UnsupportedAlgorithm, CryptoError, SerializationError).
    verify_request_signature(request)
}


// --- Constraint Evaluation (Placeholder) ---

/// Represents the context needed to evaluate constraints (e.g., current time, requestor info).
/// (Placeholder Structure)
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub current_time: DateTime<Utc>,
    pub requestor_trust_level: u32, // Example context field
    // Add other relevant context fields: location, device state, previous interactions etc.
}

/// Represents the outcome of evaluating constraints (`Passed` or `Failed(reason)`).
#[derive(Debug, PartialEq, Eq)]
pub enum ConstraintResult {
    Passed,
    Failed(String),
}

/// Evaluates constraints defined in a `PermissionSpecification`'s `constraints` field.
/// (Placeholder Implementation)
///
/// Takes an optional Protobuf `Struct` representing the constraints and a [`RequestContext`].
/// Checks implemented constraint types (e.g., time window, frequency) against the context.
///
/// **Note:** This is a basic placeholder. A real implementation would need:
/// - A way to parse the constraint keys and values robustly.
/// - Logic for each supported constraint type (time range, location, rate limit, attribute match, etc.).
/// - Access to the necessary `RequestContext` data.
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
) -> Result<ConstraintResult> {
    let Some(constraints_struct) = constraints else {
        return Ok(ConstraintResult::Passed); // No constraints to evaluate
    };

    // Convert Prost Struct to HashMap for easier access (can fail)
    let constraint_map = prost_struct_to_hashmap(Some(constraints_struct))?;

     // --- Example Constraint Checks ---

     // 1. Time Window Constraint (Example)
     if let Some(serde_json::Value::String(start_time_str)) = constraint_map.get("valid_after") {
        match start_time_str.parse::<DateTime<Utc>>() {
            Ok(start_time) => {
                if context.current_time < start_time {
                    return Ok(ConstraintResult::Failed(format!(
                        "Constraint violation: Request time {} is before valid_after {}",
                        context.current_time, start_time
                    )));
                }
            }
            Err(_) => return Err(MCPError::ConstraintEvaluationError {
                constraint_key: "valid_after".to_string(),
                reason: format!("Invalid ISO8601 timestamp format: {}", start_time_str)
            }),
        }
    }
     if let Some(serde_json::Value::String(end_time_str)) = constraint_map.get("valid_before") {
         match end_time_str.parse::<DateTime<Utc>>() {
             Ok(end_time) => {
                 if context.current_time >= end_time {
                     return Ok(ConstraintResult::Failed(format!(
                         "Constraint violation: Request time {} is not before valid_before {}",
                         context.current_time, end_time
                     )));
                 }
             }
             Err(_) => return Err(MCPError::ConstraintEvaluationError {
                 constraint_key: "valid_before".to_string(),
                 reason: format!("Invalid ISO8601 timestamp format: {}", end_time_str)
             }),
         }
     }

     // 2. Requestor Trust Level Constraint (Example)
     if let Some(serde_json::Value::Number(min_level_num)) = constraint_map.get("min_trust_level") {
         if let Some(min_level) = min_level_num.as_u64() {
             if (context.requestor_trust_level as u64) < min_level {
                  return Ok(ConstraintResult::Failed(format!(
                     "Constraint violation: Requestor trust level {} is below required minimum {}",
                     context.requestor_trust_level, min_level
                 )));
             }
         } else {
              return Err(MCPError::ConstraintEvaluationError {
                 constraint_key: "min_trust_level".to_string(),
                 reason: format!("Invalid number format for trust level: {}", min_level_num)
             });
         }
     }
     
     // 3. Location Constraint (Example) - Requires context.location
     // if let Some(serde_json::Value::String(required_region)) = constraint_map.get("required_region") {
     //     if context.location.region != *required_region {
     //         return Ok(ConstraintResult::Failed(...));
     //     }
     // }

     // TODO: Add checks for other known constraint keys...

     // If all implemented checks pass:
     Ok(ConstraintResult::Passed)
}


// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*; // Import validation functions
    use crate::builders::McpRequestBuilder;
    use crate::crypto::{self, KeyPair, sign_request}; // Import crypto helpers
    use crate::types::{RequestorIdentity, PurposeDna, PermissionSpecification, Action, CryptoSignature};
    use bytes::Bytes;
    use prost_types::Timestamp;
    use chrono::Utc;

    // --- Test Helpers --- 
    // (These might ideally live in a shared test_utils module)
    fn create_test_identity(key_pair: &KeyPair) -> RequestorIdentity {
        RequestorIdentity {
            pseudonym_id: format!("test-validator-{}", Utc::now().timestamp_nanos()),
            public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()),
            attestations: vec![],
        }
    }

    fn create_test_purpose() -> PurposeDna {
        PurposeDna {
            purpose_id: format!("test-purpose-{}", Utc::now().timestamp_nanos()),
            primary_purpose_category: 1, // Example
            specific_purpose_description: "Validate security test".to_string(),
            data_types_involved: vec!["test_sec_data".into()],
             processing_description: "Sign and verify".into(),
             storage_description: "Ephemeral".into(),
             ..Default::default()
        }
    }

    fn create_test_permission() -> PermissionSpecification {
        PermissionSpecification {
            resource_identifier: "sec-test-resource".to_string(),
            requested_action: Action::Read as i32,
            ..Default::default()
        }
    }

    fn create_and_sign_test_request() -> (KeyPair, McpRequest) {
        let key_pair = KeyPair::generate().expect("Key generation failed");
        let identity = create_test_identity(&key_pair);
        let purpose = create_test_purpose();
        let permission = create_test_permission();
        let mut request = McpRequestBuilder::new(identity, purpose, "1.0.0".to_string())
            .add_permission(permission)
            .build();
        
        // Sign the request
        let key_id = "key-for-signing".to_string();
        sign_request(&mut request, &key_pair, key_id).expect("Signing failed");
        
        (key_pair, request)
    }
    // --- End Test Helpers ---

    #[test]
    fn test_validate_security_valid_signature() {
        let (_key_pair, request) = create_and_sign_test_request();
        
        // Assume syntax validation passed
        // validate_request_syntax(&request).expect("Syntax validation failed");
        
        let result = validate_request_security(&request);
        assert!(result.is_ok(), "Validation failed for a valid signature: {:?}", result.err());
    }

    #[test]
    fn test_validate_security_missing_signature() {
        let (key_pair, request_shell) = create_and_sign_test_request();
        // Create a request *without* signing it
        let identity = create_test_identity(&key_pair);
        let purpose = create_test_purpose();
        let request_no_sig = McpRequestBuilder::new(identity, purpose, "1.0.0".to_string()).build();
        
        assert!(request_no_sig.signature.is_none()); // Pre-condition check

        let result = validate_request_security(&request_no_sig);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::MissingSignature), "Expected MissingSignature error");
    }

    #[test]
    fn test_validate_security_invalid_signature_wrong_key() {
        let (_signing_key, mut request) = create_and_sign_test_request();
        
        // Create a *different* key pair but keep the public key in the request identity the same
        let wrong_key_pair = KeyPair::generate().expect("Failed to generate wrong key");
        
        // Sign with the wrong key - create a bad signature manually
        let bytes_to_sign = crate::serialization::prepare_request_for_signing(&request).unwrap();
        let bad_signature_bytes = wrong_key_pair.sign(&bytes_to_sign);
        
        // Replace the signature with the bad one
        let original_signature = request.signature.clone().unwrap(); // Keep key_id and algo
        request.signature = Some(CryptoSignature {
            key_id: original_signature.key_id,
            algorithm: original_signature.algorithm,
            signature: Bytes::copy_from_slice(&bad_signature_bytes),
        });
        
        let result = validate_request_security(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidSignature { .. }), "Expected InvalidSignature error for wrong key");
    }

    #[test]
    fn test_validate_security_tampered_field() {
        let (_key_pair, mut request) = create_and_sign_test_request();
        
        // Tamper with a field *after* signing
        request.mcp_version = "1.1.0-tampered".to_string(); // Change version
        
        let result = validate_request_security(&request);
        assert!(result.is_err());
        // verify_request_signature should detect this and return InvalidSignature
        assert!(matches!(result.unwrap_err(), MCPError::InvalidSignature { .. }), "Expected InvalidSignature error for tampered data");
    }
    
    #[test]
    fn test_validate_security_tampered_purpose() {
        let (_key_pair, mut request) = create_and_sign_test_request();
        
        // Tamper with a field *inside* purpose_dna after signing
        let mut tampered_purpose = request.purpose_dna.clone().unwrap();
        tampered_purpose.specific_purpose_description = "A different purpose!".to_string();
        request.purpose_dna = Some(tampered_purpose);
        
        let result = validate_request_security(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidSignature { .. }), "Expected InvalidSignature error for tampered purpose");
    }

    #[test]
    fn test_validate_security_unsupported_algorithm() {
        let (key_pair, mut request) = create_and_sign_test_request();
        
        // Assume the signature is valid, but change the algorithm field
        // to something the verification function won't support.
        if let Some(sig) = request.signature.as_mut() {
            sig.algorithm = "UNSUPPORTED-ALG-XYZ".to_string();
        }
        
        let result = validate_request_security(&request);
        assert!(result.is_err());
        // This relies on verify_request_signature correctly identifying and returning this error
        assert!(matches!(result.unwrap_err(), MCPError::UnsupportedAlgorithm { .. }), "Expected UnsupportedAlgorithm error");
    }

    // Optional: Test case where the key_id in signature doesn't match anything known
    // This might be handled within verify_request_signature or a layer above it.
    // For now, we assume verify_request_signature handles the core crypto check.
} 