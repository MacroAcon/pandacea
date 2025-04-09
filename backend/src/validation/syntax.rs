use crate::error::{Result, MCPError};
use crate::types::{McpRequest, purpose_dna::PurposeCategory, permission_specification::Action};
use crate::utils::{chrono_from_prost_timestamp, is_purpose_expired};
use chrono::{Utc, Duration};

/// Validates the syntax of an [`McpRequest`] without checking signatures or semantics.
///
/// Checks required fields, formats, valid timestamps, non-expiration, etc.
/// Uses `try_from` for validating enum values (PurposeCategory, Action).
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

    // Validate Purpose Category using try_from
    match PurposeCategory::try_from(purpose.primary_purpose_category) {
        Ok(PurposeCategory::Unspecified) => return Err(MCPError::invalid_field(
            "request.purpose_dna.primary_purpose_category",
            "Primary purpose category must be specified (cannot be UNSPECIFIED)"
        )),
        Err(_) => return Err(MCPError::invalid_field(
            "request.purpose_dna.primary_purpose_category",
            &format!("Invalid purpose category value: {}", purpose.primary_purpose_category)
        )),
        Ok(_) => {} // Valid category
    }

    if purpose.specific_purpose_description.is_empty() {
        return Err(MCPError::missing_field("request.purpose_dna.specific_purpose_description"));
    }
    if purpose.data_types_involved.is_empty() {
        return Err(MCPError::missing_field("request.purpose_dna.data_types_involved"));
    }

    // Check for purpose expiration
    if is_purpose_expired(purpose) {
        let expiry_msg = purpose.purpose_expiry_timestamp.as_ref()
            .and_then(chrono_from_prost_timestamp)
            .map(|expiry| MCPError::expired_purpose(expiry))
            .unwrap_or_else(|| MCPError::expired_purpose_without_timestamp());
        return Err(expiry_msg);
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

        // Validate Action using try_from
        match Action::try_from(permission.requested_action) {
            Ok(Action::Unspecified) => return Err(MCPError::invalid_field(
                &format!("request.permissions[{}].requested_action", i),
                "Action cannot be UNSPECIFIED"
            )),
            Err(_) => return Err(MCPError::invalid_field(
                &format!("request.permissions[{}].requested_action", i),
                &format!("Invalid action value: {}", permission.requested_action)
            )),
            Ok(_) => {} // Valid action
        }
    }

    // 6. Check for request expiration
    if let Some(expiry) = request.request_expiry.as_ref() {
        let expiry_time = chrono_from_prost_timestamp(expiry)
            .ok_or_else(|| MCPError::invalid_field(
                "request.request_expiry",
                "Invalid expiry timestamp format or value"
            ))?;
        if expiry_time <= request_time {
            return Err(MCPError::invalid_field(
                "request.request_expiry",
                "Expiry timestamp must be after the request timestamp"
            ));
        }
        if expiry_time <= Utc::now() {
            return Err(MCPError::expired_request(expiry_time));
        }
    }

    // 7. Validate signature structure (just checks for presence and non-empty fields)
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

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*; // Bring parent module stuff into scope
    use crate::types::{ RequestorIdentity, PurposeDna, PermissionSpecification, Signature };
    use crate::crypto::KeyPair;
    use crate::test_utils::test_utils::*; // Import test helpers
    use prost_types::Timestamp;
    use bytes::Bytes;

    // --- Syntax Validation Tests ---
    // Most syntax tests would involve creating variations of valid requests

    #[test]
    fn test_syntax_valid_request() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("resource1", Action::Read, None)]
        );
        assert!(validate_request_syntax(&request).is_ok());
    }

    #[test]
    fn test_syntax_missing_request_id() {
        let key_pair = KeyPair::generate().unwrap();
        let mut request = create_signed_request(
            &key_pair,
            PurposeCategory::Analytics,
            vec![create_test_permission("data", Action::Read, None)]
        );
        request.request_id = "".to_string(); // Make invalid
        // Re-signing might be needed if ID is part of payload, but syntax check doesn't care
        let result = validate_request_syntax(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::MissingField { field } if field == "request.request_id"));
    }

    #[test]
    fn test_syntax_missing_identity() {
        let key_pair = KeyPair::generate().unwrap();
        let mut request = create_signed_request(
            &key_pair,
            PurposeCategory::Analytics,
            vec![create_test_permission("data", Action::Read, None)]
        );
        request.requestor_identity = None; // Make invalid
        let result = validate_request_syntax(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::MissingField { field } if field == "request.requestor_identity"));
    }

     #[test]
    fn test_syntax_invalid_purpose_category_unspecified() {
        let key_pair = KeyPair::generate().unwrap();
        let mut request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations, // Start valid
            vec![create_test_permission("data", Action::Read, None)]
        );
        // Manually set to invalid category after creation
        if let Some(purpose) = request.purpose_dna.as_mut() {
            purpose.primary_purpose_category = PurposeCategory::Unspecified as i32;
        }
        let result = validate_request_syntax(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field == "request.purpose_dna.primary_purpose_category"));
    }

    #[test]
    fn test_syntax_invalid_purpose_category_value() {
        let key_pair = KeyPair::generate().unwrap();
        let mut request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("data", Action::Read, None)]
        );
        // Manually set to invalid category value
        if let Some(purpose) = request.purpose_dna.as_mut() {
            purpose.primary_purpose_category = 999; // Assume 999 is not a valid PurposeCategory
        }
        let result = validate_request_syntax(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field == "request.purpose_dna.primary_purpose_category"));
    }

    #[test]
    fn test_syntax_invalid_action_unspecified() {
        let key_pair = KeyPair::generate().unwrap();
        let mut request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("data", Action::Read, None)] // Start valid
        );
        // Manually set action to invalid
        if let Some(perm) = request.permissions.get_mut(0) {
            perm.requested_action = Action::Unspecified as i32;
        }
        let result = validate_request_syntax(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field.contains("requested_action")));
    }

    #[test]
    fn test_syntax_invalid_action_value() {
        let key_pair = KeyPair::generate().unwrap();
        let mut request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("data", Action::Read, None)]
        );
        // Manually set action to invalid value
         if let Some(perm) = request.permissions.get_mut(0) {
            perm.requested_action = 999; // Assume 999 is not a valid Action
        }
        let result = validate_request_syntax(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field.contains("requested_action")));
    }

    #[test]
    fn test_syntax_missing_permissions() {
         let key_pair = KeyPair::generate().unwrap();
         let identity = create_test_identity(&key_pair);
         let purpose = create_base_test_purpose(PurposeCategory::Operations, vec![]);
         // Create request with empty permissions using builder or manually
         let request = McpRequest {
             request_id: "req-test-noperm".to_string(),
             timestamp: Some(current_prost_timestamp()),
             requestor_identity: Some(identity),
             purpose_dna: Some(purpose),
             permissions: vec![], // Empty permissions
             context_data: None,
             request_expiry: None,
             signature: None, // Signature check is separate stage
             mcp_version: "1.0.0".to_string(),
             // .. other fields if necessary
         };
        let result = validate_request_syntax(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::MissingField { field, .. } if field.contains("request.permissions")));
    }

    // Add more tests for: expired request, expired purpose, invalid timestamps, missing signature fields etc.

} 