use crate::error::{Result, MCPError};
use crate::types::{McpRequest, purpose_dna::PurposeCategory, permission_specification::Action};
use crate::utils::{chrono_from_prost_timestamp, is_purpose_expired, get_request_timestamp, get_expiry_timestamp};
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
    let timestamp = get_request_timestamp(request)
        .ok_or_else(|| MCPError::missing_field("request.request_time (timestamp or request_timestamp)"))?;

    let request_time = chrono_from_prost_timestamp(timestamp)
        .ok_or_else(|| MCPError::invalid_field(
            "request.request_time",
            "Invalid timestamp format or value"
        ))?;

    // Check timestamp is not too far in the future or past
    let now = Utc::now();
    if request_time > now + Duration::minutes(5) {
        return Err(MCPError::invalid_field(
            "request.request_time",
            format!("Timestamp too far in the future: {}", request_time)
        ));
    }
    if request_time < now - Duration::hours(24) {
        return Err(MCPError::invalid_field(
            "request.request_time",
            format!("Timestamp too far in the past: {}", request_time)
        ));
    }

    // 3. Check requestor_identity exists and has valid fields
    let identity = request.requestor_identity.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.requestor_identity"))?;
    if identity.pseudonym_id.is_empty() {
        return Err(MCPError::missing_field("request.requestor_identity.pseudonym_id"));
    }
    if let Some(public_key) = &identity.public_key {
        if public_key.is_empty() {
            return Err(MCPError::missing_field("request.requestor_identity.public_key"));
        }
    } else {
        return Err(MCPError::missing_field("request.requestor_identity.public_key"));
    }

    // 4. Validate purpose_dna
    let purpose = request.purpose_dna.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.purpose_dna"))?;
    if purpose.purpose_id.is_empty() {
        return Err(MCPError::missing_field("request.purpose_dna.purpose_id"));
    }

    // Validate Purpose Category using try_from
    if let Some(primary_category) = purpose.primary_purpose_category {
        match PurposeCategory::try_from(primary_category) {
            Ok(PurposeCategory::Unspecified) => return Err(MCPError::invalid_field(
                "request.purpose_dna.primary_purpose_category",
                "Primary purpose category must be specified (cannot be UNSPECIFIED)"
            )),
            Err(_) => return Err(MCPError::invalid_field(
                "request.purpose_dna.primary_purpose_category",
                &format!("Invalid purpose category value: {}", primary_category)
            )),
            Ok(_) => {} // Valid category
        }
    } else if let Some(category) = &purpose.category {
        if *category == PurposeCategory::Unspecified {
            return Err(MCPError::invalid_field(
                "request.purpose_dna.category",
                "Purpose category must be specified (cannot be UNSPECIFIED)"
            ));
        }
    } else {
        return Err(MCPError::missing_field("request.purpose_dna.category or request.purpose_dna.primary_purpose_category"));
    }

    if purpose.specific_purpose_description.is_empty() && purpose.description.is_empty() {
        return Err(MCPError::missing_field("request.purpose_dna.description or request.purpose_dna.specific_purpose_description"));
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

    // 5. Check permissions 
    let has_permissions = !request.permissions.is_empty();
    let has_permission_spec = request.permission_specification.is_some();
    
    if !has_permissions && !has_permission_spec {
        return Err(MCPError::missing_field("request.permission_specification or request.permissions"));
    }
    
    // Validate if we have individual permissions list
    if has_permissions {
        for (i, permission) in request.permissions.iter().enumerate() {
            if permission.resource_id.is_empty() {
                return Err(MCPError::missing_field(
                    &format!("request.permissions[{}].resource_id", i)
                ));
            }

            // Validate Action using try_from
            if let Some(action) = &permission.action {
                if *action == Action::Unspecified {
                    return Err(MCPError::invalid_field(
                        &format!("request.permissions[{}].action", i),
                        "Action cannot be UNSPECIFIED"
                    ));
                }
            } else {
                return Err(MCPError::missing_field(
                    &format!("request.permissions[{}].action", i)
                ));
            }
        }
    }
    
    // Validate the permission specification if it exists
    if has_permission_spec {
        let permission = request.permission_specification.as_ref().unwrap();
        if permission.resource_id.is_empty() {
            return Err(MCPError::missing_field("request.permission_specification.resource_id"));
        }
        
        // Validate Action using try_from
        if let Some(action) = &permission.action {
            if *action == Action::Unspecified {
                return Err(MCPError::invalid_field(
                    "request.permission_specification.action",
                    "Action cannot be UNSPECIFIED"
                ));
            }
        } else {
            return Err(MCPError::missing_field("request.permission_specification.action"));
        }
    }

    // 6. Check for request expiration
    let expiry_timestamp = get_expiry_timestamp(request);
    
    if let Some(expiry) = expiry_timestamp {
        let expiry_time = chrono_from_prost_timestamp(expiry)
            .ok_or_else(|| MCPError::invalid_field(
                "request.expiry_time",
                "Invalid expiry timestamp format or value"
            ))?;
        if expiry_time <= request_time {
            return Err(MCPError::invalid_field(
                "request.expiry_time",
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

/// Validates the syntax of an [`McpResponse`] without checking signatures or semantics.
///
/// Checks required fields, formats, valid timestamps, etc.
///
/// # Arguments
/// * `response`: The [`McpResponse`] to validate.
///
/// # Returns
/// * `Ok(())` if the response passes syntax validation.
/// * `Err(MCPError)` specific to the validation failure.
pub fn validate_response_syntax(response: &McpResponse) -> Result<()> {
    // 1. Check required string fields are non-empty
    if response.request_id.is_empty() {
        return Err(MCPError::missing_field("response.request_id"));
    }

    // 2. Check timestamp exists and is within reasonable range
    let timestamp = response.response_timestamp.as_ref()
        .ok_or_else(|| MCPError::missing_field("response.response_timestamp"))?;

    let response_time = chrono_from_prost_timestamp(timestamp)
        .ok_or_else(|| MCPError::invalid_field(
            "response.response_timestamp",
            "Invalid timestamp format or value"
        ))?;

    // Check timestamp is not too far in the future or past
    let now = Utc::now();
    if response_time > now + Duration::minutes(5) {
        return Err(MCPError::invalid_field(
            "response.response_timestamp",
            format!("Timestamp too far in the future: {}", response_time)
        ));
    }
    if response_time < now - Duration::hours(24) {
        return Err(MCPError::invalid_field(
            "response.response_timestamp",
            format!("Timestamp too far in the past: {}", response_time)
        ));
    }

    // 3. Check status is valid
    if response.status == crate::mcp::McpResponse_Status::Unspecified as i32 {
        return Err(MCPError::invalid_field(
            "response.status",
            "Status cannot be UNSPECIFIED"
        ));
    }

    // 4. Check responder_identity exists and has valid fields
    let identity = response.responder_identity.as_ref()
        .ok_or_else(|| MCPError::missing_field("response.responder_identity"))?;
    if identity.pseudonym_id.is_empty() {
        return Err(MCPError::missing_field("response.responder_identity.pseudonym_id"));
    }

    // 5. For "PartiallyApproved" status, each permission must have a status
    if response.status == crate::mcp::McpResponse_Status::PartiallyApproved as i32 {
        if response.permission_status.is_empty() {
            return Err(MCPError::missing_field(
                "response.permission_status (array cannot be empty for PARTIALLY_APPROVED status)"
            ));
        }
    }

    // 6. Validate signature structure
    let signature = response.signature.as_ref()
        .ok_or_else(|| MCPError::missing_field("response.signature"))?;
    if signature.key_id.is_empty() {
        return Err(MCPError::missing_field("response.signature.key_id"));
    }
    if signature.algorithm.is_empty() {
        return Err(MCPError::missing_field("response.signature.algorithm"));
    }
    if signature.signature.is_empty() {
        return Err(MCPError::missing_field("response.signature.signature"));
    }

    // 7. Check MCP version is specified
    if response.mcp_version.is_empty() {
        return Err(MCPError::missing_field("response.mcp_version"));
    }

    // 8. Validate compensation receipt if present
    if let Some(receipt) = &response.compensation_receipt {
        if receipt.receipt_id.is_empty() {
            return Err(MCPError::missing_field("response.compensation_receipt.receipt_id"));
        }
        
        if receipt.status == crate::mcp::compensation_receipt::PaymentStatus::Unspecified as i32 {
            return Err(MCPError::invalid_field(
                "response.compensation_receipt.status",
                "Payment status cannot be UNSPECIFIED"
            ));
        }
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

    // --- Response Syntax Validation Tests ---
    
    #[test]
    fn test_syntax_valid_response() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("resource1", Action::Read, None)]
        );
        let response = create_signed_response(
            &key_pair,
            &request,
            McpResponse_Status::APPROVED,
            None
        );
        
        assert!(validate_response_syntax(&response).is_ok());
    }
    
    #[test]
    fn test_syntax_missing_response_id() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("resource1", Action::Read, None)]
        );
        let mut response = create_signed_response(
            &key_pair,
            &request,
            McpResponse_Status::APPROVED,
            None
        );
        
        response.response_id = "".to_string(); // Make invalid
        
        let result = validate_response_syntax(&response);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::MissingField { field } if field == "response.response_id"));
    }
    
    #[test]
    fn test_syntax_invalid_status() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("resource1", Action::Read, None)]
        );
        let mut response = create_signed_response(
            &key_pair,
            &request,
            McpResponse_Status::APPROVED,
            None
        );
        
        response.status = 99; // Invalid status value
        
        let result = validate_response_syntax(&response);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field == "response.status"));
    }
    
    #[test]
    fn test_syntax_partially_approved_missing_statuses() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![
                create_test_permission("resource1", Action::Read, None),
                create_test_permission("resource2", Action::Write, None)
            ]
        );
        let mut response = create_signed_response(
            &key_pair,
            &request,
            McpResponse_Status::PARTIALLY_APPROVED,
            None // Missing permission statuses
        );
        
        let result = validate_response_syntax(&response);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::MissingField { field } if field.contains("permission_statuses")));
    }
} 