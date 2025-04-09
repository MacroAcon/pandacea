// src/validation/semantics.rs

use crate::error::{Result, MCPError};
use crate::types::{
    McpRequest, PurposeDna, PermissionSpecification, RequestorIdentity,
    purpose_dna::PurposeCategory,
    permission_specification::Action
};
use crate::utils::prost_struct_to_hashmap;
use std::collections::{HashMap, HashSet};
use serde_json::Value;
// Potentially need chrono for constraint checking later if merged here
// use chrono::{Utc, DateTime};

/// Validates the semantic coherence of an [`McpRequest`].
///
/// This function performs a comprehensive semantic analysis of the request, checking:
/// 1. Purpose-Permission Alignment
/// 2. Data Type Consistency
/// 3. Action Appropriateness
/// 4. Advanced Constraint Validation (basic format/value checks)
///
/// Note: Context-dependent constraint evaluation (e.g., rate limits, time windows vs current time)
/// might be handled separately after this initial validation passes.
pub fn validate_request_semantics(request: &McpRequest) -> Result<()> {
    // Extract core components, assuming syntax validation already passed
    let purpose = request.purpose_dna.as_ref()
        .ok_or_else(|| MCPError::internal("PurposeDNA missing after syntax validation"))?;
    // let identity = request.requestor_identity.as_ref()
    //     .ok_or_else(|| MCPError::internal("RequestorIdentity missing after syntax validation"))?;

    // 1. Purpose-Permission Alignment Checks
    validate_purpose_permission_alignment(purpose, &request.permissions)?;

    // 2. Data Type Consistency
    validate_data_type_consistency(purpose, &request.permissions)?;

    // 3. Action Appropriateness
    validate_action_appropriateness(purpose, &request.permissions)?;

    // 4. Advanced Constraint Validation (basic checks)
    validate_advanced_constraints(request)?;

    Ok(())
}

/// Validates alignment between purpose and requested permissions
fn validate_purpose_permission_alignment(
    purpose: &PurposeDna,
    permissions: &[PermissionSpecification]
) -> Result<()> {
    // Define purpose-action compatibility matrix
    // ENSURE PurposeCategory::LegalCompliance exists and is added if needed
    let purpose_action_rules: HashMap<PurposeCategory, Vec<Action>> = HashMap::from([
        (PurposeCategory::Analytics, vec![Action::Read]),
        (PurposeCategory::Personalization, vec![Action::Read, Action::Write]),
        (PurposeCategory::ResearchDevelopment, vec![Action::Read, Action::Observe]),
        (PurposeCategory::Security, vec![Action::Read, Action::Execute]),
        (PurposeCategory::Operations, vec![Action::Read, Action::Write, Action::Execute]),
        (PurposeCategory::LegalCompliance, vec![Action::Read]), // Uncomment if LegalCompliance exists
    ]);

    // Get purpose category (should be valid after syntax check)
    let purpose_category = PurposeCategory::try_from(purpose.primary_purpose_category)
        .map_err(|_| MCPError::internal("Invalid purpose category survived syntax validation"))?;

    let allowed_actions = purpose_action_rules.get(&purpose_category)
        .ok_or_else(|| MCPError::invalid_field(
            "purpose.primary_purpose_category", // Or maybe a ConstraintViolation error type?
            format!("No semantic rules defined for purpose category {:?}", purpose_category)
        ))?;

    for permission in permissions {
        // Get action (should be valid after syntax check)
        let current_action = Action::try_from(permission.requested_action)
             .map_err(|_| MCPError::internal("Invalid action survived syntax validation"))?;

        if !allowed_actions.contains(&current_action) {
            return Err(MCPError::invalid_field(
                "permissions.requested_action", // Or maybe ConstraintViolation?
                format!(
                    "Action {:?} is not semantically compatible with purpose category {:?}",
                    current_action,
                    purpose_category
                )
            ));
        }
    }
    Ok(())
}

/// Validates consistency between data types in purpose and permissions
fn validate_data_type_consistency(
    purpose: &PurposeDna,
    permissions: &[PermissionSpecification]
) -> Result<()> {
    let purpose_data_types: HashSet<&str> = purpose.data_types_involved.iter().map(AsRef::as_ref).collect();
    for permission in permissions {
        if !purpose_data_types.contains(permission.resource_identifier.as_str()) {
            return Err(MCPError::invalid_field(
                "permissions.resource_identifier",
                // Simplified error message
                format!("Resource '{}' not declared in purpose data_types_involved", permission.resource_identifier)
            ));
        }
    }
    Ok(())
}

/// Validates the appropriateness of actions for different purpose types
fn validate_action_appropriateness(
    purpose: &PurposeDna,
    permissions: &[PermissionSpecification]
) -> Result<()> {
     let purpose_category = PurposeCategory::try_from(purpose.primary_purpose_category)
        .map_err(|_| MCPError::internal("Invalid purpose category survived syntax validation"))?;

    // Define restrictive rules for sensitive purpose categories
    match purpose_category {
        PurposeCategory::Security => {
            for permission in permissions {
                let action = Action::try_from(permission.requested_action)
                     .map_err(|_| MCPError::internal("Invalid action survived syntax validation"))?;
                // Allow only Read and Execute for Security
                if ![Action::Read, Action::Execute].contains(&action) {
                    return Err(MCPError::invalid_field(
                        "permissions.requested_action",
                        format!("Action {:?} is not permitted for Security purposes", action)
                    ));
                }
            }
        },
        PurposeCategory::LegalCompliance => { // ENSURE this variant exists
            for permission in permissions {
                 let action = Action::try_from(permission.requested_action)
                     .map_err(|_| MCPError::internal("Invalid action survived syntax validation"))?;
                 // Allow only Read for LegalCompliance
                if action != Action::Read {
                    return Err(MCPError::invalid_field(
                        "permissions.requested_action",
                        format!("Only Read actions are permitted for LegalCompliance purposes, found {:?}", action)
                    ));
                }
            }
        },
        _ => {} // No additional restrictions for other purpose types by default
    }
    Ok(())
}

/// Validates the basic structure and values of advanced constraints.
/// Does NOT perform context-dependent checks (like time comparison or rate limit state).
fn validate_advanced_constraints(request: &McpRequest) -> Result<()> {
    for permission in &request.permissions {
        if let Some(constraints) = &permission.constraints {
            let constraint_map = prost_struct_to_hashmap(Some(constraints)).map_err(|e|
               MCPError::invalid_field("permission.constraints", &format!("Failed to parse constraints: {}", e))
            )?;

            // Perform basic format/value checks on known constraint types
            validate_frequency_constraint_value(&constraint_map)?;
            validate_data_access_scope_value(&constraint_map)?;
            validate_time_based_constraint_format(&constraint_map)?;
            // Add more checks for other constraint types as needed
        }
    }
    Ok(())
}

// --- Constraint Value/Format Validation Helpers ---

/// Validates the value format for frequency constraints.
fn validate_frequency_constraint_value(constraints: &HashMap<String, Value>) -> Result<()> {
    if let Some(value) = constraints.get("max_frequency_per_hour") {
        if value.as_u64().is_none() || value.as_u64() == Some(0) { // Must be positive integer
            return Err(MCPError::invalid_field(
                "constraints.max_frequency_per_hour",
                "Invalid frequency value (must be a positive integer)"
            ));
        }
        // Placeholder limit check (could be policy based)
        let limit: u64 = 1000; // Example higher limit for syntax/semantic check
        if value.as_u64().unwrap_or(0) > limit {
             return Err(MCPError::constraint_violation(
                "max_frequency_per_hour",
                format!("Requested frequency exceeds system limit {}", limit)
            ));
        }
    }
    // Add checks for other frequency keys (per_day, etc.)
    Ok(())
}

/// Validates the value for data access scope constraints.
fn validate_data_access_scope_value(constraints: &HashMap<String, Value>) -> Result<()> {
    if let Some(Value::String(scope)) = constraints.get("data_access_scope") {
        let valid_scopes: HashSet<&str> = ["personal", "aggregated", "anonymized"].iter().cloned().collect();
        if !valid_scopes.contains(scope.as_str()) {
            return Err(MCPError::constraint_violation(
                "data_access_scope",
                format!("Invalid data access scope '{}'. Must be one of: {:?}", scope, valid_scopes)
            ));
        }
    } else if constraints.contains_key("data_access_scope") {
        // Key exists but is not a string
        return Err(MCPError::invalid_field("constraints.data_access_scope", "Must be a string value"));
    }
    Ok(())
}

/// Validates the format of time-based constraints (doesn't compare times).
fn validate_time_based_constraint_format(constraints: &HashMap<String, Value>) -> Result<()> {
    let start_str_opt = constraints.get("valid_start_time").and_then(Value::as_str);
    let end_str_opt = constraints.get("valid_end_time").and_then(Value::as_str);

    match (start_str_opt, end_str_opt) {
        (Some(start), Some(end)) => {
            // Basic format check - Use chrono parsing in a real implementation
            if !is_valid_iso8601_ish(start) || !is_valid_iso8601_ish(end) {
                return Err(MCPError::constraint_violation(
                    "time_window",
                    "Invalid time format. Use ISO8601 format (YYYY-MM-DDTHH:MM:SSZ or with offset)"
                ));
            }
            // Could add check: start < end if parsable here, but maybe leave for evaluation stage
        },
        (Some(_), None) | (None, Some(_)) => {
            // If only one is provided, it's an invalid constraint pair
            return Err(MCPError::constraint_violation(
                "time_window",
                "Both valid_start_time and valid_end_time must be provided together"
            ));
        },
        (None, None) => { /* No time window constraint present */ }
    }

    // Also check format if other time keys exist (e.g., max_duration_minutes should be number)
    if let Some(value) = constraints.get("max_duration_minutes") {
        if value.as_u64().is_none() || value.as_u64() == Some(0) {
             return Err(MCPError::invalid_field(
                "constraints.max_duration_minutes",
                "Invalid duration value (must be a positive integer)"
            ));
        }
    }

    Ok(())
}

/// Basic ISO8601-like format validation (Placeholder - use chrono parsing).
fn is_valid_iso8601_ish(time_str: &str) -> bool {
    // VERY basic check. Use chrono::DateTime::parse_from_rfc3339 in real code.
    time_str.len() >= 20 &&
    time_str.contains('T') &&
    time_str.matches(':').count() >= 2 &&
    time_str.matches('-').count() >= 2 &&
    (time_str.ends_with('Z') || time_str.contains('+') || time_str.rfind('-').map_or(false, |i| i > 10))
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ RequestorIdentity, PurposeDna, PermissionSpecification };
    use crate::crypto::KeyPair;
    use crate::test_utils::test_utils::*; // Import helpers
    use std::collections::HashMap as StdHashMap;
    use prost_types::{Struct as ProstStruct, Value as ProstValue};

    // --- Semantic Validation Tests ---

    #[test]
    fn test_semantic_purpose_permission_alignment_valid() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Analytics,
            vec![create_test_permission("data", Action::Read, None)]
        );
        // Assume syntax passed, test semantics directly
        assert!(validate_request_semantics(&request).is_ok());
    }

    #[test]
    fn test_semantic_purpose_permission_alignment_invalid() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Analytics,
            vec![create_test_permission("data", Action::Write, None)] // Invalid action
        );
        let result = validate_request_semantics(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field == "permissions.requested_action"));
    }

    #[test]
    fn test_semantic_data_type_consistency_valid() {
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("server_logs", Action::Read, None)] // Matches helper purpose
        );
        // Helper creates purpose with data_types=[resource_id], so this should pass
         assert!(validate_request_semantics(&request).is_ok());
    }

     #[test]
    fn test_semantic_data_type_consistency_invalid() {
        let key_pair = KeyPair::generate().unwrap();
        let mut request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("unknown_resource", Action::Read, None)]
        );
        // Override the purpose created by helper to ensure inconsistency
        request.purpose_dna.as_mut().unwrap().data_types_involved = vec!["server_logs".to_string()];

        let result = validate_request_semantics(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field == "permissions.resource_identifier"));
    }

    #[test]
    fn test_semantic_action_appropriateness_valid() {
        let key_pair = KeyPair::generate().unwrap();
        // Security: Read/Execute OK
        let req_sec = create_signed_request(
            &key_pair, PurposeCategory::Security,
            vec![create_test_permission("logs", Action::Read, None),
                 create_test_permission("script", Action::Execute, None)]
        );
        assert!(validate_request_semantics(&req_sec).is_ok());

        // LegalCompliance: Read OK
        let req_legal = create_signed_request(
            &key_pair, PurposeCategory::LegalCompliance,
            vec![create_test_permission("audit", Action::Read, None)]
        );
        assert!(validate_request_semantics(&req_legal).is_ok());
    }

    #[test]
    fn test_semantic_action_appropriateness_invalid() {
        let key_pair = KeyPair::generate().unwrap();
        // Security: Write/Delete/Observe NOT OK
        for invalid_action in [Action::Write, Action::Delete, Action::Observe] {
             let req = create_signed_request(&key_pair, PurposeCategory::Security, vec![create_test_permission("config", invalid_action, None)]);
             let result = validate_request_semantics(&req);
             assert!(result.is_err(), "Action {:?} should be invalid for Security", invalid_action);
             assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field == "permissions.requested_action"));
        }
        // LegalCompliance: Write/Delete/Observe/Execute NOT OK
        for invalid_action in [Action::Write, Action::Delete, Action::Observe, Action::Execute] {
             let req = create_signed_request(&key_pair, PurposeCategory::LegalCompliance, vec![create_test_permission("report", invalid_action, None)]);
             let result = validate_request_semantics(&req);
             assert!(result.is_err(), "Action {:?} should be invalid for LegalCompliance", invalid_action);
             assert!(matches!(result.unwrap_err(), MCPError::InvalidField { field, .. } if field == "permissions.requested_action"));
        }
    }

    #[test]
    fn test_semantic_advanced_constraints_valid_values() {
        let key_pair = KeyPair::generate().unwrap();
        let mut constraints_map = StdHashMap::new();
        constraints_map.insert("max_frequency_per_hour".to_string(), serde_json::json!(50));
        constraints_map.insert("data_access_scope".to_string(), serde_json::json!("aggregated"));
        constraints_map.insert("valid_start_time".to_string(), serde_json::json!("2024-01-01T00:00:00Z"));
        constraints_map.insert("valid_end_time".to_string(), serde_json::json!("2024-12-31T23:59:59Z"));
        let constraints_struct = create_prost_struct(constraints_map);

        let request = create_signed_request(
            &key_pair, PurposeCategory::Personalization,
            vec![create_test_permission("prefs", Action::Read, Some(constraints_struct))]
        );
        assert!(validate_request_semantics(&request).is_ok());
    }

    #[test]
    fn test_semantic_advanced_constraints_invalid_frequency() {
        let key_pair = KeyPair::generate().unwrap();
        // Invalid value type (string instead of number)
        let mut map1 = StdHashMap::new();
        map1.insert("max_frequency_per_hour".to_string(), serde_json::json!("50"));
        let req1 = create_signed_request(&key_pair, PurposeCategory::Personalization, vec![create_test_permission("p", Action::Read, Some(create_prost_struct(map1)))]);
        assert!(validate_request_semantics(&req1).is_err());
        assert!(matches!(validate_request_semantics(&req1).unwrap_err(), MCPError::InvalidField { field, .. } if field.contains("frequency")));

        // Invalid value (zero)
        let mut map2 = StdHashMap::new();
        map2.insert("max_frequency_per_hour".to_string(), serde_json::json!(0));
        let req2 = create_signed_request(&key_pair, PurposeCategory::Personalization, vec![create_test_permission("p", Action::Read, Some(create_prost_struct(map2)))]);
        assert!(validate_request_semantics(&req2).is_err());
        assert!(matches!(validate_request_semantics(&req2).unwrap_err(), MCPError::InvalidField { field, .. } if field.contains("frequency")));
    }

     #[test]
    fn test_semantic_advanced_constraints_invalid_scope() {
        let key_pair = KeyPair::generate().unwrap();
        // Invalid scope value
        let mut map1 = StdHashMap::new();
        map1.insert("data_access_scope".to_string(), serde_json::json!("super_personal"));
        let req1 = create_signed_request(&key_pair, PurposeCategory::Personalization, vec![create_test_permission("p", Action::Read, Some(create_prost_struct(map1)))]);
        assert!(validate_request_semantics(&req1).is_err());
        assert!(matches!(validate_request_semantics(&req1).unwrap_err(), MCPError::ConstraintViolation { constraint, .. } if constraint == "data_access_scope"));

        // Invalid type (number instead of string)
        let mut map2 = StdHashMap::new();
        map2.insert("data_access_scope".to_string(), serde_json::json!(123));
        let req2 = create_signed_request(&key_pair, PurposeCategory::Personalization, vec![create_test_permission("p", Action::Read, Some(create_prost_struct(map2)))]);
        assert!(validate_request_semantics(&req2).is_err());
        assert!(matches!(validate_request_semantics(&req2).unwrap_err(), MCPError::InvalidField { field, .. } if field.contains("scope")));
    }

     #[test]
    fn test_semantic_advanced_constraints_invalid_time_format() {
        let key_pair = KeyPair::generate().unwrap();
        let mut map = StdHashMap::new();
        map.insert("valid_start_time".to_string(), serde_json::json!("not-a-timestamp")); // Invalid format
        map.insert("valid_end_time".to_string(), serde_json::json!("2024-12-31T23:59:59Z"));
        let req = create_signed_request(&key_pair, PurposeCategory::Personalization, vec![create_test_permission("p", Action::Read, Some(create_prost_struct(map)))]);
         assert!(validate_request_semantics(&req).is_err());
        assert!(matches!(validate_request_semantics(&req).unwrap_err(), MCPError::ConstraintViolation { constraint, .. } if constraint == "time_window"));
    }

    #[test]
    fn test_semantic_advanced_constraints_invalid_time_pair() {
        let key_pair = KeyPair::generate().unwrap();
        // Only start time provided
        let mut map = StdHashMap::new();
        map.insert("valid_start_time".to_string(), serde_json::json!("2024-01-01T00:00:00Z"));
        let req = create_signed_request(&key_pair, PurposeCategory::Personalization, vec![create_test_permission("p", Action::Read, Some(create_prost_struct(map)))]);
        assert!(validate_request_semantics(&req).is_err());
        assert!(matches!(validate_request_semantics(&req).unwrap_err(), MCPError::ConstraintViolation { constraint, .. } if constraint == "time_window"));

         // Only end time provided
        let mut map2 = StdHashMap::new();
        map2.insert("valid_end_time".to_string(), serde_json::json!("2024-12-31T23:59:59Z"));
        let req2 = create_signed_request(&key_pair, PurposeCategory::Personalization, vec![create_test_permission("p", Action::Read, Some(create_prost_struct(map2)))]);
        assert!(validate_request_semantics(&req2).is_err());
        assert!(matches!(validate_request_semantics(&req2).unwrap_err(), MCPError::ConstraintViolation { constraint, .. } if constraint == "time_window"));
    }
} 