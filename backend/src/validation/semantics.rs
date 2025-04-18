// src/validation/semantics.rs

use crate::error::{Result, MCPError};
use crate::types::{
    McpRequest, PurposeDna, PermissionSpecification, CompensationModel, TrustInformation,
    purpose_dna::PurposeCategory,
    permission_specification::Action,
    permission_specification::SensitivityLevel,
    compensation_model::CompensationType
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
/// 5. Compensation Model Validation (if present)
/// 6. Trust Information Validation (if present)
/// 7. Sensitivity Level Alignment
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
    
    // 5. Compensation Model Validation (if present)
    if let Some(compensation) = &request.compensation_model {
        validate_compensation_model(compensation)?;
    }
    
    // 6. Trust Information Validation (if present)
    if let Some(trust_info) = &request.trust_info {
        validate_trust_information(trust_info)?;
    }
    
    // 7. Sensitivity Level Alignment
    validate_sensitivity_levels(&request.permissions)?;

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

/// Validates that the compensation model is consistent and contains required fields
fn validate_compensation_model(compensation: &CompensationModel) -> Result<()> {
    // Get compensation type (should be valid after syntax check)
    let compensation_type = CompensationType::try_from(compensation.compensation_type)
        .map_err(|_| MCPError::invalid_field(
            "compensation_model.compensation_type",
            "Invalid compensation type"
        ))?;
        
    // Check requirements based on compensation type
    match compensation_type {
        CompensationType::Unspecified => {
            return Err(MCPError::invalid_field(
                "compensation_model.compensation_type",
                "Compensation type must not be UNSPECIFIED"
            ));
        },
        CompensationType::Monetary | CompensationType::Token => {
            // For monetary and token payments, amount and unit are required
            if compensation.amount <= 0.0 {
                return Err(MCPError::invalid_field(
                    "compensation_model.amount",
                    "Amount must be greater than zero for monetary or token compensation"
                ));
            }
            
            if compensation.unit.is_empty() {
                return Err(MCPError::missing_field("compensation_model.unit"));
            }
            
            // Payment method is required for monetary/token
            if compensation.payment_method.is_none() {
                return Err(MCPError::missing_field("compensation_model.payment_method"));
            }
        },
        CompensationType::RevenueShare => {
            // Revenue sharing model is required
            if compensation.revenue_sharing.is_none() {
                return Err(MCPError::missing_field("compensation_model.revenue_sharing"));
            }
            
            // Check revenue sharing details
            let revenue_sharing = compensation.revenue_sharing.as_ref().unwrap();
            if revenue_sharing.percentage <= 0.0 || revenue_sharing.percentage > 100.0 {
                return Err(MCPError::invalid_field(
                    "compensation_model.revenue_sharing.percentage",
                    "Percentage must be between 0 and 100"
                ));
            }
            
            if revenue_sharing.calculation_method.is_empty() {
                return Err(MCPError::missing_field("compensation_model.revenue_sharing.calculation_method"));
            }
        },
        _ => {} // No specific validations for other types
    }
    
    Ok(())
}

/// Validates trust information for consistency
fn validate_trust_information(trust_info: &TrustInformation) -> Result<()> {
    // Basic validation for trust score - must be between 0 and 100
    if trust_info.trust_score > 100 {
        return Err(MCPError::invalid_field(
            "trust_info.trust_score",
            "Trust score must be between 0 and 100"
        ));
    }
    
    // Validate assessment information
    if !trust_info.assessment_method.is_empty() && trust_info.assessment_provider.is_empty() {
        return Err(MCPError::missing_field(
            "trust_info.assessment_provider must be provided when assessment_method is specified"
        ));
    }
    
    // Validate credentials if present
    for (i, credential) in trust_info.trust_credentials.iter().enumerate() {
        if credential.credential_type.is_empty() {
            return Err(MCPError::missing_field(
                &format!("trust_info.trust_credentials[{}].credential_type", i)
            ));
        }
        
        if credential.issuer.is_empty() {
            return Err(MCPError::missing_field(
                &format!("trust_info.trust_credentials[{}].issuer", i)
            ));
        }
        
        if credential.credential_id.is_empty() {
            return Err(MCPError::missing_field(
                &format!("trust_info.trust_credentials[{}].credential_id", i)
            ));
        }
    }
    
    Ok(())
}

/// Validates that sensitivity levels are consistent with the actions and resource types
fn validate_sensitivity_levels(permissions: &[PermissionSpecification]) -> Result<()> {
    for (i, permission) in permissions.iter().enumerate() {
        // Skip if no sensitivity level specified
        if permission.sensitivity_level == 0 {
            continue;
        }
        
        // Get sensitivity level
        let sensitivity = SensitivityLevel::try_from(permission.sensitivity_level)
            .map_err(|_| MCPError::invalid_field(
                &format!("permissions[{}].sensitivity_level", i),
                "Invalid sensitivity level"
            ))?;
            
        // If CRITICAL sensitivity, validate additional safeguards
        if sensitivity == SensitivityLevel::Critical {
            // Check if write or delete actions have additional justification
            let action = Action::try_from(permission.requested_action)
                .map_err(|_| MCPError::internal("Invalid action survived syntax validation"))?;
                
            if (action == Action::Write || action == Action::Delete) && permission.justification.is_empty() {
                return Err(MCPError::missing_field(
                    &format!("permissions[{}].justification for CRITICAL sensitivity resource", i)
                ));
            }
            
            // Check for required constraints on high sensitivity data
            if permission.constraints.is_none() {
                return Err(MCPError::missing_field(
                    &format!("permissions[{}].constraints for CRITICAL sensitivity resource", i)
                ));
            }
        }
    }
    
    Ok(())
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

    // --- New Tests for Added Validation Functions ---
    
    #[test]
    fn test_semantic_compensation_model_valid() {
        let compensation = CompensationModel {
            compensation_type: CompensationType::Monetary as i32,
            amount: 10.0,
            unit: "USD".to_string(),
            payment_method: Some(create_test_payment_method()),
            revenue_sharing: None,
        };
        
        assert!(validate_compensation_model(&compensation).is_ok());
    }
    
    #[test]
    fn test_semantic_compensation_model_invalid() {
        let mut compensation = CompensationModel {
            compensation_type: CompensationType::Monetary as i32,
            amount: 0.0, // Invalid amount
            unit: "USD".to_string(),
            payment_method: Some(create_test_payment_method()),
            revenue_sharing: None,
        };
        
        assert!(validate_compensation_model(&compensation).is_err());
        
        // Fix amount but remove unit
        compensation.amount = 10.0;
        compensation.unit = "".to_string(); // Invalid: empty unit
        
        assert!(validate_compensation_model(&compensation).is_err());
    }
    
    #[test]
    fn test_semantic_trust_information_valid() {
        let trust_info = TrustInformation {
            trust_score: 85,
            assessment_method: "Algorithm-X".to_string(),
            assessment_provider: "TrustOrg".to_string(),
            assessment_timestamp: Some(current_prost_timestamp()),
            trust_credentials: vec![create_test_trust_credential()],
        };
        
        assert!(validate_trust_information(&trust_info).is_ok());
    }
    
    #[test]
    fn test_semantic_trust_information_invalid() {
        let trust_info = TrustInformation {
            trust_score: 120, // Invalid: over 100
            assessment_method: "Algorithm-X".to_string(),
            assessment_provider: "TrustOrg".to_string(),
            assessment_timestamp: None,
            trust_credentials: vec![],
        };
        
        assert!(validate_trust_information(&trust_info).is_err());
    }
    
    #[test]
    fn test_semantic_sensitivity_levels_valid() {
        let permissions = vec![
            PermissionSpecification {
                resource_identifier: "user.email".to_string(),
                requested_action: Action::Read as i32,
                sensitivity_level: SensitivityLevel::High as i32,
                constraints: Some(create_test_constraints()),
                justification: "Required for account verification".to_string(),
                delegation_chain: vec![],
            }
        ];
        
        assert!(validate_sensitivity_levels(&permissions).is_ok());
    }
    
    #[test]
    fn test_semantic_sensitivity_levels_invalid() {
        let permissions = vec![
            PermissionSpecification {
                resource_identifier: "user.governmentId".to_string(),
                requested_action: Action::Write as i32,
                sensitivity_level: SensitivityLevel::Critical as i32,
                constraints: None, // Missing required constraints
                justification: "".to_string(), // Missing required justification
                delegation_chain: vec![],
            }
        ];
        
        assert!(validate_sensitivity_levels(&permissions).is_err());
    }
    
    // --- Test Helpers ---
    
    fn create_test_payment_method() -> PaymentMethod {
        PaymentMethod {
            payment_type: "wallet".to_string(),
            payment_identifier: "0x123456789abcdef".to_string(),
            payment_details: None,
        }
    }
    
    fn create_test_trust_credential() -> TrustCredential {
        TrustCredential {
            credential_type: "ISO27001".to_string(),
            issuer: "CertAuthority".to_string(),
            credential_id: "CERT-123456".to_string(),
            expiry: Some(future_prost_timestamp(365)), // 1 year in future
            verification_url: "https://verify.example.com/CERT-123456".to_string(),
        }
    }
    
    fn create_test_constraints() -> google.protobuf.Struct {
        let mut map = HashMap::new();
        map.insert("max_frequency_per_hour".to_string(), Value::Number(10.into()));
        map.insert("data_access_scope".to_string(), Value::String("anonymized".to_string()));
        
        prost_struct_from_hashmap(&map).unwrap()
    }
} 