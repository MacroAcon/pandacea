use crate::error::{MCPError, Result};
use crate::types::{
    McpRequest, 
    PurposeDna, 
    PermissionSpecification, 
};
use crate::mcp::purpose_dna::PurposeCategory;
use crate::mcp::permission_specification::Action;
use chrono::Utc;
// ... rest of file ... 

pub fn validate_request_semantics(request: &McpRequest) -> Result<()> {
    // Ensure required top-level fields are present (already checked by syntax, but good practice)
    let purpose = request.purpose_dna.as_ref()
        .ok_or_else(|| MCPError::missing_field("purpose_dna"))?; // Use missing_field
    let permissions = &request.permissions;
    if permissions.is_empty() {
        return Err(MCPError::missing_field("request.permissions")); // Be more specific
    }

    // Validate purpose category and its compatibility with actions
    let purpose_category = PurposeCategory::try_from(purpose.primary_purpose_category)
        .map_err(|_| MCPError::conversion_error("Invalid purpose category value"))? // Use conversion error
        .ok_or_else(|| MCPError::invalid_field("purpose_dna.primary_purpose_category", "Purpose category cannot be Unspecified"))?;

    for perm in permissions {
        let action = Action::try_from(perm.requested_action)
            .map_err(|_| MCPError::conversion_error(format!("Invalid action value: {}", perm.requested_action)))? // Use conversion error
            .ok_or_else(|| MCPError::invalid_field("permission.requested_action", "Action cannot be Unspecified"))?;

        // Basic semantic check: Analytics purpose should typically only allow Read actions
        if purpose_category == PurposeCategory::Analytics && action != Action::Read {
            return Err(MCPError::invalid_field(
                "permission.requested_action", 
                format!("Action {:?} is incompatible with Analytics purpose (expected Read)", action)
            ));
        }

        // TODO: Add more semantic checks:
        // - Ensure requested resource identifiers align with data types in PurposeDna?
        // - Check constraints format/validity (basic structural check?)
        // - Cross-check permissions for redundancy or conflicts?

        // Validate advanced constraints (placeholder)
        validate_advanced_constraints(perm, purpose)?;
    }

    Ok(())
}

/// Placeholder for validating potentially complex constraints defined within a PermissionSpecification.
fn validate_advanced_constraints(permission: &PermissionSpecification, purpose: &PurposeDna) -> Result<()> {
    if let Some(constraints) = &permission.constraints {
        for (key, value) in &constraints.fields {
            match key.as_str() {
                "geo_boundary" => { 
                    // TODO: Implement geo-boundary validation
                    // Example placeholder check:
                    if value.kind.is_none() { // Very basic check
                         return Err(MCPError::ConstraintEvaluationError {
                             constraint_key: key.clone(),
                             reason: "Geo-boundary constraint value is missing or invalid".to_string(),
                         });
                     }
                }
                "time_window" => { 
                    // TODO: Implement time window validation
                    if value.kind.is_none() { // Very basic check
                        return Err(MCPError::ConstraintEvaluationError {
                            constraint_key: key.clone(),
                            reason: "Time window constraint value is missing or invalid".to_string(),
                        });
                    }
                }
                // Add other constraint types here
                _ => {
                    // Optionally warn or error on unrecognized constraint keys
                    // return Err(MCPError::ConstraintEvaluationError { constraint_key: key.clone(), reason: "Unrecognized constraint key".to_string() });
                }
            }
        }
    }
    Ok(())
}

/// Checks action compatibility based on purpose category.
fn check_action_compatibility(purpose_category: PurposeCategory, action: Action) -> Result<()> {
    match purpose_category {
        PurposeCategory::Unspecified => Err(MCPError::invalid_field("purpose_category", "Cannot be Unspecified")), // Handled earlier, but belt-and-suspenders
        PurposeCategory::Analytics => {
            if action == Action::Read { Ok(()) }
            else { Err(MCPError::invalid_field("action", format!("Action {:?} incompatible with Analytics purpose", action))) }
        },
        PurposeCategory::Operations => {
            // Operations might allow Read, Write, Execute
            if action == Action::Delete { // Example restriction
                Err(MCPError::invalid_field("action", "Delete action restricted for Operations purpose"))
            } else {
                Ok(())
            }
        },
        // Add rules for other categories
        _ => Ok(()), // Default allow for other categories (adjust as needed)
    }
}

/// Placeholder for complex constraint validation logic.
fn validate_constraint_value(constraint_key: &str, constraint_value: &Value, context: &RequestContext) -> Result<()> {
    match constraint_key {
        "max_queries_per_hour" => {
            if let Some(Kind::NumberValue(limit)) = constraint_value.kind {
                if limit < 1.0 { // Example validation
                    return Err(MCPError::ConstraintEvaluationError { 
                        constraint_key: constraint_key.to_string(), 
                        reason: "max_queries_per_hour must be at least 1".to_string() 
                    });
                }
                // TODO: Check against actual query rate if available in context
            } else {
                 return Err(MCPError::ConstraintEvaluationError { 
                    constraint_key: constraint_key.to_string(), 
                    reason: "max_queries_per_hour expects a number value".to_string() 
                 });
            }
        }
        "allowed_ip_ranges" => {
            if let Some(Kind::ListValue(list)) = &constraint_value.kind {
                for ip_val in &list.values {
                    if let Some(Kind::StringValue(ip_cidr)) = &ip_val.kind {
                        // TODO: Parse CIDR and check if requestor IP (from context) falls within range
                        // Requires ipnetwork crate or similar
                        if ip_cidr.is_empty() { // Dummy check
                           return Err(MCPError::ConstraintEvaluationError { 
                                constraint_key: constraint_key.to_string(), 
                                reason: format!("Invalid IP range format: {}", ip_cidr) 
                            });
                        }
                    } else {
                         return Err(MCPError::ConstraintEvaluationError { 
                            constraint_key: constraint_key.to_string(), 
                            reason: "allowed_ip_ranges expects a list of strings".to_string() 
                         });
                    }
                }
            } else {
                 return Err(MCPError::ConstraintEvaluationError { 
                    constraint_key: constraint_key.to_string(), 
                    reason: "allowed_ip_ranges expects a list value".to_string() 
                 });
            }
        }
        _ => { /* Ignore unknown constraints or return error */ }
    }
    Ok(())
} 