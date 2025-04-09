use crate::error::{MCPError, Result};
use crate::types::McpRequest;
use crate::mcp::purpose_dna::PurposeCategory;
use crate::mcp::permission_specification::Action;
use chrono::Utc; 

// Validate purpose expiry if present
if let Some(expiry) = request.purpose_dna.as_ref().and_then(|p| p.purpose_expiry_timestamp.as_ref()) {
    let expiry_chrono = utils::chrono_from_prost_timestamp(expiry)
        .map_err(|e| MCPError::conversion_error(format!("Invalid purpose expiry timestamp format: {}", e)))?;
    if utils::has_timestamp_expired(expiry_chrono, now) {
        return Err(MCPError::expired_purpose(expiry_chrono));
    }
} else {
    // Optional: Depending on policy, require purpose expiry?
    // If expiry is strictly required, use MissingField:
    // return Err(MCPError::missing_field("purpose_dna.purpose_expiry_timestamp"));
    // For now, treat as optional.
} 