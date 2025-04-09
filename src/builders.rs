//! Helper functions for building McpRequest and McpResponse messages.

use crate::types::*; // Import necessary types
use crate::utils::prost_timestamp_from_chrono; // Assuming utils.rs
use chrono::{DateTime, Utc};
use uuid::Uuid;
use bytes::Bytes;

// --- Request Builder ---

/// A helper struct to construct [`McpRequest`] messages using a fluent API.
///
/// Ensures required fields are set during creation and provides methods to add
/// optional fields like permissions, expiry, etc.
///
/// **Note:** The signature must be added separately using [`crate::crypto::sign_request`] after building.
///
/// # Example
/// ```rust
/// # use pandacea_mcp::{
/// #    builders::McpRequestBuilder, crypto::KeyPair, types::*, utils::*, error::Result
/// # };
/// # use chrono::{Utc, Duration};
/// # use bytes::Bytes;
/// # fn create_test_identity() -> (KeyPair, RequestorIdentity) {
/// #    let key_pair = KeyPair::generate().unwrap();
/// #    let identity = RequestorIdentity {
/// #       pseudonym_id: "test-id".to_string(), public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()), attestations: vec![]
/// #    };
/// #    (key_pair, identity)
/// # }
/// # fn create_test_purpose() -> PurposeDna { PurposeDna { purpose_id: "p".into(), primary_purpose_category: 1, specific_purpose_description: "d".into(), data_types_involved: vec!["dt".into()], processing_description: "p".into(), storage_description: "s".into(), ..Default::default() } }
/// # fn create_test_permission() -> PermissionSpecification { PermissionSpecification { resource_identifier: "r".into(), requested_action: Action::Read as i32, ..Default::default() } }
/// # fn main() -> Result<()> {
/// # let (key_pair, identity) = create_test_identity(); // Assume helper exists
/// # let purpose = create_test_purpose(); // Assume helper exists
/// # let perm = create_test_permission(); // Assume helper exists
/// let mut request = McpRequestBuilder::new(identity, purpose, "1.0.0".to_string())
///     .add_permission(perm)
///     .set_expiry(Utc::now() + Duration::minutes(5))
///     .build();
/// // Sign the request (function assumed to be in crypto module)
/// // crate::crypto::sign_request(&mut request, &key_pair, "key-id-01".to_string())?;
/// # Ok(())
/// # }
/// ```
pub struct McpRequestBuilder {
    request: McpRequest,
}

impl McpRequestBuilder {
    /// Creates a new `McpRequestBuilder` with essential fields.
    ///
    /// Automatically sets a unique `request_id` (UUIDv4) and the current `timestamp`.
    ///
    /// # Arguments
    /// * `requestor_identity`: The [`RequestorIdentity`] of the sender.
    /// * `purpose_dna`: The [`PurposeDna`] describing the intent.
    /// * `mcp_version`: The MCP protocol version string (e.g., "1.0.0").
    pub fn new(requestor_identity: RequestorIdentity, purpose_dna: PurposeDna, mcp_version: String) -> Self {
        Self {
            request: McpRequest {
                request_id: Uuid::new_v4().to_string(), // Generate a unique ID
                timestamp: Some(prost_timestamp_from_chrono(Utc::now())), // Use helper
                requestor_identity: Some(requestor_identity),
                purpose_dna: Some(purpose_dna),
                permissions: vec![],
                request_expiry: None, // Optional
                signature: None, // Signature added separately
                mcp_version,
                related_request_id: String::new(), // Optional
                extensions: vec![], // Initialize extensions
                // TODO: Consider adding checks for non-empty mcp_version?
            },
        }
    }

    /// Adds a [`PermissionSpecification`] to the request.
    pub fn add_permission(mut self, permission: PermissionSpecification) -> Self {
        self.request.permissions.push(permission);
        self
    }

    /// Sets the optional `request_expiry` timestamp.
    pub fn set_expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.request.request_expiry = Some(prost_timestamp_from_chrono(expiry)); // Use helper
        self
    }

    /// Sets the optional `related_request_id`.
    pub fn set_related_request_id(mut self, related_id: String) -> Self {
        self.request.related_request_id = related_id;
        self
    }
    
    /// Adds an extension field (prost_types::Any).
    pub fn add_extension(mut self, extension: prost_types::Any) -> Self {
        self.request.extensions.push(extension);
        self
    }

    /// Consumes the builder and returns the constructed [`McpRequest`].
    /// The signature field will be `None` and must be added via [`crate::crypto::sign_request`].
    pub fn build(self) -> McpRequest {
        // Potential location for final validation checks on the built request *before* signing?
        self.request
    }
}

// --- Response Builder ---

/// A helper struct to construct [`McpResponse`] messages using a fluent API.
///
/// Ensures required fields are set during creation and provides methods to add
/// optional fields like status message, permissions statuses, payload, etc.
///
/// **Note:** The signature must be added separately using [`crate::crypto::sign_response`] after building.
///
/// # Example
/// ```rust
/// # use pandacea_mcp::{
/// #   builders::McpResponseBuilder, types::*, crypto::KeyPair, error::Result
/// # };
/// # use bytes::Bytes;
/// # fn create_test_identity() -> (KeyPair, RequestorIdentity) { (KeyPair::generate().unwrap(), RequestorIdentity::default()) }
/// # fn main() -> Result<()> {
/// # let request_id = "req-123".to_string();
/// # let (key_pair, _) = create_test_identity(); // Assume helper exists
/// let mut response = McpResponseBuilder::new(request_id, Status::Approved, "1.0.0".to_string())
///     .status_message("Request granted.".to_string())
///     .set_payload(Bytes::from_static(b"example data"))
///     .build();
/// // Sign the response
/// // crate::crypto::sign_response(&mut response, &key_pair, "responder-key-01".to_string())?;
/// # Ok(())
/// # } 
/// ```
pub struct McpResponseBuilder {
    response: McpResponse,
}

impl McpResponseBuilder {
    /// Creates a new `McpResponseBuilder` with essential fields.
    ///
    /// Automatically sets a unique `response_id` (UUIDv4) and the current `timestamp`.
    ///
    /// # Arguments
    /// * `request_id`: The ID of the [`McpRequest`] this response corresponds to.
    /// * `status`: The overall [`Status`] of the request processing.
    /// * `mcp_version`: The MCP protocol version string (e.g., "1.0.0").
    pub fn new(request_id: String, status: Status, mcp_version: String) -> Self {
        // Basic validation on creation
        assert!(!request_id.is_empty(), "request_id cannot be empty");
        assert_ne!(status, Status::Unspecified, "status cannot be Unspecified");
        assert!(!mcp_version.is_empty(), "mcp_version cannot be empty");
        
        Self {
            response: McpResponse {
                response_id: Uuid::new_v4().to_string(),
                request_id,
                timestamp: Some(prost_timestamp_from_chrono(Utc::now())), // Use helper
                status: status as i32,
                status_message: String::new(), // Optional
                permission_statuses: vec![], // Optional
                response_payload: Bytes::new(), // Optional
                consent_receipt: Bytes::new(), // Optional
                signature: None, // Added separately
                mcp_version,
                extensions: vec![], // Initialize extensions
            },
        }
    }

    /// Sets the optional `status_message`.
    pub fn status_message(mut self, message: String) -> Self {
        self.response.status_message = message;
        self
    }

    /// Adds a [`PermissionStatus`] detailing the outcome for a specific permission.
    /// Primarily used when the overall status is `PARTIALLY_APPROVED`.
    pub fn add_permission_status(mut self, status: PermissionStatus) -> Self {
        self.response.permission_statuses.push(status);
        self
    }

    /// Sets the optional `response_payload` (e.g., for approved READ requests).
    pub fn set_payload(mut self, payload: Bytes) -> Self {
        // TODO: Consider size limit check for payload?
        self.response.response_payload = payload;
        self
    }

     /// Sets the optional consent receipt.
     pub fn set_consent_receipt(mut self, receipt: Bytes) -> Self {
        // TODO: Consider size limit check for receipt?
        self.response.consent_receipt = receipt;
        self
    }
    
    /// Adds an extension field (prost_types::Any).
    pub fn add_extension(mut self, extension: prost_types::Any) -> Self {
        self.response.extensions.push(extension);
        self
    }

    /// Consumes the builder and returns the constructed [`McpResponse`].
    /// The signature field will be `None` and must be added via [`crate::crypto::sign_response`].
    pub fn build(self) -> McpResponse {
        // Potential location for final validation checks *before* signing?
        // E.g., check status consistency with permission_statuses.
        // if self.response.status == Status::PartiallyApproved as i32 && self.response.permission_statuses.is_empty() { ... }
        self.response
    }
}

// --- Tests (Example Structure) ---
#[cfg(test)]
mod tests {
    use super::*; // Import builders from the same module
    use crate::types::{Action, PermissionSpecification, RequestorIdentity, PurposeDna, Status, PermissionStatus}; // Import necessary types
    use crate::utils::chrono_from_prost_timestamp; // Import helpers
    use crate::crypto::KeyPair; // Needed for identity generation
    use chrono::{Duration, TimeZone}; // Need TimeZone for assertion
    use prost_types::Any;
    
    // Helper
     fn create_test_identity() -> (KeyPair, RequestorIdentity) {
         let key_pair = KeyPair::generate().expect("Key generation failed");
         let identity = RequestorIdentity {
             pseudonym_id: "builder-test-id".to_string(),
             public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()),
             attestations: vec![],
         };
         (key_pair, identity)
     }

     fn create_test_purpose() -> PurposeDna {
         PurposeDna {
             purpose_id: "builder-test-purpose".to_string(),
             primary_purpose_category: 1, // Assuming 1 is a valid category like Research
             specific_purpose_description: "Builder testing".to_string(),
             data_types_involved: vec!["test_data".into()],
             processing_description: "Building...".into(),
             storage_description: "Storing...".into(),
             ..Default::default() // Use default for optional fields
         }
     }

     fn create_test_permission(id: &str) -> PermissionSpecification {
         PermissionSpecification {
             resource_identifier: format!("builder-res-{}", id), 
             requested_action: Action::Read as i32,
             constraints: None,
         }
     }

    #[test]
    fn test_mcp_request_builder_basic() {
        let (_key_pair, identity) = create_test_identity();
        let purpose = create_test_purpose();
        let version = "1.1.0".to_string();
        let now_before = Utc::now();

        let request = McpRequestBuilder::new(identity.clone(), purpose.clone(), version.clone())
            .build();
        
        let now_after = Utc::now();

        assert!(!request.request_id.is_empty());
        assert!(Uuid::parse_str(&request.request_id).is_ok());
        assert!(request.timestamp.is_some());
        let request_time = chrono_from_prost_timestamp(&request.timestamp.unwrap()).unwrap();
        assert!(request_time >= now_before && request_time <= now_after); // Timestamp should be recent
        assert!(request.requestor_identity.is_some());
        assert_eq!(request.requestor_identity.unwrap().pseudonym_id, identity.pseudonym_id);
        assert!(request.purpose_dna.is_some());
        assert_eq!(request.purpose_dna.unwrap().purpose_id, purpose.purpose_id);
        assert_eq!(request.mcp_version, version);
        assert!(request.permissions.is_empty());
        assert!(request.request_expiry.is_none());
        assert!(request.signature.is_none());
        assert!(request.related_request_id.is_empty());
        assert!(request.extensions.is_empty());
    }

    #[test]
    fn test_mcp_request_builder_with_options() {
        let (_key_pair, identity) = create_test_identity();
        let purpose = create_test_purpose();
        let perm1 = create_test_permission("1");
        let perm2 = create_test_permission("2");
        let expiry = Utc::now() + Duration::hours(1);
        let related_id = "prev-req-abc".to_string();
        let ext = Any { type_url: "foo.bar/baz".into(), value: vec![1,2,3] };

        let request = McpRequestBuilder::new(identity, purpose, "1.0.0".to_string())
            .add_permission(perm1.clone())
            .add_permission(perm2.clone())
            .set_expiry(expiry)
            .set_related_request_id(related_id.clone())
            .add_extension(ext.clone())
            .build();

        assert_eq!(request.permissions.len(), 2);
        assert_eq!(request.permissions[0].resource_identifier, perm1.resource_identifier);
        assert_eq!(request.permissions[1].resource_identifier, perm2.resource_identifier);
        assert!(request.request_expiry.is_some());
        let req_expiry = chrono_from_prost_timestamp(&request.request_expiry.unwrap()).unwrap();
        // Compare timestamps carefully due to potential precision loss
        assert!((req_expiry - expiry).num_milliseconds().abs() < 100); 
        assert_eq!(request.related_request_id, related_id);
        assert_eq!(request.extensions.len(), 1);
        assert_eq!(request.extensions[0].type_url, ext.type_url);
        assert_eq!(request.extensions[0].value, ext.value);
        assert!(request.signature.is_none()); // Still none
    }
    
    #[test]
    fn test_mcp_response_builder_basic() {
        let request_id = Uuid::new_v4().to_string();
        let status = Status::Approved;
        let version = "1.1.0".to_string();
        let now_before = Utc::now();
        
        let response = McpResponseBuilder::new(request_id.clone(), status, version.clone())
            .build();
            
        let now_after = Utc::now();
        
        assert!(!response.response_id.is_empty());
        assert!(Uuid::parse_str(&response.response_id).is_ok());
        assert_eq!(response.request_id, request_id);
        assert!(response.timestamp.is_some());
         let response_time = chrono_from_prost_timestamp(&response.timestamp.unwrap()).unwrap();
        assert!(response_time >= now_before && response_time <= now_after);
        assert_eq!(response.status, status as i32);
        assert_eq!(response.mcp_version, version);
        assert!(response.status_message.is_empty());
        assert!(response.permission_statuses.is_empty());
        assert!(response.response_payload.is_empty());
        assert!(response.consent_receipt.is_empty());
        assert!(response.signature.is_none());
        assert!(response.extensions.is_empty());
    }
    
    #[test]
    #[should_panic(expected = "request_id cannot be empty")]
    fn test_mcp_response_builder_empty_request_id() {
        McpResponseBuilder::new("".to_string(), Status::Approved, "1.0.0".to_string());
    }
    
    #[test]
    #[should_panic(expected = "status cannot be Unspecified")]
    fn test_mcp_response_builder_unspecified_status() {
        McpResponseBuilder::new("req-1".to_string(), Status::Unspecified, "1.0.0".to_string());
    }
    
     #[test]
    #[should_panic(expected = "mcp_version cannot be empty")]
    fn test_mcp_response_builder_empty_version() {
        McpResponseBuilder::new("req-1".to_string(), Status::Approved, "".to_string());
    }
    
     #[test]
    fn test_mcp_response_builder_with_options() {
        let request_id = "req-xyz".to_string();
        let status = Status::PartiallyApproved;
        let msg = "Some permissions granted".to_string();
        let perm_status = PermissionStatus {
            resource_identifier: "res-abc".to_string(),
            granted: true,
            reason: "Allowed by policy".to_string(),
        };
        let payload = Bytes::from_static(b"some_data");
        let receipt = Bytes::from_static(b"receipt_abc");
        let ext = Any { type_url: "ext.example/info".into(), value: vec![10, 20] };

        let response = McpResponseBuilder::new(request_id.clone(), status, "1.0.0".to_string())
            .status_message(msg.clone())
            .add_permission_status(perm_status.clone())
            .set_payload(payload.clone())
            .set_consent_receipt(receipt.clone())
            .add_extension(ext.clone())
            .build();

        assert_eq!(response.status, status as i32);
        assert_eq!(response.status_message, msg);
        assert_eq!(response.permission_statuses.len(), 1);
        assert_eq!(response.permission_statuses[0].resource_identifier, perm_status.resource_identifier);
        assert!(response.permission_statuses[0].granted);
        assert_eq!(response.response_payload, payload);
        assert_eq!(response.consent_receipt, receipt);
        assert_eq!(response.extensions.len(), 1);
        assert_eq!(response.extensions[0].type_url, ext.type_url);
        assert_eq!(response.extensions[0].value, ext.value);
        assert!(response.signature.is_none());
    }
} 