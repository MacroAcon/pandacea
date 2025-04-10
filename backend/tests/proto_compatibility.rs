use pandacea_mcp::{
    McpRequest,
    McpResponse, 
    PurposeDNA,
    RequestorIdentity,
    PermissionSpecification,
    CryptoSignature,
    purpose_dna::PurposeCategory,
    permission_specification::Action,
    mcp_response::Status,
};
use prost::Message;
use prost_types::{Timestamp, Struct};
use std::collections::BTreeMap;

#[test]
fn test_request_oneof_fields() {
    // Create a request with oneof fields filled in
    let mut request = McpRequest::default();
    
    // Set the request_time oneof field
    request.request_time = Some(pandacea_mcp::mcp_request::RequestTime::Timestamp(
        Timestamp { seconds: 1234567890, nanos: 0 }
    ));
    
    // Set the expiry_time oneof field
    request.expiry_time = Some(pandacea_mcp::mcp_request::ExpiryTime::RequestExpiry(
        Timestamp { seconds: 1234657890, nanos: 0 }
    ));
    
    // Serialize
    let serialized = request.encode_to_vec();
    
    // Deserialize
    let deserialized = McpRequest::decode(serialized.as_slice()).unwrap();
    
    // Check the oneof fields
    match deserialized.request_time {
        Some(pandacea_mcp::mcp_request::RequestTime::Timestamp(ts)) => {
            assert_eq!(ts.seconds, 1234567890);
            assert_eq!(ts.nanos, 0);
        },
        Some(pandacea_mcp::mcp_request::RequestTime::RequestTimestamp(_)) => {
            panic!("Wrong oneof field selected for request_time");
        },
        None => {
            panic!("Missing request_time");
        }
    }
    
    match deserialized.expiry_time {
        Some(pandacea_mcp::mcp_request::ExpiryTime::RequestExpiry(ts)) => {
            assert_eq!(ts.seconds, 1234657890);
            assert_eq!(ts.nanos, 0);
        },
        Some(pandacea_mcp::mcp_request::ExpiryTime::Expiration(_)) => {
            panic!("Wrong oneof field selected for expiry_time");
        },
        None => {
            panic!("Missing expiry_time");
        }
    }
}

#[test]
fn test_purpose_dna_fields() {
    // Create a purpose DNA with all fields
    let mut purpose = PurposeDNA::default();
    purpose.name = "Test Purpose".to_string();
    purpose.description = "This is a test purpose".to_string();
    purpose.category = Some(PurposeCategory::CoreService);
    purpose.purpose_id = "test-purpose-123".to_string();
    purpose.specific_purpose_description = "Specific details of test purpose".to_string();
    purpose.data_types_involved.push("profile-data".to_string());
    purpose.data_types_involved.push("usage-stats".to_string());
    
    // Add third party sharing
    let mut sharing = PurposeDNA::ThirdPartySharing::default();
    sharing.will_share = true;
    sharing.recipient_categories.push("analytics-partners".to_string());
    purpose.third_party_sharing = Some(sharing);
    
    // Add reuse limitations
    let mut reuse = PurposeDNA::ReuseLimitations::default();
    reuse.allow_repurposing = false;
    reuse.requires_consent = true;
    purpose.reuse_limitations = Some(reuse);
    
    // Serialize
    let serialized = purpose.encode_to_vec();
    
    // Deserialize
    let deserialized = PurposeDNA::decode(serialized.as_slice()).unwrap();
    
    // Verify fields
    assert_eq!(deserialized.name, "Test Purpose");
    assert_eq!(deserialized.description, "This is a test purpose");
    assert_eq!(deserialized.category, Some(PurposeCategory::CoreService));
    assert_eq!(deserialized.purpose_id, "test-purpose-123");
    assert_eq!(deserialized.data_types_involved.len(), 2);
    assert_eq!(deserialized.data_types_involved[0], "profile-data");
    
    // Verify third party sharing
    let sharing = deserialized.third_party_sharing.unwrap();
    assert_eq!(sharing.will_share, true);
    assert_eq!(sharing.recipient_categories.len(), 1);
    assert_eq!(sharing.recipient_categories[0], "analytics-partners");
    
    // Verify reuse limitations
    let reuse = deserialized.reuse_limitations.unwrap();
    assert_eq!(reuse.allow_repurposing, false);
    assert_eq!(reuse.requires_consent, true);
}

#[test]
fn test_permission_actions() {
    // Create a permission with different actions
    let mut permission = PermissionSpecification::default();
    permission.resource_id = "user-profile-123".to_string();
    permission.action = Some(Action::Read);
    
    // Serialize
    let serialized = permission.encode_to_vec();
    
    // Deserialize
    let deserialized = PermissionSpecification::decode(serialized.as_slice()).unwrap();
    
    // Verify fields
    assert_eq!(deserialized.resource_id, "user-profile-123");
    assert_eq!(deserialized.action, Some(Action::Read));
    
    // Try with different action
    let mut permission2 = PermissionSpecification::default();
    permission2.resource_id = "user-profile-123".to_string();
    permission2.action = Some(Action::Write);
    
    // Serialize
    let serialized2 = permission2.encode_to_vec();
    
    // Deserialize
    let deserialized2 = PermissionSpecification::decode(serialized2.as_slice()).unwrap();
    
    // Verify fields
    assert_eq!(deserialized2.action, Some(Action::Write));
}

#[test]
fn test_response_status_enum() {
    // Create a response with status fields
    let mut response = McpResponse::default();
    response.request_id = "req-123".to_string();
    response.status = Status::Approved as i32;
    
    // Serialize
    let serialized = response.encode_to_vec();
    
    // Deserialize
    let deserialized = McpResponse::decode(serialized.as_slice()).unwrap();
    
    // Verify fields
    assert_eq!(deserialized.request_id, "req-123");
    assert_eq!(deserialized.status, Status::Approved as i32);
    
    // Test with Status::PartiallyApproved
    let mut response2 = McpResponse::default();
    response2.request_id = "req-456".to_string();
    response2.status = Status::PartiallyApproved as i32;
    
    // Add permission status
    let mut status = McpResponse::PermissionStatus::default();
    status.resource_id = "resource-1".to_string();
    status.action = Action::Read as i32;
    status.status = Status::Approved as i32;
    response2.permission_status.push(status);
    
    let mut status2 = McpResponse::PermissionStatus::default();
    status2.resource_id = "resource-2".to_string();
    status2.action = Action::Write as i32;
    status2.status = Status::Denied as i32;
    response2.permission_status.push(status2);
    
    // Serialize
    let serialized2 = response2.encode_to_vec();
    
    // Deserialize
    let deserialized2 = McpResponse::decode(serialized2.as_slice()).unwrap();
    
    // Verify fields
    assert_eq!(deserialized2.status, Status::PartiallyApproved as i32);
    assert_eq!(deserialized2.permission_status.len(), 2);
    assert_eq!(deserialized2.permission_status[0].resource_id, "resource-1");
    assert_eq!(deserialized2.permission_status[0].status, Status::Approved as i32);
    assert_eq!(deserialized2.permission_status[1].resource_id, "resource-2");
    assert_eq!(deserialized2.permission_status[1].status, Status::Denied as i32);
}

#[test]
fn test_complete_request_roundtrip() {
    // Create a complete request with all major fields
    let mut request = McpRequest::default();
    request.request_id = "complete-request-123".to_string();
    request.mcp_version = "1.0".to_string();
    
    // Add requestor identity
    let mut identity = RequestorIdentity::default();
    identity.pseudonym_id = "requestor-abc".to_string();
    identity.name = Some("Test Requestor".to_string());
    identity.public_key = Some(vec![1, 2, 3, 4]);
    request.requestor_identity = Some(identity);
    
    // Add purpose
    let mut purpose = PurposeDNA::default();
    purpose.purpose_id = "purpose-xyz".to_string();
    purpose.name = "Test Purpose".to_string();
    purpose.description = "Complete test purpose".to_string();
    purpose.category = Some(PurposeCategory::Analytics);
    purpose.data_types_involved.push("user-data".to_string());
    request.purpose_dna = Some(purpose);
    
    // Add permission
    let mut permission = PermissionSpecification::default();
    permission.resource_id = "resource-789".to_string();
    permission.action = Some(Action::Read);
    request.permission_specification = Some(permission);
    
    // Add timestamps
    request.request_time = Some(pandacea_mcp::mcp_request::RequestTime::Timestamp(
        Timestamp { seconds: 1643969430, nanos: 0 } // 2022-02-04T12:30:30Z
    ));
    
    request.expiry_time = Some(pandacea_mcp::mcp_request::ExpiryTime::RequestExpiry(
        Timestamp { seconds: 1644055830, nanos: 0 } // 2022-02-05T12:30:30Z
    ));
    
    // Add signature
    let mut signature = CryptoSignature::default();
    signature.signature = vec![5, 6, 7, 8];
    signature.algorithm = "ed25519".to_string();
    signature.key_id = "key-456".to_string();
    request.signature = Some(signature);
    
    // Add metadata
    let mut fields = BTreeMap::new();
    let mut value = prost_types::Value::default();
    value.kind = Some(prost_types::value::Kind::StringValue("metadata-value".to_string()));
    fields.insert("test-key".to_string(), value);
    let metadata = Struct { fields };
    request.metadata = Some(metadata);
    
    // Serialize
    let serialized = request.encode_to_vec();
    
    // Deserialize
    let deserialized = McpRequest::decode(serialized.as_slice()).unwrap();
    
    // Verify all fields
    assert_eq!(deserialized.request_id, "complete-request-123");
    assert_eq!(deserialized.mcp_version, "1.0");
    
    // Check identity
    let identity = deserialized.requestor_identity.unwrap();
    assert_eq!(identity.pseudonym_id, "requestor-abc");
    assert_eq!(identity.name, Some("Test Requestor".to_string()));
    assert_eq!(identity.public_key, Some(vec![1, 2, 3, 4]));
    
    // Check purpose
    let purpose = deserialized.purpose_dna.unwrap();
    assert_eq!(purpose.purpose_id, "purpose-xyz");
    assert_eq!(purpose.name, "Test Purpose");
    assert_eq!(purpose.category, Some(PurposeCategory::Analytics));
    
    // Check permission
    let permission = deserialized.permission_specification.unwrap();
    assert_eq!(permission.resource_id, "resource-789");
    assert_eq!(permission.action, Some(Action::Read));
    
    // Check timestamps
    match deserialized.request_time {
        Some(pandacea_mcp::mcp_request::RequestTime::Timestamp(ts)) => {
            assert_eq!(ts.seconds, 1643969430);
        },
        _ => panic!("Wrong or missing request_time"),
    }
    
    match deserialized.expiry_time {
        Some(pandacea_mcp::mcp_request::ExpiryTime::RequestExpiry(ts)) => {
            assert_eq!(ts.seconds, 1644055830);
        },
        _ => panic!("Wrong or missing expiry_time"),
    }
    
    // Check signature
    let signature = deserialized.signature.unwrap();
    assert_eq!(signature.algorithm, "ed25519");
    assert_eq!(signature.key_id, "key-456");
    assert_eq!(signature.signature, vec![5, 6, 7, 8]);
    
    // Check metadata
    let metadata = deserialized.metadata.unwrap();
    let value = metadata.fields.get("test-key").unwrap();
    match &value.kind {
        Some(prost_types::value::Kind::StringValue(s)) => {
            assert_eq!(s, "metadata-value");
        },
        _ => panic!("Wrong or missing metadata value"),
    }
} 