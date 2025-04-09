#[cfg(test)]
pub mod test_utils {
    use crate::types::{McpRequest, RequestorIdentity, PurposeDna, PermissionSpecification, Signature, purpose_dna::PurposeCategory, permission_specification::Action};
    use crate::crypto::{KeyPair, sign_request_payload}; // Use sign_request_payload
    use crate::builders::McpRequestBuilder; // Assuming this builder exists
    use bytes::Bytes;
    use prost_types::{Struct as ProstStruct, Value as ProstValue, Timestamp as ProstTimestamp};
    use serde_json;
    use std::collections::HashMap as StdHashMap;
    use std::time::{SystemTime, UNIX_EPOCH};
    use chrono::{Utc};

    // Helper function to create a test identity
    pub fn create_test_identity(key_pair: &KeyPair) -> RequestorIdentity {
        RequestorIdentity {
            pseudonym_id: "test-requestor-id".to_string(),
            public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()),
            attestations: vec![],
            ..Default::default()
        }
    }

    // Helper function to create a base test purpose
    pub fn create_base_test_purpose(purpose_category: PurposeCategory, data_types: Vec<String>) -> PurposeDna {
         PurposeDna {
            purpose_id: format!("test-purpose-{}", purpose_category.as_str_name()),
            primary_purpose_category: purpose_category as i32,
            secondary_purpose_categories: vec![],
            specific_purpose_description: format!("Test purpose for {:?}", purpose_category),
            data_types_involved: data_types,
            processing_description: "Standard test processing".to_string(),
            storage_description: "Temporary test storage".to_string(),
            purpose_expiry_timestamp: None,
            legal_basis: "Consent".to_string(),
            jurisdiction: "Global".to_string(),
            third_party_sharing: None,
            ..Default::default()
        }
    }

    // Helper function to create a test permission specification
    pub fn create_test_permission(resource: &str, action: Action, constraints: Option<ProstStruct>) -> PermissionSpecification {
        PermissionSpecification {
            resource_identifier: resource.to_string(),
            requested_action: action as i32,
            constraints: constraints,
            delegation_chain: vec![],
            ..Default::default()
        }
    }

    // Helper: Get current time as Prost Timestamp
    pub fn current_prost_timestamp() -> ProstTimestamp {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
        ProstTimestamp {
            seconds: now.as_secs() as i64,
            nanos: now.subsec_nanos() as i32,
        }
    }

    // Helper function to create a complete, signed test request
    // Uses sign_request_payload consistent with verify_request_signature
    pub fn create_signed_request(
        key_pair: &KeyPair,
        purpose_category: PurposeCategory,
        permissions: Vec<PermissionSpecification>
    ) -> McpRequest {
        let identity = create_test_identity(key_pair);
        // Automatically derive data types from permissions for simplicity in most tests
        let data_types = permissions.iter().map(|p| p.resource_identifier.clone()).collect();
        let purpose = create_base_test_purpose(purpose_category, data_types);

        let mut builder = McpRequestBuilder::new(identity.clone(), purpose.clone(), "1.0.0".to_string())
            .request_id(format!("req-test-{}", Utc::now().timestamp_millis()))
            .timestamp(current_prost_timestamp())
            .permissions(permissions);

        let mut request = builder.build_unsigned().expect("Builder failed in test helper");

        // Sign using the correct payload function
        let signature = sign_request_payload(&request, key_pair)
           .expect("Signing failed in test helper");
        request.signature = Some(signature);

        request
    }

    // Helper to convert serde_json::Value to prost_types::value::Kind
    pub fn serde_to_prost_kind(value: serde_json::Value) -> Option<prost_types::value::Kind> {
        use prost_types::value::Kind;
        match value {
            serde_json::Value::Null => Some(Kind::NullValue(0)),
            serde_json::Value::Bool(b) => Some(Kind::BoolValue(b)),
            serde_json::Value::Number(n) => n.as_f64().map(Kind::NumberValue),
            serde_json::Value::String(s) => Some(Kind::StringValue(s)),
            serde_json::Value::Array(arr) => {
                let values = arr.into_iter()
                    .map(|v| ProstValue { kind: serde_to_prost_kind(v) })
                    .collect();
                Some(Kind::ListValue(prost_types::ListValue { values }))
            },
            serde_json::Value::Object(obj) => {
                 let fields = obj.into_iter()
                    .filter_map(|(k, v)| serde_to_prost_kind(v).map(|kind| (k, ProstValue { kind: Some(kind) })))
                    .collect();
                 Some(Kind::StructValue(ProstStruct { fields }))
            },
        }
    }

    // Helper to create ProstStruct from HashMap<String, serde_json::Value>
    pub fn create_prost_struct(map: StdHashMap<String, serde_json::Value>) -> ProstStruct {
         ProstStruct {
            fields: map.into_iter()
                .filter_map(|(k, v)| serde_to_prost_kind(v).map(|kind| (k, ProstValue { kind: Some(kind) }))) // Use filter_map
                .collect(),
        }
    }

     // Helper function specifically for security tests that need a known valid base request
     // Ensures the request passes basic syntax/semantics before security tests are run
     pub fn create_valid_signed_request_for_security_tests() -> (KeyPair, McpRequest) {
         let key_pair = KeyPair::generate().unwrap();
         // Use a common, generally valid scenario
         let request = create_signed_request(
             &key_pair,
             PurposeCategory::Operations,
             vec![create_test_permission("system_status", Action::Read, None)]
         );

         // Minimal validation check within the helper itself (optional but good practice)
         assert!(request.signature.is_some(), "Helper failed to create signature");
         assert!(!request.requestor_identity.as_ref().unwrap().public_key.is_empty(), "Helper failed to set public key");

         (key_pair, request)
     }
} 