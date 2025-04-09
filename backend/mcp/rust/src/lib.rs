pub mod mcp {
    include!(concat!(env!("OUT_DIR"), "/pandacea_mcp.rs"));
}

// Example function demonstrating usage (adjust as needed)
pub fn process_mcp_request(request_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use prost::Message;
    use mcp::MCPRequest; // Import the specific type

    // Decode the request
    let request = MCPRequest::decode(request_bytes)
        .map_err(|e| format!("Failed to decode MCPRequest: {}", e))?;

    println!("Processing MCPRequest ID: {}", request.request_id);
    println!("Purpose DNA: {:?}", request.purpose_dna);

    // --- Placeholder for actual request processing logic ---
    // This is where you would interact with the Consent Manager,
    // evaluate rules, etc., based on the request content.
    // For now, we'll just create a dummy response.
    // -------------------------------------------------------

    // Create a dummy response
    let response = mcp::MCPResponse { // Use the correct type
        request_id: request.request_id,
        status_code: 200, // OK
        status_message: "Request processed successfully (dummy)".to_string(),
        receipt: Some(mcp::ConsentReceipt { // Use the correct type
            receipt_id: format!("receipt-{}", uuid::Uuid::new_v4()),
            request_hash: "dummy_request_hash".to_string(), // Replace with actual hash
            consent_decision: mcp::consent_receipt::ConsentDecision::Granted.into(), // Use the enum variant
            timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
            auditor_signature: "dummy_signature".to_string(), // Replace with actual signature
            rule_ids_evaluated: vec!["rule1".to_string(), "rule2".to_string()],
        }),
        payload: None, // No payload in this dummy response
        error_details: None,
    };

    // Encode the response
    let mut response_bytes = Vec::new();
    response.encode(&mut response_bytes)
        .map_err(|e| format!("Failed to encode MCPResponse: {}", e))?;

    Ok(response_bytes)
}

// --- Add tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use uuid::Uuid;
    use mcp::{PurposeItem, DataItem, ActionItem}; // Import nested types

    #[test]
    fn test_encode_decode_request() {
        let request = mcp::MCPRequest {
            request_id: Uuid::new_v4().to_string(),
            requester_id: "requester-123".to_string(),
            target_identity: "user-xyz".to_string(),
            purpose_dna: Some(mcp::PurposeDNA {
                primary_purpose: "Analytics".to_string(),
                secondary_purposes: vec!["Personalization".to_string()],
                data_items: vec![
                    DataItem { key: "email".to_string(), retention_policy: "30d".to_string(), },
                    DataItem { key: "location".to_string(), retention_policy: "session".to_string(), }
                ],
                action_items: vec![
                    ActionItem { name: "read".to_string(), constraints: "time_of_day: 9-5".to_string(), }
                ],
                justification: "Improve user experience".to_string(),
            }),
            required_trust_tier: 2,
            expiration_timestamp: Some(prost_types::Timestamp { seconds: 1700000000, nanos: 0 }),
            payload: None,
            signature: "dummy_signature".to_string(),
            encryption_details: None,
            context_info: vec![PurposeItem { key: "app_version".to_string(), value: "1.2.0".to_string() }], // Use PurposeItem
        };

        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();
        assert!(!buf.is_empty());

        let decoded_request = mcp::MCPRequest::decode(&buf[..]).unwrap();
        assert_eq!(request.request_id, decoded_request.request_id);
        assert_eq!(request.purpose_dna.unwrap().primary_purpose, decoded_request.purpose_dna.unwrap().primary_purpose);
    }

    #[test]
    fn test_process_dummy_request() {
        let request = mcp::MCPRequest {
            request_id: Uuid::new_v4().to_string(),
            requester_id: "requester-456".to_string(),
            target_identity: "user-abc".to_string(),
            purpose_dna: Some(mcp::PurposeDNA {
                 primary_purpose: "Testing".to_string(),
                 secondary_purposes: vec![],
                 data_items: vec![DataItem { key: "test_data".to_string(), retention_policy: "1h".to_string(), }],
                 action_items: vec![ActionItem { name: "process".to_string(), constraints: "".to_string(), }],
                 justification: "Dummy processing test".to_string(),
            }),
            required_trust_tier: 1,
            expiration_timestamp: None,
            payload: None,
            signature: "another_dummy_sig".to_string(),
            encryption_details: None,
            context_info: vec![],
        };

        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();

        let result = process_mcp_request(&buf);
        assert!(result.is_ok());

        let response_bytes = result.unwrap();
        let response = mcp::MCPResponse::decode(&response_bytes[..]).unwrap();

        assert_eq!(response.request_id, request.request_id);
        assert_eq!(response.status_code, 200);
        assert!(response.receipt.is_some());
        let receipt = response.receipt.unwrap();
        assert_eq!(receipt.request_hash, "dummy_request_hash"); // Placeholder check
        assert_eq!(receipt.consent_decision, mcp::consent_receipt::ConsentDecision::Granted.into());
    }

     #[test]
    fn test_invalid_request_bytes() {
        let invalid_bytes = vec![0x01, 0x02, 0x03];
        let result = process_mcp_request(&invalid_bytes);
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("Failed to decode MCPRequest"));
    }
} 