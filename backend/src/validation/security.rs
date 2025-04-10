use crate::error::{Result};
use crate::types::{McpRequest, McpResponse};
use crate::crypto::{verify_request_signature, verify_response_signature};

/// Validates the security aspects of an [`McpRequest`], primarily its cryptographic signature.
///
/// Relies on `crate::crypto::verify_request_signature`.
///
/// # Arguments
/// * `request`: The [`McpRequest`] whose signature needs verification.
///
/// # Returns
/// * `Ok(())` if the signature is valid and verified.
/// * `Err(MCPError)` specific to signature validation failures (e.g., `MissingField`, `UnsupportedAlgorithm`, `InvalidSignature`).
pub fn validate_request_security(request: &McpRequest) -> Result<()> {
    // Delegate directly to the crypto utility function
    verify_request_signature(request)
}

/// Validates the security aspects of an [`McpResponse`], primarily its cryptographic signature.
///
/// Relies on `crate::crypto::verify_response_signature`.
///
/// # Arguments
/// * `response`: The [`McpResponse`] whose signature needs verification.
///
/// # Returns
/// * `Ok(())` if the signature is valid and verified.
/// * `Err(MCPError)` specific to signature validation failures (e.g., `MissingField`, `UnsupportedAlgorithm`, `InvalidSignature`).
pub fn validate_response_security(response: &McpResponse) -> Result<()> {
    // Delegate directly to the crypto utility function
    verify_response_signature(response)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ RequestorIdentity, PurposeDna, PermissionSpecification, Signature };
    use crate::crypto::KeyPair;
    use crate::test_utils::test_utils::*; // Import shared helpers
    use bytes::Bytes;

    // --- Request Security Validation Tests ---

    #[test]
    fn test_security_valid_request_signature() {
        // Helper creates a request that should be valid syntactically and semantically
        let (_key_pair, request) = create_valid_signed_request_for_security_tests();
        assert!(validate_request_security(&request).is_ok());
    }

    #[test]
    fn test_security_missing_signature_struct() {
        // Need to construct manually as helper always signs
         let key_pair = KeyPair::generate().unwrap();
         let identity = create_test_identity(&key_pair);
         let purpose = create_base_test_purpose(PurposeCategory::Operations, vec!["resource".to_string()]);
         let permissions = vec![create_test_permission("resource", Action::Read, None)];
         let request = McpRequest {
             request_id: "req-sig-test-miss".to_string(),
             timestamp: Some(current_prost_timestamp()),
             requestor_identity: Some(identity),
             purpose_dna: Some(purpose),
             permissions,
             context_data: None,
             request_expiry: None,
             signature: None, // Explicitly missing
             mcp_version: "1.0.0".to_string(),
         };

        let result = validate_request_security(&request);
        assert!(result.is_err());
        // verify_request_signature should return MissingField for the signature struct itself
        assert!(matches!(result.unwrap_err(), MCPError::MissingField { field } if field == "request.signature"));
    }


    #[test]
    fn test_security_invalid_signature_wrong_key() {
        let (key_pair_orig, request_orig) = create_valid_signed_request_for_security_tests();
        let key_pair_wrong = KeyPair::generate().unwrap(); // Different key pair

        // Create a request struct identical to the original, but sign with the wrong key
        let mut request_wrong_sig = request_orig.clone();
        request_wrong_sig.signature = None; // Remove original signature first

        let signature_wrong = crate::crypto::sign_request_payload(&request_wrong_sig, &key_pair_wrong)
           .expect("Signing failed in test");
        request_wrong_sig.signature = Some(signature_wrong);

        // Verify against the original identity (which has the original public key)
        let result = validate_request_security(&request_wrong_sig);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidSignature));
    }


    #[test]
    fn test_security_tampered_field() {
        let (_key_pair, mut request) = create_valid_signed_request_for_security_tests();
        // Tamper *after* signing
        request.request_id = "tampered-id-123".to_string();

        let result = validate_request_security(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidSignature));
    }

    #[test]
    fn test_security_tampered_purpose() {
        let (_key_pair, mut request) = create_valid_signed_request_for_security_tests();
        // Tamper purpose after signing
        request.purpose_dna.as_mut().unwrap().specific_purpose_description = "Maliciously tampered purpose".to_string();

        let result = validate_request_security(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidSignature));
    }

     #[test]
    fn test_security_tampered_permission() {
        let (_key_pair, mut request) = create_valid_signed_request_for_security_tests();
        // Tamper permission after signing
        request.permissions[0].resource_identifier = "tampered_resource".to_string();

        let result = validate_request_security(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidSignature));
    }

    #[test]
    fn test_security_unsupported_algorithm() {
         let (_key_pair, mut request) = create_valid_signed_request_for_security_tests();
         // Assume signature was created with a valid algo initially
         // Modify the algorithm field *after* signing
         request.signature.as_mut().unwrap().algorithm = "InvalidAlgo-SHA1".to_string();

         let result = validate_request_security(&request);
         assert!(result.is_err());
         // verify_request_signature should return UnsupportedAlgorithm
         assert!(matches!(result.unwrap_err(), MCPError::UnsupportedAlgorithm(_)));
    }

    // --- Response Security Validation Tests ---
    
    #[test]
    fn test_security_valid_response_signature() {
        let (key_pair, request) = create_valid_signed_request_for_security_tests();
        let response = create_signed_response(
            &key_pair,
            &request,
            McpResponse_Status::APPROVED,
            None
        );
        
        assert!(validate_response_security(&response).is_ok());
    }
    
    #[test]
    fn test_security_missing_response_signature() {
        let (key_pair, request) = create_valid_signed_request_for_security_tests();
        let mut response = create_signed_response(
            &key_pair,
            &request,
            McpResponse_Status::APPROVED,
            None
        );
        
        response.signature = None; // Remove signature
        
        let result = validate_response_security(&response);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::MissingField { field } if field == "response.signature"));
    }
    
    #[test]
    fn test_security_tampered_response() {
        let (key_pair, request) = create_valid_signed_request_for_security_tests();
        let mut response = create_signed_response(
            &key_pair,
            &request,
            McpResponse_Status::APPROVED,
            None
        );
        
        // Tamper with the response after signing
        response.response_id = "tampered-response-id".to_string();
        
        let result = validate_response_security(&response);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MCPError::InvalidSignature));
    }
} 