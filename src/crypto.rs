//! Cryptographic operations for MCP (signing, verification, key handling).

use crate::error::{MCPError, Result};
use crate::types::*;
use crate::serialization::{prepare_request_for_signing, prepare_response_for_signing}; // Assuming serialization.rs
use bytes::Bytes;
use ring::{ 
    signature::{self, KeyPair as RingKeyPair, Ed25519KeyPair, UnparsedPublicKey, ED25519}, 
    rand::SystemRandom, 
    error::Unspecified as RingUnspecified 
};

// --- Key Pair Abstraction ---

/// Represents a cryptographic key pair, currently supporting Ed25519.
/// Provides methods for generation, loading, and signing.
/// See struct definition notes for security considerations on storage and rotation.
#[derive(Debug)] // Added Debug derive for KeyPair
pub struct KeyPair {
    // Internal representation using the `ring` crate's Ed25519 key pair.
    // TODO(#1): Generalize this to support multiple algorithms (e.g., using an enum wrapper).
    ring_kp: Ed25519KeyPair,
    // TODO(#1): Add an algorithm identifier field when supporting multiple types.
    // algorithm: SignatureAlgorithm, 
}

// TODO(#1): Define an enum for supported signature algorithms when needed.
// pub enum SignatureAlgorithm { Ed25519, EcdsaP256, ... }

impl KeyPair {
    /// Generates a new Ed25519 `KeyPair` using a secure random number generator.
    ///
    /// # Errors
    /// Returns `MCPError::CryptoUnspecified` if the underlying random number
    /// generator fails.
    pub fn generate() -> Result<Self> {
        // TODO(#1): Adapt this if supporting multiple algorithms (take algorithm as arg?).
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| MCPError::CryptoUnspecified{ source: RingUnspecified })?; // Map error correctly
        
        // `from_pkcs8` performs necessary validation.
        Self::from_pkcs8(&pkcs8_bytes)
    }

    /// Creates an Ed25519 `KeyPair` from PKCS#8 v2 encoded private key bytes.
    ///
    /// Performs validation to ensure the key is a valid Ed25519 private key.
    ///
    /// # Arguments
    /// * `pkcs8_bytes`: The PKCS#8 encoded Ed25519 private key.
    ///
    /// # Errors
    /// Returns `MCPError::InvalidKey` if the bytes do not represent a valid Ed25519 key.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self> {
        // TODO(#1): Adapt this if supporting multiple algorithms (check algorithm metadata?).
        let ring_kp = Ed25519KeyPair::from_pkcs8(pkcs8_bytes)
            .map_err(|e| MCPError::invalid_key(e, "Failed to parse Ed25519 key from PKCS#8"))?; // Add reason
        Ok(KeyPair { ring_kp })
    }

    /// Creates an Ed25519 `KeyPair` directly from a 32-byte seed.
    ///
    /// **Warning:** Use with caution; prefer `from_pkcs8`.
    ///
    /// # Arguments
    /// * `seed_bytes`: The 32-byte seed for the Ed25519 key.
    ///
    /// # Errors
    /// Returns `MCPError::InvalidKey` if the seed length is incorrect.
    pub fn from_seed(seed_bytes: &[u8]) -> Result<Self> {
        // TODO(#1): Adapt this if supporting multiple algorithms.
        let ring_kp = Ed25519KeyPair::from_seed_unchecked(seed_bytes)
            .map_err(|e| MCPError::invalid_key(e, "Failed to create Ed25519 key from seed (length must be 32)"))?; // Add reason
        // `from_seed_unchecked` requires the caller ensures length, but ring checks anyway.
        // We could add an explicit length check here for clarity if desired.
        Ok(KeyPair { ring_kp })
    }

    /// Returns the public key bytes (32 bytes for Ed25519).
    pub fn public_key_bytes(&self) -> &[u8] {
        self.ring_kp.public_key().as_ref()
    }

    /// Signs a message using the private key. Returns `ring::signature::Signature`.
    pub fn sign(&self, message: &[u8]) -> signature::Signature {
        // TODO(#1): Adapt this if supporting multiple algorithms.
        self.ring_kp.sign(message)
    }

    // TODO(#1): Add method to get the algorithm identifier when implemented.
    // pub fn algorithm(&self) -> SignatureAlgorithm { self.algorithm } 
}

// --- Signing Operations ---

/// Signs an [`McpRequest`] in-place, populating its `signature` field.
///
/// Calculates the signature over a canonical representation of the request.
///
/// # Arguments
/// * `request`: The [`McpRequest`] to sign (mutable).
/// * `key_pair`: The [`KeyPair`] to use for signing.
/// * `key_id`: An identifier for the public key corresponding to the `key_pair`.
pub fn sign_request(request: &mut McpRequest, key_pair: &KeyPair, key_id: String) -> Result<()> {
    // Ensure signature field is None before preparing bytes
    request.signature = None; 
    
    // Prepare the data to be signed (canonical representation).
    let message_bytes = prepare_request_for_signing(request)?;

    // Sign the message.
    let signature = key_pair.sign(&message_bytes);
    
    // TODO(#1): Get algorithm string from key_pair.algorithm when implemented.
    let algorithm = "Ed25519".to_string(); 

    // Populate the signature field in the request.
    request.signature = Some(CryptoSignature {
        key_id,
        algorithm,
        signature: Bytes::copy_from_slice(signature.as_ref()),
    });

    Ok(())
}

/// Signs an [`McpResponse`] in-place, populating its `signature` field.
///
/// Calculates the signature over a canonical representation of the response.
///
/// # Arguments
/// * `response`: The [`McpResponse`] to sign (mutable).
/// * `key_pair`: The [`KeyPair`] of the responder used for signing.
/// * `key_id`: An identifier for the public key corresponding to the `key_pair`.
pub fn sign_response(response: &mut McpResponse, key_pair: &KeyPair, key_id: String) -> Result<()> {
    // Ensure signature field is None before preparing bytes
    response.signature = None;
    
    // Prepare the data to be signed (canonical representation).
    let message_bytes = prepare_response_for_signing(response)?;

    // Sign the message.
    let signature = key_pair.sign(&message_bytes);
    
    // TODO: Get algorithm from key_pair when implemented.
    let algorithm = "Ed25519".to_string(); 

    // Populate the signature field in the response.
    response.signature = Some(CryptoSignature {
        key_id,
        algorithm,
        signature: Bytes::copy_from_slice(signature.as_ref()),
    });

    Ok(())
}

// --- Verification Operations ---

/// Verifies a cryptographic signature against a message using a public key and algorithm.
///
/// Currently supports "Ed25519".
///
/// # Arguments
/// * `public_key_bytes`: The raw public key bytes.
/// * `message`: The message data that was allegedly signed.
/// * `signature_bytes`: The raw signature bytes.
/// * `algorithm`: The identifier string for the signature algorithm (e.g., "Ed25519").
///
/// # Errors
/// Returns `MCPError::InvalidKey` if the key length is incorrect for the algorithm.
/// Returns `MCPError::SignatureError` if the algorithm is unsupported or verification fails.
pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    algorithm: &str, 
) -> Result<()> {
    match algorithm.to_uppercase().as_str() {
        "ED25519" => {
            // Validate key length before creating UnparsedPublicKey
            if public_key_bytes.len() != ED25519.public_key_len() { 
                return Err(MCPError::invalid_key( 
                    ring::error::KeyRejected::wrong_length("Ed25519 public key length incorrect".into()),
                    format!("Expected {} bytes for Ed25519 public key, got {}", ED25519.public_key_len(), public_key_bytes.len())
                ));
            }
            // Validate signature length
             if signature_bytes.len() != ED25519.signature_len() { 
                 return Err(MCPError::signature_error(format!(
                     "Invalid Ed25519 signature length: expected {} bytes, got {}", ED25519.signature_len(), signature_bytes.len()
                 )));
             }
             
            let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
            public_key.verify(message, signature_bytes)
                .map_err(|e| MCPError::signature_error(format!("Ed25519 verification failed: {}", e)))
        }
        _ => {
            Err(MCPError::signature_error(format!(
                "Unsupported signature algorithm for verification: {}", algorithm
            )))
        }
    }
}

/// Verifies the signature of an [`McpRequest`] using the public key from its `requestor_identity`.
///
/// # Errors
/// Returns `MCPError::MissingField` if required identity/signature fields are absent.
/// Returns errors from [`verify_signature`] if verification fails.
pub fn verify_request_signature(request: &McpRequest) -> Result<()> {
    let signature_info = request.signature.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.signature"))?;

    let identity = request.requestor_identity.as_ref()
        .ok_or_else(|| MCPError::missing_field("request.requestor_identity"))?;
    
    if identity.public_key.is_empty() {
        return Err(MCPError::missing_field("request.requestor_identity.public_key"));
    }
    
    // Clone request and clear signature field for preparing bytes
    let mut request_for_signing = request.clone();
    request_for_signing.signature = None;
    
    // Prepare the data that was allegedly signed.
    let message_bytes = prepare_request_for_signing(&request_for_signing)?;

    // Perform verification using the algorithm specified in the signature info.
    verify_signature(
        &identity.public_key, 
        &message_bytes, 
        &signature_info.signature, 
        &signature_info.algorithm, // Pass algorithm from signature
    )
}

/// Verifies the signature of an [`McpResponse`] using an externally provided public key.
///
/// **Note:** The responder's public key must be obtained via a trusted mechanism,
/// potentially using the `key_id` from the response's signature for lookup.
///
/// # Arguments
/// * `response`: The [`McpResponse`] to verify.
/// * `responder_public_key_bytes`: The public key bytes of the entity expected to have signed.
///
/// # Errors
/// Returns `MCPError::MissingField` if the signature field is absent.
/// Returns errors from [`verify_signature`] if verification fails.
pub fn verify_response_signature(response: &McpResponse, responder_public_key_bytes: &[u8]) -> Result<()> {
    let signature_info = response.signature.as_ref()
        .ok_or_else(|| MCPError::missing_field("response.signature"))?;

    // Clone response and clear signature field for preparing bytes
    let mut response_for_signing = response.clone();
    response_for_signing.signature = None;

    // Prepare the data that was allegedly signed.
    let message_bytes = prepare_response_for_signing(&response_for_signing)?;
    
    // TODO: Optionally, add a check here: look up the key_id specified in
    // signature_info.key_id and confirm it matches the provided responder_public_key_bytes.
    // This requires a key management system or trusted configuration.
    // Example: 
    // if !key_store::verify_key_matches_id(responder_public_key_bytes, &signature_info.key_id) {
    //     return Err(MCPError::SignatureError("Provided public key does not match key_id in signature".to_string()));
    // }

    // Perform verification using the provided public key and the algorithm from the signature.
    verify_signature(
        responder_public_key_bytes,
        &message_bytes,
        &signature_info.signature,
        &signature_info.algorithm, // Use algorithm from signature info
    )
}

// --- Tests (Example Structure) ---
#[cfg(test)]
mod tests {
    use super::*; 
    use crate::builders::{McpRequestBuilder, McpResponseBuilder}; // Assuming builders.rs
    use crate::types::{RequestorIdentity, PurposeDna, PermissionSpecification, Action, Status};
    use crate::utils::prost_timestamp_from_chrono;
    use chrono::Utc;

    // Helper functions for setup
    fn setup_request() -> (KeyPair, McpRequest) {
        let key_pair = KeyPair::generate().unwrap();
        let identity = RequestorIdentity {
            pseudonym_id: "req-id-crypto".to_string(),
            public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()),
            attestations: vec![],
        };
        let purpose = PurposeDna { purpose_id: "purp-crypto".into(), /* ... other fields ... */ 
            primary_purpose_category: 1, specific_purpose_description: "desc".into(), 
            data_types_involved: vec!["dt".into()], processing_description: "p".into(),
            storage_description: "s".into(), intended_recipients: vec![],
            purpose_expiry_timestamp: None, legal_context_url: String::new(), agent_metadata: None,
            constraints: None
        };
        let perm = PermissionSpecification { resource_identifier: "res-crypto".into(), requested_action: Action::Read as i32, constraints: None };
        let mut request = McpRequestBuilder::new(identity, purpose, "1.0.0".into())
            .add_permission(perm)
            .build();
        (key_pair, request)
    }
    
    fn setup_response(request_id: String) -> (KeyPair, McpResponse) {
        let key_pair = KeyPair::generate().unwrap();
        let response = McpResponseBuilder::new(request_id, Status::Approved, "1.0.0".into())
            .build();
        (key_pair, response)
    }

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert!(kp.is_ok());
        let kp = kp.unwrap();
        assert_eq!(kp.public_key_bytes().len(), 32); // Ed25519 public key size
    }
    
    #[test]
    fn test_keypair_from_pkcs8() -> Result<()> {
        let original_kp = KeyPair::generate()?;
        let pkcs8 = original_kp.ring_kp.to_pkcs8().map_err(|_| MCPError::CryptoUnspecified{ source: RingUnspecified })?; // Get PKCS8 bytes
        let kp_from_pkcs8 = KeyPair::from_pkcs8(pkcs8.as_ref())?;
        assert_eq!(original_kp.public_key_bytes(), kp_from_pkcs8.public_key_bytes());
        Ok(())
    }
    
     #[test]
    fn test_keypair_from_seed() -> Result<()> {
         let seed = [1u8; 32];
         let kp = KeyPair::from_seed(&seed)?;
         assert!(kp.public_key_bytes().len() == 32);
         // Trying with wrong length should fail
         let bad_seed = [2u8; 31];
         assert!(KeyPair::from_seed(&bad_seed).is_err());
         let bad_seed = [3u8; 33];
         assert!(KeyPair::from_seed(&bad_seed).is_err());
         Ok(())
    }

    #[test]
    fn test_sign_request_and_verify() -> Result<()> {
        let (key_pair, mut request) = setup_request();
        let key_id = "crypto-test-key-1".to_string();

        sign_request(&mut request, &key_pair, key_id.clone())?;

        assert!(request.signature.is_some());
        let sig_info = request.signature.as_ref().unwrap();
        assert_eq!(sig_info.key_id, key_id);
        assert_eq!(sig_info.algorithm, "Ed25519");
        assert!(!sig_info.signature.is_empty());

        // Verification should pass
        let verification_result = verify_request_signature(&request);
        assert!(verification_result.is_ok(), "Verification failed: {:?}", verification_result.err());

        Ok(())
    }
    
    #[test]
    fn test_verify_request_tampered() -> Result<()> {
        let (key_pair, mut request) = setup_request();
        sign_request(&mut request, &key_pair, "tamper-key".to_string())?;
        
        // Tamper request *after* signing
        request.related_request_id = "i-am-tampering".to_string(); 
        
        let verification_result = verify_request_signature(&request);
        assert!(verification_result.is_err());
        assert!(matches!(verification_result.unwrap_err(), MCPError::SignatureError { .. }));
        
        Ok(())
    }
    
     #[test]
    fn test_verify_request_wrong_key() -> Result<()> {
         let (signing_key, mut request) = setup_request(); // `request` has pub key of `signing_key`
         let (wrong_key, _) = setup_request(); // Generate another key pair

        // Sign with the correct key
        sign_request(&mut request, &signing_key, "correct-key-id".to_string())?;
        
        // Attempt to verify using the identity in the request (which contains the correct public key)
        // This should pass.
        assert!(verify_request_signature(&request).is_ok());
        
        // Now, let's simulate if the identity contained the WRONG public key
         request.requestor_identity.as_mut().unwrap().public_key = Bytes::copy_from_slice(wrong_key.public_key_bytes());
        // Re-sign is not needed, signature is still based on `signing_key`, but identity now mismatches
        
         let verification_result = verify_request_signature(&request);
         assert!(verification_result.is_err());
         assert!(matches!(verification_result.unwrap_err(), MCPError::SignatureError { .. }));
        
         Ok(())
    }

    #[test]
    fn test_sign_response_and_verify() -> Result<()> {
        let request_id = "req-for-resp-crypto".to_string();
        let (responder_key_pair, mut response) = setup_response(request_id.clone());
        let key_id = "crypto-resp-key-1".to_string();

        sign_response(&mut response, &responder_key_pair, key_id.clone())?;

        assert!(response.signature.is_some());
        let sig_info = response.signature.as_ref().unwrap();
        assert_eq!(sig_info.key_id, key_id);
        assert_eq!(sig_info.algorithm, "Ed25519");
        assert!(!sig_info.signature.is_empty());

        // Verification should pass using the correct public key
        let verification_result = verify_response_signature(&response, responder_key_pair.public_key_bytes());
        assert!(verification_result.is_ok(), "Verification failed: {:?}", verification_result.err());

        Ok(())
    }
    
    #[test]
    fn test_verify_response_tampered() -> Result<()> {
        let (responder_key_pair, mut response) = setup_response("resp-tamper-req".into());
        sign_response(&mut response, &responder_key_pair, "resp-tamper-key".to_string())?;
        
        // Tamper response *after* signing
        response.status_message = "This response was tampered!".to_string();
        
        let verification_result = verify_response_signature(&response, responder_key_pair.public_key_bytes());
        assert!(verification_result.is_err());
        assert!(matches!(verification_result.unwrap_err(), MCPError::SignatureError { .. }));
        
        Ok(())
    }
    
    #[test]
    fn test_verify_response_wrong_key() -> Result<()> {
        let (responder_key_pair, mut response) = setup_response("resp-wrongkey-req".into());
        let (other_key_pair, _) = setup_response("other-req".into()); // Just need another key
        
        sign_response(&mut response, &responder_key_pair, "resp-wrongkey-key".to_string())?;
        
        // Attempt verification with the WRONG public key
        let verification_result = verify_response_signature(&response, other_key_pair.public_key_bytes());
        assert!(verification_result.is_err());
        assert!(matches!(verification_result.unwrap_err(), MCPError::SignatureError { .. }));
        
        Ok(())
    }
    
     #[test]
    fn test_verify_signature_direct_invalid_algo() -> Result<()> {
         let kp = KeyPair::generate()?;
         let msg = b"test message";
         let sig = kp.sign(msg);
         let result = verify_signature(kp.public_key_bytes(), msg, sig.as_ref(), "INVALID-ALGO");
         assert!(result.is_err());
         assert!(matches!(result.unwrap_err(), MCPError::SignatureError{ reason } if reason.contains("Unsupported")));
         Ok(())
    }
    
     #[test]
    fn test_verify_signature_direct_invalid_key_len() -> Result<()> {
         let kp = KeyPair::generate()?;
         let msg = b"test message";
         let sig = kp.sign(msg);
         let bad_key = &kp.public_key_bytes()[..31]; // Too short
         let result = verify_signature(bad_key, msg, sig.as_ref(), "Ed25519");
         assert!(result.is_err());
         assert!(matches!(result.unwrap_err(), MCPError::InvalidKey{ .. }));
         Ok(())
    }
    
      #[test]
    fn test_verify_signature_direct_invalid_sig_len() -> Result<()> {
         let kp = KeyPair::generate()?;
         let msg = b"test message";
         let sig = kp.sign(msg);
         let bad_sig = &sig.as_ref()[..63]; // Too short
         let result = verify_signature(kp.public_key_bytes(), msg, bad_sig, "Ed25519");
         assert!(result.is_err());
         assert!(matches!(result.unwrap_err(), MCPError::SignatureError{ reason } if reason.contains("length")));
         Ok(())
    }

} 