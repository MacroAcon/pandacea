//! Cryptographic operations for MCP (signing, verification, key handling).

use crate::error::{MCPError, Result};
use crate::types::{CryptoSignature, McpRequest, McpResponse};
use crate::serialization::{prepare_request_for_signing, prepare_response_for_signing}; 
use bytes::Bytes;
use rand::rngs::OsRng; // Used for key generation
use ed25519_dalek::{
    Signature as DalekSignature,
    Signer, 
    SigningKey, 
    Verifier, 
    VerifyingKey, 
    SIGNATURE_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH
};
use pkcs8::{
    EncodePrivateKey, // Trait for encoding
    DecodePrivateKey, // Trait for decoding
};


// --- Key Pair Abstraction ---

/// Represents a cryptographic key pair, currently supporting Ed25519.
/// Uses ed25519-dalek and the `signature` traits.
#[derive(Debug)] 
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    // TODO: Add algorithm enum later for multi-algorithm support.
    // algorithm: SignatureAlgorithm,
}

// TODO: Define SignatureAlgorithm enum when supporting multiple algorithms.

impl KeyPair {
    /// Generates a new Ed25519 `KeyPair` using `OsRng`.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        KeyPair {
            signing_key,
            verifying_key,
        }
    }

    /// Creates an Ed25519 `KeyPair` from PKCS#8 v1 encoded private key bytes.
    ///
    /// # Arguments
    /// * `pkcs8_bytes`: The DER-encoded PKCS#8 private key.
    ///
    /// # Errors
    /// Returns `MCPError::Pkcs8Error` or `MCPError::InvalidKey` on parsing failure.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self> {
        // Decode using pkcs8 crate
        let signing_key = SigningKey::from_pkcs8_der(pkcs8_bytes)
            .map_err(|e| MCPError::pkcs8_error("Failed to parse Ed25519 key from PKCS#8 DER", e))?;
        let verifying_key = signing_key.verifying_key();
        Ok(KeyPair {
            signing_key,
            verifying_key,
        })
    }

    /// Exports the private key to PKCS#8 v1 DER format.
    ///
    /// # Errors
    /// Returns `MCPError::Pkcs8Error` if encoding fails.
    pub fn to_pkcs8_der(&self) -> Result<pkcs8::SecretDocument> { // Correct return type
        self.signing_key.to_pkcs8_der()
           .map_err(|e| MCPError::pkcs8_error("Failed to encode Ed25519 key to PKCS#8 DER", e))
    }

    /// Creates an Ed25519 `KeyPair` directly from a 32-byte seed.
    ///
    /// **Warning:** Handling seeds requires care. Prefer `generate` or `from_pkcs8`.
    ///
    /// # Arguments
    /// * `seed_bytes`: The 32-byte seed for the Ed25519 key.
    ///
    /// # Errors
    /// Returns `MCPError::InvalidKey` if the seed length is incorrect.
    pub fn from_seed(seed_bytes: &[u8]) -> Result<Self> {
        let seed_array: [u8; SECRET_KEY_LENGTH] = seed_bytes.try_into().map_err(|_|
            MCPError::invalid_key(
                format!("Invalid seed length: expected {} bytes, got {}", SECRET_KEY_LENGTH, seed_bytes.len()),
                None // No specific underlying error source here
            )
        )?;
        let signing_key = SigningKey::from_bytes(&seed_array); // from_bytes does not fail for Ed25519
        let verifying_key = signing_key.verifying_key();
        Ok(KeyPair { signing_key, verifying_key })
    }

    /// Returns the verifying (public) key bytes (32 bytes for Ed25519).
    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.verifying_key.as_bytes()
    }

    /// Signs a message using the private key. Returns the signature.
    /// Uses a deterministic signing approach (no external randomness needed post-key-gen).
    pub fn sign(&self, message: &[u8]) -> DalekSignature {
        self.signing_key.sign(message)
    }

    // Optional: Sign using external RNG (less common for Ed25519)
    // pub fn sign_with_rng(&self, message: &[u8]) -> DalekSignature {
    //     let mut csprng = OsRng;
    //     self.signing_key.sign_with_rng(&mut csprng, message)
    // }
}

// --- Signing Operations ---

/// Signs an [`McpRequest`] in-place, populating its `signature` field.
/// Uses Ed25519 algorithm.
pub fn sign_request(request: &mut McpRequest, key_pair: &KeyPair, key_id: String) -> Result<()> {
    request.signature = None; // Ensure signature is None before serializing
    let message_bytes = prepare_request_for_signing(request)?;
    let signature = key_pair.sign(&message_bytes);

    request.signature = Some(CryptoSignature {
        key_id,
        algorithm: "Ed25519".to_string(), // Hardcoded for now
        signature: Bytes::copy_from_slice(signature.to_bytes().as_ref()),
    });

    Ok(())
}

/// Signs an [`McpResponse`] in-place, populating its `signature` field.
/// Uses Ed25519 algorithm.
pub fn sign_response(response: &mut McpResponse, key_pair: &KeyPair, key_id: String) -> Result<()> {
    response.signature = None; // Ensure signature is None before serializing
    let message_bytes = prepare_response_for_signing(response)?;
    let signature = key_pair.sign(&message_bytes);

    response.signature = Some(CryptoSignature {
        key_id,
        algorithm: "Ed25519".to_string(), // Hardcoded for now
        signature: Bytes::copy_from_slice(signature.to_bytes().as_ref()),
    });

    Ok(())
}

// --- Verification Operations ---

/// Verifies a cryptographic signature against a message using a public key and algorithm.
///
/// Currently supports "Ed25519".
///
/// # Arguments
/// * `public_key_bytes`: The raw public key bytes (expected 32 bytes for Ed25519).
/// * `message`: The message data that was allegedly signed.
/// * `signature_bytes`: The raw signature bytes (expected 64 bytes for Ed25519).
/// * `algorithm`: The identifier string for the signature algorithm (e.g., "Ed25519").
///
/// # Errors
/// Returns `MCPError::InvalidKey` if the key length is incorrect.
/// Returns `MCPError::SignatureError` if algorithm unsupported, sig length incorrect, or verification fails.
pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    algorithm: &str,
) -> Result<()> {
    match algorithm.to_uppercase().as_str() {
        "ED25519" => {
            // Validate public key length
            let verifying_key = VerifyingKey::try_from(public_key_bytes).map_err(|e|
                MCPError::invalid_key(
                    format!("Invalid Ed25519 public key length or format: expected {} bytes, got {}. Error: {}", PUBLIC_KEY_LENGTH, public_key_bytes.len(), e),
                    Some(Box::new(e))
                )
            )?;

            // Validate signature length and format
            let signature = DalekSignature::from_bytes(signature_bytes.try_into().map_err(|_|
                MCPError::signature_error(
                    format!("Invalid Ed25519 signature length: expected {} bytes, got {}", SIGNATURE_LENGTH, signature_bytes.len()),
                    None
                )
            )?);

            // Perform verification
            verifying_key.verify(message, &signature)
                .map_err(|e| MCPError::signature_error("Ed25519 signature verification failed".to_string(), Some(e)))
        }
        _ => Err(MCPError::signature_error(
            format!("Unsupported signature algorithm for verification: {}", algorithm),
            None
        )),
    }
}

/// Verifies the signature of an [`McpRequest`] using the public key from its `requestor_identity`.
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

    let message_bytes = prepare_request_for_signing(&request_for_signing)?;

    verify_signature(
        &identity.public_key,
        &message_bytes,
        &signature_info.signature,
        &signature_info.algorithm,
    )
}

/// Verifies the signature of an [`McpResponse`] using an externally provided public key.
pub fn verify_response_signature(response: &McpResponse, responder_public_key_bytes: &[u8]) -> Result<()> {
    let signature_info = response.signature.as_ref()
        .ok_or_else(|| MCPError::missing_field("response.signature"))?;

    // Clone response and clear signature field for preparing bytes
    let mut response_for_signing = response.clone();
    response_for_signing.signature = None;

    let message_bytes = prepare_response_for_signing(&response_for_signing)?;

    verify_signature(
        responder_public_key_bytes,
        &message_bytes,
        &signature_info.signature,
        &signature_info.algorithm,
    )
}

// --- Tests ---
// Note: Tests need to be adapted for the new API (KeyPair methods, error types)
#[cfg(test)]
mod tests {
    use super::*; // Import names from outer module
    use crate::types::{EntityIdentity, McpMessage, RequestDetails, ResponseDetails, Status};
    use prost_types::Timestamp;
    use chrono::Utc;
    use pkcs8::SecretDocument; // Use SecretDocument for PKCS#8 bytes

    // Helper to create a dummy request
    fn setup_request() -> (KeyPair, McpRequest) {
        let key_pair = KeyPair::generate();
        let requestor_id = EntityIdentity {
            identifier: "requester@example.com".to_string(),
            public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()),
            key_id: Some("key-1".to_string()),
        };
        let request = McpRequest {
            version: "1.0".to_string(),
            request_id: "req-123".to_string(),
            requestor_identity: Some(requestor_id),
            request_timestamp: Some(Timestamp::from(Utc::now())),
            request_expiry: None,
            target_identity: Some(EntityIdentity {
                 identifier: "target@example.com".to_string(),
                 public_key: Bytes::new(), // Example: Target key might not be known upfront
                 key_id: None,
            }),
            chain_id: None,
            details: Some(RequestDetails::DataRequestDetails(Default::default())), // Example
            signature: None, // Will be filled by sign_request
        };
        (key_pair, request)
    }

     // Helper to create a dummy response
     fn setup_response(request_id: String) -> (KeyPair, McpResponse) {
        let key_pair = KeyPair::generate(); // Responder's key pair
        let response = McpResponse {
            version: "1.0".to_string(),
            request_id, // Link to the original request
            responder_identity: Some(EntityIdentity { // Responder provides their identity
                identifier: "responder@example.com".to_string(),
                public_key: Bytes::copy_from_slice(key_pair.public_key_bytes()),
                key_id: Some("resp-key-1".to_string()),
            }),
            response_timestamp: Some(Timestamp::from(Utc::now())),
            status: Status::Success as i32,
            details: Some(ResponseDetails::DataResponseDetails(Default::default())), // Example
            signature: None, // Will be filled by sign_response
        };
        (key_pair, response)
    }

    #[test]
    fn test_keypair_generation() {
        let key_pair = KeyPair::generate();
        assert_eq!(key_pair.public_key_bytes().len(), PUBLIC_KEY_LENGTH);
        // Check if signing works (basic check)
        let msg = b"test message";
        let sig = key_pair.sign(msg);
        assert!(key_pair.verifying_key.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_keypair_from_to_pkcs8() -> Result<()> {
        let key_pair1 = KeyPair::generate();
        let pkcs8_doc: pkcs8::SecretDocument = key_pair1.to_pkcs8_der()?; // Use explicit path in test
        let pkcs8_bytes = pkcs8_doc.as_bytes(); // Get bytes from SecretDocument

        let key_pair2 = KeyPair::from_pkcs8(pkcs8_bytes)?;

        assert_eq!(key_pair1.public_key_bytes(), key_pair2.public_key_bytes());

        // Verify that the loaded key can sign and verify
        let msg = b"another test";
        let sig = key_pair2.sign(msg);
        assert!(key_pair1.verifying_key.verify(msg, &sig).is_ok()); // Verify with original key
        assert!(key_pair2.verifying_key.verify(msg, &sig).is_ok()); // Verify with loaded key

        Ok(())
    }

    #[test]
    fn test_keypair_from_seed() -> Result<()> {
        let seed = [0u8; SECRET_KEY_LENGTH];
        let key_pair = KeyPair::from_seed(&seed)?;
        assert_eq!(key_pair.public_key_bytes().len(), PUBLIC_KEY_LENGTH);

        // Test signing with the derived key
        let msg = b"seed test";
        let sig = key_pair.sign(msg);
        assert!(key_pair.verifying_key.verify(msg, &sig).is_ok());
        Ok(())
    }

    #[test]
    fn test_keypair_from_seed_invalid_length() {
        let short_seed = [0u8; 31];
        let result = KeyPair::from_seed(&short_seed);
        assert!(matches!(result, Err(MCPError::InvalidKey { .. })));
        assert!(result.unwrap_err().to_string().contains("Invalid seed length"));

        let long_seed = [0u8; 33];
        let result = KeyPair::from_seed(&long_seed);
        assert!(matches!(result, Err(MCPError::InvalidKey { .. })));
        assert!(result.unwrap_err().to_string().contains("Invalid seed length"));
    }

    #[test]
    fn test_sign_request_and_verify() -> Result<()> {
        let (key_pair, mut request) = setup_request();
        let key_id = "key-1".to_string();

        sign_request(&mut request, &key_pair, key_id.clone())?;

        assert!(request.signature.is_some());
        let sig_info = request.signature.as_ref().unwrap();
        assert_eq!(sig_info.key_id, key_id);
        assert_eq!(sig_info.algorithm, "Ed25519");
        assert_eq!(sig_info.signature.len(), SIGNATURE_LENGTH);

        // Now verify the signature
        verify_request_signature(&request)
    }

    #[test]
    fn test_verify_request_tampered() -> Result<()> {
        let (key_pair, mut request) = setup_request();
        sign_request(&mut request, &key_pair, "key-1".to_string())?;

        // Tamper with the request *after* signing
        request.request_id = "tampered-req-id".to_string();

        let result = verify_request_signature(&request);
        assert!(matches!(result, Err(MCPError::SignatureError { .. })));
        Ok(())
    }

    #[test]
    fn test_verify_request_wrong_key() -> Result<()> {
        let (signing_key_pair, mut request) = setup_request();
        sign_request(&mut request, &signing_key_pair, "key-1".to_string())?;

        // Create a different key pair for verification attempt
        let wrong_key_pair = KeyPair::generate();
        request.requestor_identity.as_mut().unwrap().public_key =
            Bytes::copy_from_slice(wrong_key_pair.public_key_bytes());

        let result = verify_request_signature(&request);
        assert!(matches!(result, Err(MCPError::SignatureError { .. })));
        Ok(())
    }

     #[test]
     fn test_sign_response_and_verify() -> Result<()> {
         let (req_kp, request) = setup_request(); // Need request ID
         let (resp_kp, mut response) = setup_response(request.request_id.clone());
         let resp_key_id = "resp-key-1".to_string();

         sign_response(&mut response, &resp_kp, resp_key_id.clone())?;

         assert!(response.signature.is_some());
         let sig_info = response.signature.as_ref().unwrap();
         assert_eq!(sig_info.key_id, resp_key_id);
         assert_eq!(sig_info.algorithm, "Ed25519");
         assert_eq!(sig_info.signature.len(), SIGNATURE_LENGTH);

         // Now verify the signature using the correct public key
         verify_response_signature(&response, resp_kp.public_key_bytes())
     }

     #[test]
     fn test_verify_response_tampered() -> Result<()> {
         let (_, request) = setup_request();
         let (resp_kp, mut response) = setup_response(request.request_id.clone());
         sign_response(&mut response, &resp_kp, "resp-key-1".to_string())?;

         // Tamper with the response *after* signing
         response.status = Status::InternalError as i32;

         let result = verify_response_signature(&response, resp_kp.public_key_bytes());
         assert!(matches!(result, Err(MCPError::SignatureError { .. })));
         Ok(())
     }

     #[test]
     fn test_verify_response_wrong_key() -> Result<()> {
         let (_, request) = setup_request();
         let (signing_resp_kp, mut response) = setup_response(request.request_id.clone());
         sign_response(&mut response, &signing_resp_kp, "resp-key-1".to_string())?;

         // Generate a different key pair for verification
         let wrong_kp = KeyPair::generate();

         let result = verify_response_signature(&response, wrong_kp.public_key_bytes());
         assert!(matches!(result, Err(MCPError::SignatureError { .. })));
         Ok(())
     }

    #[test]
    fn test_verify_signature_direct_invalid_algo() -> Result<()> {
        let key_pair = KeyPair::generate();
        let msg = b"test message";
        let sig = key_pair.sign(msg);

        let result = verify_signature(
            key_pair.public_key_bytes(),
            msg,
            sig.to_bytes().as_ref(),
            "UnsupportedAlgorithm",
        );
        assert!(matches!(result, Err(MCPError::SignatureError { .. })));
        assert!(result.unwrap_err().to_string().contains("Unsupported signature algorithm"));
        Ok(())
    }

    #[test]
    fn test_verify_signature_direct_invalid_key_len() -> Result<()> {
        let key_pair = KeyPair::generate();
        let msg = b"test message";
        let sig = key_pair.sign(msg);
        let mut wrong_key = key_pair.public_key_bytes().to_vec();
        wrong_key.pop(); // Make it too short

        let result = verify_signature(
            &wrong_key,
            msg,
            sig.to_bytes().as_ref(),
            "Ed25519",
        );
        assert!(matches!(result, Err(MCPError::InvalidKey { .. })));
        assert!(result.unwrap_err().to_string().contains("Invalid Ed25519 public key length"));
        Ok(())
    }

    #[test]
    fn test_verify_signature_direct_invalid_sig_len() -> Result<()> {
        let key_pair = KeyPair::generate();
        let msg = b"test message";
        let mut sig_bytes = key_pair.sign(msg).to_bytes().to_vec();
        sig_bytes.pop(); // Make signature too short

        let result = verify_signature(
            key_pair.public_key_bytes(),
            msg,
            &sig_bytes,
            "Ed25519",
        );
         assert!(matches!(result, Err(MCPError::SignatureError { .. })));
         assert!(result.unwrap_err().to_string().contains("Invalid Ed25519 signature length"));
        Ok(())
    }
} 