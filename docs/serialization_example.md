# MCP Serialization Examples

This document provides practical examples of using the Pandacea MCP serialization system.

## Basic Request Serialization

```rust
use pandacea::serialization::{serialize_request, deserialize_request};
use pandacea::types::{McpRequest, RequestorIdentity, PurposeDNA, PermissionSpecification};
use pandacea::types::permission_specification::Action;
use pandacea::types::purpose_dna::PurposeCategory;
use bytes::Bytes;
use prost_types::Timestamp;
use std::time::SystemTime;

// Create a basic request
fn create_sample_request() -> McpRequest {
    // Create a timestamp (now)
    let now = SystemTime::now();
    let timestamp = Timestamp {
        seconds: now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
        nanos: 0,
    };
    
    // Create identity
    let identity = RequestorIdentity {
        pseudonym_id: "user-123".to_string(),
        public_key: Bytes::from_static(&[1, 2, 3, 4]), // Sample key
        ..Default::default()
    };
    
    // Create purpose
    let purpose = PurposeDNA {
        purpose_id: "purpose-456".to_string(),
        primary_purpose_category: PurposeCategory::Analytics as i32,
        specific_purpose_description: "Analyzing usage patterns".to_string(),
        data_types_involved: vec!["app.usage".to_string()],
        processing_description: "Aggregated statistics".to_string(),
        storage_description: "30 days, encrypted".to_string(),
        ..Default::default()
    };
    
    // Create permission
    let permission = PermissionSpecification {
        resource_identifier: "app.usage".to_string(),
        requested_action: Action::Read as i32,
        ..Default::default()
    };
    
    // Assemble request
    McpRequest {
        request_id: "req-789".to_string(),
        timestamp: Some(timestamp),
        requestor_identity: Some(identity),
        purpose_dna: Some(purpose),
        permissions: vec![permission],
        mcp_version: "1.1.0".to_string(),
        ..Default::default()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a request
    let request = create_sample_request();
    
    // Serialize to bytes (for network transmission)
    let serialized_bytes = serialize_request(&request)?;
    println!("Serialized size: {} bytes", serialized_bytes.len());
    
    // Deserialize back to a request
    let deserialized = deserialize_request(&serialized_bytes)?;
    assert_eq!(request.request_id, deserialized.request_id);
    
    Ok(())
}
```

## Signing a Request

```rust
use pandacea::serialization::prepare_request_for_signing;
use pandacea::types::{McpRequest, CryptoSignature};
use pandacea::crypto::{KeyPair, sign_request, verify_request_signature};
use bytes::Bytes;

fn sign_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create a sample request
    let mut request = create_sample_request();
    
    // Generate a key pair
    let key_pair = KeyPair::generate();
    
    // Method 1: Use the sign_request helper
    sign_request(&mut request, &key_pair, "key-1".to_string())?;
    
    // Method 2: Manual signing process
    // 1. Prepare canonical bytes
    let canonical_bytes = prepare_request_for_signing(&request)?;
    
    // 2. Sign the bytes
    let signature = key_pair.sign(&canonical_bytes);
    
    // 3. Add signature to request
    request.signature = Some(CryptoSignature {
        key_id: "key-1".to_string(),
        algorithm: "Ed25519".to_string(),
        signature: Bytes::copy_from_slice(signature.to_bytes().as_ref()),
        ..Default::default()
    });
    
    // Verify the signature
    verify_request_signature(&request)?;
    println!("Signature verified successfully");
    
    Ok(())
}
```

## Response Serialization

```rust
use pandacea::serialization::{serialize_response, deserialize_response};
use pandacea::types::{McpResponse, McpResponse_PermissionStatus};
use pandacea::types::mcp_response::Status as ResponseStatus;
use prost_types::Timestamp;
use std::time::SystemTime;

fn response_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create a timestamp (now)
    let now = SystemTime::now();
    let timestamp = Timestamp {
        seconds: now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
        nanos: 0,
    };
    
    // Create permission status
    let status = McpResponse_PermissionStatus {
        resource_identifier: "app.usage".to_string(),
        requested_action: Action::Read as i32,
        granted: true,
        ..Default::default()
    };
    
    // Create response
    let response = McpResponse {
        response_id: "resp-abc".to_string(),
        request_id: "req-789".to_string(),
        timestamp: Some(timestamp),
        status: ResponseStatus::Approved as i32,
        permission_statuses: vec![status],
        mcp_version: "1.1.0".to_string(),
        ..Default::default()
    };
    
    // Serialize and deserialize
    let serialized = serialize_response(&response)?;
    let deserialized = deserialize_response(&serialized)?;
    
    assert_eq!(response.response_id, deserialized.response_id);
    assert_eq!(response.status, deserialized.status);
    
    Ok(())
}
```

## Working with Compensation Models

```rust
use pandacea::types::{McpRequest, CompensationModel, PaymentMethod};
use pandacea::types::compensation_model::CompensationType;
use pandacea::serialization::prepare_request_for_signing;

fn compensation_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create a sample request
    let mut request = create_sample_request();
    
    // Add a compensation model
    let payment_method = PaymentMethod {
        payment_type: "wallet".to_string(),
        payment_identifier: "0x1234567890abcdef".to_string(),
        ..Default::default()
    };
    
    let compensation = CompensationModel {
        compensation_type: CompensationType::Token as i32,
        amount: 0.25,
        unit: "DATA_TOKEN".to_string(),
        payment_method: Some(payment_method),
        ..Default::default()
    };
    
    request.compensation_model = Some(compensation);
    
    // When we prepare for signing, the compensation model will be
    // included in the canonical representation
    let canonical_bytes1 = prepare_request_for_signing(&request)?;
    
    // If we create another request with a slightly different floating point value
    // but semantically the same, the canonical representation should be identical
    let mut request2 = request.clone();
    if let Some(comp) = request2.compensation_model.as_mut() {
        comp.amount = 0.250000001; // Slightly different but effectively the same
    }
    
    let canonical_bytes2 = prepare_request_for_signing(&request2)?;
    
    // The canonical bytes should be identical despite the floating point difference
    assert_eq!(canonical_bytes1, canonical_bytes2);
    
    Ok(())
}
```

## Field Order Independence

```rust
use pandacea::serialization::prepare_request_for_signing;
use pandacea::types::McpRequest;
use prost::Message;

fn field_order_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create two requests with different field ordering
    let request1 = create_sample_request();
    
    // Create a second request by serializing and deserializing
    // This can sometimes result in different internal ordering
    let mut buf = Vec::new();
    request1.encode(&mut buf)?;
    let request2 = McpRequest::decode(buf.as_slice())?;
    
    // Despite potentially different internal representation,
    // the canonical serialization should be identical
    let canonical1 = prepare_request_for_signing(&request1)?;
    let canonical2 = prepare_request_for_signing(&request2)?;
    
    assert_eq!(canonical1, canonical2);
    println!("Canonical serialization is order-independent");
    
    Ok(())
}
```

## Full Example

For a complete working example that demonstrates all these concepts together, refer to the unit tests in the `serialization.rs` file:

```rust
// In backend/src/serialization.rs

#[cfg(test)]
mod tests {
    // Tests include:
    // - request_serialization_roundtrip
    // - response_serialization_roundtrip
    // - request_canonical_serialization
    // - response_canonical_serialization
    // - floating_point_determinism
    // - canonical_serialization_excludes_signature
    // - deserialize_invalid_data
    // - oversized_data_rejection
}
```

## Common Error Handling

```rust
use pandacea::error::MCPError;
use pandacea::serialization::deserialize_request;

fn error_handling_example() {
    // Attempt to deserialize invalid data
    let invalid_data = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let result = deserialize_request(&invalid_data);
    
    match result {
        Ok(_) => println!("Unexpectedly succeeded"),
        Err(e) => match e {
            MCPError::DeserializationError { context, source } => {
                println!("Deserialization error: {}", context);
                println!("Cause: {}", source);
            },
            MCPError::SerializationError { context, source } => {
                println!("Serialization error: {}", context);
                println!("Cause: {}", source);
            },
            _ => println!("Other error: {}", e),
        }
    }
}
```

## Best Practices

1. **Always check results**: All serialization functions return `Result` types that should be checked.
2. **Set size limits**: Be aware of the built-in size limits for network transmission.
3. **Handle signatures properly**: When manually signing, use `prepare_request_for_signing` rather than creating your own canonical form.
4. **Test with different inputs**: Verify that your code works with various message structures and field combinations.
5. **Use the high-level helpers**: For most cases, the high-level functions like `sign_request` are safer than manual signing.
6. **Be careful with floating point**: Don't rely on exact floating point equality in your application logic.
7. **Keep signatures separate**: For security-critical applications, consider keeping cryptographic keys separate from message processing. 