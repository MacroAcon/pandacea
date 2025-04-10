# MCP Serialization and Canonicalization

This document describes the serialization approaches used in the Pandacea Model Context Protocol (MCP).

## Overview

MCP uses two distinct serialization mechanisms for different purposes:

1. **Protocol Buffers (Protobuf)** - For network transmission and storage
2. **Canonical CBOR** - For cryptographic operations (signing and verification)

## Protobuf Serialization

Protocol Buffers is used as the primary wire format for MCP messages due to its efficiency, schema evolution capabilities, and wide platform support.

### Key Functions

- `serialize_request(request: &McpRequest) -> Result<Vec<u8>>`
- `deserialize_request(buf: &[u8]) -> Result<McpRequest>`
- `serialize_response(response: &McpResponse) -> Result<Vec<u8>>`
- `deserialize_response(buf: &[u8]) -> Result<McpResponse>`

### Usage

```rust
// Serializing a request
let bytes = serialize_request(&request)?;

// Deserializing a request
let request = deserialize_request(&bytes)?;
```

## Canonical Serialization for Signatures

For cryptographic operations, MCP uses a deterministic CBOR (Concise Binary Object Representation) encoding to ensure consistent byte output regardless of platform or implementation details.

### Why Canonical Serialization is Necessary

Protobuf doesn't guarantee a canonical representation - the same data can be serialized to different byte sequences:

1. Field order can vary
2. Map fields aren't deterministically ordered
3. Floats aren't guaranteed to have the same binary representation across platforms
4. Optional fields can be represented differently

This poses problems for signatures and cryptographic verification, where byte-for-byte consistency is required.

### The CBOR Approach

The canonical serialization approach:

1. Transforms MCP messages into an intermediate CBOR structure with deterministic field ordering
2. Explicitly converts floating point values to strings to ensure consistent representation
3. Uses sorted maps (BTreeMap) to ensure deterministic key ordering
4. Applies consistent formatting for timestamps, binary data, and other special types

### Key Functions

- `prepare_request_for_signing(request: &McpRequest) -> Result<Vec<u8>>`
- `prepare_response_for_signing(response: &McpResponse) -> Result<Vec<u8>>`

These functions:
1. Convert the message to a canonical form (excluding the signature field)
2. Serialize using deterministic CBOR encoding
3. Return a byte array suitable for cryptographic operations

### Canonicalization Guarantees

The canonicalization system guarantees:

1. **Deterministic Ordering**: Fields are always serialized in lexicographic order
2. **Consistent Representation**: The same data will always produce the same bytes
3. **Platform Independence**: The output is consistent across different operating systems, architectures, and languages
4. **Floating Point Stability**: Floating point numbers are converted to strings with fixed precision
5. **Binary Format Consistency**: Timestamp, binary data, and other special types are encoded in a consistent way

## Implementation Details

### CBOR Encoding Rules

The CBOR encoding follows these deterministic rules:

1. Map keys are sorted lexicographically
2. Integer values are encoded in the smallest possible representation
3. Floating point values are converted to strings with 8 decimal places
4. Binary data is tagged with CBOR tag 24
5. Timestamps are represented as tag 1 with integer nanoseconds since epoch

### Handling Special Types

- **Timestamps**: Converted to nanoseconds since epoch with CBOR tag 1
- **Binary Data**: Tagged with CBOR tag 24 for consistent handling
- **Floating Point**: Converted to strings with fixed precision
- **Maps/Objects**: Keys sorted lexicographically using BTreeMap

## Example

```rust
// Original request with signature
let original_request = McpRequest { /* ... */ };

// Prepare for signing (this creates a canonical byte representation)
let canonical_bytes = prepare_request_for_signing(&original_request)?;

// Sign the canonical bytes
let signature = key_pair.sign(&canonical_bytes);

// Add signature to request
request.signature = Some(CryptoSignature {
    key_id: "key-1".to_string(),
    algorithm: "Ed25519".to_string(),
    signature: Bytes::copy_from_slice(signature.as_ref()),
});

// Later, for verification:
let verification_bytes = prepare_request_for_signing(&signed_request)?;
let is_valid = verify_signature(public_key, &verification_bytes, &signature, "Ed25519")?;
```

## Security Considerations

1. **Signature Exclusion**: When preparing a message for signing, the signature field itself is excluded
2. **Size Limits**: The implementation enforces maximum size limits for serialized data
3. **Error Handling**: All serialization operations return Result types with detailed error information
4. **Determinism Testing**: The implementation includes tests to verify deterministic behavior across field orders and message variants

## Performance Considerations

While canonical CBOR serialization adds an extra step compared to direct signing of Protobuf bytes, the security benefits outweigh the minor performance impact. The implementation is optimized for:

1. Minimal memory allocations
2. Efficient handling of large binary fields
3. Reasonable size limits to prevent DOS attacks

## Extending the Protocol

When adding new fields to the MCP protocol:

1. Add them to the appropriate proto definition
2. Add corresponding conversion logic in the canonicalization functions
3. Ensure deterministic handling of any new data types
4. Add tests to verify the canonical serialization works as expected 