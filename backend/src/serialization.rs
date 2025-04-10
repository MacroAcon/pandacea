//! Serialization and deserialization functions for MCP messages.

use crate::types::{
    McpRequest, McpResponse, RequestorIdentity, PurposeDNA, PermissionSpecification,
    CompensationModel, TrustInformation, AuthenticationInfo, UsageLimitations,
    compensation_model::{CompensationType, PaymentMethod, RevenueSharing},
    trust_information::Credential,
    permission_specification::{Action, SensitivityLevel}
}; 
use crate::error::{Result, MCPError}; // Import Result and Error
use prost::Message;
use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, HashMap};
use std::cmp::Ordering;
use ciborium::value::{Value as CborValue, Integer};
use bytes::Bytes;

// CBOR Tag numbers for custom serialization
const CBOR_TAG_TIMESTAMP: u64 = 1; // Standard CBOR tag for timestamps
const CBOR_TAG_BINARY: u64 = 24; // Standard CBOR tag for encoded binary data

// Helper function to convert BTreeMap to Vec<(Value, Value)> for CBOR
fn btreemap_to_cbor_map(map: BTreeMap<&str, CborValue>) -> Vec<(CborValue, CborValue)> {
    map.into_iter()
        .map(|(k, v)| (CborValue::Text(k.to_string()), v))
        .collect()
}

// --- Request Serialization/Deserialization ---

/// Serializes an [`McpRequest`] into Protobuf bytes (`Vec<u8>`).
///
/// # Arguments
/// * `request`: The [`McpRequest`] to serialize.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the serialized Protobuf bytes.
/// * `Err(MCPError::SerializationError)` if encoding fails.
pub fn serialize_request(request: &McpRequest) -> Result<Vec<u8>> {
    // TODO: Consider adding size limit checks before serialization if needed.
    let mut buf = Vec::new();
    buf.reserve(request.encoded_len());
    request.encode(&mut buf)
        .map_err(|e| MCPError::SerializationError { 
            context: "McpRequest encoding".to_string(), 
            source: Box::new(e) 
        })?;
    Ok(buf)
}

/// Deserializes Protobuf bytes (`&[u8]`) into an [`McpRequest`].
///
/// # Arguments
/// * `buf`: The byte slice containing the serialized Protobuf data.
///
/// # Returns
/// * `Ok(McpRequest)` if deserialization is successful.
/// * `Err(MCPError::DeserializationError)` if decoding fails.
pub fn deserialize_request(buf: &[u8]) -> Result<McpRequest> {
    // Check maximum size - 10MB as a reasonable upper limit
    if buf.len() > 10_000_000 {
        return Err(MCPError::DeserializationError { 
            context: "Request size exceeds maximum allowed".to_string(), 
            source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Data too large"))
        });
    }
    
    McpRequest::decode(buf)
         .map_err(|e| MCPError::DeserializationError { 
             context: "McpRequest decoding".to_string(), 
             source: Box::new(e) 
         })
}

// --- Response Serialization/Deserialization ---

/// Serializes an [`McpResponse`] into Protobuf bytes (`Vec<u8>`).
///
/// # Arguments
/// * `response`: The [`McpResponse`] to serialize.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the serialized Protobuf bytes.
/// * `Err(MCPError::SerializationError)` if encoding fails.
pub fn serialize_response(response: &McpResponse) -> Result<Vec<u8>> {
    // Check for oversized response_payload
    if let Some(payload) = &response.response_payload {
        if payload.len() > 5_000_000 { // 5MB limit for payload
            return Err(MCPError::SerializationError { 
                context: "Response payload too large".to_string(), 
                source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Payload exceeds maximum size"))
            });
        }
    }

    let mut buf = Vec::new();
    buf.reserve(response.encoded_len());
    response.encode(&mut buf)
         .map_err(|e| MCPError::SerializationError { 
             context: "McpResponse encoding".to_string(), 
             source: Box::new(e) 
         })?;
    Ok(buf)
}

/// Deserializes Protobuf bytes (`&[u8]`) into an [`McpResponse`].
///
/// # Arguments
/// * `buf`: The byte slice containing the serialized Protobuf data.
///
/// # Returns
/// * `Ok(McpResponse)` if deserialization is successful.
/// * `Err(MCPError::DeserializationError)` if decoding fails.
pub fn deserialize_response(buf: &[u8]) -> Result<McpResponse> {
    // Check maximum size - 10MB as a reasonable upper limit
    if buf.len() > 10_000_000 {
        return Err(MCPError::DeserializationError { 
            context: "Response size exceeds maximum allowed".to_string(), 
            source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Data too large"))
        });
    }
    
    McpResponse::decode(buf)
        .map_err(|e| MCPError::DeserializationError { 
            context: "McpResponse decoding".to_string(), 
            source: Box::new(e) 
        })
}

// --- Canonicalization for Signatures ---

/// Prepares an [`McpRequest`] for signing by creating a canonical byte representation.
///
/// This involves:
/// 1. Converting the request to a canonical form (without the signature field)
/// 2. Serializing using deterministic CBOR encoding
///
/// # Arguments
/// * `request`: The [`McpRequest`] to prepare.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the byte sequence to be signed.
/// * `Err(MCPError)` if serialization fails.
pub fn prepare_request_for_signing(request: &McpRequest) -> Result<Vec<u8>> {
    // Step 1: Convert to canonical CBOR value
    let cbor_value = request_to_cbor_value(request)?;
    
    // Step 2: Serialize with deterministic CBOR encoding
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cbor_value, &mut buf)
        .map_err(|e| {
            MCPError::SerializationError { 
                context: format!("CBOR canonicalization of request failed: {:?}", e),
                source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
            }
        })?;
    
    Ok(buf)
}

/// Prepares an [`McpResponse`] for signing by creating a canonical byte representation.
///
/// This involves:
/// 1. Converting the response to a canonical form (without the signature field)
/// 2. Serializing using deterministic CBOR encoding
///
/// # Arguments
/// * `response`: The [`McpResponse`] to prepare.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the byte sequence to be signed.
/// * `Err(MCPError)` if serialization fails.
pub fn prepare_response_for_signing(response: &McpResponse) -> Result<Vec<u8>> {
    // Step 1: Convert to canonical CBOR value
    let cbor_value = response_to_cbor_value(response)?;
    
    // Step 2: Serialize with deterministic CBOR encoding
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cbor_value, &mut buf)
        .map_err(|e| {
            MCPError::SerializationError { 
                context: format!("CBOR canonicalization of response failed: {:?}", e),
                source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
            }
        })?;
    
    Ok(buf)
}

/// Converts an [`McpRequest`] to a canonical CBOR value.
///
/// This is the core conversion function for canonical representation of requests.
/// 
/// # Arguments
/// * `request`: The [`McpRequest`] to convert.
///
/// # Returns
/// * `Ok(CborValue)` containing the canonical value.
/// * `Err(MCPError)` if conversion fails.
fn request_to_cbor_value(request: &McpRequest) -> Result<CborValue> {
    // Create a BTreeMap for key-ordered representation
    let mut map = BTreeMap::new();
    
    // Add required fields
    map.insert("request_id", CborValue::Text(request.request_id.clone()));
    map.insert("mcp_version", CborValue::Text(request.mcp_version.clone()));
    
    // Add timestamp
    let timestamp = match &request.request_time {
        Some(crate::mcp::mcp_request::RequestTime::Timestamp(ts)) => Some(ts),
        Some(crate::mcp::mcp_request::RequestTime::RequestTimestamp(ts)) => Some(ts),
        None => None,
    }.ok_or_else(|| MCPError::missing_field("request.timestamp or request.request_timestamp"))?;
    
    // Convert to nanoseconds since epoch
    let timestamp_nanos = (timestamp.seconds * 1_000_000_000) + i64::from(timestamp.nanos);
    map.insert("timestamp", CborValue::Tag(
        CBOR_TAG_TIMESTAMP,
        Box::new(CborValue::Integer(Integer::from(timestamp_nanos)))
    ));
    
    // Add optional request_expiry
    if let Some(expiry_time) = &request.expiry_time {
        let expiry = match expiry_time {
            crate::mcp::mcp_request::ExpiryTime::Expiration(ts) => ts,
            crate::mcp::mcp_request::ExpiryTime::RequestExpiry(ts) => ts,
        };
        let expiry_nanos = (expiry.seconds * 1_000_000_000) + i64::from(expiry.nanos);
        map.insert("request_expiry", CborValue::Tag(
            CBOR_TAG_TIMESTAMP,
            Box::new(CborValue::Integer(Integer::from(expiry_nanos)))
        ));
    }
    
    // Add related_request_id if present
    if !request.related_request_id.is_empty() {
        map.insert("related_request_id", CborValue::Text(request.related_request_id.clone()));
    }
    
    // Add requestor_identity
    if let Some(identity) = &request.requestor_identity {
        map.insert("requestor_identity", identity_to_cbor_value(identity)?);
    } else {
        return Err(MCPError::missing_field("request.requestor_identity"));
    }
    
    // Add purpose_dna
    if let Some(purpose) = &request.purpose_dna {
        map.insert("purpose_dna", purpose_to_cbor_value(purpose)?);
    } else {
        return Err(MCPError::missing_field("request.purpose_dna"));
    }
    
    // Add permissions
    let permissions = request.permissions.iter()
        .map(permission_to_cbor_value)
        .collect::<Result<Vec<CborValue>>>()?;
    
    map.insert("permissions", CborValue::Array(permissions));
    
    // Add context_data if present
    if let Some(context) = &request.context_data {
        map.insert("context_data", prost_struct_to_cbor_value(context)?);
    }
    
    // Add compensation_model if present
    if let Some(compensation) = &request.compensation_model {
        map.insert("compensation_model", compensation_to_cbor_value(compensation)?);
    }
    
    // Add trust_information if present
    if let Some(trust) = &request.trust_information {
        map.insert("trust_information", trust_to_cbor_value(trust)?);
    }
    
    // Add authentication_info if present
    if let Some(auth) = &request.authentication_info {
        map.insert("authentication_info", auth_to_cbor_value(auth)?);
    }
    
    // Add metadata if present
    if let Some(metadata) = &request.metadata {
        map.insert("metadata", prost_struct_to_cbor_value(metadata)?);
    }
    
    // The signature field is intentionally excluded from canonicalization
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts an [`McpResponse`] to a canonical CBOR value.
///
/// This is the core conversion function for canonical representation of responses.
/// 
/// # Arguments
/// * `response`: The [`McpResponse`] to convert.
///
/// # Returns
/// * `Ok(CborValue)` containing the canonical value.
/// * `Err(MCPError)` if conversion fails.
fn response_to_cbor_value(response: &McpResponse) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    // Required fields
    map.insert("response_id", CborValue::Text(response.response_id.clone()));
    map.insert("request_id", CborValue::Text(response.request_id.clone()));
    map.insert("mcp_version", CborValue::Text(response.mcp_version.clone()));
    map.insert("status", CborValue::Integer(response.status.into()));
    
    // Add timestamp
    if let Some(timestamp) = &response.timestamp {
        // Convert to nanoseconds since epoch
        let timestamp_nanos = (timestamp.seconds * 1_000_000_000) + i64::from(timestamp.nanos);
        map.insert("timestamp", CborValue::Tag(
            CBOR_TAG_TIMESTAMP,
            Box::new(CborValue::Integer(Integer::from(timestamp_nanos)))
        ));
    } else {
        return Err(MCPError::missing_field("response.timestamp"));
    }
    
    // Optional fields
    if !response.status_message.is_empty() {
        map.insert("status_message", CborValue::Text(response.status_message.clone()));
    }
    
    // Permission statuses
    if !response.permission_statuses.is_empty() {
        let statuses = response.permission_statuses.iter()
            .map(permission_status_to_cbor_value)
            .collect::<Result<Vec<CborValue>>>()?;
        map.insert("permission_statuses", CborValue::Array(statuses));
    }
    
    // Response payload
    if !response.response_payload.is_empty() {
        map.insert("response_payload", CborValue::Tag(
            CBOR_TAG_BINARY,
            Box::new(CborValue::Bytes(response.response_payload.clone()))
        ));
    }
    
    // Consent receipt
    if !response.consent_receipt.is_empty() {
        map.insert("consent_receipt", CborValue::Tag(
            CBOR_TAG_BINARY,
            Box::new(CborValue::Bytes(response.consent_receipt.clone()))
        ));
    }
    
    // Extensions
    if !response.extensions.is_empty() {
        let extensions = response.extensions.iter()
            .map(|ext| {
                let mut ext_map = BTreeMap::new();
                ext_map.insert("type_url", CborValue::Text(ext.type_url.clone()));
                ext_map.insert("value", CborValue::Tag(
                    CBOR_TAG_BINARY,
                    Box::new(CborValue::Bytes(ext.value.clone()))
                ));
                CborValue::Map(ext_map)
            })
            .collect();
        
        map.insert("extensions", CborValue::Array(extensions));
    }
    
    // Compensation receipt
    if let Some(receipt) = &response.compensation_receipt {
        map.insert("compensation_receipt", compensation_receipt_to_cbor_value(receipt)?);
    }
    
    // Consent expiry
    if let Some(expiry) = &response.consent_expiry {
        let expiry_nanos = (expiry.seconds * 1_000_000_000) + i64::from(expiry.nanos);
        map.insert("consent_expiry", CborValue::Tag(
            CBOR_TAG_TIMESTAMP,
            Box::new(CborValue::Integer(Integer::from(expiry_nanos)))
        ));
    }
    
    // Usage limitations
    if let Some(limitations) = &response.usage_limitations {
        map.insert("usage_limitations", usage_limitations_to_cbor_value(limitations)?);
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`McpResponse_PermissionStatus`] to a canonical CBOR value.
fn permission_status_to_cbor_value(status: &McpResponse_PermissionStatus) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    map.insert("resource_identifier", CborValue::Text(status.resource_identifier.clone()));
    map.insert("requested_action", CborValue::Integer(status.requested_action.into()));
    map.insert("granted", CborValue::Bool(status.granted));
    
    if !status.reason.is_empty() {
        map.insert("reason", CborValue::Text(status.reason.clone()));
    }
    
    if let Some(conditions) = &status.conditions {
        map.insert("conditions", prost_struct_to_cbor_value(conditions)?);
    }
    
    if status.duration_seconds > 0 {
        map.insert("duration_seconds", CborValue::Integer(status.duration_seconds.into()));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`CompensationReceipt`] to a canonical CBOR value.
fn compensation_receipt_to_cbor_value(receipt: &CompensationReceipt) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    map.insert("transaction_id", CborValue::Text(receipt.transaction_id.clone()));
    map.insert("status", CborValue::Integer(receipt.status.into()));
    
    // Handle floating point values deterministically
    map.insert("amount", CborValue::Text(format!("{:.8}", receipt.amount)));
    
    if !receipt.unit.is_empty() {
        map.insert("unit", CborValue::Text(receipt.unit.clone()));
    }
    
    if let Some(timestamp) = &receipt.timestamp {
        let timestamp_nanos = (timestamp.seconds * 1_000_000_000) + i64::from(timestamp.nanos);
        map.insert("timestamp", CborValue::Tag(
            CBOR_TAG_TIMESTAMP,
            Box::new(CborValue::Integer(Integer::from(timestamp_nanos)))
        ));
    }
    
    if !receipt.verification_data.is_empty() {
        map.insert("verification_data", CborValue::Tag(
            CBOR_TAG_BINARY,
            Box::new(CborValue::Bytes(receipt.verification_data.clone()))
        ));
    }
    
    if let Some(metadata) = &receipt.payment_metadata {
        map.insert("payment_metadata", prost_struct_to_cbor_value(metadata)?);
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`UsageLimitations`] to a canonical CBOR value.
fn usage_limitations_to_cbor_value(limitations: &UsageLimitations) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    if limitations.max_retention_days > 0 {
        map.insert("max_retention_days", CborValue::Integer(limitations.max_retention_days.into()));
    }
    
    map.insert("must_delete_after_use", CborValue::Bool(limitations.must_delete_after_use));
    map.insert("allow_offline_processing", CborValue::Bool(limitations.allow_offline_processing));
    
    if !limitations.geographic_restrictions.is_empty() {
        let restrictions = limitations.geographic_restrictions.iter()
            .map(|r| CborValue::Text(r.clone()))
            .collect();
        map.insert("geographic_restrictions", CborValue::Array(restrictions));
    }
    
    if !limitations.environment_restrictions.is_empty() {
        let restrictions = limitations.environment_restrictions.iter()
            .map(|r| CborValue::Text(r.clone()))
            .collect();
        map.insert("environment_restrictions", CborValue::Array(restrictions));
    }
    
    if !limitations.processing_limitations.is_empty() {
        let procs = limitations.processing_limitations.iter()
            .map(processing_limitation_to_cbor_value)
            .collect::<Result<Vec<CborValue>>>()?;
        map.insert("processing_limitations", CborValue::Array(procs));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`UsageLimitations_ProcessingLimitation`] to a canonical CBOR value.
fn processing_limitation_to_cbor_value(limitation: &UsageLimitations_ProcessingLimitation) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    if !limitation.limitation_type.is_empty() {
        map.insert("limitation_type", CborValue::Text(limitation.limitation_type.clone()));
    }
    
    if !limitation.description.is_empty() {
        map.insert("description", CborValue::Text(limitation.description.clone()));
    }
    
    if !limitation.enforcement_mechanism.is_empty() {
        map.insert("enforcement_mechanism", CborValue::Text(limitation.enforcement_mechanism.clone()));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`RequestorIdentity`] to a canonical CBOR value.
fn identity_to_cbor_value(identity: &RequestorIdentity) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    // Required fields
    map.insert("pseudonym_id", CborValue::Text(identity.pseudonym_id.clone()));
    map.insert("public_key", CborValue::Tag(
        CBOR_TAG_BINARY,
        Box::new(CborValue::Bytes(identity.public_key.clone()))
    ));
    
    // Optional fields
    if !identity.attestations.is_empty() {
        let attestations = identity.attestations.iter()
            .map(|att| CborValue::Text(att.clone()))
            .collect();
        map.insert("attestations", CborValue::Array(attestations));
    }
    
    if identity.trust_tier > 0 {
        map.insert("trust_tier", CborValue::Integer(identity.trust_tier.into()));
    }
    
    if !identity.organization_id.is_empty() {
        map.insert("organization_id", CborValue::Text(identity.organization_id.clone()));
    }
    
    if !identity.display_name.is_empty() {
        map.insert("display_name", CborValue::Text(identity.display_name.clone()));
    }
    
    if !identity.profile_url.is_empty() {
        map.insert("profile_url", CborValue::Text(identity.profile_url.clone()));
    }
    
    if identity.requestor_type > 0 {
        map.insert("requestor_type", CborValue::Integer(identity.requestor_type.into()));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`PurposeDNA`] to a canonical CBOR value.
fn purpose_to_cbor_value(purpose: &PurposeDNA) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    // Add fields
    map.insert("purpose_id", CborValue::Text(purpose.purpose_id.clone()));
    
    if !purpose.name.is_empty() {
        map.insert("name", CborValue::Text(purpose.name.clone()));
    }
    
    if !purpose.description.is_empty() {
        map.insert("description", CborValue::Text(purpose.description.clone()));
    }
    
    if !purpose.specific_purpose_description.is_empty() {
        map.insert("specific_purpose_description", CborValue::Text(purpose.specific_purpose_description.clone()));
    }
    
    // Handle category - prefer the new field, fall back to primary_purpose_category
    if let Some(category) = &purpose.category {
        map.insert("category", CborValue::Integer(Integer::from(*category as i32)));
    } else if let Some(primary_category) = purpose.primary_purpose_category {
        map.insert("primary_purpose_category", CborValue::Integer(Integer::from(primary_category)));
    }
    
    // Add data_types_involved
    let data_types = purpose.data_types_involved.iter()
        .map(|dt| CborValue::Text(dt.clone()))
        .collect();
    map.insert("data_types_involved", CborValue::Array(data_types));
    
    // Add third_party_sharing if present
    if let Some(sharing) = &purpose.third_party_sharing {
        map.insert("third_party_sharing", third_party_sharing_to_cbor_value(sharing)?);
    }
    
    // Add reuse_limitations if present
    if let Some(reuse) = &purpose.reuse_limitations {
        map.insert("reuse_limitations", reuse_limitations_to_cbor_value(reuse)?);
    }
    
    // Add usage_duration if present
    if let Some(duration) = &purpose.usage_duration {
        let mut dur_map = BTreeMap::new();
        
        dur_map.insert("duration_seconds", CborValue::Integer(Integer::from(duration.duration_seconds)));
        
        if !duration.duration_text.is_empty() {
            dur_map.insert("duration_text", CborValue::Text(duration.duration_text.clone()));
        }
        
        if let Some(expiration) = &duration.expiration {
            let exp_nanos = (expiration.seconds * 1_000_000_000) + i64::from(expiration.nanos);
            dur_map.insert("expiration", CborValue::Tag(
                CBOR_TAG_TIMESTAMP,
                Box::new(CborValue::Integer(Integer::from(exp_nanos)))
            ));
        }
        
        map.insert("usage_duration", CborValue::Map(btreemap_to_cbor_map(dur_map)));
    }
    
    // Add purpose_expiry_timestamp if present
    if let Some(expiry) = &purpose.purpose_expiry_timestamp {
        let exp_nanos = (expiry.seconds * 1_000_000_000) + i64::from(expiry.nanos);
        map.insert("purpose_expiry_timestamp", CborValue::Tag(
            CBOR_TAG_TIMESTAMP,
            Box::new(CborValue::Integer(Integer::from(exp_nanos)))
        ));
    }
    
    // Add policy_links
    if !purpose.policy_links.is_empty() {
        let links = purpose.policy_links.iter()
            .map(|link| CborValue::Text(link.clone()))
            .collect();
        map.insert("policy_links", CborValue::Array(links));
    }
    
    // Add details if present
    if let Some(details) = &purpose.details {
        map.insert("details", prost_struct_to_cbor_value(details)?);
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts third party sharing info to a canonical CBOR value.
fn third_party_sharing_to_cbor_value(sharing: &PurposeDNA_ThirdPartySharing) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    map.insert("is_shared", CborValue::Bool(sharing.is_shared));
    
    if !sharing.recipients.is_empty() {
        let recipients = sharing.recipients.iter()
            .map(|r| CborValue::Text(r.clone()))
            .collect();
        map.insert("recipients", CborValue::Array(recipients));
    }
    
    if !sharing.sharing_purpose_description.is_empty() {
        map.insert("sharing_purpose_description", CborValue::Text(sharing.sharing_purpose_description.clone()));
    }
    
    if !sharing.shared_data_elements.is_empty() {
        let elements = sharing.shared_data_elements.iter()
            .map(|e| CborValue::Text(e.clone()))
            .collect();
        map.insert("shared_data_elements", CborValue::Array(elements));
    }
    
    if !sharing.user_controls.is_empty() {
        map.insert("user_controls", CborValue::Text(sharing.user_controls.clone()));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts reuse limitations to a canonical CBOR value.
fn reuse_limitations_to_cbor_value(reuse: &PurposeDNA_ReuseLimitations) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    map.insert("is_reuse_allowed", CborValue::Bool(reuse.is_reuse_allowed));
    
    if !reuse.permitted_reuse_types.is_empty() {
        let types = reuse.permitted_reuse_types.iter()
            .map(|t| CborValue::Integer((*t).into()))
            .collect();
        map.insert("permitted_reuse_types", CborValue::Array(types));
    }
    
    if !reuse.reuse_conditions.is_empty() {
        map.insert("reuse_conditions", CborValue::Text(reuse.reuse_conditions.clone()));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`PermissionSpecification`] to a canonical CBOR value.
fn permission_to_cbor_value(permission: &PermissionSpecification) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    // Required fields
    map.insert("resource_id", CborValue::Text(permission.resource_id.clone()));
    
    // Optional fields
    if let Some(action) = &permission.action {
        map.insert("action", CborValue::Integer((*action as i32).into()));
    }
    
    // Convert constraints if present - note constraints is a repeated field (Vec) not an Option
    if !permission.constraints.is_empty() {
        let constraints: Vec<CborValue> = permission.constraints.iter()
            .map(|c| {
                let mut constraint_map = BTreeMap::new();
                constraint_map.insert("constraint_type", CborValue::Text(c.constraint_type.clone()));
                constraint_map.insert("description", CborValue::Text(c.description.clone()));
                // Add parameters if present
                if let Some(params) = &c.parameters {
                    match prost_struct_to_cbor_value(params) {
                        Ok(val) => { constraint_map.insert("parameters", val); },
                        Err(_) => { /* Skip on error */ }
                    }
                }
                Ok(CborValue::Map(btreemap_to_cbor_map(constraint_map)))
            })
            .collect::<Result<Vec<CborValue>>>()?;
        map.insert("constraints", CborValue::Array(constraints));
    }
    
    // Convert delegation_chain if present
    if !permission.delegation_chain.is_empty() {
        let chain: Vec<CborValue> = permission.delegation_chain.iter()
            .map(|d| {
                let mut delegation_map = BTreeMap::new();
                delegation_map.insert("delegator_id", CborValue::Text(d.delegator_id.clone()));
                delegation_map.insert("delegatee_id", CborValue::Text(d.delegatee_id.clone()));
                // Add other delegation fields if needed
                Ok(CborValue::Map(btreemap_to_cbor_map(delegation_map)))
            })
            .collect::<Result<Vec<CborValue>>>()?;
        map.insert("delegation_chain", CborValue::Array(chain));
    }
    
    if let Some(sensitivity_level) = permission.sensitivity_level {
        map.insert("sensitivity_level", CborValue::Integer(sensitivity_level.into()));
    }
    
    if !permission.justification.is_empty() {
        map.insert("justification", CborValue::Text(permission.justification.clone()));
    }
    
    if let Some(resource_type) = &permission.resource_type {
        map.insert("resource_type", CborValue::Text(resource_type.clone()));
    }
    
    if let Some(details) = &permission.details {
        map.insert("details", prost_struct_to_cbor_value(details)?);
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`CompensationModel`] to a canonical CBOR value.
fn compensation_to_cbor_value(compensation: &CompensationModel) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    map.insert("compensation_type", CborValue::Integer(compensation.compensation_type.into()));
    
    // Handle floating point values deterministically
    // We convert to a string to ensure deterministic representation
    map.insert("amount", CborValue::Text(format!("{:.8}", compensation.amount)));
    
    if !compensation.unit.is_empty() {
        map.insert("unit", CborValue::Text(compensation.unit.clone()));
    }
    
    if let Some(payment_method) = &compensation.payment_method {
        map.insert("payment_method", payment_method_to_cbor_value(payment_method)?);
    }
    
    if let Some(revenue_sharing) = &compensation.revenue_sharing {
        map.insert("revenue_sharing", revenue_sharing_to_cbor_value(revenue_sharing)?);
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`PaymentMethod`] to a canonical CBOR value.
fn payment_method_to_cbor_value(payment: &PaymentMethod) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    if !payment.payment_type.is_empty() {
        map.insert("payment_type", CborValue::Text(payment.payment_type.clone()));
    }
    
    if !payment.payment_identifier.is_empty() {
        map.insert("payment_identifier", CborValue::Text(payment.payment_identifier.clone()));
    }
    
    if let Some(details) = &payment.payment_details {
        map.insert("payment_details", prost_struct_to_cbor_value(details)?);
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`RevenueSharing`] to a canonical CBOR value.
fn revenue_sharing_to_cbor_value(revenue: &RevenueSharing) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    // Handle floating point values deterministically
    map.insert("percentage", CborValue::Text(format!("{:.8}", revenue.percentage)));
    
    if !revenue.calculation_method.is_empty() {
        map.insert("calculation_method", CborValue::Text(revenue.calculation_method.clone()));
    }
    
    if !revenue.payment_frequency.is_empty() {
        map.insert("payment_frequency", CborValue::Text(revenue.payment_frequency.clone()));
    }
    
    if revenue.minimum_threshold > 0.0 {
        map.insert("minimum_threshold", CborValue::Text(format!("{:.8}", revenue.minimum_threshold)));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`TrustInformation`] to a canonical CBOR value.
fn trust_to_cbor_value(trust: &TrustInformation) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    map.insert("trust_score", CborValue::Integer(trust.trust_score.into()));
    
    if !trust.assessment_method.is_empty() {
        map.insert("assessment_method", CborValue::Text(trust.assessment_method.clone()));
    }
    
    if !trust.assessment_provider.is_empty() {
        map.insert("assessment_provider", CborValue::Text(trust.assessment_provider.clone()));
    }
    
    if let Some(timestamp) = &trust.assessment_timestamp {
        let timestamp_nanos = (timestamp.seconds * 1_000_000_000) + i64::from(timestamp.nanos);
        map.insert("assessment_timestamp", CborValue::Tag(
            CBOR_TAG_TIMESTAMP,
            Box::new(CborValue::Integer(Integer::from(timestamp_nanos)))
        ));
    }
    
    if !trust.trust_credentials.is_empty() {
        let credentials = trust.trust_credentials.iter()
            .map(trust_credential_to_cbor_value)
            .collect::<Result<Vec<CborValue>>>()?;
        map.insert("trust_credentials", CborValue::Array(credentials));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`TrustCredential`] to a canonical CBOR value.
fn trust_credential_to_cbor_value(credential: &Credential) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    if !credential.credential_type.is_empty() {
        map.insert("credential_type", CborValue::Text(credential.credential_type.clone()));
    }
    
    if !credential.issuer.is_empty() {
        map.insert("issuer", CborValue::Text(credential.issuer.clone()));
    }
    
    if !credential.credential_id.is_empty() {
        map.insert("credential_id", CborValue::Text(credential.credential_id.clone()));
    }
    
    if let Some(expiry) = &credential.expiry {
        let expiry_nanos = (expiry.seconds * 1_000_000_000) + i64::from(expiry.nanos);
        map.insert("expiry", CborValue::Tag(
            CBOR_TAG_TIMESTAMP,
            Box::new(CborValue::Integer(Integer::from(expiry_nanos)))
        ));
    }
    
    if !credential.verification_url.is_empty() {
        map.insert("verification_url", CborValue::Text(credential.verification_url.clone()));
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts an [`AuthenticationInfo`] to a canonical CBOR value.
fn auth_to_cbor_value(auth: &AuthenticationInfo) -> Result<CborValue> {
    let mut map = BTreeMap::new();
    
    map.insert("auth_method", CborValue::Integer(auth.auth_method.into()));
    
    if !auth.auth_provider.is_empty() {
        map.insert("auth_provider", CborValue::Text(auth.auth_provider.clone()));
    }
    
    map.insert("auth_level", CborValue::Integer(auth.auth_level.into()));
    
    if let Some(timestamp) = &auth.auth_timestamp {
        let timestamp_nanos = (timestamp.seconds * 1_000_000_000) + i64::from(timestamp.nanos);
        map.insert("auth_timestamp", CborValue::Tag(
            CBOR_TAG_TIMESTAMP,
            Box::new(CborValue::Integer(Integer::from(timestamp_nanos)))
        ));
    }
    
    if let Some(details) = &auth.auth_details {
        map.insert("auth_details", prost_struct_to_cbor_value(details)?);
    }
    
    Ok(CborValue::Map(btreemap_to_cbor_map(map)))
}

/// Converts a [`prost_types::Struct`] to a canonical CBOR value.
fn prost_struct_to_cbor_value(struct_value: &prost_types::Struct) -> Result<CborValue> {
    let map = struct_value.fields.iter()
        .map(|(k, v)| Ok((k.clone(), prost_value_to_cbor_value(v.clone())?)))
        .collect::<Result<BTreeMap<String, CborValue>>>()?;
    
    // Convert BTreeMap<String, CborValue> to Vec<(CborValue, CborValue)>
    let cbor_map = map.into_iter()
        .map(|(k, v)| (CborValue::Text(k), v))
        .collect();
    
    Ok(CborValue::Map(cbor_map))
}

/// Converts a [`prost_types::Value`] to a canonical CBOR value.
fn prost_value_to_cbor_value(value: &prost_types::Value) -> Result<CborValue> {
    use prost_types::value::Kind;
    
    match &value.kind {
        Some(Kind::NullValue(_)) => Ok(CborValue::Null),
        Some(Kind::NumberValue(n)) => {
            // Convert floating point to string to ensure deterministic representation
            Ok(CborValue::Text(format!("{:.8}", n)))
        },
        Some(Kind::StringValue(s)) => Ok(CborValue::Text(s.clone())),
        Some(Kind::BoolValue(b)) => Ok(CborValue::Bool(*b)),
        Some(Kind::StructValue(s)) => prost_struct_to_cbor_value(s),
        Some(Kind::ListValue(list)) => {
            let values = list.values.iter()
                .map(prost_value_to_cbor_value)
                .collect::<Result<Vec<CborValue>>>()?;
            Ok(CborValue::Array(values))
        },
        None => Err(MCPError::ConversionError { 
            message: "Empty prost value".to_string() 
        }),
    }
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use crate::types::mcp_response::Status as ResponseStatus;
    use prost_types::{Timestamp, Any};
    use bytes::Bytes;
    use chrono::Utc;
    use std::time::{SystemTime, Duration};

    // Helper functions
    fn create_test_request() -> McpRequest {
        let now = SystemTime::now();
        let timestamp = Timestamp {
            seconds: now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
            nanos: 0,
        };
        
        let identity = RequestorIdentity {
            pseudonym_id: "test-user-1".to_string(),
            public_key: Bytes::from_static(&[1, 2, 3, 4]),
            attestations: vec!["https://example.com/attestation1".to_string()],
            trust_tier: 2,
            organization_id: "org-123".to_string(),
            display_name: "Test User".to_string(),
            profile_url: "https://example.com/profile/1".to_string(),
            requestor_type: RequestorIdentity_RequestorType::Individual as i32,
        };
        
        let purpose = PurposeDNA {
            purpose_id: "purpose-1".to_string(),
            primary_purpose_category: PurposeDNA_PurposeCategory::ResearchDevelopment as i32,
            specific_purpose_description: "Testing the serialization".to_string(),
            data_types_involved: vec!["user.profile".to_string(), "user.preferences".to_string()],
            processing_description: "For test cases only".to_string(),
            storage_description: "Temporary in-memory storage".to_string(),
            ..Default::default()
        };
        
        let permission = PermissionSpecification {
            resource_identifier: "user.profile".to_string(),
            requested_action: PermissionSpecification_Action::Read as i32,
            sensitivity_level: PermissionSpecification_SensitivityLevel::Low as i32,
            justification: "Required for testing".to_string(),
            ..Default::default()
        };
        
        McpRequest {
            request_id: "req-12345".to_string(),
            timestamp: Some(timestamp),
            requestor_identity: Some(identity),
            purpose_dna: Some(purpose),
            permissions: vec![permission],
            mcp_version: "1.1.0".to_string(),
            ..Default::default()
        }
    }
    
    fn create_test_response() -> McpResponse {
        let now = SystemTime::now();
        let timestamp = Timestamp {
            seconds: now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
            nanos: 0,
        };
        
        let expiry = Timestamp {
            seconds: (now + Duration::from_secs(3600)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
            nanos: 0,
        };
        
        let status = McpResponse_PermissionStatus {
            resource_identifier: "user.profile".to_string(),
            requested_action: PermissionSpecification_Action::Read as i32,
            granted: true,
            reason: "".to_string(),
            ..Default::default()
        };
        
        McpResponse {
            response_id: "resp-67890".to_string(),
            request_id: "req-12345".to_string(),
            timestamp: Some(timestamp),
            status: ResponseStatus::Approved as i32,
            status_message: "Request approved".to_string(),
            permission_statuses: vec![status],
            consent_expiry: Some(expiry),
            mcp_version: "1.1.0".to_string(),
            ..Default::default()
        }
    }
    
    #[test]
    fn test_request_serialization_roundtrip() {
        let request = create_test_request();
        
        let serialized = serialize_request(&request).expect("Failed to serialize request");
        let deserialized = deserialize_request(&serialized).expect("Failed to deserialize request");
        
        assert_eq!(request.request_id, deserialized.request_id);
        assert_eq!(request.mcp_version, deserialized.mcp_version);
        
        // Compare serialized forms to ensure exact byte-for-byte equality
        let serialized2 = serialize_request(&deserialized).expect("Failed to re-serialize request");
        assert_eq!(serialized, serialized2, "Re-serialized request differs from original");
    }
    
    #[test]
    fn test_response_serialization_roundtrip() {
        let response = create_test_response();
        
        let serialized = serialize_response(&response).expect("Failed to serialize response");
        let deserialized = deserialize_response(&serialized).expect("Failed to deserialize response");
        
        assert_eq!(response.response_id, deserialized.response_id);
        assert_eq!(response.request_id, deserialized.request_id);
        assert_eq!(response.status, deserialized.status);
        
        // Compare serialized forms to ensure exact byte-for-byte equality
        let serialized2 = serialize_response(&deserialized).expect("Failed to re-serialize response");
        assert_eq!(serialized, serialized2, "Re-serialized response differs from original");
    }
    
    #[test]
    fn test_request_canonical_serialization() {
        let mut request1 = create_test_request();
        let mut request2 = create_test_request();
        
        // Modify request2 to have fields in different order
        let permission = request2.permissions.remove(0);
        request2.permissions.push(permission);
        
        // They should still produce identical canonical representations
        let canonical1 = prepare_request_for_signing(&request1).expect("Failed to canonicalize request1");
        let canonical2 = prepare_request_for_signing(&request2).expect("Failed to canonicalize request2");
        
        assert_eq!(canonical1, canonical2, "Canonical serializations differ despite semantic equivalence");
    }
    
    #[test]
    fn test_response_canonical_serialization() {
        let mut response1 = create_test_response();
        let mut response2 = create_test_response();
        
        // Modify response2 to have fields in different order
        let status = response2.permission_statuses.remove(0);
        response2.permission_statuses.push(status);
        
        // They should still produce identical canonical representations
        let canonical1 = prepare_response_for_signing(&response1).expect("Failed to canonicalize response1");
        let canonical2 = prepare_response_for_signing(&response2).expect("Failed to canonicalize response2");
        
        assert_eq!(canonical1, canonical2, "Canonical serializations differ despite semantic equivalence");
    }
    
    #[test]
    fn test_floating_point_determinism() {
        // Create two requests with floating point values that are semantically the same
        // but might have different binary representations
        let mut request1 = create_test_request();
        let mut request2 = create_test_request();
        
        // Add compensation models with slightly different representations of the same value
        request1.compensation_model = Some(CompensationModel {
            compensation_type: CompensationType::Monetary as i32,
            amount: 1.1,
            unit: "USD".to_string(),
            ..Default::default()
        });
        
        request2.compensation_model = Some(CompensationModel {
            compensation_type: CompensationType::Monetary as i32,
            amount: 1.1000000000000001, // Same value with floating point imprecision
            unit: "USD".to_string(),
            ..Default::default()
        });
        
        // They should still produce identical canonical representations
        let canonical1 = prepare_request_for_signing(&request1).expect("Failed to canonicalize request1");
        let canonical2 = prepare_request_for_signing(&request2).expect("Failed to canonicalize request2");
        
        assert_eq!(canonical1, canonical2, "Canonical serializations differ despite semantically equivalent floating point values");
    }
    
    #[test]
    fn test_canonical_serialization_excludes_signature() {
        let mut request = create_test_request();
        
        // Create a canonical representation without a signature
        let canonical1 = prepare_request_for_signing(&request).expect("Failed to canonicalize request");
        
        // Add a signature
        request.signature = Some(CryptoSignature {
            key_id: "test-key".to_string(),
            algorithm: "Ed25519".to_string(),
            signature: Bytes::from_static(&[0, 1, 2, 3]),
            ..Default::default()
        });
        
        // Create a canonical representation with a signature
        let canonical2 = prepare_request_for_signing(&request).expect("Failed to canonicalize request with signature");
        
        // The canonical representations should be identical
        assert_eq!(canonical1, canonical2, "Canonical serialization should not include the signature field");
    }
    
    #[test]
    fn test_deserialize_invalid_data() {
        // Test with invalid Protobuf data
        let invalid_data = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let result = deserialize_request(&invalid_data);
        assert!(result.is_err(), "Deserializing invalid data should fail");
        
        let result = deserialize_response(&invalid_data);
        assert!(result.is_err(), "Deserializing invalid data should fail");
    }
    
    #[test]
    fn test_oversized_data_rejection() {
        // Create a very large payload that should be rejected
        let large_data = vec![0; 15_000_000]; // 15MB, should exceed our limit
        
        let result = deserialize_request(&large_data);
        assert!(result.is_err(), "Oversized request should be rejected");
        
        let result = deserialize_response(&large_data);
        assert!(result.is_err(), "Oversized response should be rejected");
    }
} 