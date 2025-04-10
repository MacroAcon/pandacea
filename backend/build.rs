use std::io::Result;

fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    // Enable mapping google.protobuf.Timestamp to chrono::DateTime<Utc>
    config.protoc_arg("--experimental_allow_proto3_optional"); // Needed for prost >= 0.12 with optional fields
    config.bytes(["RequestorIdentity.public_key", "CryptoSignature.signature", "McpResponse.response_payload", "McpResponse.consent_receipt"]);
    config.type_attribute(".google.protobuf.Timestamp", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".google.protobuf.Timestamp", "#[serde(with = \"prost_wkt_types::TimestampDef\")]");
    config.type_attribute(".google.protobuf.Struct", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".google.protobuf.Struct", "#[serde(with = \"prost_wkt_types::StructDef\")]");
    
    // Add serde derives for our enum types
    config.type_attribute(".pandacea.mcp.purpose_dna.PurposeCategory", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".pandacea.mcp.permission_specification.Action", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".pandacea.mcp.mcp_response.Status", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".pandacea.mcp.compensation_model.CompensationType", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".pandacea.mcp.compensation_receipt.PaymentStatus", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".pandacea.mcp.permission_specification.SensitivityLevel", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".pandacea.mcp.usage_limitations.processing_limitations.ProcessingLimitation", "#[derive(serde::Serialize, serde::Deserialize)]");

    config.compile_protos(&["proto/mcp.proto"], // Input .proto file
                           &["."])?;      // Include path for imports

    println!("cargo:rerun-if-changed=proto/mcp.proto"); // Re-run if proto file changes
    Ok(())
} 