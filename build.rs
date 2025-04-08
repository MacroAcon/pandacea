use std::io::Result;

fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    // Enable mapping google.protobuf.Timestamp to chrono::DateTime<Utc>
    config.protoc_arg("--experimental_allow_proto3_optional"); // Needed for prost >= 0.12 with optional fields
    config.bytes(["RequestorIdentity.public_key", "CryptoSignature.signature", "MCPResponse.response_payload", "MCPResponse.consent_receipt"]);
    config.type_attribute(".google.protobuf.Timestamp", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".google.protobuf.Timestamp", "#[serde(with = \"prost_wkt_types::TimestampDef\")]");
    config.type_attribute(".google.protobuf.Struct", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".google.protobuf.Struct", "#[serde(with = \"prost_wkt_types::StructDef\")]");

    config.compile_protos(&["mcp.proto"], // Input .proto file
                           &["."])?;      // Include path for imports

    println!("cargo:rerun-if-changed=mcp.proto"); // Re-run if proto file changes
    Ok(())
} 