//! Demo application for the Consent Manager.
//! 
//! This example demonstrates how to use the Consent Manager to process MCP requests
//! by creating a simple ruleset and simulating various types of requests.

use std::collections::HashSet;
use chrono::Utc;
use pandacea_mcp::{
    ConsentManager, ConsentManagerConfig, ConsentRule, ConsentDecision, RequestorFilter,
    SentinelConfig, SensitivityLevel,
    serialize_request, deserialize_response,
    McpRequest, purpose_dna::PurposeCategory, permission_specification::Action,
    Status,
};
use pandacea_mcp::crypto::KeyPair;

fn create_test_request(
    key_pair: &KeyPair,
    purpose_category: PurposeCategory,
    resource: &str,
    action: Action,
) -> McpRequest {
    let builder = pandacea_mcp::builders::McpRequestBuilder::new()
        .with_random_id()
        .with_version("1.0")
        .with_requestor_identity("test-requestor", key_pair.public_key_pem())
        .with_purpose_dna(
            purpose_category,
            "Test purpose",
            "Testing the Consent Manager",
            None,
            None,
        )
        .add_permission(resource, action, None);
    
    let request = builder.build();
    let signed_request = pandacea_mcp::crypto::sign_request(&request, key_pair).unwrap();
    signed_request
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Pandacea Consent Manager Demo ===");
    
    // Create a new Consent Manager with custom configuration
    let config = ConsentManagerConfig {
        genome_path: "demo_genome.json".to_string(),
        audit_log_path: "demo_audit.log".to_string(),
        sentinel_config: SentinelConfig {
            max_recent_requests: 50,
            max_requests_per_hour: 20,
            sensitivity_level: SensitivityLevel::Medium,
        },
        default_decision: ConsentDecision::Prompt,
        enable_audit: true,
    };
    
    let mut consent_manager = ConsentManager::with_config(config);
    
    // Create a cryptographic key pair for signing requests
    let key_pair = KeyPair::generate()?;
    
    // Create some example consent rules
    
    // Rule 1: Deny all marketing requests
    let mut rule1 = ConsentRule {
        id: "rule1".to_string(),
        name: "Deny Marketing".to_string(),
        description: Some("Deny all marketing requests".to_string()),
        priority: 10,
        requestor_filter: None,
        purpose_filter: Some([PurposeCategory::Marketing].iter().copied().collect()),
        resource_filter: None,
        action_filter: None,
        decision: ConsentDecision::Deny,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        enabled: true,
    };
    
    // Rule 2: Allow read access to basic profile data
    let mut rule2 = ConsentRule {
        id: "rule2".to_string(),
        name: "Allow Basic Profile Read".to_string(),
        description: Some("Allow reading basic profile information".to_string()),
        priority: 20,
        requestor_filter: None,
        purpose_filter: None,
        resource_filter: Some(["user.name", "user.email"].iter().map(|s| s.to_string()).collect()),
        action_filter: Some([Action::Read].iter().copied().collect()),
        decision: ConsentDecision::Allow,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        enabled: true,
    };
    
    // Rule 3: Prompt for sensitive data access
    let mut rule3 = ConsentRule {
        id: "rule3".to_string(),
        name: "Prompt for Sensitive Data".to_string(),
        description: Some("Prompt user for sensitive data access".to_string()),
        priority: 30,
        requestor_filter: None,
        purpose_filter: None,
        resource_filter: Some(["user.health", "user.finance"].iter().map(|s| s.to_string()).collect()),
        action_filter: None,
        decision: ConsentDecision::Prompt,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        enabled: true,
    };
    
    // Rule 4: Block specific requestor
    let mut blocked_requestors = HashSet::new();
    blocked_requestors.insert("malicious-requestor".to_string());
    let rule4 = ConsentRule {
        id: "rule4".to_string(),
        name: "Block Malicious Requestors".to_string(),
        description: Some("Block known malicious requestors".to_string()),
        priority: 50, // Highest priority
        requestor_filter: Some(RequestorFilter::Exclude(blocked_requestors)),
        purpose_filter: None,
        resource_filter: None,
        action_filter: None,
        decision: ConsentDecision::Deny,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        enabled: true,
    };
    
    // Add the rules to the consent manager
    consent_manager.add_rule(rule1)?;
    consent_manager.add_rule(rule2)?;
    consent_manager.add_rule(rule3)?;
    consent_manager.add_rule(rule4)?;
    
    // Save the consent genome
    consent_manager.save_genome("demo_genome.json")?;
    
    println!("Created consent genome with {} rules", consent_manager.get_rules().len());
    
    // Test Case 1: Marketing request for email access (should be DENIED by rule1)
    let marketing_request = create_test_request(
        &key_pair,
        PurposeCategory::Marketing,
        "user.email",
        Action::Read,
    );
    let marketing_request_bytes = serialize_request(&marketing_request)?;
    
    println!("\nProcessing Marketing Request for user.email...");
    let response_bytes = consent_manager.process_request(&marketing_request_bytes)?;
    let response = deserialize_response(&response_bytes)?;
    
    println!("  Decision: {:?}", Status::try_from(response.status).unwrap());
    
    // Test Case 2: Operations request for basic profile (should be ALLOWED by rule2)
    let profile_request = create_test_request(
        &key_pair,
        PurposeCategory::Operations,
        "user.name",
        Action::Read,
    );
    let profile_request_bytes = serialize_request(&profile_request)?;
    
    println!("\nProcessing Operations Request for user.name...");
    let response_bytes = consent_manager.process_request(&profile_request_bytes)?;
    let response = deserialize_response(&response_bytes)?;
    
    println!("  Decision: {:?}", Status::try_from(response.status).unwrap());
    
    // Test Case 3: Research request for health data (should PROMPT by rule3)
    let health_request = create_test_request(
        &key_pair,
        PurposeCategory::Research,
        "user.health",
        Action::Read,
    );
    let health_request_bytes = serialize_request(&health_request)?;
    
    println!("\nProcessing Research Request for user.health...");
    let response_bytes = consent_manager.process_request(&health_request_bytes)?;
    let response = deserialize_response(&response_bytes)?;
    
    println!("  Decision: {:?}", Status::try_from(response.status).unwrap());
    
    // Print the audit log
    println!("\nAudit Log:");
    for (i, entry) in consent_manager.get_audit_log().iter().enumerate() {
        println!("  [{}] Request: {}", i+1, entry.request_id);
        println!("      Purpose: {}", entry.purpose);
        println!("      Decision: {:?}", entry.decision);
        println!("      Rule: {}", entry.matching_rule_id.as_deref().unwrap_or("None"));
        println!("      Time: {}", entry.timestamp);
        println!();
    }
    
    Ok(())
} 