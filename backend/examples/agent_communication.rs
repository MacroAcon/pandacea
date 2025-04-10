//! Agent Communication Demo
//!
//! This example demonstrates a basic communication setup between
//! a requestor agent and a responder agent using the Pandacea
//! communication layer and the MCP protocol.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::time::sleep;
use uuid::Uuid;

use pandacea::{
    AgentType, ConsentDecision, ConsentManager, ConsentManagerConfig, ConsentRule, 
    CoordinationService, Endpoint, McpRequest, McpRequestBuilder, MessageRouter, 
    RequestorIdentity, PermissionSpecification, PurposeDna, Action,
};
use pandacea::mcp::purpose_dna::PurposeCategory;
use prost_types::Timestamp;

// Helper function to create a test consent rule
fn create_test_rule(id: &str, name: &str, priority: u32, decision: ConsentDecision) -> ConsentRule {
    ConsentRule {
        id: id.to_string(),
        name: name.to_string(),
        description: Some("Automatically generated rule for testing".to_string()),
        priority,
        requestor_filter: None, // Apply to all requestors
        purpose_filter: None,   // Apply to all purposes
        resource_filter: None,  // Apply to all resources
        action_filter: None,    // Apply to all actions
        decision,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        enabled: true,
    }
}

// Helper function to create a test request
fn create_test_request() -> McpRequest {
    let request_id = Uuid::new_v4().to_string();
    
    let requestor_identity = RequestorIdentity {
        pseudonym_id: "requestor-123".to_string(),
        name: Some("Test Requestor".to_string()),
        verification_url: Some("https://example.com/verify".to_string()),
        ..Default::default()
    };
    
    let purpose = PurposeDna {
        name: "Test Purpose".to_string(),
        description: "Testing the MCP protocol".to_string(),
        category: Some(PurposeCategory::Research as i32),
        ..Default::default()
    };
    
    let permissions = PermissionSpecification {
        resource_id: "user/data123".to_string(),
        action: Some(Action::Read as i32),
        ..Default::default()
    };
    
    let now = Utc::now();
    let now_proto = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    };
    
    McpRequestBuilder::new(request_id)
        .with_mcp_version("1.0".to_string())
        .with_requestor_identity(requestor_identity)
        .with_purpose_dna(purpose)
        .with_permission_specification(permissions)
        .with_request_timestamp(now_proto)
        .build()
}

// Requestor agent that sends MCP requests
struct RequestorAgent {
    router: Arc<MessageRouter>,
    endpoint_id: String,
}

impl RequestorAgent {
    async fn new(coordination_service: Arc<CoordinationService>, endpoint_id: String, name: String) -> Self {
        // Create a new message router for this agent
        let router = MessageRouter::new(
            endpoint_id.clone(),
            name,
            AgentType::Requestor,
        ).await.expect("Failed to create message router");
        
        let router = Arc::new(router);
        
        // Register with the coordination service
        let endpoint = Endpoint {
            id: endpoint_id.clone(),
            name: format!("Requestor Agent {}", endpoint_id),
            address: "127.0.0.1:8081".to_string(), // This would be a real address in production
            agent_type: AgentType::Requestor,
            last_active: Utc::now(),
        };
        
        coordination_service.register_endpoint(endpoint).await.expect("Failed to register endpoint");
        
        Self {
            router,
            endpoint_id,
        }
    }
    
    async fn send_request(&self, responder_id: &str) -> pandacea::Result<()> {
        println!("Requestor {} sending request to responder {}", self.endpoint_id, responder_id);
        
        // Create a test request
        let request = create_test_request();
        println!("Request ID: {}", request.request_id);
        
        // Send the request via the router
        let response = self.router.send_request(responder_id, request.clone()).await?;
        
        println!("Received response from {}: {:?}", responder_id, response);
        println!("Response status: {:?}", response.status);
        
        Ok(())
    }
}

// Responder agent that processes MCP requests
struct ResponderAgent {
    router: Arc<MessageRouter>,
    endpoint_id: String,
    consent_manager: ConsentManager,
}

impl ResponderAgent {
    async fn new(coordination_service: Arc<CoordinationService>, endpoint_id: String, name: String) -> Self {
        // Create a new message router for this agent
        let router = MessageRouter::new(
            endpoint_id.clone(),
            name,
            AgentType::Responder,
        ).await.expect("Failed to create message router");
        
        let router_arc = Arc::new(router);
        
        // Register with the coordination service
        let endpoint = Endpoint {
            id: endpoint_id.clone(),
            name: format!("Responder Agent {}", endpoint_id),
            address: "127.0.0.1:8082".to_string(), // This would be a real address in production
            agent_type: AgentType::Responder,
            last_active: Utc::now(),
        };
        
        coordination_service.register_endpoint(endpoint).await.expect("Failed to register endpoint");
        
        // Create a consent manager with default config
        let mut consent_manager = ConsentManager::with_config(
            ConsentManagerConfig::default()
        );
        
        // Add a rule that allows all research requests
        let rule = create_test_rule(
            "rule1", 
            "Allow Research",
            100, 
            ConsentDecision::Allow
        );
        
        consent_manager.add_rule(rule).expect("Failed to add rule");
        
        // Configure the consent manager to use the router
        let consent_manager = consent_manager.with_message_router(router_arc.clone(), endpoint_id.clone());
        
        Self {
            router: router_arc,
            endpoint_id,
            consent_manager,
        }
    }
    
    async fn start_listening(&mut self) -> pandacea::Result<()> {
        println!("Responder {} starting to listen for requests", self.endpoint_id);
        
        // In a real implementation, we would set up listeners on the router
        // and connect them to the consent manager
        
        // For now, just initialize the listener
        self.consent_manager.start_request_listener().await?;
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Pandacea Agent Communication Demo ===");
    
    // Create a coordination service
    let coordination_service = CoordinationService::new().await?;
    let coordination_service = Arc::new(coordination_service);
    
    // Create a responder agent
    let mut responder = ResponderAgent::new(
        coordination_service.clone(),
        "responder-1".to_string(),
        "Test Responder".to_string(),
    ).await;
    
    // Start the responder listening for requests
    responder.start_listening().await?;
    
    // Create a requestor agent
    let requestor = RequestorAgent::new(
        coordination_service.clone(),
        "requestor-1".to_string(),
        "Test Requestor".to_string(),
    ).await;
    
    // Wait a moment for things to initialize
    sleep(Duration::from_millis(500)).await;
    
    println!("\n=== Listing registered endpoints ===");
    let endpoints = coordination_service.get_endpoints();
    for endpoint in endpoints {
        println!("Endpoint: {} ({})", endpoint.name, endpoint.id);
    }
    
    println!("\n=== Sending test request ===");
    
    // In a real implementation, the responder would receive this request via its router
    // and process it using the consent manager. Since our router doesn't actually send
    // messages over the network in this demo, we'll simulate it:
    
    let request = create_test_request();
    println!("Request ID: {}", request.request_id);
    
    // Manually process the request with the consent manager (simulating what would happen)
    let request_bytes = pandacea::serialize_request(&request)?;
    let response_bytes = responder.consent_manager.process_request(&request_bytes)?;
    let response = pandacea::deserialize_response(&response_bytes)?;
    
    println!("Response status: {:?}", response.status);
    
    println!("\n=== Demo completed successfully ===");
    
    Ok(())
} 