//! Consent Manager: Evaluates data requests against user consent rules.
//! 
//! The Consent Manager is an edge-native component that runs on the user's device 
//! and enforces their data sovereignty by evaluating MCP requests against their
//! Consent Genome (ruleset for data sharing).

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use crate::error::{MCPError, Result};
use crate::sentinel::{SentinelAgent, SentinelConfig, SecurityAlert};
use crate::serialization::{deserialize_request, serialize_response};
use crate::types::{
    McpRequest, McpResponse, 
    purpose_dna::PurposeCategory,
    permission_specification::Action,
    mcp_response::{Status as ResponseStatus, PermissionStatus},
};
use crate::validation;

/// Decision outcome for a consent rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentDecision {
    /// Allow the request without user intervention
    Allow,
    /// Deny the request without user intervention
    Deny,
    /// Prompt the user for a decision
    Prompt,
}

/// A rule in the Consent Genome that specifies how to handle specific requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRule {
    /// Unique identifier for this rule
    pub id: String,
    /// Human-readable name for this rule
    pub name: String,
    /// Optional description explaining the rule's purpose
    pub description: Option<String>,
    /// Priority of this rule (higher values = higher priority)
    pub priority: u32,
    /// Which requestor(s) this rule applies to (None = all)
    pub requestor_filter: Option<RequestorFilter>,
    /// Which purpose categories this rule applies to (None = all)
    pub purpose_filter: Option<HashSet<PurposeCategory>>,
    /// Which data types/resources this rule applies to (None = all)
    pub resource_filter: Option<HashSet<String>>,
    /// Which actions this rule applies to (None = all)
    pub action_filter: Option<HashSet<Action>>,
    /// The decision to make when this rule matches
    pub decision: ConsentDecision,
    /// When this rule was created
    pub created_at: DateTime<Utc>,
    /// When this rule was last modified
    pub modified_at: DateTime<Utc>,
    /// Whether this rule is enabled
    pub enabled: bool,
}

/// Filter that specifies which requestors a rule applies to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestorFilter {
    /// Specific requestor IDs this rule applies to
    Specific(HashSet<String>),
    /// Categories of requestors this rule applies to
    Category(HashSet<String>),
    /// Specific requestors excluded from this rule
    Exclude(HashSet<String>),
}

/// Entry in the audit log recording a decision made by the Consent Manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// When this decision was made
    pub timestamp: DateTime<Utc>,
    /// The request ID that was processed
    pub request_id: String,
    /// The requestor ID (if available)
    pub requestor_id: Option<String>,
    /// Short description of the request purpose
    pub purpose: String,
    /// The decision that was made
    pub decision: ConsentDecision,
    /// The rule ID that triggered this decision (if any)
    pub matching_rule_id: Option<String>,
    /// Whether the user was prompted for this decision
    pub user_prompted: bool,
    /// Any security alerts generated during processing
    pub security_alerts: Vec<String>,
    /// Additional context about the decision
    pub context: Option<String>,
}

/// Configuration for the Consent Manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentManagerConfig {
    /// Path to the consent genome file
    pub genome_path: String,
    /// Path to the audit log file
    pub audit_log_path: String,
    /// Configuration for the Sentinel Agent
    pub sentinel_config: SentinelConfig,
    /// Default decision when no rules match
    pub default_decision: ConsentDecision,
    /// Whether to enable audit logging
    pub enable_audit: bool,
}

impl Default for ConsentManagerConfig {
    fn default() -> Self {
        Self {
            genome_path: "consent_genome.json".to_string(),
            audit_log_path: "consent_audit.log".to_string(),
            sentinel_config: SentinelConfig::default(),
            default_decision: ConsentDecision::Prompt,
            enable_audit: true,
        }
    }
}

/// The Consent Manager is responsible for evaluating MCP requests against
/// the user's Consent Genome and making decisions about data access.
pub struct ConsentManager {
    /// Configuration for the Consent Manager
    config: ConsentManagerConfig,
    /// The user's consent genome (ruleset)
    rules: Vec<ConsentRule>,
    /// Security component for threat detection
    sentinel: SentinelAgent,
    /// Audit log of decisions
    audit_log: Vec<AuditLogEntry>,
    /// Message router for communication (Optional)
    message_router: Option<Arc<crate::communication::MessageRouter>>,
    /// Local endpoint ID when using the message router
    endpoint_id: Option<String>,
}

impl ConsentManager {
    /// Create a new Consent Manager with default configuration.
    pub fn new() -> Self {
        Self::with_config(ConsentManagerConfig::default())
    }

    /// Create a Consent Manager with custom configuration.
    pub fn with_config(config: ConsentManagerConfig) -> Self {
        let sentinel = SentinelAgent::with_config(config.sentinel_config.clone());
        let rules = Self::load_genome(&config.genome_path).unwrap_or_default();
        let audit_log = Self::load_audit_log(&config.audit_log_path).unwrap_or_default();

        Self {
            config,
            rules,
            sentinel,
            audit_log,
            message_router: None,
            endpoint_id: None,
        }
    }

    /// Configure the Consent Manager to use the given message router.
    pub fn with_message_router(mut self, router: Arc<crate::communication::MessageRouter>, endpoint_id: String) -> Self {
        self.message_router = Some(router);
        self.endpoint_id = Some(endpoint_id);
        self
    }

    /// Process an MCP request and generate a response based on consent rules.
    pub fn process_request(&mut self, request_bytes: &[u8]) -> Result<Vec<u8>> {
        // Deserialize and validate the request
        let request = deserialize_request(request_bytes)?;
        validation::validate_request(&request)?;

        // Run security analysis
        let mut sentinel = self.sentinel.clone();
        let security_alerts = sentinel.analyze_request(&request);

        // Evaluate request against consent rules
        let (decision, matching_rule_id) = self.evaluate_request(&request, &security_alerts);

        // Generate response based on decision
        let response = self.generate_response(&request, decision, &security_alerts)?;

        // Log the decision to audit log
        if self.config.enable_audit {
            self.log_decision(&request, decision, matching_rule_id, &security_alerts);
            self.save_audit_log(&self.config.audit_log_path)?;
        }

        // Serialize the response
        let response_bytes = serialize_response(&response)?;
        Ok(response_bytes)
    }

    /// Evaluate a request against the consent genome rules.
    /// 
    /// Returns the decision and the ID of the matching rule (if any).
    fn evaluate_request(&self, request: &McpRequest, alerts: &[SecurityAlert]) -> (ConsentDecision, Option<String>) {
        // If there are security alerts, default to prompting the user
        if !alerts.is_empty() && self.has_critical_alerts(alerts) {
            return (ConsentDecision::Prompt, None);
        }

        // Get the request metadata needed for rule matching
        let requestor_id = request.requestor_identity.as_ref()
            .map(|identity| identity.pseudonym_id.clone());
        
        let purpose_category = request.purpose_dna.as_ref()
            .and_then(|purpose| purpose.category);
        
        // Sort rules by priority (highest first)
        let mut matching_rules: Vec<&ConsentRule> = self.rules.iter()
            .filter(|rule| rule.enabled)
            .filter(|rule| self.rule_matches(rule, request, &requestor_id, purpose_category))
            .collect();
        
        matching_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        // Return the highest priority matching rule's decision, or the default
        matching_rules.first()
            .map(|rule| (rule.decision.clone(), Some(rule.id.clone())))
            .unwrap_or((self.config.default_decision.clone(), None))
    }

    /// Check if a rule matches the given request.
    fn rule_matches(
        &self, 
        rule: &ConsentRule, 
        request: &McpRequest,
        requestor_id: &Option<String>,
        purpose_category: Option<i32>,
    ) -> bool {
        // Check requestor filter
        if let Some(ref filter) = rule.requestor_filter {
            if !self.requestor_matches(filter, requestor_id) {
                return false;
            }
        }

        // Check purpose filter
        if let Some(ref purpose_filter) = rule.purpose_filter {
            let purpose_category = purpose_category
                .and_then(|cat| PurposeCategory::try_from(cat).ok());
            
            if let Some(category) = purpose_category {
                if !purpose_filter.contains(&category) {
                    return false;
                }
            } else if !purpose_filter.is_empty() {
                return false;
            }
        }

        // Check resource and action filters for each permission
        if let Some(ref resource_filter) = rule.resource_filter {
            if !request.permission_specs.iter().any(|perm| {
                resource_filter.contains(&perm.resource)
            }) {
                return false;
            }
        }

        if let Some(ref action_filter) = rule.action_filter {
            if !request.permission_specs.iter().any(|perm| {
                perm.action
                    .and_then(|a| Action::try_from(a).ok())
                    .map_or(false, |action| action_filter.contains(&action))
            }) {
                return false;
            }
        }

        true
    }

    /// Check if the requestor matches the given filter.
    fn requestor_matches(&self, filter: &RequestorFilter, requestor_id: &Option<String>) -> bool {
        match filter {
            RequestorFilter::Specific(ids) => {
                requestor_id.as_ref().map_or(false, |id| ids.contains(id))
            },
            RequestorFilter::Category(_categories) => {
                // In a real implementation, this would check if the requestor 
                // belongs to any of the specified categories
                // For now, we'll just return true as a placeholder
                true
            },
            RequestorFilter::Exclude(ids) => {
                requestor_id.as_ref().map_or(true, |id| !ids.contains(id))
            },
        }
    }

    /// Check if there are any critical security alerts.
    fn has_critical_alerts(&self, alerts: &[SecurityAlert]) -> bool {
        // Consider any security alert as critical for now
        // In a more sophisticated implementation, we'd categorize alerts by severity
        !alerts.is_empty()
    }

    /// Generate an MCP response based on the consent decision.
    fn generate_response(
        &self, 
        request: &McpRequest, 
        decision: ConsentDecision,
        _alerts: &[SecurityAlert]
    ) -> Result<McpResponse> {
        let status = match decision {
            ConsentDecision::Allow => ResponseStatus::Approved,
            ConsentDecision::Deny => ResponseStatus::Denied,
            ConsentDecision::Prompt => ResponseStatus::PartiallyApproved, // Placeholder for prompt
        };

        // Create a basic response
        // In a real implementation, we'd need to properly set all fields,
        // including cryptographic signatures
        let response = McpResponse {
            request_id: request.request_id.clone(),
            status: status as i32,
            // Set other fields as needed
            ..Default::default()
        };

        Ok(response)
    }

    /// Log a decision to the audit log.
    fn log_decision(
        &mut self,
        request: &McpRequest,
        decision: ConsentDecision,
        matching_rule_id: Option<String>,
        alerts: &[SecurityAlert],
    ) {
        let requestor_id = request.requestor_identity.as_ref()
            .map(|identity| identity.pseudonym_id.clone());
        
        let purpose = request.purpose_dna.as_ref()
            .map(|purpose| purpose.description.clone())
            .unwrap_or_else(|| "Unknown purpose".to_string());

        let alert_strings: Vec<String> = alerts.iter()
            .map(|alert| format!("{:?}: {}", alert.alert_type, alert.details))
            .collect();

        let entry = AuditLogEntry {
            timestamp: Utc::now(),
            request_id: request.request_id.clone(),
            requestor_id,
            purpose,
            decision,
            matching_rule_id,
            user_prompted: decision == ConsentDecision::Prompt,
            security_alerts: alert_strings,
            context: None,
        };

        self.audit_log.push(entry);
    }

    /// Load the consent genome from a file.
    fn load_genome(path: &str) -> Result<Vec<ConsentRule>> {
        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }

        let data = fs::read_to_string(path)
            .map_err(|e| MCPError::GenomeError { 
                context: format!("Failed to read genome file: {}", path),
                source: Box::new(e) 
            })?;

        serde_json::from_str(&data)
            .map_err(|e| MCPError::GenomeError { 
                context: format!("Failed to parse genome file: {}", path),
                source: Box::new(e) 
            })
    }

    /// Save the consent genome to a file.
    pub fn save_genome(&self, path: &str) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.rules)
            .map_err(|e| MCPError::GenomeError { 
                context: "Failed to serialize genome".to_string(),
                source: Box::new(e) 
            })?;

        fs::write(path, data)
            .map_err(|e| MCPError::GenomeError { 
                context: format!("Failed to write genome file: {}", path),
                source: Box::new(e) 
            })?;

        Ok(())
    }

    /// Load the audit log from a file.
    fn load_audit_log(path: &str) -> Result<Vec<AuditLogEntry>> {
        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }

        let data = fs::read_to_string(path)
            .map_err(|e| MCPError::AuditError { 
                context: format!("Failed to read audit log file: {}", path),
                source: Box::new(e) 
            })?;

        serde_json::from_str(&data)
            .map_err(|e| MCPError::AuditError { 
                context: format!("Failed to parse audit log file: {}", path),
                source: Box::new(e) 
            })
    }

    /// Save the audit log to a file.
    fn save_audit_log(&self, path: &str) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.audit_log)
            .map_err(|e| MCPError::AuditError { 
                context: "Failed to serialize audit log".to_string(),
                source: Box::new(e) 
            })?;

        fs::write(path, data)
            .map_err(|e| MCPError::AuditError { 
                context: format!("Failed to write audit log file: {}", path),
                source: Box::new(e) 
            })?;

        Ok(())
    }

    /// Add a new rule to the consent genome.
    pub fn add_rule(&mut self, rule: ConsentRule) -> Result<()> {
        // Check if rule with this ID already exists
        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(MCPError::GenomeError { 
                context: format!("Rule with ID {} already exists", rule.id),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "Duplicate rule ID"
                ))
            });
        }

        self.rules.push(rule);
        Ok(())
    }

    /// Remove a rule from the consent genome.
    pub fn remove_rule(&mut self, rule_id: &str) -> Result<()> {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);

        if self.rules.len() == initial_len {
            return Err(MCPError::GenomeError { 
                context: format!("Rule with ID {} not found", rule_id),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Rule not found"
                ))
            });
        }

        Ok(())
    }

    /// Update an existing rule in the consent genome.
    pub fn update_rule(&mut self, rule: ConsentRule) -> Result<()> {
        let found = self.rules.iter_mut().find(|r| r.id == rule.id);

        match found {
            Some(existing) => {
                *existing = rule;
                Ok(())
            },
            None => Err(MCPError::GenomeError { 
                context: format!("Rule with ID {} not found", rule.id),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Rule not found"
                ))
            }),
        }
    }

    /// Get all rules in the consent genome.
    pub fn get_rules(&self) -> &[ConsentRule] {
        &self.rules
    }

    /// Get a specific rule by ID.
    pub fn get_rule(&self, rule_id: &str) -> Option<&ConsentRule> {
        self.rules.iter().find(|r| r.id == rule_id)
    }

    /// Get the audit log.
    pub fn get_audit_log(&self) -> &[AuditLogEntry] {
        &self.audit_log
    }

    /// Start listening for incoming MCP requests on the message router.
    pub async fn start_request_listener(&self) -> Result<()> {
        if let Some(router) = &self.message_router {
            if let Some(endpoint_id) = &self.endpoint_id {
                println!("Starting consent manager request listener for endpoint: {}", endpoint_id);
                // This would normally set up listeners on the router
                // For now we're just returning Ok since we haven't fully implemented the router's callbacks
                Ok(())
            } else {
                Err(MCPError::CommunicationError {
                    context: "No endpoint ID configured for consent manager".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Missing endpoint ID",
                    )),
                })
            }
        } else {
            Err(MCPError::CommunicationError {
                context: "No message router configured for consent manager".to_string(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing router",
                )),
            })
        }
    }

    /// Process an MCP request received from the network and send the response back.
    pub async fn process_network_request(&mut self, request_bytes: &[u8], from_endpoint_id: &str) -> Result<()> {
        // Process the request normally
        let response_bytes = self.process_request(request_bytes)?;
        
        // Send the response back through the message router if configured
        if let Some(router) = &self.message_router {
            let response = deserialize_response(&response_bytes)?;
            
            // Convert the raw bytes back to a response so we can get the request ID for logs
            println!("Sending response for request {} to endpoint {}", response.request_id, from_endpoint_id);
            
            // We would normally send the response back through the router here
            // For now just log that we would have sent it
            // router.send_response(from_endpoint_id, response).await?;
            
            Ok(())
        } else {
            Err(MCPError::CommunicationError {
                context: "No message router configured for consent manager".to_string(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing router",
                )),
            })
        }
    }

    /// Send an MCP response directly to a specific endpoint.
    pub async fn send_response(&self, to_endpoint_id: &str, response: McpResponse) -> Result<()> {
        if let Some(router) = &self.message_router {
            println!("Sending response for request {} to endpoint {}", response.request_id, to_endpoint_id);
            
            // Convert the response to bytes for transport
            let response_bytes = serialize_response(&response)?;
            
            // In a real implementation, we would send through the router
            // router.send_response(to_endpoint_id, response_bytes).await?;
            
            Ok(())
        } else {
            Err(MCPError::CommunicationError {
                context: "No message router configured for consent manager".to_string(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing router",
                )),
            })
        }
    }

    /// Handle an incoming MCP request from the message router.
    pub async fn handle_incoming_request(&mut self, request: McpRequest, from_endpoint_id: &str) -> Result<McpResponse> {
        // Serialize the request to bytes (since our process_request expects bytes)
        let request_bytes = serialize_request(&request)?;
        
        // Process the request
        let response_bytes = self.process_request(&request_bytes)?;
        
        // Deserialize the response
        let response = deserialize_response(&response_bytes)?;
        
        // Log that we handled it
        println!("Handled request {} from endpoint {}", request.request_id, from_endpoint_id);
        
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::test_utils::test_utils::*;

    fn create_test_rule(
        id: &str, 
        name: &str, 
        priority: u32, 
        decision: ConsentDecision
    ) -> ConsentRule {
        ConsentRule {
            id: id.to_string(),
            name: name.to_string(),
            description: None,
            priority,
            requestor_filter: None,
            purpose_filter: None,
            resource_filter: None,
            action_filter: None,
            decision,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            enabled: true,
        }
    }

    #[test]
    fn test_consent_manager_initialization() {
        let manager = ConsentManager::new();
        assert!(manager.get_rules().is_empty());
        assert!(manager.get_audit_log().is_empty());
    }

    #[test]
    fn test_add_rule() {
        let mut manager = ConsentManager::new();
        let rule = create_test_rule("rule1", "Test Rule", 10, ConsentDecision::Allow);
        
        assert!(manager.add_rule(rule.clone()).is_ok());
        assert_eq!(manager.get_rules().len(), 1);
        
        // Adding the same rule ID should fail
        assert!(manager.add_rule(rule).is_err());
    }

    #[test]
    fn test_update_rule() {
        let mut manager = ConsentManager::new();
        let rule = create_test_rule("rule1", "Test Rule", 10, ConsentDecision::Allow);
        
        assert!(manager.add_rule(rule.clone()).is_ok());
        
        let mut updated_rule = rule;
        updated_rule.name = "Updated Rule".to_string();
        updated_rule.decision = ConsentDecision::Deny;
        
        assert!(manager.update_rule(updated_rule).is_ok());
        
        let retrieved_rule = manager.get_rule("rule1").unwrap();
        assert_eq!(retrieved_rule.name, "Updated Rule");
        assert_eq!(retrieved_rule.decision, ConsentDecision::Deny);
    }

    #[test]
    fn test_remove_rule() {
        let mut manager = ConsentManager::new();
        let rule = create_test_rule("rule1", "Test Rule", 10, ConsentDecision::Allow);
        
        assert!(manager.add_rule(rule).is_ok());
        assert_eq!(manager.get_rules().len(), 1);
        
        assert!(manager.remove_rule("rule1").is_ok());
        assert_eq!(manager.get_rules().len(), 0);
        
        // Removing a non-existent rule should fail
        assert!(manager.remove_rule("rule1").is_err());
    }

    #[test]
    fn test_rule_matching() {
        let mut manager = ConsentManager::new();
        
        // Add a rule that matches a specific purpose category
        let mut rule = create_test_rule("rule1", "Marketing Rule", 10, ConsentDecision::Deny);
        let mut purpose_filter = HashSet::new();
        purpose_filter.insert(PurposeCategory::Marketing);
        rule.purpose_filter = Some(purpose_filter);
        
        assert!(manager.add_rule(rule).is_ok());
        
        // Create a request with marketing purpose
        let key_pair = KeyPair::generate().unwrap();
        let marketing_request = create_signed_request(
            &key_pair,
            PurposeCategory::Marketing,
            vec![create_test_permission("user.email", Action::Read, None)]
        );
        
        // Create a request with operations purpose
        let operations_request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("user.email", Action::Read, None)]
        );
        
        let request_id = marketing_request.requestor_identity.as_ref()
            .map(|id| Some(id.pseudonym_id.clone()));
        
        // The marketing request should match the rule
        let marketing_matches = manager.rule_matches(
            &manager.get_rule("rule1").unwrap(),
            &marketing_request,
            &request_id,
            Some(PurposeCategory::Marketing as i32)
        );
        assert!(marketing_matches);
        
        // The operations request should not match the rule
        let operations_matches = manager.rule_matches(
            &manager.get_rule("rule1").unwrap(),
            &operations_request,
            &request_id,
            Some(PurposeCategory::Operations as i32)
        );
        assert!(!operations_matches);
    }

    #[test]
    fn test_evaluate_request() {
        let mut manager = ConsentManager::new();
        
        // Add a rule for denying marketing requests
        let mut rule1 = create_test_rule("rule1", "Marketing Rule", 10, ConsentDecision::Deny);
        let mut purpose_filter = HashSet::new();
        purpose_filter.insert(PurposeCategory::Marketing);
        rule1.purpose_filter = Some(purpose_filter);
        
        // Add a higher priority rule for allowing specific resources
        let mut rule2 = create_test_rule("rule2", "Allow Email Rule", 20, ConsentDecision::Allow);
        let mut resource_filter = HashSet::new();
        resource_filter.insert("user.email".to_string());
        rule2.resource_filter = Some(resource_filter);
        
        assert!(manager.add_rule(rule1).is_ok());
        assert!(manager.add_rule(rule2).is_ok());
        
        // Create a request with marketing purpose for email
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Marketing,
            vec![create_test_permission("user.email", Action::Read, None)]
        );
        
        // The higher priority rule should win
        let (decision, rule_id) = manager.evaluate_request(&request, &[]);
        assert_eq!(decision, ConsentDecision::Allow);
        assert_eq!(rule_id.unwrap(), "rule2");
    }

    #[test]
    fn test_process_request() {
        let mut manager = ConsentManager::new();
        
        // Add a rule for allowing operations requests
        let mut rule = create_test_rule("rule1", "Operations Rule", 10, ConsentDecision::Allow);
        let mut purpose_filter = HashSet::new();
        purpose_filter.insert(PurposeCategory::Operations);
        rule.purpose_filter = Some(purpose_filter);
        
        assert!(manager.add_rule(rule).is_ok());
        
        // Create and serialize a request
        let key_pair = KeyPair::generate().unwrap();
        let request = create_signed_request(
            &key_pair,
            PurposeCategory::Operations,
            vec![create_test_permission("system.config", Action::Read, None)]
        );
        
        let request_bytes = serialize_request(&request).unwrap();
        
        // Process the request
        let response_bytes = manager.process_request(&request_bytes).unwrap();
        let response = deserialize_response(&response_bytes).unwrap();
        
        assert_eq!(response.request_id, request.request_id);
        assert_eq!(response.status, ResponseStatus::Approved as i32);
        
        // Check that the audit log was updated
        assert_eq!(manager.get_audit_log().len(), 1);
        let log_entry = &manager.get_audit_log()[0];
        assert_eq!(log_entry.request_id, request.request_id);
        assert_eq!(log_entry.decision, ConsentDecision::Allow);
    }
} 