//! The Sentinel Agent: Core logic for processing MCP requests and enforcing consent.

use crate::mcp::McpRequest;
// Remove unused McpResponse, PurposeDna, RequestorIdentity (commented out usage)
// use crate::types::{McpResponse, PurposeDna, RequestorIdentity};
use crate::types::{McpResponse, PurposeDNA}; // Update to PurposeDNA
use crate::error::{Result}; // Remove unused MCPError
use crate::types::purpose_dna::PurposeCategory;
// use crate::validation; // Remove unused validation import
use crate::validation::semantics::validate_request_semantics;
use crate::utils::{get_request_timestamp, chrono_from_prost_timestamp}; // Add utils for timestamp handling
// Already commented out: consent_storage, audit
// Remove unused Arc, Mutex (commented out usage)
// use std::sync::{Arc, Mutex};
// use std::sync::{Arc, Mutex}; // Remove unused Arc, Mutex imports
use std::collections::{HashMap, VecDeque, HashSet};
use chrono::{DateTime, Utc, Duration as ChronoDuration, Timelike};
use serde::{Serialize, Deserialize};

/// Configuration for the Sentinel Agent's behavior
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Maximum number of recent requests to track per requestor
    pub max_recent_requests: usize,
    /// Threshold for suspicious request frequency (requests per hour)
    pub max_requests_per_hour: u32,
    /// Sensitivity levels for different threat detection strategies
    pub sensitivity_level: SensitivityLevel,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        SentinelConfig {
            max_recent_requests: 100,
            max_requests_per_hour: 50,
            sensitivity_level: SensitivityLevel::Medium,
        }
    }
}

/// Sensitivity levels for threat detection
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize, Deserialize
pub enum SensitivityLevel {
    Low,
    Medium,
    High,
}

/// Represents an anomaly or suspicious activity detected by the Sentinel Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub timestamp: DateTime<Utc>,
    pub alert_type: AlertType,
    pub request_id: Option<String>, // Link alert to specific request if applicable
    pub requestor_id: Option<String>,
    pub details: String,
}

/// Types of security alerts the Sentinel Agent can generate
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize, Deserialize
pub enum AlertType {
    /// Invalid semantic structure or incompatible fields
    SemanticViolation,
    /// Unusual request frequency
    HighFrequencyAccess,
    /// Deviation from typical purpose patterns
    UnexpectedPurpose,
    /// Potential data access beyond normal scope (Placeholder)
    DataScopeViolation,
    /// Repeated denied or partially approved requests (Placeholder)
    RepeatedDenials,
    /// Suspicious time-based access patterns
    UnusualTimingAccess,
}

// Simple placeholder for RequestContext if not imported
// Remove this if RequestContext is properly defined and exported from validation module
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub current_time: DateTime<Utc>,
    pub requestor_trust_level: u32,
}

/// The Sentinel Agent monitors and analyzes request patterns.
/// It performs checks beyond basic validation, looking for suspicious behavior over time.
#[derive(Debug)]
pub struct SentinelAgent {
    /// Configuration for the Sentinel Agent
    config: SentinelConfig,
    /// Tracking of recent requests per requestor (requestor_id -> deque of requests)
    request_history: HashMap<String, VecDeque<McpRequest>>,
    // Comment out unused fields
    // consent_storage: Arc<Mutex<dyn ConsentStorage + Send + Sync>>,
    // audit_twin: Arc<Mutex<dyn AuditTwin + Send + Sync>>,
}

impl SentinelAgent {
    /// Create a new Sentinel Agent with default configuration.
    pub fn new() -> Self {
        Self::with_config(SentinelConfig::default())
    }

    /// Create a Sentinel Agent with custom configuration.
    pub fn with_config(config: SentinelConfig) -> Self {
        Self {
            config,
            request_history: HashMap::new(),
            // consent_storage: Arc::new(Mutex::new(ConsentStorage::new())),
            // audit_twin: Arc::new(Mutex::new(AuditTwin::new())),
        }
    }

    /// Analyze an incoming request for potential security risks and update history.
    ///
    /// Returns a list of generated alerts. It does NOT store alerts internally.
    pub fn analyze_request(&mut self, request: &McpRequest) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        let requestor_id_opt = request.requestor_identity.as_ref().map(|id| id.pseudonym_id.clone());

        // 1. Semantic Validation
        self.check_semantic_consistency(request, requestor_id_opt.as_deref(), &mut alerts);

        if let Some(ref requestor_id) = requestor_id_opt {
            // 2. Request Frequency Analysis
            self.analyze_request_frequency(request, requestor_id, &mut alerts);

            // 3. Purpose and Action Pattern Analysis
            self.analyze_purpose_patterns(request, requestor_id, &mut alerts);

            // 4. Time-based Access Pattern Analysis
            self.analyze_timing_patterns(request, requestor_id, &mut alerts);

            // Update request history *after* analysis based on current history
            self.update_request_history(request, requestor_id);
        }

        alerts
    }

    /// Validate semantic consistency and generate a specific alert type.
    fn check_semantic_consistency(
        &self,
        request: &McpRequest,
        requestor_id: Option<&str>,
        alerts: &mut Vec<SecurityAlert>
    ) {
        // Use existing semantic validation from the validation module
        if let Err(e) = validate_request_semantics(request) {
            alerts.push(SecurityAlert {
                timestamp: Utc::now(),
                alert_type: AlertType::SemanticViolation,
                request_id: Some(request.request_id.clone()),
                requestor_id: requestor_id.map(String::from),
                details: format!("Semantic validation failed: {}", e),
            });
        }
    }

    /// Analyze request frequency for potential abuse.
    fn analyze_request_frequency(
        &self,
        request: &McpRequest,
        requestor_id: &str,
        alerts: &mut Vec<SecurityAlert>
    ) {
        if let Some(history) = self.request_history.get(requestor_id) {
            let now = Utc::now();
            let one_hour_ago = now - ChronoDuration::hours(1);

            let requests_in_last_hour = history.iter()
                .filter(|req| {
                    get_request_timestamp(req)
                        .and_then(chrono_from_prost_timestamp)
                        .map_or(false, |req_time| req_time >= one_hour_ago)
                })
                .count();

            let current_count = requests_in_last_hour + 1;
            if current_count as u32 > self.config.max_requests_per_hour {
                alerts.push(SecurityAlert {
                    timestamp: now,
                    alert_type: AlertType::HighFrequencyAccess,
                    request_id: Some(request.request_id.clone()),
                    requestor_id: Some(requestor_id.to_string()),
                    details: format!(
                        "High frequency access detected: {} requests within the last hour (threshold: {})",
                        current_count,
                        self.config.max_requests_per_hour
                    ),
                });
            }
        }
    }

    /// Analyze purpose patterns for unusual behavior (Placeholder/Simple Example).
    fn analyze_purpose_patterns(
        &self,
        request: &McpRequest,
        requestor_id: &str,
        alerts: &mut Vec<SecurityAlert>
    ) {
        if let Some(purpose) = &request.purpose_dna {
            // Check for category - either in the category field or primary_purpose_category field
            let current_category = if let Some(category) = purpose.category {
                Some(category)
            } else if let Some(primary_category) = purpose.primary_purpose_category {
                PurposeCategory::try_from(primary_category).ok()
            } else {
                None
            };
            
            if let Some(current_category) = current_category {
                if current_category != PurposeCategory::Unspecified {
                    let historical_purposes = self.get_historical_purpose_categories(requestor_id);
                    if !historical_purposes.is_empty() && !historical_purposes.contains(&current_category) {
                        alerts.push(SecurityAlert {
                            timestamp: Utc::now(),
                            alert_type: AlertType::UnexpectedPurpose,
                            request_id: Some(request.request_id.clone()),
                            requestor_id: Some(requestor_id.to_string()),
                            details: format!(
                                "New purpose category {:?} observed for requestor (previously seen: {:?})",
                                current_category,
                                historical_purposes
                            ),
                        });
                    }
                }
            }
        }
    }

    /// Analyze timing patterns for suspicious access (Simple Example).
    fn analyze_timing_patterns(
        &self,
        request: &McpRequest,
        requestor_id: &str,
        alerts: &mut Vec<SecurityAlert>
    ) {
        let timestamp = get_request_timestamp(request);
        if let Some(timestamp) = timestamp {
            if let Some(req_time) = chrono_from_prost_timestamp(timestamp) {
                let hour = req_time.hour(); 
                // Example thresholds (adjust as needed)
                let typical_start_hour = 6;
                let typical_end_hour = 22;

                if hour < typical_start_hour || hour >= typical_end_hour { // Use >= for end hour
                    alerts.push(SecurityAlert {
                        timestamp: Utc::now(), // Alert time, not request time
                        alert_type: AlertType::UnusualTimingAccess,
                        request_id: Some(request.request_id.clone()),
                        requestor_id: Some(requestor_id.to_string()),
                        details: format!(
                            "Access attempted at {}:{} UTC, outside typical hours ({}:00-{}):00 UTC)",
                            hour, req_time.minute(), typical_start_hour, typical_end_hour
                        ),
                    });
                }
            }
        }
    }

    /// Update the stored request history for a requestor.
    fn update_request_history(&mut self, request: &McpRequest, requestor_id: &str) {
        let history = self.request_history
            .entry(requestor_id.to_string())
            .or_insert_with(VecDeque::new);

        // Enforce max history length
        if history.len() >= self.config.max_recent_requests {
            history.pop_front();
        }

        // Clone the request to store in history
        history.push_back(request.clone());
    }

    /// Retrieve the purpose categories seen historically for a requestor.
    fn get_historical_purpose_categories(&self, requestor_id: &str) -> HashSet<PurposeCategory> {
        self.request_history.get(requestor_id)
            .map(|history| {
                history.iter()
                    .filter_map(|req| req.purpose_dna.as_ref())
                    .filter_map(|purpose| {
                        // Try category first, then primary_purpose_category
                        if let Some(category) = purpose.category {
                            Some(category)
                        } else if let Some(primary_category) = purpose.primary_purpose_category {
                            PurposeCategory::try_from(primary_category).ok()
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(HashSet::new)
    }

    /// Get the current request history for all requestors.
    pub fn get_request_history(&self) -> &HashMap<String, VecDeque<McpRequest>> {
        &self.request_history
    }

    /// Check historical patterns for a given request (Placeholder/Future Implementation)
    fn check_historical_patterns(&self, request: &McpRequest) -> Result<()> {
        if let Some(purpose) = &request.purpose_dna {
            // Check for category - either in the category field or primary_purpose_category field
            let current_category = if let Some(category) = purpose.category {
                Some(category)
            } else if let Some(primary_category) = purpose.primary_purpose_category {
                PurposeCategory::try_from(primary_category).ok()
            } else {
                None
            };
            
            if let Some(current_category) = current_category {
                // Could add more sophisticated pattern matching here
                // For now just return Ok
                return Ok(());
            }
        }

        // Placeholder for more complex historical pattern analysis
        Ok(())
    }

    /// Record a consent decision (Placeholder/Future Implementation)
    #[allow(unused_variables)] // Use until implementation is complete
    fn record_consent_decision(&self, request_id: &str, granted: bool, response: Option<&McpResponse>) {
        // Placeholder - future implementation to record decisions for pattern analysis
        // consent_storage.record_decision(request_id, granted);
        // audit_twin.log_decision(request_id, granted, response);
    }
}

#[cfg(test)]
mod tests {
    // Test code would go here
    // Would need to be updated for the new field structure
} 