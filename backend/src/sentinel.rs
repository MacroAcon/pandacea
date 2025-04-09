//! The Sentinel Agent: Core logic for processing MCP requests and enforcing consent.

use crate::mcp::McpRequest;
// Remove unused McpResponse, PurposeDna, RequestorIdentity (commented out usage)
// use crate::types::{McpResponse, PurposeDna, RequestorIdentity};
use crate::types::McpResponse; // Needed for record_consent_decision signature
use crate::error::{Result}; // Remove unused MCPError
use crate::types::purpose_dna::PurposeCategory;
// use crate::validation; // Remove unused validation import
use crate::validation::semantics::validate_request_semantics;
// Already commented out: consent_storage, audit
// Remove unused Arc, Mutex (commented out usage)
// use std::sync::{Arc, Mutex};
// use std::sync::{Arc, Mutex}; // Remove unused Arc, Mutex imports
use std::collections::{HashMap, VecDeque, HashSet};
use chrono::{DateTime, Utc, Duration as ChronoDuration, Timelike};

/// Configuration for the Sentinel Agent's behavior
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug, PartialEq, Eq)] // Added Eq
pub enum SensitivityLevel {
    Low,
    Medium,
    High,
}

/// Represents an anomaly or suspicious activity detected by the Sentinel Agent
#[derive(Debug, Clone)]
pub struct SecurityAlert {
    pub timestamp: DateTime<Utc>,
    pub alert_type: AlertType,
    pub request_id: Option<String>, // Link alert to specific request if applicable
    pub requestor_id: Option<String>,
    pub details: String,
}

/// Types of security alerts the Sentinel Agent can generate
#[derive(Debug, Clone, PartialEq, Eq)] // Added Eq
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
                    req.timestamp.as_ref()
                        .and_then(|ts| DateTime::from_timestamp(ts.seconds, ts.nanos as u32))
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
            // Use try_from().ok() to get an Option<PurposeCategory>
            if let Some(current_category) = PurposeCategory::try_from(purpose.primary_purpose_category).ok() {
                if current_category != PurposeCategory::Unspecified { // Check category after getting Some
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
        if let Some(timestamp) = &request.timestamp { // Use request.timestamp directly (assume it exists)
            if let Some(req_time) = DateTime::from_timestamp(timestamp.seconds, timestamp.nanos as u32) {
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

    /// Update request history for a given requestor.
    fn update_request_history(&mut self, request: &McpRequest, requestor_id: &str) {
        let history = self.request_history
            .entry(requestor_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(self.config.max_recent_requests));

        // Add new request to the front
        history.push_front(request.clone());

        // Trim history if it exceeds max size
        history.truncate(self.config.max_recent_requests);
    }

    /// Retrieve historical purpose categories for a requestor.
    fn get_historical_purpose_categories(&self, requestor_id: &str) -> HashSet<PurposeCategory> {
        self.request_history
            .get(requestor_id)
            .map(|history| {
                history.iter()
                    .filter_map(|req| req.purpose_dna.as_ref())
                    // Use try_from().ok() which returns Option<PurposeCategory>
                    .filter_map(|purpose| PurposeCategory::try_from(purpose.primary_purpose_category).ok())
                    .filter(|cat| *cat != PurposeCategory::Unspecified)
                    .collect::<HashSet<PurposeCategory>>()
            })
            .unwrap_or_default()
    }

     /// Get a snapshot of the current request history (for debugging/testing).
    pub fn get_request_history(&self) -> &HashMap<String, VecDeque<McpRequest>> {
        &self.request_history
    }

    // Example internal logic: Check against historical consent patterns
    fn check_historical_patterns(&self, request: &McpRequest) -> Result<()> {
        let requestor_id = request.requestor_identity.as_ref()
            .map(|id| id.pseudonym_id.as_str())
            .unwrap_or("unknown_requestor");

        let historical_categories = self.get_historical_purpose_categories(requestor_id);

        if let Some(purpose) = &request.purpose_dna {
            // Use try_from().ok()
            if let Some(current_category) = PurposeCategory::try_from(purpose.primary_purpose_category).ok() {
                if historical_categories.contains(&current_category) {
                    // Potentially allow based on history (or flag for review)
                } else {
                    // ... rest of file ...
                }
            }
        }
        Ok(())
    }

    // Placeholder: Record consent decision
    fn record_consent_decision(&self, request_id: &str, granted: bool, response: Option<&McpResponse>) {
        // TODO: Implement interaction with ConsentStorage and AuditTwin (commented out)
        println!(
            "Placeholder: Recording consent decision for request {}: Granted = {}. Response: {:?}",
            request_id,
            granted,
            response.map(|r| r.status)
        );
        // self.storage.store_consent(...);
        // self.audit_twin.log_decision(...);
    }
}

// Tests for the Sentinel Agent
#[cfg(test)]
mod tests {
    use super::*; // Import items from outer module
    // Assuming test_utils is declared in lib.rs or available
    use crate::test_utils::test_utils::*; // Import common test helpers
    use crate::types::{permission_specification::Action, McpRequest, Signature }; // Specify Action directly
    use prost_types::{Timestamp as ProstTimestamp, Struct as ProstStruct};
    use std::thread; // For simulating time passing
    use chrono::TimeZone; // For creating specific DateTime

    // Helper specifically for sentinel tests, allowing timestamp control
    fn create_sentinel_test_request(
        key_pair: &KeyPair,
        purpose_category: PurposeCategory,
        requestor_id: &str,
        timestamp: ProstTimestamp,
        resource: &str,
        action: Action,
    ) -> McpRequest {
        let identity = create_test_identity(key_pair);
        let purpose = create_base_test_purpose(purpose_category, vec![resource.to_string()]);
        let permissions = vec![create_test_permission(resource, action, None)];

        let mut builder = McpRequestBuilder::new(identity.clone(), purpose.clone(), "1.0.0".to_string())
            .request_id(format!("req-sentest-{}-{}", requestor_id, timestamp.seconds))
            .timestamp(timestamp)
            .permissions(permissions);

        let mut request = builder.build_unsigned().expect("Builder failed");
        let signature = sign_request_payload(&request, key_pair).expect("Signing failed");
        request.signature = Some(signature);
        request
    }

    #[test]
    fn test_sentinel_agent_initialization() {
        let sentinel = SentinelAgent::new(); // Uses Default trait for SentinelConfig
        assert_eq!(sentinel.config.max_recent_requests, 100);
        assert_eq!(sentinel.config.max_requests_per_hour, 50);
        assert_eq!(sentinel.config.sensitivity_level, SensitivityLevel::Medium);
    }

    #[test]
    fn test_request_frequency_analysis_below_threshold() {
        let mut sentinel = SentinelAgent::with_config(SentinelConfig {
            max_requests_per_hour: 10,
            max_recent_requests: 50,
            sensitivity_level: SensitivityLevel::Medium,
        });
        let key_pair = KeyPair::generate().unwrap();
        let requestor_id = "freq_user_ok";

        // 5 requests within an hour - should be OK
        for i in 0..5 {
            let timestamp = current_prost_timestamp();
            let req = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, timestamp, "data", Action::Read);
            let alerts = sentinel.analyze_request(&req);
            assert!(alerts.is_empty(), "Alert generated unexpectedly on request {}", i);
            // Simulate small delay
            thread::sleep(StdDuration::from_millis(10));
        }
    }

     #[test]
    fn test_request_frequency_analysis_above_threshold() {
        let threshold = 5;
        let mut sentinel = SentinelAgent::with_config(SentinelConfig {
            max_requests_per_hour: threshold,
            max_recent_requests: 50,
            sensitivity_level: SensitivityLevel::Medium,
        });
        let key_pair = KeyPair::generate().unwrap();
        let requestor_id = "freq_user_bad";

        let mut alerts_generated = 0;
        // Send threshold + 1 requests quickly
        for i in 0..(threshold + 1) {
            let timestamp = current_prost_timestamp(); // Assume these happen within the hour
            let req = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, timestamp, "data", Action::Read);
            let alerts = sentinel.analyze_request(&req);

            if i < threshold {
                 assert!(alerts.is_empty(), "Alert generated too early on request {}", i);
            } else {
                // The request *exceeding* the threshold should trigger the alert
                 assert!(alerts.iter().any(|a| a.alert_type == AlertType::HighFrequencyAccess),
                    "HighFrequencyAccess alert missing on request {}", i);
                 alerts_generated += 1;
            }
            thread::sleep(StdDuration::from_millis(5)); // Small delay
        }
        assert_eq!(alerts_generated, 1, "Expected exactly one HighFrequencyAccess alert");
    }

    #[test]
    fn test_request_frequency_analysis_over_time() {
         let threshold = 5;
        let mut sentinel = SentinelAgent::with_config(SentinelConfig {
            max_requests_per_hour: threshold,
            max_recent_requests: 50,
            sensitivity_level: SensitivityLevel::Medium,
        });
        let key_pair = KeyPair::generate().unwrap();
        let requestor_id = "freq_user_time";

        // Simulate threshold requests just over an hour ago
        let hour_ago = Utc::now() - ChronoDuration::hours(1);
        let hour_ago_ts = ProstTimestamp { seconds: hour_ago.timestamp(), nanos: 0 };
        for _ in 0..threshold {
             let req = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, hour_ago_ts, "data", Action::Read);
             sentinel.analyze_request(&req); // Analyze but ignore alerts, just populate history
        }

        // Now send one more request - should NOT trigger alert as old ones expired
        let now_ts = current_prost_timestamp();
        let req_now = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, now_ts, "data", Action::Read);
        let alerts = sentinel.analyze_request(&req_now);

        assert!(alerts.is_empty(), "Alert generated even though old requests expired");
    }


    #[test]
    fn test_unusual_purpose_detection_first_request() {
        let mut sentinel = SentinelAgent::new();
        let key_pair = KeyPair::generate().unwrap();
        let requestor_id = "new_user_purpose";

        // First request ever for this user
        let req = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, current_prost_timestamp(), "d", Action::Read);
        let alerts = sentinel.analyze_request(&req);

        // Should not trigger 'UnexpectedPurpose' on the very first request
        assert!(!alerts.iter().any(|a| a.alert_type == AlertType::UnexpectedPurpose),
                "UnexpectedPurpose alert triggered on first request");
    }

     #[test]
    fn test_unusual_purpose_detection_new_purpose() {
        let mut sentinel = SentinelAgent::new();
        let key_pair = KeyPair::generate().unwrap();
        let requestor_id = "varied_user_purpose";

        // Request 1: Analytics
        let ts1 = current_prost_timestamp();
        let req1 = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, ts1, "d1", Action::Read);
        let alerts1 = sentinel.analyze_request(&req1);
        assert!(!alerts1.iter().any(|a| a.alert_type == AlertType::UnexpectedPurpose));

        thread::sleep(StdDuration::from_millis(10));

        // Request 2: Operations (Same user, different purpose)
        let ts2 = current_prost_timestamp();
        let req2 = create_sentinel_test_request(&key_pair, PurposeCategory::Operations, requestor_id, ts2, "d2", Action::Write);
        let alerts2 = sentinel.analyze_request(&req2);

        // Should trigger 'UnexpectedPurpose' as Operations wasn't seen before
         assert!(alerts2.iter().any(|a| a.alert_type == AlertType::UnexpectedPurpose),
                "UnexpectedPurpose alert missing on new purpose");
    }

     #[test]
    fn test_unusual_purpose_detection_repeated_purpose() {
        let mut sentinel = SentinelAgent::new();
        let key_pair = KeyPair::generate().unwrap();
        let requestor_id = "consistent_user_purpose";

        // Request 1: Analytics
        let req1 = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, current_prost_timestamp(), "d1", Action::Read);
        sentinel.analyze_request(&req1);
        thread::sleep(StdDuration::from_millis(10));

        // Request 2: Analytics again
        let req2 = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, current_prost_timestamp(), "d2", Action::Read);
        let alerts2 = sentinel.analyze_request(&req2);

        // Should NOT trigger 'UnexpectedPurpose'
        assert!(!alerts2.iter().any(|a| a.alert_type == AlertType::UnexpectedPurpose),
                "UnexpectedPurpose alert triggered on repeated purpose");
    }

    #[test]
    fn test_timing_pattern_analysis_normal_hours() {
        let mut sentinel = SentinelAgent::new();
        let key_pair = KeyPair::generate().unwrap();
        let requestor_id = "time_user_ok";

        // Timestamp within typical hours (e.g., 14:00 UTC)
        let normal_time = Utc::now().with_hour(14).unwrap();
        let normal_ts = ProstTimestamp { seconds: normal_time.timestamp(), nanos: 0 };
        let req = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, normal_ts, "d", Action::Read);
        let alerts = sentinel.analyze_request(&req);

        assert!(!alerts.iter().any(|a| a.alert_type == AlertType::UnusualTimingAccess),
                "UnusualTimingAccess alert triggered during normal hours");
    }

    #[test]
    fn test_timing_pattern_analysis_unusual_hours() {
        let mut sentinel = SentinelAgent::new();
        let key_pair = KeyPair::generate().unwrap();
        let requestor_id = "time_user_bad";

        // Timestamp outside typical hours (e.g., 3 AM UTC)
        let unusual_time = Utc::now().with_hour(3).unwrap();
        let unusual_ts = ProstTimestamp { seconds: unusual_time.timestamp(), nanos: 0 };
        let req = create_sentinel_test_request(&key_pair, PurposeCategory::Analytics, requestor_id, unusual_ts, "d", Action::Read);
        let alerts = sentinel.analyze_request(&req);

        assert!(alerts.iter().any(|a| a.alert_type == AlertType::UnusualTimingAccess),
                "UnusualTimingAccess alert missing for unusual hours");
    }

     #[test]
    fn test_semantic_violation_alert() {
         let mut sentinel = SentinelAgent::new();
         let key_pair = KeyPair::generate().unwrap();
         let requestor_id = "semantic_violator";

         // Create a semantically invalid request (e.g., Write action for Analytics purpose)
         let invalid_req = create_sentinel_test_request(
             &key_pair,
             PurposeCategory::Analytics, // Read only
             requestor_id,
             current_prost_timestamp(),
             "analytics_data",
             Action::Write, // Invalid action for Analytics
         );

         let alerts = sentinel.analyze_request(&invalid_req);

         // Should trigger SemanticViolation alert
         assert!(alerts.iter().any(|a| a.alert_type == AlertType::SemanticViolation),
                "SemanticViolation alert missing for invalid request");

         // Should ideally not trigger other history-based alerts if semantics fail early,
         // depending on implementation details (current implementation runs all checks).
         // For this test, we primarily care that SemanticViolation was caught.
    }
} 