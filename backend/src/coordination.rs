//! Coordination Service: Manages endpoint registration and message routing.
//! 
//! The coordination service provides a centralized registration and discovery 
//! mechanism for Pandacea agents, enabling them to find and communicate with
//! each other.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::interval;

use crate::communication::{AgentType, Endpoint, MessageRouter};
use crate::error::{MCPError, Result};
use crate::types::{McpRequest, McpResponse};

/// Configuration for the CoordinationService
#[derive(Debug, Clone)]
pub struct CoordinationServiceConfig {
    /// Address to bind the coordination service to
    pub bind_address: String,
    /// How often to purge stale endpoints (in seconds)
    pub cleanup_interval: u64,
    /// How long until an endpoint is considered stale (in seconds)
    pub endpoint_ttl: u64,
}

impl Default for CoordinationServiceConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:9090".to_string(),
            cleanup_interval: 60,
            endpoint_ttl: 300, // 5 minutes
        }
    }
}

/// Message type for internal coordination service communication
#[derive(Debug)]
enum CoordinationMessage {
    /// Register a new endpoint
    RegisterEndpoint {
        /// The endpoint to register
        endpoint: Endpoint,
        /// Channel to notify of registration result
        response: Sender<Result<()>>,
    },
    /// Unregister an endpoint
    UnregisterEndpoint {
        /// ID of the endpoint to unregister
        endpoint_id: String,
        /// Channel to notify of unregistration result
        response: Sender<Result<()>>,
    },
    /// Find endpoints by type
    FindEndpoints {
        /// Type of agent to look for
        agent_type: Option<AgentType>,
        /// Channel to send matching endpoints back on
        response: Sender<Result<Vec<Endpoint>>>,
    },
    /// Forward a request to an endpoint
    ForwardRequest {
        /// Target endpoint ID
        target_id: String,
        /// The request to forward
        request: McpRequest,
        /// Channel to send the response back on
        response: Sender<Result<McpResponse>>,
    },
    /// Heartbeat from an endpoint to keep it active
    Heartbeat {
        /// ID of the endpoint sending the heartbeat
        endpoint_id: String,
        /// Channel to notify of heartbeat result
        response: Sender<Result<()>>,
    },
}

/// A coordination service for the Pandacea network.
pub struct CoordinationService {
    /// Service configuration
    config: CoordinationServiceConfig,
    /// Message router for communication
    router: Arc<MessageRouter>,
    /// Channel for sending messages to the service
    message_sender: Sender<CoordinationMessage>,
    /// Registered endpoints with their last heartbeat time
    endpoints: Arc<Mutex<HashMap<String, (Endpoint, Instant)>>>,
}

impl CoordinationService {
    /// Create a new CoordinationService with default configuration.
    pub async fn new() -> Result<Self> {
        let config = CoordinationServiceConfig::default();
        Self::with_config(config).await
    }

    /// Create a new CoordinationService with custom configuration.
    pub async fn with_config(config: CoordinationServiceConfig) -> Result<Self> {
        // Initialize the message router for this coordination service
        let router = MessageRouter::new(
            "coordination-service".to_string(),
            "Pandacea Coordination Service".to_string(),
            AgentType::Hybrid,
        ).await?;

        let router = Arc::new(router);
        let endpoints = Arc::new(Mutex::new(HashMap::new()));
        
        // Set up message channels
        let (tx, rx) = mpsc::channel(100);

        let service = Self {
            config,
            router,
            message_sender: tx,
            endpoints,
        };

        service.start_worker(rx).await?;
        
        Ok(service)
    }

    /// Start the coordination service worker.
    async fn start_worker(&self, mut rx: Receiver<CoordinationMessage>) -> Result<()> {
        let endpoints = self.endpoints.clone();
        let router = self.router.clone();
        let config = self.config.clone();

        // Start the cleanup task
        let endpoints_cleanup = endpoints.clone();
        let cleanup_interval = config.cleanup_interval;
        let endpoint_ttl = config.endpoint_ttl;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(cleanup_interval));
            loop {
                interval.tick().await;
                Self::cleanup_stale_endpoints(endpoints_cleanup.clone(), endpoint_ttl).await;
            }
        });

        // Start the message processor
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    CoordinationMessage::RegisterEndpoint { endpoint, response } => {
                        let mut endpoints_guard = endpoints.lock().unwrap();
                        let endpoint_id = endpoint.id.clone();
                        
                        // Update or add the endpoint
                        endpoints_guard.insert(endpoint_id.clone(), (endpoint.clone(), Instant::now()));
                        
                        // Register with the router
                        drop(endpoints_guard);
                        let result = router.register_endpoint(endpoint);
                        let _ = response.send(result).await;
                    },
                    CoordinationMessage::UnregisterEndpoint { endpoint_id, response } => {
                        let mut endpoints_guard = endpoints.lock().unwrap();
                        endpoints_guard.remove(&endpoint_id);
                        drop(endpoints_guard);
                        
                        // Unregister from the router
                        let result = router.unregister_endpoint(&endpoint_id);
                        let _ = response.send(result).await;
                    },
                    CoordinationMessage::FindEndpoints { agent_type, response } => {
                        let endpoints_guard = endpoints.lock().unwrap();
                        let mut matching_endpoints = Vec::new();
                        
                        for (_, (endpoint, _)) in endpoints_guard.iter() {
                            if let Some(ref target_type) = agent_type {
                                if &endpoint.agent_type == target_type || endpoint.agent_type == AgentType::Hybrid {
                                    matching_endpoints.push(endpoint.clone());
                                }
                            } else {
                                matching_endpoints.push(endpoint.clone());
                            }
                        }
                        
                        drop(endpoints_guard);
                        let _ = response.send(Ok(matching_endpoints)).await;
                    },
                    CoordinationMessage::ForwardRequest { target_id, request, response } => {
                        // Forward the request using the router
                        let result = router.send_request(&target_id, request).await;
                        let _ = response.send(result).await;
                    },
                    CoordinationMessage::Heartbeat { endpoint_id, response } => {
                        let mut endpoints_guard = endpoints.lock().unwrap();
                        if let Some((_, timestamp)) = endpoints_guard.get_mut(&endpoint_id) {
                            *timestamp = Instant::now();
                            drop(endpoints_guard);
                            let _ = response.send(Ok(())).await;
                        } else {
                            drop(endpoints_guard);
                            let err = MCPError::CommunicationError {
                                context: format!("Unknown endpoint: {}", endpoint_id),
                                source: Box::new(std::io::Error::new(
                                    std::io::ErrorKind::NotFound,
                                    "Endpoint not found",
                                )),
                            };
                            let _ = response.send(Err(err)).await;
                        }
                    },
                }
            }
        });

        Ok(())
    }

    /// Clean up stale endpoints.
    async fn cleanup_stale_endpoints(endpoints: Arc<Mutex<HashMap<String, (Endpoint, Instant)>>>, ttl: u64) {
        let now = Instant::now();
        let mut endpoints_guard = endpoints.lock().unwrap();
        
        // Find stale endpoints
        let stale_keys: Vec<String> = endpoints_guard
            .iter()
            .filter(|(_, (_, timestamp))| {
                now.duration_since(*timestamp).as_secs() > ttl
            })
            .map(|(key, _)| key.clone())
            .collect();
        
        // Remove stale endpoints
        for key in stale_keys {
            endpoints_guard.remove(&key);
        }
    }

    /// Register an endpoint with the coordination service.
    pub async fn register_endpoint(&self, endpoint: Endpoint) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        
        self.message_sender
            .send(CoordinationMessage::RegisterEndpoint {
                endpoint,
                response: tx,
            })
            .await
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to send registration request: {}", e),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Channel send error",
                    )),
                }
            })?;
        
        rx.recv()
            .await
            .ok_or_else(|| {
                MCPError::CommunicationError {
                    context: "Response channel closed".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Channel closed",
                    )),
                }
            })?
    }

    /// Unregister an endpoint from the coordination service.
    pub async fn unregister_endpoint(&self, endpoint_id: &str) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        
        self.message_sender
            .send(CoordinationMessage::UnregisterEndpoint {
                endpoint_id: endpoint_id.to_string(),
                response: tx,
            })
            .await
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to send unregistration request: {}", e),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Channel send error",
                    )),
                }
            })?;
        
        rx.recv()
            .await
            .ok_or_else(|| {
                MCPError::CommunicationError {
                    context: "Response channel closed".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Channel closed",
                    )),
                }
            })?
    }

    /// Find endpoints by agent type.
    pub async fn find_endpoints(&self, agent_type: Option<AgentType>) -> Result<Vec<Endpoint>> {
        let (tx, mut rx) = mpsc::channel(1);
        
        self.message_sender
            .send(CoordinationMessage::FindEndpoints {
                agent_type,
                response: tx,
            })
            .await
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to send find endpoints request: {}", e),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Channel send error",
                    )),
                }
            })?;
        
        rx.recv()
            .await
            .ok_or_else(|| {
                MCPError::CommunicationError {
                    context: "Response channel closed".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Channel closed",
                    )),
                }
            })?
    }

    /// Send a request to an endpoint.
    pub async fn send_request(&self, target_id: &str, request: McpRequest) -> Result<McpResponse> {
        let (tx, mut rx) = mpsc::channel(1);
        
        self.message_sender
            .send(CoordinationMessage::ForwardRequest {
                target_id: target_id.to_string(),
                request,
                response: tx,
            })
            .await
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to send forward request: {}", e),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Channel send error",
                    )),
                }
            })?;
        
        rx.recv()
            .await
            .ok_or_else(|| {
                MCPError::CommunicationError {
                    context: "Response channel closed".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Channel closed",
                    )),
                }
            })?
    }

    /// Send a heartbeat to keep an endpoint registration active.
    pub async fn send_heartbeat(&self, endpoint_id: &str) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        
        self.message_sender
            .send(CoordinationMessage::Heartbeat {
                endpoint_id: endpoint_id.to_string(),
                response: tx,
            })
            .await
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to send heartbeat: {}", e),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Channel send error",
                    )),
                }
            })?;
        
        rx.recv()
            .await
            .ok_or_else(|| {
                MCPError::CommunicationError {
                    context: "Response channel closed".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Channel closed",
                    )),
                }
            })?
    }
    
    /// Get all registered endpoints.
    pub fn get_endpoints(&self) -> Vec<Endpoint> {
        let endpoints_guard = self.endpoints.lock().unwrap();
        endpoints_guard.values().map(|(endpoint, _)| endpoint.clone()).collect()
    }
    
    /// Get the message router.
    pub fn get_router(&self) -> Arc<MessageRouter> {
        self.router.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // TODO: Add tests for the CoordinationService
} 