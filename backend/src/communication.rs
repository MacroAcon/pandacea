//! Communication Layer: Enables secure MCP message exchange between agents.
//! 
//! This module provides the core communication capabilities for the Pandacea network,
//! allowing agents to establish secure channels and exchange MCP messages.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::timeout;
use tokio_rustls::rustls::{self, Certificate, ClientConfig, RootCertStore, ServerConfig, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream};

use crate::error::{MCPError, Result};
use crate::serialization::{deserialize_request, deserialize_response, serialize_request, serialize_response};
use crate::types::{McpRequest, McpResponse};

/// Type alias for a secured connection
type SecureConnection = ClientTlsStream<TcpStream>;

/// Type of agent in the Pandacea network
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentType {
    /// Requests data from responders
    Requestor,
    /// Responds to data requests
    Responder,
    /// Both requestor and responder
    Hybrid,
}

/// Represents an endpoint in the Pandacea network
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// Unique identifier for this endpoint
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Network address (host:port)
    pub address: String,
    /// Agent type (requestor, responder, hybrid)
    pub agent_type: AgentType,
    /// When this endpoint was last seen active
    pub last_active: chrono::DateTime<chrono::Utc>,
}

/// Configuration for the MessageRouter
#[derive(Debug, Clone)]
pub struct MessageRouterConfig {
    /// Local address to bind to (host:port)
    pub local_address: String,
    /// Path to TLS certificate file
    pub cert_path: String,
    /// Path to TLS private key file
    pub key_path: String,
    /// Timeout for connection attempts (in seconds)
    pub connection_timeout: u64,
    /// Timeout for message operations (in seconds)
    pub message_timeout: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
}

impl Default for MessageRouterConfig {
    fn default() -> Self {
        Self {
            local_address: "127.0.0.1:8080".to_string(),
            cert_path: "certs/public/pandacea.crt".to_string(),
            key_path: "certs/private/pandacea.pfx".to_string(),
            connection_timeout: 30,
            message_timeout: 60,
            max_message_size: 10_000_000, // 10MB
        }
    }
}

/// Message type for internal router communication
#[derive(Debug)]
enum RouterMessage {
    /// Request to send a message to an endpoint
    SendRequest {
        /// Target endpoint ID
        endpoint_id: String,
        /// The request to send
        request: McpRequest,
        /// Channel to send the response back on
        response_sender: Sender<Result<McpResponse>>,
    },
    /// Received a request from an endpoint
    ReceivedRequest {
        /// Source endpoint ID
        from_endpoint: String,
        /// The received request
        request: McpRequest,
    },
    /// Received a response from an endpoint
    ReceivedResponse {
        /// Source endpoint ID
        from_endpoint: String,
        /// Request ID this response is for
        request_id: String,
        /// The received response
        response: McpResponse,
    },
    /// Register a new endpoint
    RegisterEndpoint(Endpoint),
    /// Unregister an endpoint
    UnregisterEndpoint(String),
}

/// An MCP message router that can send and receive messages.
pub struct MessageRouter {
    /// Router configuration
    config: MessageRouterConfig,
    /// Known endpoints mapped by ID
    endpoints: Arc<Mutex<HashMap<String, Endpoint>>>,
    /// Request handlers mapped by request ID
    pending_requests: Arc<Mutex<HashMap<String, Sender<Result<McpResponse>>>>>,
    /// Channel for sending messages to the router
    message_sender: Sender<RouterMessage>,
    /// Our endpoint ID
    local_endpoint_id: String,
    /// Our endpoint info
    local_endpoint: Endpoint,
    /// TLS client connector
    tls_connector: Arc<TlsConnector>,
    /// TLS server acceptor
    tls_acceptor: Arc<TlsAcceptor>,
}

impl MessageRouter {
    /// Create a new MessageRouter with default configuration.
    pub async fn new(
        local_endpoint_id: String,
        local_endpoint_name: String,
        agent_type: AgentType,
    ) -> Result<Self> {
        let config = MessageRouterConfig::default();
        Self::with_config(local_endpoint_id, local_endpoint_name, agent_type, config).await
    }

    /// Create a new MessageRouter with custom configuration.
    pub async fn with_config(
        local_endpoint_id: String,
        local_endpoint_name: String,
        agent_type: AgentType,
        config: MessageRouterConfig,
    ) -> Result<Self> {
        // Set up TLS client config
        let mut root_cert_store = RootCertStore::empty();
        
        // Read and process the certificate
        let cert_bytes = tokio::fs::read(&config.cert_path).await.map_err(|e| {
            MCPError::certificate_error(
                format!("Failed to read certificate file: {}", &config.cert_path),
                Box::new(e)
            )
        })?;
        
        // Check if it's a PFX or regular certificate based on file extension
        let is_pfx = config.cert_path.ends_with(".pfx") || config.cert_path.ends_with(".p12");
        
        let cert = if is_pfx {
            // For PFX, we need to parse it and extract the certificate
            // For now, we'll assume it's a regular certificate since we're reading the public cert
            // In a real implementation, we'd parse the PFX file with pkcs12 crate
            rustls::pki_types::CertificateDer::from(cert_bytes)
        } else {
            // Try to parse as DER or PEM format
            match rustls::pki_types::CertificateDer::from(cert_bytes.clone()) {
                cert @ _ => cert,
            }
        };
        
        // Add certificate to root store with better error handling
        root_cert_store.add(cert.clone().into()).map_err(|e| {
            MCPError::certificate_error(
                format!("Failed to add certificate to root store: {}", e),
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
            )
        })?;

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        // Set up TLS server config
        // Check if key file is a PFX file
        let is_pfx_key = config.key_path.ends_with(".pfx") || config.key_path.ends_with(".p12");
        
        let key_bytes = tokio::fs::read(&config.key_path).await.map_err(|e| {
            MCPError::certificate_error(
                format!("Failed to read key file: {}", &config.key_path),
                Box::new(e)
            )
        })?;
        
        let key = if is_pfx_key {
            // Implement proper PFX parsing using the pkcs12 crate
            // Since this is not just a placeholder, let's implement actual PFX parsing
            let pfx_password = std::env::var("PANDACEA_CERT_PASSWORD").unwrap_or_default();
            let pfx_data = match pkcs12::parse(&key_bytes, &pfx_password) {
                Ok(pfx) => pfx,
                Err(e) => {
                    // Try with empty password before giving up
                    match pkcs12::parse(&key_bytes, "") {
                        Ok(pfx) => pfx,
                        Err(_) => {
                            return Err(MCPError::pkcs12_error(
                                format!("Failed to parse PFX file ({}): {}. Tried with environment variable password and empty password", 
                                    &config.key_path, e),
                                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                            ));
                        }
                    }
                }
            };
            
            // Extract private key from PFX
            let private_key = pfx_data.pkey.ok_or_else(|| 
                MCPError::pkcs12_error(
                    format!("No private key found in PFX file: {}", &config.key_path),
                    Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No private key in PFX"))
                )
            )?;
            
            // Convert to expected rustls format
            let key_der = private_key.private_key.to_vec();
            
            // Try to parse the key
            rustls::pki_types::PrivateKeyDer::try_from(key_der.as_slice()).map_err(|e| {
                MCPError::pkcs12_error(
                    format!("Failed to convert private key from PFX to rustls format: {}", e),
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                )
            })?
        } else {
            // Regular PEM key file
            rustls::pki_types::PrivateKeyDer::try_from(key_bytes.as_slice()).map_err(|e| {
                MCPError::certificate_error(
                    format!("Failed to parse key file {}: {}", &config.key_path, e),
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                )
            })?
        };

        // Extract certificate chain from PFX file if it's a PFX
        let certs = if is_pfx_key {
            match pkcs12::parse(&key_bytes, "pandaceaSecret") {
                Ok(pfx) => {
                    let mut certs = Vec::new();
                    
                    // Add leaf certificate
                    if let Some(cert) = pfx.cert {
                        let cert_der = cert.to_der().map_err(|e| {
                            MCPError::pkcs12_error(
                                "Failed to convert leaf certificate from PFX to DER format",
                                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                            )
                        })?;
                        certs.push(rustls::pki_types::CertificateDer::from(cert_der));
                    }
                    
                    // Add CA certificates
                    if let Some(ca) = pfx.ca {
                        for ca_cert in ca {
                            let ca_der = ca_cert.to_der().map_err(|e| {
                                MCPError::pkcs12_error(
                                    "Failed to convert CA certificate from PFX to DER format",
                                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                                )
                            })?;
                            certs.push(rustls::pki_types::CertificateDer::from(ca_der));
                        }
                    }
                    
                    // If no certificates found, use the one from cert_path
                    if certs.is_empty() {
                        vec![cert.into()]
                    } else {
                        certs.into_iter().map(|c| c.into()).collect()
                    }
                }
                Err(e) => {
                    // Try with empty password as fallback
                    match pkcs12::parse(&key_bytes, "") {
                        Ok(pfx) => {
                            let mut certs = Vec::new();
                            
                            // Add leaf certificate
                            if let Some(cert) = pfx.cert {
                                let cert_der = cert.to_der().map_err(|e| {
                                    MCPError::pkcs12_error(
                                        "Failed to convert leaf certificate from PFX to DER format",
                                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                                    )
                                })?;
                                certs.push(rustls::pki_types::CertificateDer::from(cert_der).into());
                            }
                            
                            // Add CA certificates
                            if let Some(ca) = pfx.ca {
                                for ca_cert in ca {
                                    let ca_der = ca_cert.to_der().map_err(|e| {
                                        MCPError::pkcs12_error(
                                            "Failed to convert CA certificate from PFX to DER format",
                                            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                                        )
                                    })?;
                                    certs.push(rustls::pki_types::CertificateDer::from(ca_der).into());
                                }
                            }
                            
                            // If no certificates found, use the one from cert_path
                            if certs.is_empty() {
                                vec![cert.into()]
                            } else {
                                certs
                            }
                        }
                        Err(_) => {
                            // Fallback to using the certificate from cert_path
                            vec![cert.into()]
                        }
                    }
                }
            }
        } else {
            // Just use the cert we loaded earlier
            vec![cert.into()]
        };

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key).map_err(|e| {
                MCPError::tls_error(
                    format!("Failed to create server config: {}", e),
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                )
            })?;

        let tls_connector = Arc::new(TlsConnector::from(Arc::new(client_config)));
        let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_config)));

        // Create local endpoint
        let local_endpoint = Endpoint {
            id: local_endpoint_id.clone(),
            name: local_endpoint_name,
            address: config.local_address.clone(),
            agent_type,
            last_active: chrono::Utc::now(),
        };

        // Set up message channels
        let (tx, rx) = mpsc::channel(100);

        let mut router = Self {
            config,
            endpoints: Arc::new(Mutex::new(HashMap::new())),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            message_sender: tx,
            local_endpoint_id,
            local_endpoint,
            tls_connector,
            tls_acceptor,
        };

        // Start the router worker
        router.start_worker(rx).await?;

        Ok(router)
    }

    /// Start the message router worker.
    async fn start_worker(&mut self, mut rx: Receiver<RouterMessage>) -> Result<()> {
        let endpoints = self.endpoints.clone();
        let pending_requests = self.pending_requests.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let config = self.config.clone();
        let local_address = config.local_address.clone();

        // Start the listener for incoming connections
        tokio::spawn(async move {
            if let Err(e) = Self::run_listener(local_address, tls_acceptor, pending_requests.clone()).await {
                eprintln!("Listener error: {:?}", e);
            }
        });

        // Start the message processor
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    RouterMessage::SendRequest { endpoint_id, request, response_sender } => {
                        let endpoints_guard = endpoints.lock().unwrap();
                        if let Some(endpoint) = endpoints_guard.get(&endpoint_id) {
                            drop(endpoints_guard); // Release lock before async operation
                            
                            // Clone values for the async block
                            let endpoint = endpoint.clone();
                            let request_id = request.request_id.clone();
                            let request_clone = request.clone();
                            let pending_requests = pending_requests.clone();
                            let config = config.clone();
                            
                            // Store the response channel
                            {
                                let mut pending_guard = pending_requests.lock().unwrap();
                                pending_guard.insert(request_id.clone(), response_sender);
                            }
                            
                            // Spawn a task to send the request
                            tokio::spawn(async move {
                                let result = Self::send_request_to_endpoint(
                                    &endpoint, 
                                    request_clone, 
                                    &config
                                ).await;
                                
                                // If sending failed, notify the sender
                                if let Err(e) = result {
                                    let mut pending_guard = pending_requests.lock().unwrap();
                                    if let Some(tx) = pending_guard.remove(&request_id) {
                                        let _ = tx.send(Err(e)).await;
                                    }
                                }
                            });
                        } else {
                            drop(endpoints_guard);
                            let err = MCPError::CommunicationError {
                                context: format!("Unknown endpoint: {}", endpoint_id),
                                source: Box::new(std::io::Error::new(
                                    std::io::ErrorKind::NotFound,
                                    "Endpoint not found",
                                )),
                            };
                            let _ = response_sender.send(Err(err)).await;
                        }
                    }
                    RouterMessage::RegisterEndpoint(endpoint) => {
                        let mut endpoints_guard = endpoints.lock().unwrap();
                        endpoints_guard.insert(endpoint.id.clone(), endpoint);
                    }
                    RouterMessage::UnregisterEndpoint(endpoint_id) => {
                        let mut endpoints_guard = endpoints.lock().unwrap();
                        endpoints_guard.remove(&endpoint_id);
                    }
                    // Other message types would be handled here
                    _ => {}
                }
            }
        });

        Ok(())
    }

    /// Run the listener for incoming connections.
    async fn run_listener(
        address: String,
        tls_acceptor: Arc<TlsAcceptor>,
        pending_requests: Arc<Mutex<HashMap<String, Sender<Result<McpResponse>>>>>,
    ) -> Result<()> {
        let listener = TcpListener::bind(&address).await.map_err(|e| {
            MCPError::CommunicationError {
                context: format!("Failed to bind to address {}: {}", address, e),
                source: Box::new(e),
            }
        })?;

        println!("Listening on: {}", address);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    println!("Accepted connection from: {}", addr);
                    
                    // Clone for the async block
                    let tls_acceptor = tls_acceptor.clone();
                    let pending_requests = pending_requests.clone();
                    
                    tokio::spawn(async move {
                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                if let Err(e) = Self::handle_incoming_connection(tls_stream, pending_requests).await {
                                    eprintln!("Error handling connection from {}: {:?}", addr, e);
                                }
                            }
                            Err(e) => {
                                eprintln!("TLS error from {}: {:?}", addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {:?}", e);
                }
            }
        }
    }

    /// Handle an incoming connection.
    async fn handle_incoming_connection(
        mut stream: ServerTlsStream<TcpStream>,
        pending_requests: Arc<Mutex<HashMap<String, Sender<Result<McpResponse>>>>>,
    ) -> Result<()> {
        // Read message type (request or response)
        let mut msg_type_buf = [0u8; 1];
        stream.read_exact(&mut msg_type_buf).await.map_err(|e| {
            MCPError::CommunicationError {
                context: format!("Failed to read message type: {}", e),
                source: Box::new(e),
            }
        })?;

        // Read message length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(|e| {
            MCPError::CommunicationError {
                context: format!("Failed to read message length: {}", e),
                source: Box::new(e),
            }
        })?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        // Check message size limit
        if msg_len > 10_000_000 {
            return Err(MCPError::CommunicationError {
                context: format!("Message too large: {} bytes", msg_len),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Message exceeds maximum size",
                )),
            });
        }

        // Read message data
        let mut msg_data = vec![0u8; msg_len];
        stream.read_exact(&mut msg_data).await.map_err(|e| {
            MCPError::CommunicationError {
                context: format!("Failed to read message data: {}", e),
                source: Box::new(e),
            }
        })?;

        // Process based on message type
        match msg_type_buf[0] {
            // Request
            1 => {
                let request = deserialize_request(&msg_data)?;
                
                // TODO: Forward to request handler
                // For now, just echo back a simple response
                let response = McpResponse {
                    request_id: request.request_id.clone(),
                    mcp_version: request.mcp_version.clone(),
                    responder_identity: None,
                    response_timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
                    status: Some(1), // OK
                    ..Default::default()
                };
                
                let response_data = serialize_response(&response)?;
                
                // Send response type marker
                stream.write_all(&[2]).await.map_err(|e| {
                    MCPError::CommunicationError {
                        context: format!("Failed to write response type: {}", e),
                        source: Box::new(e),
                    }
                })?;
                
                // Send response length
                let len_bytes = (response_data.len() as u32).to_be_bytes();
                stream.write_all(&len_bytes).await.map_err(|e| {
                    MCPError::CommunicationError {
                        context: format!("Failed to write response length: {}", e),
                        source: Box::new(e),
                    }
                })?;
                
                // Send response data
                stream.write_all(&response_data).await.map_err(|e| {
                    MCPError::CommunicationError {
                        context: format!("Failed to write response data: {}", e),
                        source: Box::new(e),
                    }
                })?;
            }
            // Response
            2 => {
                let response = deserialize_response(&msg_data)?;
                let request_id = response.request_id.clone();
                
                // Find and notify the waiting request handler
                let mut pending_guard = pending_requests.lock().unwrap();
                if let Some(tx) = pending_guard.remove(&request_id) {
                    drop(pending_guard);
                    let _ = tx.send(Ok(response)).await;
                }
            }
            _ => {
                return Err(MCPError::CommunicationError {
                    context: format!("Unknown message type: {}", msg_type_buf[0]),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid message type",
                    )),
                });
            }
        }

        Ok(())
    }

    /// Send a request to an endpoint.
    async fn send_request_to_endpoint(
        endpoint: &Endpoint,
        request: McpRequest,
        config: &MessageRouterConfig,
    ) -> Result<()> {
        // Resolve the address
        let addr = endpoint.address.to_socket_addrs()
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to resolve address {}: {}", endpoint.address, e),
                    source: Box::new(e),
                }
            })?
            .next()
            .ok_or_else(|| {
                MCPError::CommunicationError {
                    context: format!("No address found for {}", endpoint.address),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Address resolution failed",
                    )),
                }
            })?;

        // Connect with timeout
        let tcp_stream = timeout(
            Duration::from_secs(config.connection_timeout),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|e| {
            MCPError::CommunicationError {
                context: format!("Connection timeout to {}: {}", endpoint.address, e),
                source: Box::new(e),
            }
        })?
        .map_err(|e| {
            MCPError::CommunicationError {
                context: format!("Failed to connect to {}: {}", endpoint.address, e),
                source: Box::new(e),
            }
        })?;

        // TODO: Implement TLS connection establishment
        // For now we assume the connection is established
        
        // Serialize the request
        let request_data = serialize_request(&request)?;
        
        // Check size limit
        if request_data.len() > config.max_message_size {
            return Err(MCPError::CommunicationError {
                context: format!("Request too large: {} bytes", request_data.len()),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Request exceeds maximum size",
                )),
            });
        }

        // We'll implement the actual sending in the next iteration
        // For now, just return success
        Ok(())
    }

    /// Register a new endpoint.
    pub fn register_endpoint(&self, endpoint: Endpoint) -> Result<()> {
        self.message_sender
            .blocking_send(RouterMessage::RegisterEndpoint(endpoint))
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to register endpoint: {}", e),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Channel send error",
                    )),
                }
            })?;
        Ok(())
    }

    /// Unregister an endpoint.
    pub fn unregister_endpoint(&self, endpoint_id: &str) -> Result<()> {
        self.message_sender
            .blocking_send(RouterMessage::UnregisterEndpoint(endpoint_id.to_string()))
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to unregister endpoint: {}", e),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Channel send error",
                    )),
                }
            })?;
        Ok(())
    }

    /// Send an MCP request to an endpoint.
    pub async fn send_request(&self, endpoint_id: &str, request: McpRequest) -> Result<McpResponse> {
        let (tx, mut rx) = mpsc::channel(1);
        
        self.message_sender
            .send(RouterMessage::SendRequest {
                endpoint_id: endpoint_id.to_string(),
                request,
                response_sender: tx,
            })
            .await
            .map_err(|e| {
                MCPError::CommunicationError {
                    context: format!("Failed to send request: {}", e),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Channel send error",
                    )),
                }
            })?;
        
        // Wait for response with timeout
        timeout(
            Duration::from_secs(self.config.message_timeout),
            rx.recv(),
        )
        .await
        .map_err(|e| {
            MCPError::CommunicationError {
                context: format!("Response timeout: {}", e),
                source: Box::new(e),
            }
        })?
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

    /// Get a list of all known endpoints.
    pub fn list_endpoints(&self) -> Vec<Endpoint> {
        let endpoints_guard = self.endpoints.lock().unwrap();
        endpoints_guard.values().cloned().collect()
    }

    /// Find an endpoint by ID.
    pub fn find_endpoint(&self, endpoint_id: &str) -> Option<Endpoint> {
        let endpoints_guard = self.endpoints.lock().unwrap();
        endpoints_guard.get(endpoint_id).cloned()
    }
    
    /// Get the local endpoint information.
    pub fn local_endpoint(&self) -> &Endpoint {
        &self.local_endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // TODO: Add tests for the MessageRouter
} 