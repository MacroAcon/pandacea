//! Basic Communication Demo
//!
//! This example demonstrates a simplified version of the communication layer
//! without depending on the full MCP protocol implementation.

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::sleep;

/// A simplified message that can be sent between agents
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Message {
    id: String,
    sender: String,
    recipient: String,
    message_type: MessageType,
    payload: String,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum MessageType {
    Request,
    Response,
    Error,
}

impl Message {
    fn new_request(sender: &str, recipient: &str, payload: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            message_type: MessageType::Request,
            payload: payload.to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    fn new_response(request: &Message, payload: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender: request.recipient.clone(),
            recipient: request.sender.clone(),
            message_type: MessageType::Response,
            payload: payload.to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// A simple agent that can send and receive messages
struct Agent {
    id: String,
    name: String,
    address: SocketAddr,
    messages: Arc<Mutex<Vec<Message>>>,
}

impl Agent {
    fn new(id: &str, name: &str, port: u16) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn start(&self) -> Result<(), Box<dyn Error>> {
        println!("Agent {} starting at {}", self.name, self.address);
        
        let messages = self.messages.clone();
        let addr = self.address;
        let id = self.id.clone();
        let name = self.name.clone();
        
        // Start the listener
        tokio::spawn(async move {
            let listener = TcpListener::bind(addr).await.unwrap();
            println!("{} listening on {}", name, addr);
            
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let messages = messages.clone();
                        let id = id.clone();
                        let name = name.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, messages, &id, &name).await {
                                eprintln!("Error handling connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Error accepting connection: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }

    async fn send_message(&self, message: Message) -> Result<Message, Box<dyn Error>> {
        println!("{} sending message to {}: {:?}", self.name, message.recipient, message.payload);
        
        // Connect to the recipient
        let mut stream = TcpStream::connect(self.address).await?;
        
        // Serialize the message
        let message_data = serde_json::to_string(&message)?;
        let message_bytes = message_data.as_bytes();
        
        // Send the message length first (4 bytes)
        let len_bytes = (message_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        
        // Then send the message data
        stream.write_all(message_bytes).await?;
        
        // Read the response length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;
        
        // Read the response
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await?;
        
        // Deserialize the response
        let response: Message = serde_json::from_slice(&response_buf)?;
        
        // Store the response
        {
            let mut messages = self.messages.lock().await;
            messages.push(response.clone());
        }
        
        Ok(response)
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    messages: Arc<Mutex<Vec<Message>>>,
    agent_id: &str,
    agent_name: &str,
) -> Result<(), Box<dyn Error>> {
    // Read message length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let message_len = u32::from_be_bytes(len_buf) as usize;
    
    // Read message data
    let mut message_buf = vec![0u8; message_len];
    stream.read_exact(&mut message_buf).await?;
    
    // Deserialize the message
    let message: Message = serde_json::from_slice(&message_buf)?;
    
    println!("{} received message from {}: {:?}", agent_name, message.sender, message.payload);
    
    // Store the message
    {
        let mut messages_vec = messages.lock().await;
        messages_vec.push(message.clone());
    }
    
    // Create and send a response
    let response = Message::new_response(
        &message,
        &format!("Received your message: {}", message.payload),
    );
    
    // Serialize the response
    let response_data = serde_json::to_string(&response)?;
    let response_bytes = response_data.as_bytes();
    
    // Send the response length first
    let len_bytes = (response_bytes.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    
    // Then send the response data
    stream.write_all(response_bytes).await?;
    
    // Store the response
    {
        let mut messages_vec = messages.lock().await;
        messages_vec.push(response.clone());
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Basic Communication Demo ===");
    
    // Create agents
    let requestor = Agent::new("agent1", "Requestor Agent", 8081);
    let responder = Agent::new("agent2", "Responder Agent", 8082);
    
    // Start the agents
    requestor.start().await?;
    responder.start().await?;
    
    // Give the agents time to start
    sleep(Duration::from_millis(100)).await;
    
    // Send a message from requestor to responder
    let message = Message::new_request(
        &requestor.id,
        &responder.id,
        "Hello from the requestor! Can I access your data?",
    );
    
    println!("\n=== Sending test message ===");
    let response = requestor.send_message(message).await?;
    
    println!("\n=== Message exchange completed ===");
    println!("Response: {:?}", response.payload);
    
    // Display message history
    println!("\n=== Requestor message history ===");
    let requestor_messages = requestor.messages.lock().await;
    for (i, msg) in requestor_messages.iter().enumerate() {
        println!("{}. [{:?}] {} -> {}: {}", 
            i + 1, 
            msg.message_type, 
            msg.sender, 
            msg.recipient, 
            msg.payload
        );
    }
    
    println!("\n=== Demo completed successfully ===");
    
    // Keep the program running for a bit
    sleep(Duration::from_secs(1)).await;
    
    Ok(())
} 