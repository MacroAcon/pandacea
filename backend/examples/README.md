# Pandacea Examples

This directory contains examples demonstrating how to use the Pandacea MCP library.

## Agent Communication Demo

The `agent_communication.rs` example demonstrates a basic communication setup between a requestor agent and a responder agent using the Pandacea communication layer and the MCP protocol.

### Features Demonstrated

- Setting up a coordination service for endpoint discovery
- Creating requestor and responder agents
- Establishing secure communication channels
- Sending and processing MCP requests
- Consent evaluation via the ConsentManager
- End-to-end message exchange

### Running the Example

```bash
cargo run --example agent_communication
```

### Expected Output

```
=== Pandacea Agent Communication Demo ===
Responder responder-1 starting to listen for requests
Starting consent manager request listener for endpoint: responder-1

=== Listing registered endpoints ===
Endpoint: Requestor Agent requestor-1 (requestor-1)
Endpoint: Responder Agent responder-1 (responder-1)

=== Sending test request ===
Request ID: f8f05124-daa7-4fe1-8e64-ac5268d7e87c
Response status: Some(1)

=== Demo completed successfully ===
```

### Implementation Notes

This is a simulated example that demonstrates the architecture and API, but does not actually send network messages. In a real deployment:

1. The agents would run on different machines or containers
2. TLS certificates would be properly set up
3. The coordination service would run on a dedicated server
4. The message router would establish real network connections

## Consent Manager Demo

The `consent_manager_demo.rs` example demonstrates how to use the ConsentManager to evaluate MCP requests against consent rules.

### Running the Example

```bash
cargo run --example consent_manager_demo
``` 