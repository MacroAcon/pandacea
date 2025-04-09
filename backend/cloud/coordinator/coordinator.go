package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// --- Configuration ---

const (
	listenAddr = ":8080" // Address the coordinator listens on
)

// --- Discovery Registry (Simplified In-Memory) ---
// IMPORTANT: In a real system, this MUST be replaced with a distributed,
// persistent discovery service (e.g., etcd, Consul, Redis, database)
// to maintain statelessness of the coordinator instances and enable scaling/federation.
type DiscoveryRegistry struct {
	mu        sync.RWMutex // Read-Write mutex for concurrent access
	endpoints map[string]string // Map pseudonym_id -> network_address (e.g., "http://192.168.1.10:9090")
}

func NewDiscoveryRegistry() *DiscoveryRegistry {
	return &DiscoveryRegistry{
		endpoints: make(map[string]string),
	}
}

// Register adds or updates an endpoint address for a given ID.
func (r *DiscoveryRegistry) Register(id, address string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	log.Printf("Registering endpoint: ID=%s, Address=%s\n", id, address)
	r.endpoints[id] = address
}

// Discover retrieves the address for a given ID.
func (r *DiscoveryRegistry) Discover(id string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	address, found := r.endpoints[id]
	// TODO: Federation Hook: If not found locally, query peer coordinators.
	return address, found
}

// --- Coordinator Service ---

type Coordinator struct {
	registry *DiscoveryRegistry
	// TODO: Add configuration for peer coordinators for federation.
	// peerCoordinators []string
	httpClient *http.Client // Client for forwarding messages
}

func NewCoordinator() *Coordinator {
	return &Coordinator{
		registry: NewDiscoveryRegistry(),
		httpClient: &http.Client{
			Timeout: 10 * time.Second, // Example timeout for forwarding
		},
	}
}

// --- HTTP Handlers ---

// RegisterRequest is the expected JSON body for the /register endpoint.
type RegisterRequest struct {
	PseudonymID string `json:"pseudonym_id"`
	Address     string `json:"address"` // Network address (e.g., "http://host:port")
}

// handleRegister registers an endpoint.
// Expects POST request with JSON body: {"pseudonym_id": "...", "address": "..."}
func (c *Coordinator) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Bad Request: Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if req.PseudonymID == "" || req.Address == "" {
		http.Error(w, "Bad Request: pseudonym_id and address are required", http.StatusBadRequest)
		return
	}

	// Basic validation (a real system needs more robust address validation)
	if !(len(req.Address) > 7 && (req.Address[:7] == "http://" || req.Address[:8] == "https://")) {
		log.Printf("Warning: Registering potentially invalid address format: %s", req.Address)
		// Allow for now, but could reject here.
	}


c.registry.Register(req.PseudonymID, req.Address)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Endpoint registered successfully")
}

// handleDiscover looks up an endpoint address.
// Expects GET request like /discover/{pseudonym_id}
func (c *Coordinator) handleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from path (simple example, needs more robust routing/parsing)
	id := r.URL.Path[len("/discover/"):]
	if id == "" {
		http.Error(w, "Bad Request: Missing pseudonym_id in path", http.StatusBadRequest)
		return
	}

	address, found := c.registry.Discover(id)
	if !found {
		// TODO: Federation Hook: If not found locally, query peers before returning 404.
		// Example:
		// for _, peer := range c.peerCoordinators {
		//    addr, peerFound := queryPeer(peer, id)
		//    if peerFound { address = addr; found = true; break; }
		// }
		// if !found { ... return 404 ... }

		http.Error(w, fmt.Sprintf("Not Found: Endpoint ID '%s' not registered", id), http.StatusNotFound)
		return
	}

	response := map[string]string{"pseudonym_id": id, "address": address}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding discovery response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// RouteRequest is the expected JSON body for the /route endpoint.
type RouteRequest struct {
	TargetPseudonymID string `json:"target_pseudonym_id"`
	MCPMessageBytes   []byte `json:"mcp_message_bytes"` // Base64 encoding might be better for JSON
}

// handleRoute receives an MCP message and forwards it to the target.
// Expects POST request with JSON body: {"target_pseudonym_id": "...", "mcp_message_bytes": <byte_array>}
// NOTE: This assumes the message is opaque bytes. No MCP validation is done here.
func (c *Coordinator) handleRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RouteRequest
	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit example

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Bad Request: Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if req.TargetPseudonymID == "" || len(req.MCPMessageBytes) == 0 {
		http.Error(w, "Bad Request: target_pseudonym_id and mcp_message_bytes are required", http.StatusBadRequest)
		return
	}

	// 1. Discover the target address
	targetAddress, found := c.registry.Discover(req.TargetPseudonymID)
	if !found {
		// TODO: Federation Hook: Query peers if not found locally.
		http.Error(w, fmt.Sprintf("Not Found: Target endpoint ID '%s' not registered", req.TargetPseudonymID), http.StatusNotFound)
		return
	}

	// 2. Forward the message (Simulated - just POSTs the raw bytes)
	// A real system might use gRPC or another protocol, and potentially add metadata.
	// The target endpoint needs to know how to handle these raw bytes.
	// Content-Type is set to protobuf, adjust if needed.
	forwardReq, err := http.NewRequest(http.MethodPost, targetAddress+"/mcp", bytes.NewReader(req.MCPMessageBytes))
	if err != nil {
		log.Printf("Error creating forward request: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	forwardReq.Header.Set("Content-Type", "application/protobuf") // Or application/octet-stream
	// TODO: Add headers for tracing, source identification, federation hops, etc.

	log.Printf("Routing message to %s (%s)", req.TargetPseudonymID, targetAddress)
	forwardResp, err := c.httpClient.Do(forwardReq)
	if err != nil {
		log.Printf("Error forwarding message to %s: %v", targetAddress, err)
		http.Error(w, "Bad Gateway: Failed to forward message to target", http.StatusBadGateway)
		return
	}
	defer forwardResp.Body.Close()

	// 3. Relay the response back to the original caller
	log.Printf("Received response from target %s: Status %d", targetAddress, forwardResp.StatusCode)
	// Copy headers from the target's response
	for key, values := range forwardResp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	// Set the status code from the target's response
	w.WriteHeader(forwardResp.StatusCode)
	// Copy the body from the target's response
	if _, err := io.Copy(w, forwardResp.Body); err != nil {
		log.Printf("Error relaying response body: %v", err)
		// Don't write another error header if already written
	}
}

// handleAuditSync (Placeholder) - Handles Audit Twin synchronization requests.
// A real implementation would involve receiving cryptographic summaries,
// comparing them (potentially with other nodes in federation), and storing/flagging discrepancies.
func (c *Coordinator) handleAuditSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// Placeholder: Read body, log, return OK
	bodyBytes, _ := io.ReadAll(r.Body)
	log.Printf("Received Audit Sync request (length: %d bytes) - Placeholder", len(bodyBytes))

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Audit Sync received (Placeholder)")

	// TODO: Implement actual Audit Twin comparison and storage/flagging logic.
	// This might involve interacting with a persistent store or other federated nodes.
}

// handleFederation (Placeholder) - Manages peering with other coordinators.
func (c *Coordinator) handleFederation(w http.ResponseWriter, r *http.Request) {
	// Placeholder for adding/removing/querying peer coordinators
	log.Printf("Received Federation request - Placeholder")
	http.Error(w, "Not Implemented", http.StatusNotImplemented)
	// TODO: Implement federation handshake, peer list management, etc.
}


// --- Main Function ---

func main() {
	coordinator := NewCoordinator()

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/register", coordinator.handleRegister)
	mux.HandleFunc("/discover/", coordinator.handleDiscover) // Note trailing slash for path matching
	mux.HandleFunc("/route", coordinator.handleRoute)
	mux.HandleFunc("/sync/audit", coordinator.handleAuditSync) // Placeholder
	mux.HandleFunc("/federate/", coordinator.handleFederation) // Placeholder

	log.Printf("Starting Pandacea Cloud Coordinator on %s\n", listenAddr)
	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
		// Add timeouts for production
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v\n", listenAddr, err)
	}
} 