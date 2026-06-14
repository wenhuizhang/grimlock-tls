// Minimal A2A-compatible agent for Grimlock demo
// This agent speaks plain HTTP - Grimlock provides the mTLS transparently
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// A2A Protocol Types (minimal subset)

// AgentCard describes the agent's capabilities (served at /.well-known/agent.json)
type AgentCard struct {
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	URL                string            `json:"url"`
	Version            string            `json:"version"`
	Capabilities       AgentCapabilities `json:"capabilities"`
	DefaultInputModes  []string          `json:"defaultInputModes"`
	DefaultOutputModes []string          `json:"defaultOutputModes"`
	Skills             []AgentSkill      `json:"skills"`
}

type AgentCapabilities struct {
	Streaming         bool `json:"streaming"`
	PushNotifications bool `json:"pushNotifications"`
}

type AgentSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Examples    []string `json:"examples,omitempty"`
}

// JSON-RPC types
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// A2A Message types
type MessageSendParams struct {
	Message Message `json:"message"`
}

type Message struct {
	Role  string `json:"role"`
	Parts []Part `json:"parts"`
}

type Part struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
}

type Task struct {
	ID        string     `json:"id"`
	ContextID string     `json:"contextId"`
	Status    TaskStatus `json:"status"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

type TaskStatus struct {
	State   string `json:"state"`
	Message *Message `json:"message,omitempty"`
}

type Artifact struct {
	ArtifactID string `json:"artifactId"`
	Name       string `json:"name,omitempty"`
	Parts      []Part `json:"parts"`
}

// Agent configuration
var (
	agentName = getEnv("AGENT_NAME", "demo-agent")
	agentPort = getEnv("AGENT_PORT", "8080")
	agentHost = getEnv("AGENT_HOST", "0.0.0.0")
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	
	log.Printf("Starting A2A Agent: %s", agentName)
	log.Printf("Agent Card: http://%s:%s/.well-known/agent.json", agentHost, agentPort)
	log.Printf("A2A Endpoint: http://%s:%s/a2a", agentHost, agentPort)
	log.Printf("NOTE: Running plain HTTP (no TLS configured)")
	log.Println("---")

	http.HandleFunc("/.well-known/agent.json", handleAgentCard)
	http.HandleFunc("/a2a", handleA2A)
	http.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf("%s:%s", agentHost, agentPort)
	log.Printf("Listening on %s", addr)
	
	if err := http.ListenAndServe(addr, logMiddleware(http.DefaultServeMux)); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// Middleware to log all requests
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf(">> %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("<< %s %s completed in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// GET /.well-known/agent.json - Agent Card discovery
func handleAgentCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the external URL (for the agent card)
	scheme := "http" // We intentionally use HTTP - Grimlock adds TLS
	host := r.Host
	if host == "" {
		host = fmt.Sprintf("localhost:%s", agentPort)
	}

	card := AgentCard{
		Name:        agentName,
		Description: fmt.Sprintf("Grimlock demo agent (%s). This agent demonstrates A2A communication secured by infrastructure-level mTLS.", agentName),
		URL:         fmt.Sprintf("%s://%s/a2a", scheme, host),
		Version:     "1.0.0",
		Capabilities: AgentCapabilities{
			Streaming:         false,
			PushNotifications: false,
		},
		DefaultInputModes:  []string{"text/plain", "application/json"},
		DefaultOutputModes: []string{"text/plain", "application/json"},
		Skills: []AgentSkill{
			{
				ID:          "echo",
				Name:        "Echo",
				Description: "Echoes back the received message (useful for testing)",
				Tags:        []string{"demo", "test"},
				Examples:    []string{"Hello, agent!", "Test message"},
			},
			{
				ID:          "info",
				Name:        "Agent Info",
				Description: "Returns information about this agent",
				Tags:        []string{"demo", "info"},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(card)
}

// POST /a2a - Handle A2A JSON-RPC requests
func handleA2A(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, nil, -32700, "Parse error", err.Error())
		return
	}

	log.Printf("   A2A Request: method=%s id=%v", req.Method, req.ID)

	switch req.Method {
	case "message/send":
		handleMessageSend(w, &req)
	default:
		sendError(w, req.ID, -32601, "Method not found", fmt.Sprintf("Unknown method: %s", req.Method))
	}
}

func handleMessageSend(w http.ResponseWriter, req *JSONRPCRequest) {
	var params MessageSendParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		sendError(w, req.ID, -32602, "Invalid params", err.Error())
		return
	}

	// Extract the text from the message
	var receivedText string
	for _, part := range params.Message.Parts {
		if part.Kind == "text" {
			receivedText = part.Text
			break
		}
	}

	log.Printf("   Received message: %q", receivedText)

	// Create response task with echo
	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	responseText := fmt.Sprintf("[%s] Received your message: %q", agentName, receivedText)

	task := Task{
		ID:        taskID,
		ContextID: fmt.Sprintf("ctx-%d", time.Now().UnixNano()),
		Status: TaskStatus{
			State: "completed",
		},
		Artifacts: []Artifact{
			{
				ArtifactID: "response-1",
				Name:       "Response",
				Parts: []Part{
					{Kind: "text", Text: responseText},
				},
			},
		},
	}

	log.Printf("   Responding with: %q", responseText)

	sendResult(w, req.ID, task)
}

// GET /health - Health check endpoint
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "healthy",
		"agent":  agentName,
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func sendResult(w http.ResponseWriter, id interface{}, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	})
}

func sendError(w http.ResponseWriter, id interface{}, code int, message, data string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	})
}
