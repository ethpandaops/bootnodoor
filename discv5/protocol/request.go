package protocol

import (
	"sync"
	"time"

	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
)

// DefaultRequestTimeout is the default timeout for requests (5 seconds).
const DefaultRequestTimeout = 5 * time.Second

// Common errors
var (
	ErrTimeout  = &ProtocolError{Code: "timeout", Message: "request timed out"}
	ErrCanceled = &ProtocolError{Code: "canceled", Message: "request canceled"}
)

// ProtocolError represents a protocol-level error.
type ProtocolError struct {
	Code    string
	Message string
}

func (e *ProtocolError) Error() string {
	return e.Message
}

// PendingRequest tracks an outgoing request waiting for a response.
type PendingRequest struct {
	// RequestID is the unique ID for this request
	RequestID []byte

	// NodeID is the target node
	NodeID node.ID

	// Timeout is when the request expires
	Timeout time.Time

	// ResponseChan receives the response or error
	ResponseChan chan *Response

	// Retries is the number of retry attempts
	Retries int

	// For multi-packet NODES responses
	ExpectedTotal    uint   // Total number of NODES packets expected
	ReceivedCount    uint   // Number of NODES packets received so far
	AccumulatedNodes *Nodes // Accumulated NODES message
}

// Response wraps a protocol message response.
type Response struct {
	// Message is the decoded response message
	Message Message

	// NodeID is the responding node
	NodeID node.ID

	// Error is set if the request failed
	Error error
}

// RequestTracker manages pending requests and matches responses.
type RequestTracker struct {
	// requests maps request ID to pending request
	requests map[string]*PendingRequest

	// timeout is the default request timeout
	timeout time.Duration

	// mu protects concurrent access
	mu sync.RWMutex

	// Stats
	totalRequests      int
	timedOutRequests   int
	successfulRequests int
}

// NewRequestTracker creates a new request tracker.
func NewRequestTracker(timeout time.Duration) *RequestTracker {
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}

	return &RequestTracker{
		requests: make(map[string]*PendingRequest),
		timeout:  timeout,
	}
}

// AddRequest registers a pending request.
//
// Returns a channel that will receive the response or timeout.
func (rt *RequestTracker) AddRequest(requestID []byte, nodeID node.ID, msgType byte) <-chan *Response {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()

	req := &PendingRequest{
		RequestID:    requestID,
		NodeID:       nodeID,
		Timeout:      now.Add(rt.timeout),
		ResponseChan: make(chan *Response, 1),
		Retries:      0,
	}

	// Use request ID as key
	key := string(requestID)
	rt.requests[key] = req
	rt.totalRequests++

	// Start timeout goroutine
	go rt.handleTimeout(key, req)

	return req.ResponseChan
}

// MatchResponse matches a response to a pending request.
//
// Returns true if the request was matched and notified.
func (rt *RequestTracker) MatchResponse(requestID []byte, nodeID node.ID, msg Message) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	key := string(requestID)
	req, exists := rt.requests[key]
	if !exists {
		return false
	}

	// Verify node ID matches
	if req.NodeID != nodeID {
		return false
	}

	// Handle multi-packet NODES responses
	if nodesMsg, ok := msg.(*Nodes); ok && nodesMsg.Total > 1 {
		// Initialize accumulator on first packet
		if req.AccumulatedNodes == nil {
			req.AccumulatedNodes = &Nodes{
				RequestID: nodesMsg.RequestID,
				Total:     nodesMsg.Total,
				Records:   make([]*enr.Record, 0),
			}
			req.ExpectedTotal = nodesMsg.Total
			req.ReceivedCount = 0
		}

		// Accumulate records from this packet
		req.AccumulatedNodes.Records = append(req.AccumulatedNodes.Records, nodesMsg.Records...)
		req.ReceivedCount++

		// If we haven't received all packets yet, keep waiting
		if req.ReceivedCount < req.ExpectedTotal {
			return true
		}

		// All packets received, send accumulated response
		msg = req.AccumulatedNodes
	}

	// Send response
	select {
	case req.ResponseChan <- &Response{
		Message: msg,
		NodeID:  nodeID,
		Error:   nil,
	}:
		rt.successfulRequests++
	default:
		// Channel is full or closed
	}

	// Remove from pending
	delete(rt.requests, key)
	close(req.ResponseChan)

	return true
}

// handleTimeout handles request timeout.
func (rt *RequestTracker) handleTimeout(key string, req *PendingRequest) {
	// Wait for timeout
	time.Sleep(time.Until(req.Timeout))

	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Check if still pending
	if _, exists := rt.requests[key]; !exists {
		return
	}

	// Send timeout error
	select {
	case req.ResponseChan <- &Response{
		Message: nil,
		NodeID:  req.NodeID,
		Error:   ErrTimeout,
	}:
	default:
	}

	rt.timedOutRequests++

	// Remove from pending
	delete(rt.requests, key)
	close(req.ResponseChan)
}

// CancelRequest cancels a pending request.
func (rt *RequestTracker) CancelRequest(requestID []byte) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	key := string(requestID)
	req, exists := rt.requests[key]
	if !exists {
		return
	}

	// Close channel and remove
	close(req.ResponseChan)
	delete(rt.requests, key)
}

// CleanupExpired removes expired requests.
//
// Returns the number of requests cleaned up.
func (rt *RequestTracker) CleanupExpired() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for key, req := range rt.requests {
		if now.After(req.Timeout) {
			toRemove = append(toRemove, key)
		}
	}

	for _, key := range toRemove {
		req := rt.requests[key]
		close(req.ResponseChan)
		delete(rt.requests, key)
	}

	return len(toRemove)
}

// GetStats returns statistics about requests.
type RequestStats struct {
	PendingRequests    int
	TotalRequests      int
	TimedOutRequests   int
	SuccessfulRequests int
	SuccessRate        float64
}

// GetStats returns request statistics.
func (rt *RequestTracker) GetStats() RequestStats {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	successRate := 0.0
	if rt.totalRequests > 0 {
		successRate = float64(rt.successfulRequests) / float64(rt.totalRequests) * 100
	}

	return RequestStats{
		PendingRequests:    len(rt.requests),
		TotalRequests:      rt.totalRequests,
		TimedOutRequests:   rt.timedOutRequests,
		SuccessfulRequests: rt.successfulRequests,
		SuccessRate:        successRate,
	}
}
