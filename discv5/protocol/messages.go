// Package protocol implements the discv5 wire protocol message types and codec.
//
// The discv5 protocol defines several message types for node discovery:
//   - PING/PONG: Liveness checks
//   - FINDNODE/NODES: Peer discovery
//   - TALKREQ/TALKRESP: Generic request/response
//   - REGTOPIC/TICKET/REGCONFIRMATION: Topic registration
//   - TOPICQUERY: Topic-based discovery
//
// All messages are RLP-encoded and encrypted using session keys.
package protocol

import (
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethpandaops/bootnodoor/crypto"
	"github.com/ethpandaops/bootnodoor/enr"
)

// Message type constants for discv5 protocol
const (
	// PingMsg is sent to check if a node is alive
	PingMsg byte = 0x01

	// PongMsg is the response to PING
	PongMsg byte = 0x02

	// FindNodeMsg requests nodes at a given distance
	FindNodeMsg byte = 0x03

	// NodesMsg is the response to FINDNODE, containing discovered nodes
	NodesMsg byte = 0x04

	// TalkReqMsg is a generic application-level request
	TalkReqMsg byte = 0x05

	// TalkRespMsg is the response to TALKREQ
	TalkRespMsg byte = 0x06

	// RegTopicMsg registers interest in a topic (optional extension)
	RegTopicMsg byte = 0x07

	// TicketMsg provides a ticket for topic registration (optional extension)
	TicketMsg byte = 0x08

	// RegConfirmationMsg confirms topic registration (optional extension)
	RegConfirmationMsg byte = 0x09

	// TopicQueryMsg queries for nodes on a topic (optional extension)
	TopicQueryMsg byte = 0x0A
)

// Message is the interface implemented by all discv5 messages.
type Message interface {
	// Type returns the message type byte
	Type() byte

	// Encode returns the RLP encoding of the message
	Encode() ([]byte, error)
}

// Ping is sent to check if a node is alive.
//
// The ping message includes the sender's ENR sequence number,
// allowing the recipient to request an updated ENR if needed.
//
// Format: [request-id, enr-seq]
type Ping struct {
	// RequestID is a unique identifier for matching request/response pairs
	RequestID []byte

	// ENRSeq is the sender's current ENR sequence number
	ENRSeq uint64
}

// Type returns the message type
func (p *Ping) Type() byte {
	return PingMsg
}

// Encode returns the RLP encoding of the PING message
func (p *Ping) Encode() ([]byte, error) {
	return encodeMessage(PingMsg, []interface{}{p.RequestID, p.ENRSeq})
}

// Pong is the response to a PING message.
//
// It echoes back the request ID and includes the responder's
// ENR sequence number and IP/port information.
//
// Format: [request-id, enr-seq, ip, port]
type Pong struct {
	// RequestID matches the request ID from the PING
	RequestID []byte

	// ENRSeq is the responder's current ENR sequence number
	ENRSeq uint64

	// IP is the responder's IP address as seen by the recipient
	IP []byte

	// Port is the responder's UDP port
	Port uint16
}

// Type returns the message type
func (p *Pong) Type() byte {
	return PongMsg
}

// Encode returns the RLP encoding of the PONG message
func (p *Pong) Encode() ([]byte, error) {
	return encodeMessage(PongMsg, []interface{}{p.RequestID, p.ENRSeq, p.IP, p.Port})
}

// FindNode requests nodes at a specific distance from the target.
//
// The distance is specified as a list of logarithmic distances
// (bucket indices). A distance of [256] means "all nodes", while
// specific distances like [253, 254, 255] request nodes in those buckets.
//
// Format: [request-id, [distance1, distance2, ...]]
type FindNode struct {
	// RequestID is a unique identifier for matching request/response pairs
	RequestID []byte

	// Distances is a list of Kademlia distances to query
	// Each distance is a bucket index (0-256)
	// Special case: [256] means return all known nodes
	Distances []uint
}

// Type returns the message type
func (f *FindNode) Type() byte {
	return FindNodeMsg
}

// Encode returns the RLP encoding of the FINDNODE message
func (f *FindNode) Encode() ([]byte, error) {
	return encodeMessage(FindNodeMsg, []interface{}{f.RequestID, f.Distances})
}

// Nodes is the response to a FINDNODE request.
//
// It contains a list of ENR records for discovered nodes.
// If the response is too large for a single packet, it's split
// across multiple NODES messages with the same request ID.
//
// Format: [request-id, total, [enr1, enr2, ...]]
type Nodes struct {
	// RequestID matches the request ID from the FINDNODE
	RequestID []byte

	// Total is the total number of NODES messages for this response
	Total uint

	// Records contains the ENR records in this message
	Records []*enr.Record
}

// Type returns the message type
func (n *Nodes) Type() byte {
	return NodesMsg
}

// Encode returns the RLP encoding of the NODES message
func (n *Nodes) Encode() ([]byte, error) {
	// Encode each ENR record and wrap in rlp.RawValue to prevent double-encoding
	records := make([]interface{}, len(n.Records))
	for i, record := range n.Records {
		encoded, err := record.EncodeRLPBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to encode ENR %d: %w", i, err)
		}
		// Use rlp.RawValue to include already-encoded RLP data
		records[i] = rlp.RawValue(encoded)
	}

	return encodeMessage(NodesMsg, []interface{}{n.RequestID, n.Total, records})
}

// TalkReq is a generic application-level request.
//
// This allows protocols to exchange custom messages over the
// discv5 transport without defining new message types.
//
// Format: [request-id, protocol, request]
type TalkReq struct {
	// RequestID is a unique identifier for matching request/response pairs
	RequestID []byte

	// Protocol identifies the application protocol (e.g., "eth2")
	Protocol []byte

	// Request is the application-specific request data
	Request []byte
}

// Type returns the message type
func (t *TalkReq) Type() byte {
	return TalkReqMsg
}

// Encode returns the RLP encoding of the TALKREQ message
func (t *TalkReq) Encode() ([]byte, error) {
	return encodeMessage(TalkReqMsg, []interface{}{t.RequestID, t.Protocol, t.Request})
}

// TalkResp is the response to a TALKREQ message.
//
// Format: [request-id, response]
type TalkResp struct {
	// RequestID matches the request ID from the TALKREQ
	RequestID []byte

	// Response is the application-specific response data
	Response []byte
}

// Type returns the message type
func (t *TalkResp) Type() byte {
	return TalkRespMsg
}

// Encode returns the RLP encoding of the TALKRESP message
func (t *TalkResp) Encode() ([]byte, error) {
	return encodeMessage(TalkRespMsg, []interface{}{t.RequestID, t.Response})
}

// RegTopic registers interest in a topic (optional extension).
//
// Topic discovery is an optional extension to the core discv5 protocol.
// It allows nodes to advertise and discover peers interested in specific topics.
//
// Format: [request-id, topic, enr, ticket]
type RegTopic struct {
	RequestID []byte
	Topic     []byte
	ENR       *enr.Record
	Ticket    []byte
}

// Type returns the message type
func (r *RegTopic) Type() byte {
	return RegTopicMsg
}

// Encode returns the RLP encoding of the REGTOPIC message
func (r *RegTopic) Encode() ([]byte, error) {
	enrBytes, err := r.ENR.EncodeRLPBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to encode ENR: %w", err)
	}
	return encodeMessage(RegTopicMsg, []interface{}{r.RequestID, r.Topic, enrBytes, r.Ticket})
}

// Ticket provides a ticket for topic registration (optional extension).
//
// Format: [request-id, ticket, wait-time]
type Ticket struct {
	RequestID []byte
	Ticket    []byte
	WaitTime  uint64
}

// Type returns the message type
func (t *Ticket) Type() byte {
	return TicketMsg
}

// Encode returns the RLP encoding of the TICKET message
func (t *Ticket) Encode() ([]byte, error) {
	return encodeMessage(TicketMsg, []interface{}{t.RequestID, t.Ticket, t.WaitTime})
}

// RegConfirmation confirms topic registration (optional extension).
//
// Format: [request-id, topic]
type RegConfirmation struct {
	RequestID []byte
	Topic     []byte
}

// Type returns the message type
func (r *RegConfirmation) Type() byte {
	return RegConfirmationMsg
}

// Encode returns the RLP encoding of the REGCONFIRMATION message
func (r *RegConfirmation) Encode() ([]byte, error) {
	return encodeMessage(RegConfirmationMsg, []interface{}{r.RequestID, r.Topic})
}

// TopicQuery queries for nodes on a topic (optional extension).
//
// Format: [request-id, topic]
type TopicQuery struct {
	RequestID []byte
	Topic     []byte
}

// Type returns the message type
func (t *TopicQuery) Type() byte {
	return TopicQueryMsg
}

// Encode returns the RLP encoding of the TOPICQUERY message
func (t *TopicQuery) Encode() ([]byte, error) {
	return encodeMessage(TopicQueryMsg, []interface{}{t.RequestID, t.Topic})
}

// NewRequestID generates a new random request ID.
//
// Request IDs are used to match requests with their responses.
// They should be unique for each request to prevent confusion.
//
// Returns an 8-byte random request ID.
func NewRequestID() ([]byte, error) {
	requestID, err := crypto.GenerateRandomBytes(8)
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}
	return requestID, nil
}
