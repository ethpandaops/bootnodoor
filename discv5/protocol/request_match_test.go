package protocol

import (
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/discv5/node"
)

// Request IDs are ours but the peer learns them, so a response must also be the
// kind the request asked for. Otherwise a PONG matches a pending FINDNODE: it
// fires the PONG side effects and consumes the entry, stranding the lookup.
func TestMatchResponseRejectsWrongResponseType(t *testing.T) {
	rt := NewRequestTracker(time.Second)

	n, err := node.New(signedRecord(t, generateKey(t), 1, nil))
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}

	requestID := []byte{0x01, 0x02, 0x03, 0x04}
	ch := rt.AddRequest(requestID, n, &FindNode{RequestID: requestID, Distances: []uint{1}})

	pong := &Pong{RequestID: requestID, IP: []byte{9, 9, 9, 9}, Port: 30303}
	if rt.MatchResponse(requestID, n.ID(), pong) {
		t.Fatal("a PONG matched a pending FINDNODE")
	}

	select {
	case resp := <-ch:
		t.Fatalf("pending FINDNODE was resolved by a PONG: %+v", resp)
	default:
	}

	nodes := &Nodes{RequestID: requestID, Total: 1}
	if !rt.MatchResponse(requestID, n.ID(), nodes) {
		t.Fatal("the matching NODES response was rejected")
	}
}

// The PING/PONG pair must still match, or gating handlePong on this would drop
// every legitimate PONG.
func TestMatchResponseAcceptsPongForPing(t *testing.T) {
	rt := NewRequestTracker(time.Second)

	n, err := node.New(signedRecord(t, generateKey(t), 1, nil))
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}

	requestID := []byte{0x0a, 0x0b}
	rt.AddRequest(requestID, n, &Ping{RequestID: requestID})

	if !rt.MatchResponse(requestID, n.ID(), &Pong{RequestID: requestID}) {
		t.Fatal("a PONG did not match its pending PING")
	}
}
