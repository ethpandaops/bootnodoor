package protocol

import (
	"net"
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

	peerAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 30303}
	requestID := []byte{0x01, 0x02, 0x03, 0x04}
	ch := rt.AddRequest(requestID, n, &FindNode{RequestID: requestID, Distances: []uint{1}}, peerAddr)

	pong := &Pong{RequestID: requestID, IP: []byte{9, 9, 9, 9}, Port: 30303}
	if rt.MatchResponse(requestID, n.ID(), pong) != nil {
		t.Fatal("a PONG matched a pending FINDNODE")
	}

	select {
	case resp := <-ch:
		t.Fatalf("pending FINDNODE was resolved by a PONG: %+v", resp)
	default:
	}

	nodes := &Nodes{RequestID: requestID, Total: 1}
	if rt.MatchResponse(requestID, n.ID(), nodes) == nil {
		t.Fatal("the matching NODES response was rejected")
	}
}

// MatchResponse must hand back the destination so handlePong can tell a PONG that
// came from the address we pinged apart from one with a forged source. Sessions
// are keyed by node ID and accept packets from a changed address, so the source
// alone proves nothing about where the request went.
func TestMatchResponseReportsRequestDestination(t *testing.T) {
	rt := NewRequestTracker(time.Second)

	n, err := node.New(signedRecord(t, generateKey(t), 1, nil))
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}

	peerAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 30303}
	requestID := []byte{0x11, 0x22}
	rt.AddRequest(requestID, n, &Ping{RequestID: requestID}, peerAddr)

	req := rt.MatchResponse(requestID, n.ID(), &Pong{RequestID: requestID})
	if req == nil {
		t.Fatal("a PONG did not match its pending PING")
	}
	if req.DestAddr == nil || !req.DestAddr.IP.Equal(peerAddr.IP) {
		t.Fatalf("DestAddr = %v, want the address the PING was sent to (%v)", req.DestAddr, peerAddr.IP)
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

	peerAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 30303}
	requestID := []byte{0x0a, 0x0b}
	rt.AddRequest(requestID, n, &Ping{RequestID: requestID}, peerAddr)

	if rt.MatchResponse(requestID, n.ID(), &Pong{RequestID: requestID}) == nil {
		t.Fatal("a PONG did not match its pending PING")
	}
}
