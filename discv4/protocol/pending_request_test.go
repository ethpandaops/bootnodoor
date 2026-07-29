package protocol

import (
	"crypto/ecdsa"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

func makeKeyedNode(t *testing.T, port int) (*node.Node, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return node.New(&key.PublicKey, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: port}), key
}

func signedV4Record(t *testing.T, key *ecdsa.PrivateKey, seq uint64) *enr.Record {
	t.Helper()
	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(1, 2, 3, 4)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(30303)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	rec.SetSeq(seq)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rec
}

func expectResponse(t *testing.T, req *PendingRequest) interface{} {
	t.Helper()
	select {
	case resp := <-req.ResponseChan:
		return resp
	case <-time.After(2 * time.Second):
		t.Fatal("expected a delivered response")
		return nil
	}
}

func expectNoResponse(t *testing.T, req *PendingRequest) {
	t.Helper()
	select {
	case resp := <-req.ResponseChan:
		t.Fatalf("unexpected response delivered: %v", resp)
	default:
	}
}

// TestIdenticalRequestsToDifferentPeersDoNotAlias covers the collision that
// poisoned live routing tables: ENRREQUEST carries only a 1s-granularity
// expiration and signatures are deterministic, so same-second requests to
// different peers share a packet hash. A response from one peer must resolve
// only that peer's request and must not touch the other node's ENR.
func TestIdenticalRequestsToDifferentPeersDoNotAlias(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	nodeA, _ := makeKeyedNode(t, 30301)
	nodeB, keyB := makeKeyedNode(t, 30302)
	hash := []byte("same-second-packet")

	reqA, err := h.addPendingRequest(hash, nodeA, ENRRequestPacket)
	if err != nil {
		t.Fatalf("addPendingRequest A: %v", err)
	}
	reqB, err := h.addPendingRequest(hash, nodeB, ENRRequestPacket)
	if err != nil {
		t.Fatalf("addPendingRequest B: %v", err)
	}

	recB := signedV4Record(t, keyB, 7)
	if err := h.handleENRResponse(nodeB, nodeB.Addr(), &ENRResponse{ReplyTok: hash, Record: recB}); err != nil {
		t.Fatalf("handleENRResponse: %v", err)
	}

	if got := expectResponse(t, reqB); got != recB {
		t.Fatalf("request B received %v, want node B's record", got)
	}
	expectNoResponse(t, reqA)
	if nodeA.ENR() != nil {
		t.Fatal("node B's response installed a record on node A")
	}
	if nodeB.ENR() != recB {
		t.Fatal("node B's record was not installed on node B")
	}
}

// TestSamePeerDuplicateRequestsBothComplete covers concurrent identical
// requests to one peer (the lookup fires RequestENR per neighbor before
// dedup): every waiter gets the response, and removing one request must not
// orphan the other's pending entry.
func TestSamePeerDuplicateRequestsBothComplete(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	n, key := makeKeyedNode(t, 30301)
	hash := []byte("same-second-packet")

	req1, err := h.addPendingRequest(hash, n, ENRRequestPacket)
	if err != nil {
		t.Fatalf("addPendingRequest 1: %v", err)
	}
	req2, err := h.addPendingRequest(hash, n, ENRRequestPacket)
	if err != nil {
		t.Fatalf("addPendingRequest 2: %v", err)
	}

	h.removePendingRequest(req1)
	if got := len(h.getPendingRequests(hash, n.ID())); got != 1 {
		t.Fatalf("after removing one duplicate, %d pending remain, want 1", got)
	}

	rec := signedV4Record(t, key, 3)
	if err := h.handleENRResponse(n, n.Addr(), &ENRResponse{ReplyTok: hash, Record: rec}); err != nil {
		t.Fatalf("handleENRResponse: %v", err)
	}
	if got := expectResponse(t, req2); got != rec {
		t.Fatalf("surviving request received %v, want the record", got)
	}
}

// TestUnsolicitedENRResponseDoesNotMutate covers replay: ENRRESPONSE has no
// expiration, so a response matching no pending request must not touch the
// node's ENR at all.
func TestUnsolicitedENRResponseDoesNotMutate(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	n, key := makeKeyedNode(t, 30301)
	newer := signedV4Record(t, key, 9)
	n.SetENR(newer)

	older := signedV4Record(t, key, 2)
	if err := h.handleENRResponse(n, n.Addr(), &ENRResponse{ReplyTok: []byte("nothing-pending"), Record: older}); err != nil {
		t.Fatalf("handleENRResponse: %v", err)
	}
	if n.ENR() != newer {
		t.Fatal("unsolicited response replaced the node's ENR")
	}
}

// TestStaleENRResponseNotInstalled covers rollback through a matched request:
// an equal-or-lower-sequence record must not replace a newer one.
func TestStaleENRResponseNotInstalled(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	n, key := makeKeyedNode(t, 30301)
	newer := signedV4Record(t, key, 9)
	n.SetENR(newer)

	hash := []byte("pending")
	req, err := h.addPendingRequest(hash, n, ENRRequestPacket)
	if err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	stale := signedV4Record(t, key, 9)
	if err := h.handleENRResponse(n, n.Addr(), &ENRResponse{ReplyTok: hash, Record: stale}); err != nil {
		t.Fatalf("handleENRResponse: %v", err)
	}
	if n.ENR() != newer {
		t.Fatal("equal-sequence response replaced the node's ENR")
	}
	if got := expectResponse(t, req); got != stale {
		t.Fatalf("waiter received %v, want the response record", got)
	}
}

// TestMismatchedIdentityENRResponseDropped: a matched response whose record is
// signed by a different key must neither install nor be delivered.
func TestMismatchedIdentityENRResponseDropped(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30301)
	_, otherKey := makeKeyedNode(t, 30302)

	hash := []byte("pending")
	req, err := h.addPendingRequest(hash, n, ENRRequestPacket)
	if err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	foreign := signedV4Record(t, otherKey, 5)
	if err := h.handleENRResponse(n, n.Addr(), &ENRResponse{ReplyTok: hash, Record: foreign}); err != nil {
		t.Fatalf("handleENRResponse: %v", err)
	}
	if n.ENR() != nil {
		t.Fatal("foreign record was installed")
	}
	expectNoResponse(t, req)
}

// TestIdenticalFindnodeToDifferentPeersSeparateAccumulators: colliding
// FINDNODE hashes to different peers must keep separate NEIGHBORS
// accumulators and deliver each peer's response to its own request.
func TestIdenticalFindnodeToDifferentPeersSeparateAccumulators(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	nodeA, _ := makeKeyedNode(t, 30301)
	nodeB, _ := makeKeyedNode(t, 30302)
	hash := []byte("same-target-same-second")

	reqA, err := h.addPendingRequest(hash, nodeA, FindnodePacket)
	if err != nil {
		t.Fatalf("addPendingRequest A: %v", err)
	}
	reqB, err := h.addPendingRequest(hash, nodeB, FindnodePacket)
	if err != nil {
		t.Fatalf("addPendingRequest B: %v", err)
	}

	if err := h.handleNeighbors(nodeA, nodeA.Addr(), makeNeighbors(t, 2)); err != nil {
		t.Fatalf("handleNeighbors: %v", err)
	}

	nodes, ok := expectResponse(t, reqA).([]*node.Node)
	if !ok || len(nodes) != 2 {
		t.Fatalf("request A received %v, want 2 nodes", nodes)
	}
	expectNoResponse(t, reqB)

	h.pendingNeighborsMu.RLock()
	_, sharedKey := h.pendingNeighbors[string(hash)]
	bEntry := h.pendingNeighbors[requestKey(hash, nodeB.ID())]
	h.pendingNeighborsMu.RUnlock()
	if sharedKey {
		t.Fatal("accumulator stored under the bare hash key")
	}
	if bEntry != nil {
		t.Fatal("node A's NEIGHBORS created an accumulator for node B's request")
	}
}

// TestSecondFindnodeToSamePeerRejected: NEIGHBORS has no reply token, so two
// in-flight FINDNODEs to one peer cannot be told apart and the second must be
// refused.
func TestSecondFindnodeToSamePeerRejected(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30301)
	if _, err := h.addPendingRequest([]byte("hash-1"), n, FindnodePacket); err != nil {
		t.Fatalf("first findnode: %v", err)
	}
	if _, err := h.addPendingRequest([]byte("hash-2"), n, FindnodePacket); err == nil {
		t.Fatal("second in-flight findnode to the same peer was accepted")
	}
}
