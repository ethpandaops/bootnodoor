package protocol

import (
	"context"
	"net"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

// captureTransport records every packet sent so a test can decode it.
type captureTransport struct{ sent [][]byte }

func (c *captureTransport) SendTo(b []byte, _ *net.UDPAddr) error {
	c.sent = append(c.sent, b)
	return nil
}
func (c *captureTransport) Send(b []byte, _ *net.UDPAddr, _ *net.UDPAddr) error {
	c.sent = append(c.sent, b)
	return nil
}

// TestSendNeighborsAlwaysSendsAtLeastOnePacket verifies BUG3: an empty result
// still produces exactly one (empty) NEIGHBORS packet, so a go-ethereum querier
// returns immediately instead of waiting out its request timeout on silence.
func TestSendNeighborsAlwaysSendsAtLeastOnePacket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, _ := ethcrypto.GenerateKey()
	ct := &captureTransport{}
	h := NewHandler(ctx, HandlerConfig{PrivateKey: key}, ct)

	pub, id := makeNodeID(t)
	to := h.lookupOrCreateNode(id, pub, testAddr())

	if err := h.sendNeighbors(to, testAddr(), nil, nil); err != nil {
		t.Fatalf("sendNeighbors(empty): %v", err)
	}
	if len(ct.sent) != 1 {
		t.Fatalf("empty result sent %d packets, want exactly 1", len(ct.sent))
	}
	pkt, err := DecodePacket(ct.sent[0])
	if err != nil {
		t.Fatalf("decode NEIGHBORS: %v", err)
	}
	nb, ok := pkt.(*Neighbors)
	if !ok {
		t.Fatalf("wrong packet type %T", pkt)
	}
	if len(nb.Nodes) != 0 {
		t.Fatalf("empty NEIGHBORS carried %d nodes", len(nb.Nodes))
	}
}

// TestSendNeighborsAdvertisesEnrTCPPort verifies BUG4: the NEIGHBORS record
// advertises the node's real TCP port from its ENR, not the UDP port.
func TestSendNeighborsAdvertisesEnrTCPPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, _ := ethcrypto.GenerateKey()
	ct := &captureTransport{}
	h := NewHandler(ctx, HandlerConfig{PrivateKey: key}, ct)

	// Build a peer whose ENR advertises tcp=40404 at udp=30303.
	peerKey, _ := ethcrypto.GenerateKey()
	rec := enr.New()
	_ = rec.Set("id", "v4")
	_ = rec.Set("ip", net.IPv4(203, 0, 113, 7).To4())
	_ = rec.Set("udp", uint16(30303))
	_ = rec.Set("tcp", uint16(40404))
	if err := rec.Sign(peerKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	peer := node.New(&peerKey.PublicKey, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 30303})
	peer.SetENR(rec)

	pub, id := makeNodeID(t)
	to := h.lookupOrCreateNode(id, pub, testAddr())

	if err := h.sendNeighbors(to, testAddr(), nil, []*node.Node{peer}); err != nil {
		t.Fatalf("sendNeighbors: %v", err)
	}
	if len(ct.sent) != 1 {
		t.Fatalf("sent %d packets, want 1", len(ct.sent))
	}
	pkt, _ := DecodePacket(ct.sent[0])
	nb := pkt.(*Neighbors)
	if len(nb.Nodes) != 1 {
		t.Fatalf("NEIGHBORS carried %d nodes, want 1", len(nb.Nodes))
	}
	if nb.Nodes[0].TCP != 40404 {
		t.Fatalf("advertised TCP=%d, want 40404 (the ENR tcp port, not the UDP port)", nb.Nodes[0].TCP)
	}
	if nb.Nodes[0].UDP != 30303 {
		t.Fatalf("advertised UDP=%d, want 30303", nb.Nodes[0].UDP)
	}
}

// TestFloodDoesNotEvictBondedPeers verifies the #34 follow-up: when the node map
// is full, inserts evict a stale unbonded entry (so genuine new peers are never
// locked out) while bonded, endpoint-proven peers are retained.
func TestFloodDoesNotEvictBondedPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 10
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)

	// A genuine, bonded peer.
	pub, bondedID := makeNodeID(t)
	bonded := h.lookupOrCreateNode(bondedID, pub, testAddr())
	bonded.MarkPongReceived(time.Hour, testAddr())

	// Fill the rest with unbonded nodes, then flood well past the cap.
	for i := 0; i < maxNodes*20; i++ {
		p, id := makeNodeID(t)
		h.lookupOrCreateNode(id, p, testAddr())
	}

	if got := len(h.AllNodes()); got != maxNodes {
		t.Fatalf("map not bounded under flood: got %d want %d", got, maxNodes)
	}
	if h.GetNode(bondedID) == nil {
		t.Fatal("bonded peer was evicted by an unbonded-ID flood")
	}
	// A brand-new node still gets retained (evicting an unbonded entry).
	p, freshID := makeNodeID(t)
	h.lookupOrCreateNode(freshID, p, testAddr())
	if h.GetNode(freshID) == nil {
		t.Fatal("new peer not retained when map full")
	}
}
