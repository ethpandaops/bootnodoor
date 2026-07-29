package protocol

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/discv5/session"
	"github.com/sirupsen/logrus"
)

type sentPacket struct {
	data []byte
	to   *net.UDPAddr
}

// recordingTransport captures where packets went, so a test can assert a
// challenge was not reflected at the victim's address.
type recordingTransport struct {
	mu   sync.Mutex
	sent []sentPacket
}

func (r *recordingTransport) SendTo(data []byte, to *net.UDPAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, sentPacket{data: data, to: to})
	return nil
}

func (r *recordingTransport) Send(data []byte, to *net.UDPAddr, _ *net.UDPAddr) error {
	return r.SendTo(data, to)
}

func (r *recordingTransport) destinations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.sent))
	for _, p := range r.sent {
		out = append(out, p.to.String())
	}
	return out
}

func sessionHandler(t *testing.T) (*Handler, *recordingTransport, *session.Cache, context.CancelFunc) {
	t.Helper()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	localKey := generateKey(t)
	localNode, err := node.New(signedRecord(t, localKey, 1, nil))
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}

	cache := session.NewCache(16, time.Hour, logger)
	ctx, cancel := context.WithCancel(context.Background())
	h := NewHandler(ctx, HandlerConfig{
		LocalNode:  localNode,
		Sessions:   cache,
		PrivateKey: localKey,
		Logger:     logger,
	})

	tr := &recordingTransport{}
	h.SetTransport(tr)
	return h, tr, cache, cancel
}

// victimSession installs a session for a peer reachable at addr, returning the
// peer's node ID and the keys the session was built with.
func victimSession(t *testing.T, cache *session.Cache, addr *net.UDPAddr) (*node.Node, *session.Session) {
	t.Helper()

	peerKey := generateKey(t)
	peerNode, err := node.New(signedRecord(t, peerKey, 1, nil))
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}

	keys := &session.SessionKeys{
		InitiatorKey: []byte("0123456789abcdef"),
		RecipientKey: []byte("fedcba9876543210"),
	}
	sess := session.NewSession(peerNode.ID(), addr, keys, false, time.Hour)
	sess.SetNode(peerNode)
	cache.Put(sess)

	return peerNode, sess
}

// garbageOrdinaryPacket builds a syntactically valid ordinary packet that names
// srcID but whose ciphertext cannot decrypt against any real session key.
func garbageOrdinaryPacket(t *testing.T, srcID, destID node.ID) []byte {
	t.Helper()

	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	authdata := srcID[:]
	maskingIV, _, err := BuildOrdinaryHeaderData(srcID, nonce, authdata)
	if err != nil {
		t.Fatalf("BuildOrdinaryHeaderData: %v", err)
	}

	data, err := EncodeOrdinaryPacket(srcID, destID, maskingIV, nonce, authdata, []byte("not-a-valid-ciphertext"))
	if err != nil {
		t.Fatalf("EncodeOrdinaryPacket: %v", err)
	}
	return data
}

// A node ID is public information from an ENR, so an attacker who knows only that
// must not be able to move a peer's session to an address of their choosing.
func TestSpoofedOrdinaryPacketDoesNotMigrateSession(t *testing.T) {
	h, _, cache, cancel := sessionHandler(t)
	defer cancel()

	victimAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	victim, sess := victimSession(t, cache, victimAddr)
	victimID := victim.ID()

	attackerAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 40404}
	data := garbageOrdinaryPacket(t, victimID, h.config.LocalNode.ID())
	_ = h.HandleIncomingPacket(data, attackerAddr, victimAddr)

	if got := sess.Addr().String(); got != victimAddr.String() {
		t.Fatalf("session migrated to %s on an unauthenticated packet, want %s", got, victimAddr)
	}
}

// Deleting on decrypt failure let anyone holding a peer's public node ID destroy
// that peer's session, repeatably. The session must survive.
func TestDecryptFailureKeepsSession(t *testing.T) {
	h, tr, cache, cancel := sessionHandler(t)
	defer cancel()

	victimAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	victim, _ := victimSession(t, cache, victimAddr)
	victimID := victim.ID()

	attackerAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 40404}
	data := garbageOrdinaryPacket(t, victimID, h.config.LocalNode.ID())

	for i := 0; i < 5; i++ {
		_ = h.HandleIncomingPacket(data, attackerAddr, victimAddr)
		if cache.Get(victimID) == nil {
			t.Fatalf("session destroyed by unauthenticated packet %d", i+1)
		}
	}

	// The challenge answers the packet source, which is the only address a peer
	// that genuinely lost its keys could be reached at.
	for _, dst := range tr.destinations() {
		if dst == victimAddr.String() {
			t.Fatal("challenge was reflected at the victim's address")
		}
	}
}

// WHOAREYOU is unauthenticated and answering one replaces the session keys, so a
// challenge quoting a nonce we never sent must be ignored.
func TestSpoofedWhoareyouDoesNotReplaceSession(t *testing.T) {
	h, _, cache, cancel := sessionHandler(t)
	defer cancel()

	victimAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	victim, sess := victimSession(t, cache, victimAddr)
	victimID := victim.ID()

	keysBefore := sess.EncryptionKey()

	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = 0xAA
	}
	data, _, err := EncodeWHOAREYOUPacket(h.config.LocalNode.ID(), nonce, &WHOAREYOUChallenge{
		IDNonce: make([]byte, 16),
		ENRSeq:  0,
	})
	if err != nil {
		t.Fatalf("EncodeWHOAREYOUPacket: %v", err)
	}

	_ = h.HandleIncomingPacket(data, victimAddr, victimAddr)

	after := cache.Get(victimID)
	if after == nil {
		t.Fatal("spoofed WHOAREYOU destroyed the session")
	}
	if string(after.EncryptionKey()) != string(keysBefore) {
		t.Fatal("spoofed WHOAREYOU replaced the session keys")
	}
}

// With a request in flight the forged challenge reaches handshake recovery, which
// derives new keys and replaces the session by node ID. Asserting a session still
// exists is not enough here — it exists but the real peer cannot read it.
func TestSpoofedWhoareyouWithPendingRequestKeepsKeys(t *testing.T) {
	h, _, cache, cancel := sessionHandler(t)
	defer cancel()

	victimAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	victim, sess := victimSession(t, cache, victimAddr)
	victimID := victim.ID()

	keysBefore := string(sess.EncryptionKey())

	requestID := []byte{0x01, 0x02, 0x03, 0x04}
	h.requests.AddRequest(requestID, victim, &Ping{RequestID: requestID})

	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = 0xBB
	}
	data, _, err := EncodeWHOAREYOUPacket(h.config.LocalNode.ID(), nonce, &WHOAREYOUChallenge{
		IDNonce: make([]byte, 16),
		ENRSeq:  0,
	})
	if err != nil {
		t.Fatalf("EncodeWHOAREYOUPacket: %v", err)
	}

	_ = h.HandleIncomingPacket(data, victimAddr, victimAddr)

	after := cache.Get(victimID)
	if after == nil {
		t.Fatal("spoofed WHOAREYOU destroyed the session")
	}
	if string(after.EncryptionKey()) != keysBefore {
		t.Fatal("spoofed WHOAREYOU replaced the session keys via handshake recovery")
	}
}
