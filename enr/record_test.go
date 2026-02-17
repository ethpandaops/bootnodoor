package enr

import (
	"net"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// TestRecordCreation tests basic record creation and signing
func TestRecordCreation(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	record := New()
	record.Set("ip", net.IPv4(192, 168, 1, 1))
	record.Set("udp", uint16(9000))
	record.Set("tcp", uint16(9000))

	if err := record.Sign(privKey); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}

	if !record.VerifySignature() {
		t.Fatal("Signature verification failed")
	}
}

// TestRecordEncoding tests RLP encoding and decoding
func TestRecordEncoding(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	original := New()
	original.Set("ip", net.IPv4(192, 168, 1, 1))
	original.Set("udp", uint16(9000))

	if err := original.Sign(privKey); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}

	encoded, err := original.EncodeRLP()
	if err != nil {
		t.Fatalf("Failed to encode record: %v", err)
	}

	decoded := New()
	if err := decoded.DecodeRLPBytes(encoded); err != nil {
		t.Fatalf("Failed to decode record: %v", err)
	}

	if decoded.Seq() != original.Seq() {
		t.Errorf("Sequence mismatch: got %d, want %d", decoded.Seq(), original.Seq())
	}

	if decoded.UDP() != original.UDP() {
		t.Errorf("UDP port mismatch: got %d, want %d", decoded.UDP(), original.UDP())
	}
}

// TestBase64Encoding tests base64 encoding and decoding
func TestBase64Encoding(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	original, err := CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	if err != nil {
		t.Fatalf("Failed to create record: %v", err)
	}

	b64, err := original.EncodeBase64()
	if err != nil {
		t.Fatalf("Failed to encode base64: %v", err)
	}

	decoded, err := DecodeBase64(b64)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	if decoded.Seq() != original.Seq() {
		t.Errorf("Sequence mismatch: got %d, want %d", decoded.Seq(), original.Seq())
	}
}

// TestFilters tests ENR filtering functions
func TestFilters(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	record, err := CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	if err != nil {
		t.Fatalf("Failed to create record: %v", err)
	}

	// Test ByKey filter
	udpFilter := ByKey("udp")
	if !udpFilter(record) {
		t.Error("ByKey filter failed for existing key")
	}

	tcpFilter := ByKey("tcp")
	if tcpFilter(record) {
		t.Error("ByKey filter should reject missing key")
	}

	// Test ByUDPPort filter
	portFilter := ByUDPPort(9000)
	if !portFilter(record) {
		t.Error("ByUDPPort filter failed for matching port")
	}

	wrongPortFilter := ByUDPPort(8000)
	if wrongPortFilter(record) {
		t.Error("ByUDPPort filter should reject non-matching port")
	}
}

// TestChainFilters tests filter chaining
func TestChainFilters(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	record, err := CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	if err != nil {
		t.Fatalf("Failed to create record: %v", err)
	}

	// Chain multiple filters
	filter := ChainFilters(
		ByKey("udp"),
		ByUDPPort(9000),
		ByIdentityScheme("v4"),
	)

	if !filter(record) {
		t.Error("Chained filter should accept record matching all criteria")
	}

	// Chain with failing filter
	failFilter := ChainFilters(
		ByKey("udp"),
		ByUDPPort(8000), // Wrong port
	)

	if failFilter(record) {
		t.Error("Chained filter should reject record when any criterion fails")
	}
}

// TestLANAddressDetection tests LAN/WAN address detection
func TestLANAddressDetection(t *testing.T) {
	tests := []struct {
		ip    string
		isLAN bool
	}{
		{"192.168.1.1", true},  // RFC1918
		{"10.0.0.1", true},     // RFC1918
		{"172.16.0.1", true},   // RFC1918
		{"127.0.0.1", true},    // Loopback
		{"8.8.8.8", false},     // Public
		{"1.1.1.1", false},     // Public
		{"::1", true},          // IPv6 loopback
		{"fe80::1", true},      // IPv6 link-local
		{"2001:db8::1", false}, // IPv6 global (doc range, but not private)
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Errorf("Failed to parse IP: %s", tt.ip)
			continue
		}

		isLAN := IsLANAddress(ip)
		if isLAN != tt.isLAN {
			t.Errorf("IsLANAddress(%s) = %v, want %v", tt.ip, isLAN, tt.isLAN)
		}

		isWAN := IsWANAddress(ip)
		if isWAN == tt.isLAN {
			t.Errorf("IsWANAddress(%s) = %v, want %v", tt.ip, isWAN, !tt.isLAN)
		}
	}
}

// TestUpdateRecord tests record updating with incremented sequence number
func TestUpdateRecord(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	original, err := CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	if err != nil {
		t.Fatalf("Failed to create record: %v", err)
	}

	updated, err := UpdateRecord(
		original,
		privKey,
		"ip", net.IPv4(192, 168, 1, 2),
		"udp", uint16(9001),
	)
	if err != nil {
		t.Fatalf("Failed to update record: %v", err)
	}

	if updated.Seq() != original.Seq()+1 {
		t.Errorf("Sequence number not incremented: got %d, want %d", updated.Seq(), original.Seq()+1)
	}

	if updated.UDP() != 9001 {
		t.Errorf("UDP port not updated: got %d, want %d", updated.UDP(), 9001)
	}

	if !updated.IP().Equal(net.IPv4(192, 168, 1, 2)) {
		t.Errorf("IP not updated: got %v, want %v", updated.IP(), net.IPv4(192, 168, 1, 2))
	}
}

func TestEthFieldDecodeFromRLPBytes(t *testing.T) {
	record := New()

	ethField := []struct {
		Hash []byte
		Next uint64
	}{
		{
			Hash: []byte{0xaa, 0xbb, 0xcc, 0xdd},
			Next: 12345,
		},
	}

	encoded, err := rlp.EncodeToBytes(ethField)
	if err != nil {
		t.Fatalf("failed to encode eth field: %v", err)
	}

	record.Set("eth", encoded)

	decoded, ok := record.Eth()
	if !ok {
		t.Fatal("failed to decode eth field from RLP bytes")
	}

	if len(decoded) != 1 {
		t.Fatalf("unexpected eth fork list length: got %d", len(decoded))
	}

	if decoded[0].ForkID != [4]byte{0xaa, 0xbb, 0xcc, 0xdd} {
		t.Fatalf("unexpected fork id: got %x", decoded[0].ForkID)
	}

	if decoded[0].NextForkEpoch != 12345 {
		t.Fatalf("unexpected next fork epoch: got %d", decoded[0].NextForkEpoch)
	}
}

// BenchmarkRecordCreation benchmarks record creation and signing
func BenchmarkRecordCreation(b *testing.B) {
	privKey, _ := crypto.GenerateKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record := New()
		record.Set("ip", net.IPv4(192, 168, 1, 1))
		record.Set("udp", uint16(9000))
		record.Sign(privKey)
	}
}

// BenchmarkRecordEncoding benchmarks RLP encoding
func BenchmarkRecordEncoding(b *testing.B) {
	privKey, _ := crypto.GenerateKey()
	record, _ := CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record.EncodeRLP()
	}
}
