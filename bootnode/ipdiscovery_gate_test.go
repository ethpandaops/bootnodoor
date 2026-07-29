package bootnode

import (
	"net"
	"testing"
)

// An explicitly configured ENR address is authoritative, so peer reports must not
// move it while running. reconcileStoredENR honours this at startup; without the
// same check at runtime a configured address is overwritten and only restored on
// the next restart.
func TestUpdateENRWithDiscoveredIP_KeepsExplicitAddress(t *testing.T) {
	el := &identity{key: mustKey(t), servesEL: true, bindPort: 9000, enrPort: 9000, storeKey: "local_enr"}
	s := newTestService(t, []*identity{el})
	s.config.ENRIPProvided = true

	before := el.localNode.Record().IP()
	if before == nil {
		t.Fatal("test identity has no ENR IP to protect")
	}

	s.updateENRWithDiscoveredIP(net.ParseIP("9.9.9.9"), 31000, false)

	if got := el.localNode.Record().IP(); !got.Equal(before) {
		t.Fatalf("configured ENR IP was overwritten by discovery: %v -> %v", before, got)
	}
}

// The same path must still self-correct when the address was auto-detected, or
// the guard above would disable IP discovery entirely.
func TestUpdateENRWithDiscoveredIP_UpdatesAutoDetectedAddress(t *testing.T) {
	el := &identity{key: mustKey(t), servesEL: true, bindPort: 9000, enrPort: 9000, storeKey: "local_enr"}
	s := newTestService(t, []*identity{el})

	s.updateENRWithDiscoveredIP(net.ParseIP("9.9.9.9"), 31000, false)

	if got := el.localNode.Record().IP(); !got.Equal(net.ParseIP("9.9.9.9")) {
		t.Fatalf("auto-detected ENR IP = %v, want the discovered 9.9.9.9", got)
	}
}

// The default was declared false while nothing in the runtime path read it, so
// discovery ran unconditionally. Pin the default that the runtime gate now honours.
func TestDefaultConfigEnablesIPDiscovery(t *testing.T) {
	if !DefaultConfig().EnableIPDiscovery {
		t.Fatal("EnableIPDiscovery default is false; the runtime gate would disable discovery for everyone")
	}
}
