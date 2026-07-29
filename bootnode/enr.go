package bootnode

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

// ENRManager handles ENR creation and updates for a single identity.
//
// The fork filters are always built for whatever layers the chain config enables
// (so any manager can classify a remote node), but the eth/eth2 fields written
// into this manager's own record are gated by servesEL/servesCL.
type ENRManager struct {
	// config is the bootnode configuration
	config *Config

	key *ecdsa.PrivateKey

	servesEL bool
	servesCL bool

	// elFilter is the EL fork ID filter (nil if EL disabled)
	elFilter *elconfig.ForkFilter

	// clFilter is the CL fork digest filter (nil if CL disabled)
	clFilter *clconfig.ForkDigestFilter

	// localNode is the local discv5 node
	localNode *v5node.Node
}

// NewENRManager creates a new ENR manager for one identity.
func NewENRManager(cfg *Config, key *ecdsa.PrivateKey, localNode *v5node.Node, servesEL, servesCL bool) *ENRManager {
	manager := &ENRManager{
		config:    cfg,
		key:       key,
		servesEL:  servesEL,
		servesCL:  servesCL,
		localNode: localNode,
	}

	// Create EL fork filter if enabled
	if cfg.HasEL() {
		manager.elFilter = elconfig.NewForkFilter(
			cfg.ELGenesisHash,
			cfg.ELConfig,
			cfg.ELGenesisTime,
		)
	}

	// Create CL fork filter if enabled
	if cfg.HasCL() {
		manager.clFilter = clconfig.NewForkDigestFilter(cfg.CLConfig, cfg.GracePeriod)
		manager.clFilter.SetLogger(cfg.Logger)
	}

	return manager
}

// StaticHead returns the head a bootnode evaluates fork schedules at. It
// tracks no chain, so every block-scheduled fork counts as passed (exact on
// post-merge networks, which can only schedule forks by time) and the time
// head is the wall clock.
func StaticHead() (block, timestamp uint64) {
	return math.MaxUint64 - 1, uint64(time.Now().Unix())
}

// UpdateENR updates the local ENR with current eth and eth2 fields, reporting
// whether the record actually changed.
//
// It is a no-op when the computed fields already match the published record,
// so periodic callers do not churn the sequence number (peers re-fetch a
// record on every bump).
//
// This should be called:
//   - On startup
//   - After fork transitions
//   - When head changes significantly (for EL fork ID Next field)
func (m *ENRManager) UpdateENR(currentBlock, currentTime uint64) (bool, error) {
	record := m.localNode.Record()

	// A bootnode serves no TCP, so never advertise tcp/tcp6 — including any
	// inherited from an ENR persisted by an older, TCP-advertising version.
	changed := record.Has("tcp") || record.Has("tcp6")

	serveEL := m.servesEL && m.config.HasEL()
	serveCL := m.servesCL && m.config.HasCL()

	var forkID elconfig.ForkID
	switch {
	case serveEL:
		forkID = m.elFilter.GetCurrentForkID(currentBlock, currentTime)
		if current, ok := record.Eth(); !ok || len(current) == 0 ||
			current[0].ForkID != forkID.Hash || current[0].NextForkEpoch != forkID.Next {
			changed = true
			m.config.Logger.WithField("forkID", forkID.String()).Debug("updated ENR with eth field")
		}
	case record.Has("eth"):
		// Drop any stale eth field (e.g. inherited from a reused shared ENR).
		changed = true
	}

	var eth2Field []byte
	switch {
	case serveCL:
		eth2Field = m.clFilter.ComputeEth2Field()

		var currentEth2 []byte
		if err := record.Get("eth2", &currentEth2); err != nil || !bytes.Equal(currentEth2, eth2Field) {
			changed = true

			var forkDigest [4]byte
			if len(eth2Field) >= 4 {
				copy(forkDigest[:], eth2Field[0:4])
			}
			m.config.Logger.WithField("forkDigest", fmt.Sprintf("%#x", forkDigest)).Debug("updated ENR with eth2 field")
		}
	case record.Has("eth2"):
		changed = true
	}

	if !changed {
		return false, nil
	}

	newRecord, err := record.Clone()
	if err != nil {
		return false, fmt.Errorf("failed to clone ENR: %w", err)
	}

	newRecord.Delete("tcp")
	newRecord.Delete("tcp6")

	if serveEL {
		// The eth field format is [[Hash, Next]] - a list containing fork IDs.
		newRecord.Set("eth", []struct {
			Hash []byte
			Next uint64
		}{
			{
				Hash: forkID.Hash[:],
				Next: forkID.Next,
			},
		})
	} else {
		newRecord.Delete("eth")
	}

	if serveCL {
		newRecord.Set("eth2", eth2Field)
	} else {
		newRecord.Delete("eth2")
	}

	newRecord.SetSeq(record.Seq() + 1)

	if err := newRecord.Sign(m.key); err != nil {
		return false, fmt.Errorf("failed to sign ENR: %w", err)
	}

	if !m.localNode.UpdateENR(newRecord) {
		return false, fmt.Errorf("failed to update local node ENR (sequence number may be stale)")
	}

	m.config.Logger.WithField("seq", newRecord.Seq()).Info("updated local ENR with eth/eth2 fields")
	return true, nil
}

// ClassifyELNode reports whether a record is an execution node on a compatible
// fork, along with the fork ID it advertised.
//
// It is pure: no counter moves. Use it for per-packet layer classification, and
// AdmitELNode when the result decides admission.
func (m *ENRManager) ClassifyELNode(record *enr.Record) (bool, elconfig.ForkID) {
	if !m.config.HasEL() || record == nil {
		return false, elconfig.ForkID{}
	}

	// Extract 'eth' field - it's RLP-encoded as [[Hash, Next]]
	// The eth field contains a list of fork IDs (typically just one)
	// The record.Get() method automatically handles RLP decoding
	forkList, ok := record.Eth()
	if !ok {
		return false, elconfig.ForkID{}
	}

	// Check if we have at least one fork ID
	if len(forkList) == 0 {
		m.config.Logger.Debug("eth field is empty")
		return false, elconfig.ForkID{}
	}

	// Use the first (current) fork ID
	forkData := forkList[0]

	// Validate hash is 4 bytes
	if len(forkData.ForkID) != 4 {
		m.config.Logger.WithField("hashLen", len(forkData.ForkID)).Debug("invalid fork hash length in eth field")
		return false, elconfig.ForkID{}
	}

	// Convert to ForkID struct
	var forkID elconfig.ForkID
	copy(forkID.Hash[:], forkData.ForkID[:])
	forkID.Next = forkData.NextForkEpoch

	// Validate fork ID
	return m.elFilter.Filter(forkID), forkID
}

// AdmitELNode is ClassifyELNode plus stats. Call it from admission paths only.
//
// Records with no eth entry are consensus nodes, not wrong-fork execution nodes,
// and are not counted (see services.AdmissionRejectedLayer).
func (m *ENRManager) AdmitELNode(record *enr.Record) (bool, elconfig.ForkID) {
	accepted, forkID := m.ClassifyELNode(record)

	if m.elFilter != nil && record != nil && record.Has("eth") {
		m.elFilter.RecordAdmission(accepted, forkID)
	}

	return accepted, forkID
}

// ClassifyCLNode reports whether a record is a consensus node on an accepted
// fork digest.
//
// It is pure: no counter moves. Use it for per-packet layer classification, and
// AdmitCLNode when the result decides admission.
func (m *ENRManager) ClassifyCLNode(record *enr.Record) bool {
	if !m.config.HasCL() {
		return false
	}

	return m.clFilter.Matches(record)
}

// AdmitCLNode is ClassifyCLNode plus stats. Call it from admission paths only.
func (m *ENRManager) AdmitCLNode(record *enr.Record) bool {
	if !m.config.HasCL() {
		return false
	}

	return m.clFilter.Admit(record)
}

// GetELFilter returns the EL fork filter (may be nil).
func (m *ENRManager) GetELFilter() *elconfig.ForkFilter {
	return m.elFilter
}

// GetCLFilter returns the CL fork digest filter (may be nil).
func (m *ENRManager) GetCLFilter() *clconfig.ForkDigestFilter {
	return m.clFilter
}

// UpdateENRWithIP updates the local ENR with a new IPv4 address and UDP port.
func (m *ENRManager) UpdateENRWithIP(ip net.IP, port uint16) error {
	record := m.localNode.Record()

	// Clone the current ENR to preserve all fields
	newRecord, err := record.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone ENR: %w", err)
	}

	// Update IP and UDP port
	newRecord.Set("ip", ip.To4())
	newRecord.Set("udp", port)

	// Increment sequence number
	newRecord.SetSeq(record.Seq() + 1)

	// Re-sign the record
	if err := newRecord.Sign(m.key); err != nil {
		return fmt.Errorf("failed to sign ENR: %w", err)
	}

	// Update local node's ENR
	if !m.localNode.UpdateENR(newRecord) {
		return fmt.Errorf("failed to update local node ENR (sequence number may be stale)")
	}

	m.config.Logger.WithField("seq", newRecord.Seq()).Info("updated local ENR with new IPv4 address")
	return nil
}

// UpdateENRWithIP6 updates the local ENR with a new IPv6 address and UDP port.
func (m *ENRManager) UpdateENRWithIP6(ip net.IP, port uint16) error {
	record := m.localNode.Record()

	// Clone the current ENR to preserve all fields
	newRecord, err := record.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone ENR: %w", err)
	}

	// Update IP6 and UDP port
	newRecord.Set("ip6", ip.To16())
	newRecord.Set("udp6", port)

	// Increment sequence number
	newRecord.SetSeq(record.Seq() + 1)

	// Re-sign the record
	if err := newRecord.Sign(m.key); err != nil {
		return fmt.Errorf("failed to sign ENR: %w", err)
	}

	// Update local node's ENR
	if !m.localNode.UpdateENR(newRecord) {
		return fmt.Errorf("failed to update local node ENR (sequence number may be stale)")
	}

	m.config.Logger.WithField("seq", newRecord.Seq()).Info("updated local ENR with new IPv6 address")
	return nil
}
