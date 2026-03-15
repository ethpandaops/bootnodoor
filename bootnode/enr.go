package bootnode

import (
	"fmt"
	"net"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

// ENRManager handles ENR creation and updates for separate EL and CL ENRs.
type ENRManager struct {
	// config is the bootnode configuration
	config *Config

	// elFilter is the EL fork ID filter (nil if EL disabled)
	elFilter *elconfig.ForkFilter

	// clFilter is the CL fork digest filter (nil if CL disabled)
	clFilter *clconfig.ForkDigestFilter

	// elLocalNode is the local EL discv5 node (nil if EL disabled)
	elLocalNode *v5node.Node

	// clLocalNode is the local CL discv5 node (nil if CL disabled)
	clLocalNode *v5node.Node
}

// NewENRManager creates a new ENR manager with separate EL and CL local nodes.
func NewENRManager(cfg *Config, elLocalNode, clLocalNode *v5node.Node) *ENRManager {
	manager := &ENRManager{
		config:      cfg,
		elLocalNode: elLocalNode,
		clLocalNode: clLocalNode,
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

// UpdateELENR updates the EL local ENR with the current eth field.
//
// This should be called:
//   - On startup
//   - After fork transitions
//   - When head changes significantly (for EL fork ID Next field)
func (m *ENRManager) UpdateELENR(currentBlock, currentTime uint64) error {
	if m.elLocalNode == nil || !m.config.HasEL() {
		return nil
	}

	record := m.elLocalNode.Record()

	// Clone the current ENR to preserve all fields
	newRecord, err := record.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone EL ENR: %w", err)
	}

	// Add EL 'eth' field
	forkID := m.elFilter.GetCurrentForkID(currentBlock, currentTime)
	// Set eth field as a list of fork IDs - ENR.Set() will handle RLP encoding
	// The eth field format is [[Hash, Next]] - a list containing fork IDs
	ethField := []struct {
		Hash []byte
		Next uint64
	}{
		{
			Hash: forkID.Hash[:],
			Next: forkID.Next,
		},
	}
	newRecord.Set("eth", ethField)

	m.config.Logger.WithField("forkID", forkID.String()).Debug("updated EL ENR with eth field")

	// Increment sequence number
	newRecord.SetSeq(record.Seq() + 1)

	// Re-sign the record
	if err := newRecord.Sign(m.config.PrivateKey); err != nil {
		return fmt.Errorf("failed to sign EL ENR: %w", err)
	}

	// Update local node's ENR
	if !m.elLocalNode.UpdateENR(newRecord) {
		return fmt.Errorf("failed to update EL local node ENR (sequence number may be stale)")
	}

	m.config.Logger.WithField("seq", newRecord.Seq()).Info("updated EL local ENR")
	return nil
}

// UpdateCLENR updates the CL local ENR with the current eth2 field.
func (m *ENRManager) UpdateCLENR() error {
	if m.clLocalNode == nil || !m.config.HasCL() {
		return nil
	}

	record := m.clLocalNode.Record()

	// Clone the current ENR to preserve all fields
	newRecord, err := record.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone CL ENR: %w", err)
	}

	// Add CL 'eth2' field
	eth2Field := m.clFilter.ComputeEth2Field()
	newRecord.Set("eth2", eth2Field)

	// eth2Field is []byte, extract first 4 bytes as fork digest for logging
	var forkDigest [4]byte
	if len(eth2Field) >= 4 {
		copy(forkDigest[:], eth2Field[0:4])
	}
	m.config.Logger.WithField("forkDigest", fmt.Sprintf("%#x", forkDigest)).Debug("updated CL ENR with eth2 field")

	// Increment sequence number
	newRecord.SetSeq(record.Seq() + 1)

	// Re-sign the record
	if err := newRecord.Sign(m.config.PrivateKey); err != nil {
		return fmt.Errorf("failed to sign CL ENR: %w", err)
	}

	// Update local node's ENR
	if !m.clLocalNode.UpdateENR(newRecord) {
		return fmt.Errorf("failed to update CL local node ENR (sequence number may be stale)")
	}

	m.config.Logger.WithField("seq", newRecord.Seq()).Info("updated CL local ENR")
	return nil
}

// FilterELNode checks if an EL node's fork ID is valid.
//
// Returns true if the node should be accepted, false otherwise.
func (m *ENRManager) FilterELNode(record *enr.Record) (bool, elconfig.ForkID) {
	if !m.config.HasEL() {
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

// FilterCLNode checks if a CL node's fork digest is valid.
//
// Returns true if the node should be accepted, false otherwise.
func (m *ENRManager) FilterCLNode(record *enr.Record) bool {
	if !m.config.HasCL() {
		return false
	}

	// Use existing fork digest filter
	return m.clFilter.Filter(record)
}

// GetELFilter returns the EL fork filter (may be nil).
func (m *ENRManager) GetELFilter() *elconfig.ForkFilter {
	return m.elFilter
}

// GetCLFilter returns the CL fork digest filter (may be nil).
func (m *ENRManager) GetCLFilter() *clconfig.ForkDigestFilter {
	return m.clFilter
}

// UpdateELENRWithIP updates the EL local ENR with a new IPv4 address and UDP port.
func (m *ENRManager) UpdateELENRWithIP(ip net.IP, port uint16) error {
	if m.elLocalNode == nil {
		return nil
	}
	return m.updateNodeENRWithIP(m.elLocalNode, ip, port, "EL")
}

// UpdateELENRWithIP6 updates the EL local ENR with a new IPv6 address and UDP port.
func (m *ENRManager) UpdateELENRWithIP6(ip net.IP, port uint16) error {
	if m.elLocalNode == nil {
		return nil
	}
	return m.updateNodeENRWithIP6(m.elLocalNode, ip, port, "EL")
}

// UpdateCLENRWithIP updates the CL local ENR with a new IPv4 address and UDP port.
func (m *ENRManager) UpdateCLENRWithIP(ip net.IP, port uint16) error {
	if m.clLocalNode == nil {
		return nil
	}
	return m.updateNodeENRWithIP(m.clLocalNode, ip, port, "CL")
}

// UpdateCLENRWithIP6 updates the CL local ENR with a new IPv6 address and UDP port.
func (m *ENRManager) UpdateCLENRWithIP6(ip net.IP, port uint16) error {
	if m.clLocalNode == nil {
		return nil
	}
	return m.updateNodeENRWithIP6(m.clLocalNode, ip, port, "CL")
}

// updateNodeENRWithIP updates a local node's ENR with a new IPv4 address and UDP port.
func (m *ENRManager) updateNodeENRWithIP(node *v5node.Node, ip net.IP, port uint16, layer string) error {
	record := node.Record()

	// Clone the current ENR to preserve all fields
	newRecord, err := record.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone %s ENR: %w", layer, err)
	}

	// Update IP and UDP port
	newRecord.Set("ip", ip.To4())
	newRecord.Set("udp", port)

	// Increment sequence number
	newRecord.SetSeq(record.Seq() + 1)

	// Re-sign the record
	if err := newRecord.Sign(m.config.PrivateKey); err != nil {
		return fmt.Errorf("failed to sign %s ENR: %w", layer, err)
	}

	// Update local node's ENR
	if !node.UpdateENR(newRecord) {
		return fmt.Errorf("failed to update %s local node ENR (sequence number may be stale)", layer)
	}

	m.config.Logger.WithField("seq", newRecord.Seq()).Infof("updated %s local ENR with new IPv4 address", layer)
	return nil
}

// updateNodeENRWithIP6 updates a local node's ENR with a new IPv6 address and UDP port.
func (m *ENRManager) updateNodeENRWithIP6(node *v5node.Node, ip net.IP, port uint16, layer string) error {
	record := node.Record()

	// Clone the current ENR to preserve all fields
	newRecord, err := record.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone %s ENR: %w", layer, err)
	}

	// Update IP6 and UDP port
	newRecord.Set("ip6", ip.To16())
	newRecord.Set("udp6", port)

	// Increment sequence number
	newRecord.SetSeq(record.Seq() + 1)

	// Re-sign the record
	if err := newRecord.Sign(m.config.PrivateKey); err != nil {
		return fmt.Errorf("failed to sign %s ENR: %w", layer, err)
	}

	// Update local node's ENR
	if !node.UpdateENR(newRecord) {
		return fmt.Errorf("failed to update %s local node ENR (sequence number may be stale)", layer)
	}

	m.config.Logger.WithField("seq", newRecord.Seq()).Infof("updated %s local ENR with new IPv6 address", layer)
	return nil
}
