package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/nodes"
	"github.com/ethpandaops/bootnodoor/webui/server"
)

// ELNodeData represents the data for a single EL node in the template.
type ELNodeData struct {
	PeerID          string
	IP              string
	Port            int
	Enode           string
	ENR             string
	ENRSeq          uint64
	FirstSeen       time.Time
	LastSeen        time.Time
	SuccessCount    int
	FailureCount    int
	IsAlive         bool
	Score           float64
	AvgRTT          time.Duration
	ForkDigest      string
	HasForkData     bool
	IsCurrentFork   bool
	HasV4           bool   // Supports discv4 protocol
	HasV5           bool   // Supports discv5 protocol
	ProtocolSupport string // Human-readable protocol support string
}

// ELNodesPageData represents the data for the EL nodes page.
type ELNodesPageData struct {
	TotalNodes        int
	ActiveNodes       int
	InactiveNodes     int
	AliveNodes        int
	DeadNodes         int
	CurrentForkDigest string
	Nodes             []ELNodeData
}

// ELNodes handles the EL nodes page.
func (fh *FrontendHandler) ELNodes(w http.ResponseWriter, r *http.Request) {
	// Check if AJAX request
	if r.URL.Query().Get("ajax") == "1" {
		fh.ELNodesJSON(w, r)
		return
	}

	// Get EL table
	elTable := fh.bootnodeService.ELTable()
	if elTable == nil {
		http.Error(w, "EL table not configured", http.StatusNotImplemented)
		return
	}

	// Get table statistics
	stats := elTable.GetStats()

	// Get active nodes
	activeNodes := elTable.GetActiveNodes()

	// Get current fork ID from EL config via ENR manager
	currentForkDigest := ""
	var forkScoringInfo *nodes.ForkScoringInfo
	if enrMgr := fh.bootnodeService.ENRManager(); enrMgr != nil {
		if elFilter := enrMgr.GetELFilter(); elFilter != nil {
			// Use a very high block/time to get the latest fork
			currentForkID := elFilter.GetCurrentForkID(999999999, uint64(time.Now().Unix()))
			currentForkDigest = fmt.Sprintf("0x%02x%02x%02x%02x",
				currentForkID.Hash[0], currentForkID.Hash[1], currentForkID.Hash[2], currentForkID.Hash[3])

			// Build fork scoring info for comprehensive node scoring
			// For EL, we use the genesis fork ID and current fork ID
			// Get all fork IDs to find genesis
			allForkIDs := elFilter.GetAllForkIDs()
			genesisForkID := elconfig.ForkID{}
			if len(allForkIDs) > 0 {
				genesisForkID = allForkIDs[0] // First fork is always genesis
			}

			forkScoringInfo = &nodes.ForkScoringInfo{
				CurrentForkDigest:  currentForkID.Hash,
				GenesisForkDigest:  genesisForkID.Hash,
				PreviousForkDigest: [4]byte{}, // EL doesn't track previous fork
				// TODO: Add grace period support
				GracePeriodEnd: time.Time{},
			}
		}
	}

	// Convert nodes to template data
	nodeData := make([]ELNodeData, 0, len(activeNodes))
	aliveCount := 0
	deadCount := 0

	for _, node := range activeNodes {
		nd := convertNodeToELData(node, currentForkDigest, forkScoringInfo)
		nodeData = append(nodeData, nd)

		if nd.IsAlive {
			aliveCount++
		} else {
			deadCount++
		}
	}

	// Sort nodes by peer ID
	sort.Slice(nodeData, func(i, j int) bool {
		return nodeData[i].PeerID < nodeData[j].PeerID
	})

	pageData := ELNodesPageData{
		TotalNodes:        stats.TotalNodes,
		ActiveNodes:       stats.ActiveNodes,
		InactiveNodes:     stats.TotalNodes - stats.ActiveNodes,
		AliveNodes:        aliveCount,
		DeadNodes:         deadCount,
		CurrentForkDigest: currentForkDigest,
		Nodes:             nodeData,
	}

	// Render template
	templateFiles := server.LayoutTemplateFiles
	templateFiles = append(templateFiles, "nodes/el-nodes.html")
	pageTemplate := server.GetTemplate(templateFiles...)
	data := server.InitPageData(r, "el-nodes", "/el-nodes", "Execution Layer Nodes", templateFiles)
	data.SetBootnodeStatus(fh.bootnodeService.ELTable() != nil, fh.bootnodeService.CLTable() != nil)
	data.Data = pageData

	w.Header().Set("Content-Type", "text/html")
	if server.HandleTemplateError(w, r, "el-nodes.go", "ELNodes", "", pageTemplate.ExecuteTemplate(w, "layout", data)) != nil {
		return // an error has occurred and was processed
	}
}

// ELNodesJSON returns the EL nodes data as JSON for AJAX updates.
func (fh *FrontendHandler) ELNodesJSON(w http.ResponseWriter, r *http.Request) {
	// Get EL table
	elTable := fh.bootnodeService.ELTable()
	if elTable == nil {
		http.Error(w, "EL table not configured", http.StatusNotImplemented)
		return
	}

	// Get table statistics
	stats := elTable.GetStats()

	// Get active nodes
	activeNodes := elTable.GetActiveNodes()

	// Get current fork ID from EL config via ENR manager
	currentForkDigest := ""
	var forkScoringInfo *nodes.ForkScoringInfo
	if enrMgr := fh.bootnodeService.ENRManager(); enrMgr != nil {
		if elFilter := enrMgr.GetELFilter(); elFilter != nil {
			// Use a very high block/time to get the latest fork
			currentForkID := elFilter.GetCurrentForkID(999999999, uint64(time.Now().Unix()))
			currentForkDigest = fmt.Sprintf("0x%02x%02x%02x%02x",
				currentForkID.Hash[0], currentForkID.Hash[1], currentForkID.Hash[2], currentForkID.Hash[3])

			// Build fork scoring info for comprehensive node scoring
			// For EL, we use the genesis fork ID and current fork ID
			// Get all fork IDs to find genesis
			allForkIDs := elFilter.GetAllForkIDs()
			genesisForkID := elconfig.ForkID{}
			if len(allForkIDs) > 0 {
				genesisForkID = allForkIDs[0] // First fork is always genesis
			}

			forkScoringInfo = &nodes.ForkScoringInfo{
				CurrentForkDigest:  currentForkID.Hash,
				GenesisForkDigest:  genesisForkID.Hash,
				PreviousForkDigest: [4]byte{}, // EL doesn't track previous fork
				// TODO: Add grace period support
				GracePeriodEnd: time.Time{},
			}
		}
	}

	// Convert nodes to template data
	nodeData := make([]ELNodeData, 0, len(activeNodes))
	aliveCount := 0
	deadCount := 0

	for _, node := range activeNodes {
		nd := convertNodeToELData(node, currentForkDigest, forkScoringInfo)
		nodeData = append(nodeData, nd)

		if nd.IsAlive {
			aliveCount++
		} else {
			deadCount++
		}
	}

	// Sort nodes by peer ID
	sort.Slice(nodeData, func(i, j int) bool {
		return nodeData[i].PeerID < nodeData[j].PeerID
	})

	pageData := ELNodesPageData{
		TotalNodes:        stats.TotalNodes,
		ActiveNodes:       stats.ActiveNodes,
		InactiveNodes:     stats.TotalNodes - stats.ActiveNodes,
		AliveNodes:        aliveCount,
		DeadNodes:         deadCount,
		CurrentForkDigest: currentForkDigest,
		Nodes:             nodeData,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pageData)
}

// convertNodeToELData converts a generic node to EL-specific template data.
func convertNodeToELData(node *nodes.Node, currentForkDigest string, forkScoringInfo *nodes.ForkScoringInfo) ELNodeData {
	data := ELNodeData{
		PeerID:       node.PeerID(),
		FirstSeen:    node.FirstSeen(),
		LastSeen:     node.LastSeen(),
		SuccessCount: node.SuccessCount(),
		FailureCount: node.FailureCount(),
		AvgRTT:       node.AvgRTT(),
		HasForkData:  false,
	}

	// Get node address
	addr := node.Addr()
	if addr != nil {
		data.IP = addr.IP.String()
		data.Port = addr.Port
	}

	// Get enode (for EL nodes)
	enode := node.Enode()
	if enode != nil {
		data.Enode = enode.String()
	}

	// Get ENR
	enr := node.ENR()
	if enr != nil {
		enrStr, err := enr.EncodeBase64()
		if err == nil {
			data.ENR = enrStr
		}
		data.ENRSeq = enr.Seq()

		// Extract fork ID from ENR "eth" field using the helper function
		forkID, err := extractForkID(node)
		if err == nil {
			data.HasForkData = true
			data.ForkDigest = fmt.Sprintf("0x%02x%02x%02x%02x",
				forkID.Hash[0], forkID.Hash[1], forkID.Hash[2], forkID.Hash[3])
			// Check if it matches the current fork
			data.IsCurrentFork = (data.ForkDigest == currentForkDigest)
		}
	}

	// Calculate if node is alive (last seen within last 5 minutes)
	data.IsAlive = time.Since(data.LastSeen) < 5*time.Minute

	// Calculate comprehensive score using the node's scoring logic
	data.Score = node.CalculateScore(forkScoringInfo)

	// Check protocol support
	data.HasV4 = node.HasV4()
	data.HasV5 = node.HasV5()

	// Build protocol support string
	if data.HasV4 && data.HasV5 {
		data.ProtocolSupport = "v4+v5"
	} else if data.HasV5 {
		data.ProtocolSupport = "v5"
	} else if data.HasV4 {
		data.ProtocolSupport = "v4"
	} else {
		data.ProtocolSupport = "none"
	}

	return data
}

// extractForkID extracts the fork ID from an ENR record's 'eth' field.
//
// The eth field is RLP-encoded as [[ForkHash, ForkNext]] - a list of fork IDs.
// The ENR's Get() method automatically handles RLP decoding.
func extractForkID(record *nodes.Node) (elconfig.ForkID, error) {
	if record.Record() == nil {
		return elconfig.ForkID{}, fmt.Errorf("node has no ENR record")
	}

	// Extract 'eth' field - it's a list of fork IDs
	var forkList []struct {
		Hash []byte
		Next uint64
	}

	if err := record.Record().Get("eth", &forkList); err != nil {
		return elconfig.ForkID{}, fmt.Errorf("failed to get eth field: %w", err)
	}

	// Check if we have at least one fork ID
	if len(forkList) == 0 {
		return elconfig.ForkID{}, fmt.Errorf("eth field is empty")
	}

	// Use the first (current) fork ID
	forkData := forkList[0]

	// Validate hash is 4 bytes
	if len(forkData.Hash) != 4 {
		return elconfig.ForkID{}, fmt.Errorf("invalid fork hash length: %d bytes (expected 4)", len(forkData.Hash))
	}

	var id elconfig.ForkID
	copy(id.Hash[:], forkData.Hash)
	id.Next = forkData.Next

	return id, nil
}
