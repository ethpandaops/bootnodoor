package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/ethpandaops/bootnodoor/nodes"
	"github.com/ethpandaops/bootnodoor/webui/server"
)

// CLNodeData represents the data for a single CL node in the template.
type CLNodeData struct {
	PeerID          string
	IP              string
	Port            int
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
}

// CLNodesPageData represents the data for the CL nodes page.
type CLNodesPageData struct {
	TotalNodes        int
	ActiveNodes       int
	InactiveNodes     int
	AliveNodes        int
	DeadNodes         int
	CurrentForkDigest string
	Nodes             []CLNodeData
}

// CLNodes handles the CL nodes page.
func (fh *FrontendHandler) CLNodes(w http.ResponseWriter, r *http.Request) {
	// Check if AJAX request
	if r.URL.Query().Get("ajax") == "1" {
		fh.CLNodesJSON(w, r)
		return
	}

	// Get CL table
	clTable := fh.bootnodeService.CLTable()
	if clTable == nil {
		http.Error(w, "CL table not configured", http.StatusNotImplemented)
		return
	}

	// Get table statistics
	stats := clTable.GetStats()

	// Get active nodes
	activeNodes := clTable.GetActiveNodes()

	// Get current fork digest from CL config
	currentForkDigest := ""
	var forkScoringInfo *nodes.ForkScoringInfo
	if clConfig := fh.bootnodeService.CLConfig(); clConfig != nil {
		digest := clConfig.GetCurrentForkDigest()
		currentForkDigest = "0x" + digest.String()

		// Build fork scoring info for comprehensive node scoring
		forkScoringInfo = &nodes.ForkScoringInfo{
			CurrentForkDigest:  [4]byte(clConfig.GetCurrentForkDigest()),
			PreviousForkDigest: [4]byte(clConfig.GetPreviousForkDigest()),
			GenesisForkDigest:  [4]byte(clConfig.GetGenesisForkDigest()),
			// TODO: Add grace period support - for now we don't have access to it
			GracePeriodEnd: time.Time{},
		}
	}

	// Convert nodes to template data
	nodeData := make([]CLNodeData, 0, len(activeNodes))
	aliveCount := 0
	deadCount := 0

	for _, node := range activeNodes {
		nd := convertNodeToCLData(node, currentForkDigest, forkScoringInfo)
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

	pageData := CLNodesPageData{
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
	templateFiles = append(templateFiles, "nodes/cl-nodes.html")
	pageTemplate := server.GetTemplate(templateFiles...)
	data := server.InitPageData(r, "cl-nodes", "/cl-nodes", "Consensus Layer Nodes", templateFiles)
	data.SetBootnodeStatus(fh.bootnodeService.ELTable() != nil, fh.bootnodeService.CLTable() != nil)
	data.Data = pageData

	w.Header().Set("Content-Type", "text/html")
	if server.HandleTemplateError(w, r, "cl-nodes.go", "CLNodes", "", pageTemplate.ExecuteTemplate(w, "layout", data)) != nil {
		return // an error has occurred and was processed
	}
}

// CLNodesJSON returns the CL nodes data as JSON for AJAX updates.
func (fh *FrontendHandler) CLNodesJSON(w http.ResponseWriter, r *http.Request) {
	// Get CL table
	clTable := fh.bootnodeService.CLTable()
	if clTable == nil {
		http.Error(w, "CL table not configured", http.StatusNotImplemented)
		return
	}

	// Get table statistics
	stats := clTable.GetStats()

	// Get active nodes
	activeNodes := clTable.GetActiveNodes()

	// Get current fork digest from CL config
	currentForkDigest := ""
	var forkScoringInfo *nodes.ForkScoringInfo
	if clConfig := fh.bootnodeService.CLConfig(); clConfig != nil {
		digest := clConfig.GetCurrentForkDigest()
		currentForkDigest = "0x" + digest.String()

		// Build fork scoring info for comprehensive node scoring
		forkScoringInfo = &nodes.ForkScoringInfo{
			CurrentForkDigest:  [4]byte(clConfig.GetCurrentForkDigest()),
			PreviousForkDigest: [4]byte(clConfig.GetPreviousForkDigest()),
			GenesisForkDigest:  [4]byte(clConfig.GetGenesisForkDigest()),
			// TODO: Add grace period support - for now we don't have access to it
			GracePeriodEnd: time.Time{},
		}
	}

	// Convert nodes to template data
	nodeData := make([]CLNodeData, 0, len(activeNodes))
	aliveCount := 0
	deadCount := 0

	for _, node := range activeNodes {
		nd := convertNodeToCLData(node, currentForkDigest, forkScoringInfo)
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

	pageData := CLNodesPageData{
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

// convertNodeToCLData converts a generic node to CL-specific template data.
func convertNodeToCLData(node *nodes.Node, currentForkDigest string, forkScoringInfo *nodes.ForkScoringInfo) CLNodeData {
	data := CLNodeData{
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

	// Get ENR
	enr := node.ENR()
	if enr != nil {
		enrStr, err := enr.EncodeBase64()
		if err == nil {
			data.ENR = enrStr
		}
		data.ENRSeq = enr.Seq()

		// Extract fork digest from ENR "eth2" field
		var eth2Field []byte
		if err := enr.Get("eth2", &eth2Field); err == nil && len(eth2Field) >= 4 {
			data.HasForkData = true
			data.ForkDigest = fmt.Sprintf("0x%02x%02x%02x%02x",
				eth2Field[0], eth2Field[1], eth2Field[2], eth2Field[3])
			// Check if it matches the current fork
			data.IsCurrentFork = (data.ForkDigest == currentForkDigest)
		}
	}

	// Calculate if node is alive (last seen within last 5 minutes)
	data.IsAlive = time.Since(data.LastSeen) < 5*time.Minute

	// Calculate comprehensive score using the node's scoring logic
	data.Score = node.CalculateScore(forkScoringInfo)

	return data
}
