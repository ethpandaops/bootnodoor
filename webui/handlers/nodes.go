package handlers

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/webui/server"
)

// NodesPageData contains data for the nodes page
type NodesPageData struct {
	TotalNodes        int
	ActiveNodes       int
	InactiveNodes     int
	CurrentForkDigest string
	Nodes             []NodeInfo
}

// NodeInfo contains node information for display
type NodeInfo struct {
	PeerID        string
	IP            string
	Port          int
	FirstSeen     time.Time
	LastSeen      time.Time
	SuccessCount  int
	FailureCount  int
	IsAlive       bool
	Score         float64
	ForkDigest    string
	HasForkData   bool
	IsCurrentFork bool
	ENRSeq        uint64
	ENR           string
	AvgRTT        time.Duration
}

// Nodes renders the nodes page
func (fh *FrontendHandler) Nodes(w http.ResponseWriter, r *http.Request) {
	templateFiles := server.LayoutTemplateFiles
	templateFiles = append(templateFiles, "nodes/nodes.html")
	pageTemplate := server.GetTemplate(templateFiles...)
	data := server.InitPageData(r, "nodes", "/nodes", "Nodes", templateFiles)

	var pageError error
	data.Data, pageError = fh.getNodesPageData()
	if pageError != nil {
		server.HandlePageError(w, r, pageError)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	if server.HandleTemplateError(w, r, "nodes.go", "Nodes", "", pageTemplate.ExecuteTemplate(w, "layout", data)) != nil {
		return
	}
}

func (fh *FrontendHandler) getNodesPageData() (*NodesPageData, error) {
	nodes := fh.bootnodeService.GetActiveNodes()
	stats := fh.bootnodeService.GetStats()

	// Get current fork digest if available
	var currentForkDigest string
	if stats.ForkFilter != nil {
		currentForkDigest = stats.ForkFilter.CurrentDigest
	}

	pageData := &NodesPageData{
		CurrentForkDigest: currentForkDigest,
		ActiveNodes:       stats.ActiveNodes,
		InactiveNodes:     stats.InactiveNodes,
		Nodes:             make([]NodeInfo, 0, len(nodes)),
	}

	// Use the default maxNodeAge and maxFailures for IsAlive check
	// These match the bootnode config defaults
	maxNodeAge := 24 * time.Hour
	maxFailures := 3

	// Get fork scoring info for accurate node scoring
	var forkScoringInfo *node.ForkScoringInfo
	if forkFilter := fh.bootnodeService.ForkFilter(); forkFilter != nil {
		filterInfo := forkFilter.GetForkScoringInfo()
		// Convert to node.ForkScoringInfo
		forkScoringInfo = &node.ForkScoringInfo{
			CurrentForkDigest:  [4]byte(filterInfo.CurrentForkDigest),
			PreviousForkDigest: [4]byte(filterInfo.PreviousForkDigest),
			GenesisForkDigest:  [4]byte(filterInfo.GenesisForkDigest),
			GracePeriodEnd:     filterInfo.GracePeriodEnd,
		}
	}

	for _, n := range nodes {
		nodeInfo := NodeInfo{
			PeerID:       n.PeerID(),
			IP:           n.IP().String(),
			Port:         int(n.UDPPort()),
			FirstSeen:    n.FirstSeen(),
			LastSeen:     n.LastSeen(),
			SuccessCount: n.SuccessCount(),
			FailureCount: n.FailureCount(),
			IsAlive:      n.IsAlive(maxNodeAge, maxFailures),
			Score:        n.CalculateScore(forkScoringInfo),
			ENRSeq:       n.Record().Seq(),
			AvgRTT:       n.AvgRTT(),
		}

		// Extract eth2 fork digest if available
		if eth2Data, ok := n.Record().Eth2(); ok {
			nodeInfo.ForkDigest = fmt.Sprintf("%x", eth2Data.ForkDigest)
			nodeInfo.HasForkData = true
			nodeInfo.IsCurrentFork = (nodeInfo.ForkDigest == currentForkDigest)
		}

		// Get ENR string
		if enrStr, err := n.Record().EncodeBase64(); err == nil {
			nodeInfo.ENR = enrStr
		}

		pageData.Nodes = append(pageData.Nodes, nodeInfo)
	}

	// Sort nodes by PeerID for consistent ordering
	sort.Slice(pageData.Nodes, func(i, j int) bool {
		return pageData.Nodes[i].PeerID < pageData.Nodes[j].PeerID
	})

	pageData.TotalNodes = len(nodes)

	return pageData, nil
}
