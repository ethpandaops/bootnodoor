package handlers

import (
	"net/http"
	"time"

	"github.com/pk910/bootoor/webui/server"
)

// NodesPageData contains data for the nodes page
type NodesPageData struct {
	TotalNodes        int
	CurrentForkDigest string
	Buckets           []BucketInfo
}

type BucketInfo struct {
	Index     int
	Distance  string
	NodeCount int
	Nodes     []NodeInfo
}

type NodeInfo struct {
	PeerID        string
	IP            string
	Port          int
	FirstSeen     time.Time
	LastSeen      time.Time
	SuccessCount  int
	FailureCount  int
	IsAlive       bool
	Score         int
	ForkDigest    string
	HasForkData   bool
	IsCurrentFork bool
	ENRSeq        uint64
	ENR           string
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
	buckets := fh.bootnodeService.GetBuckets()
	stats := fh.bootnodeService.GetStats()

	// Get current fork digest if available
	var currentForkDigest string
	if stats.ForkFilter != nil {
		currentForkDigest = stats.ForkFilter.CurrentDigest
	}

	pageData := &NodesPageData{
		CurrentForkDigest: currentForkDigest,
		Buckets:           make([]BucketInfo, 0, len(buckets)),
	}

	totalNodes := 0
	for _, bucket := range buckets {
		if len(bucket.Nodes) == 0 {
			continue
		}

		bucketInfo := BucketInfo{
			Index:     bucket.Index,
			Distance:  bucket.Distance,
			NodeCount: len(bucket.Nodes),
			Nodes:     make([]NodeInfo, 0, len(bucket.Nodes)),
		}

		for _, node := range bucket.Nodes {
			nodeInfo := NodeInfo{
				PeerID:       node.PeerID,
				IP:           node.IP,
				Port:         node.Port,
				FirstSeen:    node.FirstSeen,
				LastSeen:     node.LastSeen,
				SuccessCount: node.SuccessCount,
				FailureCount: node.FailureCount,
				IsAlive:      node.IsAlive,
				Score:        node.Score,
				ForkDigest:   node.ForkDigest,
				HasForkData:  node.HasForkData,
				ENRSeq:       node.ENRSeq,
				ENR:          node.ENR,
			}

			// Check if this node is on the current fork
			if node.HasForkData && currentForkDigest != "" {
				nodeInfo.IsCurrentFork = (node.ForkDigest == currentForkDigest)
			}

			bucketInfo.Nodes = append(bucketInfo.Nodes, nodeInfo)
			totalNodes++
		}

		pageData.Buckets = append(pageData.Buckets, bucketInfo)
	}

	pageData.TotalNodes = totalNodes

	return pageData, nil
}
