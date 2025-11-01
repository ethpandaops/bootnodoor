package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/pk910/bootoor/webui/server"
)

// OverviewPageData contains data for the overview page
type OverviewPageData struct {
	Status          string
	NetworkName     string
	StartTime       time.Time
	PeerID          string
	BindAddress     string
	LocalENR        string
	LocalENRSeq     uint64
	CurrentFork     string
	CurrentDigest   string
	OldDigests      []OldDigestInfo
	GracePeriod     string

	// Routing table stats
	TableSize       int
	BucketsFilled   int // Deprecated for flat table
	ActiveNodes     int
	InactiveNodes   int

	// Discovery stats
	LookupsStarted   int
	LookupsCompleted int
	LookupsFailed    int

	// Ping stats
	PingsSent       int
	PongsReceived   int
	PingSuccessRate float64

	// Session stats
	SessionsTotal   int
	SessionsActive  int
	SessionsExpired int

	// Pending operations
	PendingHandshakes int
	PendingChallenges int

	// Handler stats
	PacketsReceived   int
	PacketsSent       int
	InvalidPackets    int
	FilteredResponses int
	FindNodeReceived  int

	// Fork filter stats
	FilterAcceptedCurrent int
	FilterAcceptedOld     int
	FilterRejectedInvalid int
	FilterRejectedExpired int
	FilterTotalChecks     int
}

type OldDigestInfo struct {
	Digest    string
	Remaining time.Duration
}

// ENR serves the local ENR as plain text
func (fh *FrontendHandler) ENR(w http.ResponseWriter, r *http.Request) {
	localNode := fh.bootnodeService.LocalNode()
	localENR, err := localNode.Record().EncodeBase64()
	if err != nil {
		http.Error(w, "Failed to encode ENR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(localENR))
}

// Overview renders the overview page
func (fh *FrontendHandler) Overview(w http.ResponseWriter, r *http.Request) {
	// Check if this is an AJAX request for JSON data
	if r.URL.Query().Get("ajax") == "1" {
		pageData, err := fh.getOverviewPageData()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pageData)
		return
	}

	templateFiles := server.LayoutTemplateFiles
	templateFiles = append(templateFiles, "overview/overview.html")
	pageTemplate := server.GetTemplate(templateFiles...)
	data := server.InitPageData(r, "overview", "/", "Overview", templateFiles)

	var pageError error
	data.Data, pageError = fh.getOverviewPageData()
	if pageError != nil {
		server.HandlePageError(w, r, pageError)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	if server.HandleTemplateError(w, r, "overview.go", "Overview", "", pageTemplate.ExecuteTemplate(w, "layout", data)) != nil {
		return
	}
}

func (fh *FrontendHandler) getOverviewPageData() (*OverviewPageData, error) {
	stats := fh.bootnodeService.GetStats()

	// Get local node ENR
	localNode := fh.bootnodeService.LocalNode()
	localENR, err := localNode.Record().EncodeBase64()
	if err != nil {
		localENR = "" // Fallback to empty string on error
	}

	pageData := &OverviewPageData{
		Status:            "Online",
		StartTime:         time.Now().Add(-stats.Uptime),
		PeerID:            stats.PeerID,
		BindAddress:       stats.BindAddress,
		LocalENR:          localENR,
		LocalENRSeq:       localNode.Record().Seq(),
		TableSize:         stats.TableSize,
		BucketsFilled:     stats.BucketsFilled,
		ActiveNodes:       stats.ActiveNodes,
		InactiveNodes:     stats.InactiveNodes,
		LookupsStarted:    stats.LookupStats.LookupsStarted,
		LookupsCompleted:  stats.LookupStats.LookupsCompleted,
		LookupsFailed:     stats.LookupStats.LookupsFailed,
		PingsSent:         stats.PingStats.PingsSent,
		PongsReceived:     stats.PingStats.PongsReceived,
		PingSuccessRate:   stats.PingStats.SuccessRate,
		SessionsTotal:     stats.SessionStats.Total,
		SessionsActive:    stats.SessionStats.Active,
		SessionsExpired:   stats.SessionStats.Expired,
		PendingHandshakes: stats.HandlerStats.PendingHandshakes,
		PendingChallenges: stats.HandlerStats.PendingChallenges,
		PacketsReceived:   stats.HandlerStats.PacketsReceived,
		PacketsSent:       stats.HandlerStats.PacketsSent,
		InvalidPackets:    stats.HandlerStats.InvalidPackets,
		FilteredResponses: stats.HandlerStats.FilteredResponses,
		FindNodeReceived:  stats.HandlerStats.FindNodeReceived,
	}

	// Add fork filter stats if available
	if stats.ForkFilter != nil {
		pageData.NetworkName = stats.ForkFilter.NetworkName
		pageData.CurrentFork = stats.ForkFilter.CurrentFork
		pageData.CurrentDigest = stats.ForkFilter.CurrentDigest
		pageData.GracePeriod = stats.ForkFilter.GracePeriod
		pageData.FilterAcceptedCurrent = stats.ForkFilter.AcceptedCurrent
		pageData.FilterAcceptedOld = stats.ForkFilter.AcceptedOld
		pageData.FilterRejectedInvalid = stats.ForkFilter.RejectedInvalid
		pageData.FilterRejectedExpired = stats.ForkFilter.RejectedExpired
		pageData.FilterTotalChecks = stats.ForkFilter.TotalChecks

		// Convert old digests map
		pageData.OldDigests = make([]OldDigestInfo, 0, len(stats.ForkFilter.OldDigests))
		for digest, remaining := range stats.ForkFilter.OldDigests {
			pageData.OldDigests = append(pageData.OldDigests, OldDigestInfo{
				Digest:    digest,
				Remaining: remaining,
			})
		}
	}

	return pageData, nil
}
