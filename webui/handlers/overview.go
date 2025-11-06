package handlers

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ethpandaops/bootnodoor/enode"
	"github.com/ethpandaops/bootnodoor/webui/server"
)

// ForkInfo represents fork information for display.
type ForkInfo struct {
	Name       string
	Digest     string
	Activation string // Block number, timestamp, or epoch
}

// OverviewPageData contains data for the overview page
type OverviewPageData struct {
	Status         string
	NetworkName    string
	StartTime      time.Time
	PeerID         string
	BindAddress    string
	LocalENR       string
	LocalEnode     string // NEW: Enode derived from ENR
	LocalENRSeq    uint64
	CurrentFork    string
	CurrentDigest  string
	PreviousFork   string
	PreviousDigest string
	GenesisDigest  string
	OldDigests     []OldDigestInfo
	GracePeriod    string

	// Fork lists
	ELForks []ForkInfo // Execution Layer forks
	CLForks []ForkInfo // Consensus Layer forks

	// Routing table stats (combined)
	TableSize     int
	BucketsFilled int // Deprecated for flat table
	ActiveNodes   int
	InactiveNodes int

	// EL Statistics (NEW)
	ELActiveNodes int
	ELTotalNodes  int
	ELTableStats  TableStats

	// CL Statistics (NEW)
	CLActiveNodes int
	CLTotalNodes  int
	CLTableStats  TableStats

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

	// Database stats
	DBQueueSize        int
	DBProcessedUpdates int64
	DBMergedUpdates    int64
	DBFailedUpdates    int64
	DBTransactions     int64
	DBTotalQueries     int64
	DBOpenConnections  int
}

// TableStats contains statistics for a routing table
type TableStats struct {
	ActiveNodes   int
	InactiveNodes int
	TotalNodes    int
	BucketsFilled int
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

// Enode serves the local enode URL as plain text
func (fh *FrontendHandler) Enode(w http.ResponseWriter, r *http.Request) {
	localNode := fh.bootnodeService.LocalNode()

	// Get TCP port from ENR, fallback to UDP port if not available
	tcpPort := localNode.TCPPort()
	if tcpPort == 0 {
		tcpPort = localNode.UDPPort()
	}

	// Create enode from local node info
	localEnode := &enode.Enode{
		PublicKey: localNode.PublicKey(),
		IP:        localNode.IP(),
		TCP:       tcpPort,
		UDP:       localNode.UDPPort(),
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(localEnode.String()))
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
	data.SetBootnodeStatus(fh.bootnodeService.ELTable() != nil, fh.bootnodeService.CLTable() != nil)

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
	// Get local node ENR
	localNode := fh.bootnodeService.LocalNode()
	localENR, err := localNode.Record().EncodeBase64()
	if err != nil {
		localENR = "" // Fallback to empty string on error
	}

	// Derive Enode from ENR
	localEnode := deriveEnodeFromENR(localNode.Record())

	// Get PeerID
	peerID := localNode.ID().String()

	// Get bind address
	bindAddr := "N/A"
	if addr := localNode.Addr(); addr != nil {
		bindAddr = addr.String()
	}

	// Initialize page data with basic info
	pageData := &OverviewPageData{
		Status:      "Online",
		StartTime:   time.Now(), // TODO: Track actual start time in service
		PeerID:      peerID,
		BindAddress: bindAddr,
		LocalENR:    localENR,
		LocalEnode:  localEnode,
		LocalENRSeq: localNode.Record().Seq(),
	}

	// Get EL table stats if available
	if elTable := fh.bootnodeService.ELTable(); elTable != nil {
		elStats := elTable.GetStats()
		elInactiveNodes := elStats.TotalNodes - elStats.ActiveNodes
		pageData.ELActiveNodes = elStats.ActiveNodes
		pageData.ELTotalNodes = elStats.TotalNodes
		pageData.ELTableStats = TableStats{
			ActiveNodes:   elStats.ActiveNodes,
			InactiveNodes: elInactiveNodes,
			TotalNodes:    elStats.TotalNodes,
			BucketsFilled: elStats.BucketsFilled,
		}
		// Update combined stats
		pageData.ActiveNodes += elStats.ActiveNodes
		pageData.TableSize += elStats.TotalNodes
		pageData.InactiveNodes += elInactiveNodes
	}

	// Get CL table stats if available
	if clTable := fh.bootnodeService.CLTable(); clTable != nil {
		clStats := clTable.GetStats()
		clInactiveNodes := clStats.TotalNodes - clStats.ActiveNodes
		pageData.CLActiveNodes = clStats.ActiveNodes
		pageData.CLTotalNodes = clStats.TotalNodes
		pageData.CLTableStats = TableStats{
			ActiveNodes:   clStats.ActiveNodes,
			InactiveNodes: clInactiveNodes,
			TotalNodes:    clStats.TotalNodes,
			BucketsFilled: clStats.BucketsFilled,
		}
		// Update combined stats
		pageData.ActiveNodes += clStats.ActiveNodes
		pageData.TableSize += clStats.TotalNodes
		pageData.InactiveNodes += clInactiveNodes
	}

	// Get EL fork list with names
	if elConfig := fh.bootnodeService.ELConfig(); elConfig != nil {
		if enrMgr := fh.bootnodeService.ENRManager(); enrMgr != nil {
			if elFilter := enrMgr.GetELFilter(); elFilter != nil {
				// Get genesis time from config
				genesisTime := uint64(0)
				if fh.bootnodeService.ELConfig() != nil {
					// Note: We'd need the genesis time here, defaulting to 0
				}

				allForksWithNames := elFilter.GetAllForkIDsWithNames(genesisTime)
				pageData.ELForks = make([]ForkInfo, 0, len(allForksWithNames))
				for _, fork := range allForksWithNames {
					// Format activation point
					activation := "0"
					if fork.Activation > 0 {
						if fork.IsTime {
							activation = fmt.Sprintf("@%d", fork.Activation)
						} else {
							activation = fmt.Sprintf("#%d", fork.Activation)
						}
					}

					pageData.ELForks = append(pageData.ELForks, ForkInfo{
						Name:       fork.Name,
						Digest:     fmt.Sprintf("%#x", fork.ForkID.Hash),
						Activation: activation,
					})
				}
			}
		}
	}

	// Get CL fork list - show all forks (past, current, and future)
	if clConfig := fh.bootnodeService.CLConfig(); clConfig != nil {
		allForkInfos := clConfig.GetAllForkDigestInfos()

		// Filter to keep only the last fork at each epoch
		// Build a map of epoch -> last fork at that epoch
		epochMap := make(map[uint64]int) // epoch -> index in allForkInfos
		for i, forkInfo := range allForkInfos {
			// Always update to the latest fork at this epoch
			epochMap[forkInfo.Epoch] = i
		}

		// Sort epochs to maintain order
		epochOrder := make([]uint64, 0, len(epochMap))
		for epoch := range epochMap {
			epochOrder = append(epochOrder, epoch)
		}
		// Simple bubble sort
		for i := 0; i < len(epochOrder); i++ {
			for j := i + 1; j < len(epochOrder); j++ {
				if epochOrder[i] > epochOrder[j] {
					epochOrder[i], epochOrder[j] = epochOrder[j], epochOrder[i]
				}
			}
		}

		// Build the filtered fork list in epoch order
		pageData.CLForks = make([]ForkInfo, 0, len(epochMap))
		for _, epoch := range epochOrder {
			idx := epochMap[epoch]
			forkInfo := allForkInfos[idx]

			// Format display name
			displayName := forkInfo.Name

			// For genesis (epoch 0), format as "ForkName/Genesis"
			if forkInfo.Epoch == 0 {
				// Extract the fork name (everything before "/Genesis" if present)
				baseName := displayName
				if len(displayName) > 8 && displayName[len(displayName)-8:] == "/Genesis" {
					baseName = displayName[:len(displayName)-8]
				}
				// Capitalize first letter
				if len(baseName) > 0 && baseName[0] >= 'a' && baseName[0] <= 'z' {
					baseName = string(baseName[0]-32) + baseName[1:]
				}
				displayName = baseName + "/Genesis"
			} else {
				// Capitalize first letter for non-genesis forks
				if len(displayName) > 0 && displayName[0] >= 'a' && displayName[0] <= 'z' {
					displayName = string(displayName[0]-32) + displayName[1:]
				}
			}

			// Format epoch
			epochStr := fmt.Sprintf("%d", forkInfo.Epoch)

			pageData.CLForks = append(pageData.CLForks, ForkInfo{
				Name:       displayName,
				Digest:     "0x" + forkInfo.Digest.String(),
				Activation: epochStr,
			})
		}
	}

	// Get database stats by combining EL and CL stats
	if elNodeDB := fh.bootnodeService.ELNodeDB(); elNodeDB != nil {
		elDBStats := elNodeDB.GetStats()
		pageData.DBQueueSize += elDBStats.QueueSize
		pageData.DBProcessedUpdates += elDBStats.ProcessedUpdates
		pageData.DBMergedUpdates += elDBStats.MergedUpdates
		pageData.DBFailedUpdates += elDBStats.FailedUpdates
		pageData.DBTransactions += elDBStats.Transactions
		pageData.DBTotalQueries += elDBStats.TotalQueries
		pageData.DBOpenConnections = elDBStats.OpenConnections // Use max, not sum
	}

	if clNodeDB := fh.bootnodeService.CLNodeDB(); clNodeDB != nil {
		clDBStats := clNodeDB.GetStats()
		pageData.DBQueueSize += clDBStats.QueueSize
		pageData.DBProcessedUpdates += clDBStats.ProcessedUpdates
		pageData.DBMergedUpdates += clDBStats.MergedUpdates
		pageData.DBFailedUpdates += clDBStats.FailedUpdates
		pageData.DBTransactions += clDBStats.Transactions
		pageData.DBTotalQueries += clDBStats.TotalQueries
		// Use CL's connection count if it's higher (they share the same DB though)
		if clDBStats.OpenConnections > pageData.DBOpenConnections {
			pageData.DBOpenConnections = clDBStats.OpenConnections
		}
	}

	// Note: Detailed stats (lookups, pings, sessions, etc.) are not available
	// through the public API of the new bootnode service. These would need to be
	// exposed through additional methods if required.

	return pageData, nil
}

// deriveEnodeFromENR derives an enode:// URL from an ENR record
func deriveEnodeFromENR(record interface {
	IP() net.IP
	UDP() uint16
	PublicKey() *ecdsa.PublicKey
}) string {
	ip := record.IP()
	udpPort := record.UDP()
	pubKey := record.PublicKey()

	if ip == nil || udpPort == 0 || pubKey == nil {
		return ""
	}

	// Convert public key to uncompressed format (65 bytes: 0x04 + X + Y)
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	pubKey.X.FillBytes(pubKeyBytes[1:33])
	pubKey.Y.FillBytes(pubKeyBytes[33:65])

	// For enode, we only use X and Y coordinates (skip the 0x04 prefix)
	pubKeyHex := hex.EncodeToString(pubKeyBytes[1:])

	// Format IP address
	ipStr := ip.String()

	// Build enode URL
	return fmt.Sprintf("enode://%s@%s:%d", pubKeyHex, ipStr, udpPort)
}
