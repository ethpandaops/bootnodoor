package handlers

import (
	"github.com/ethpandaops/bootnodoor/bootnode"
	"github.com/ethpandaops/bootnodoor/webui/ipnames"
)

type FrontendHandler struct {
	bootnodeService *bootnode.Service
	ipNames         *ipnames.Resolver
}

// NewFrontendHandler creates a frontend handler. ipNames may be nil, in
// which case nodes are shown by IP only.
func NewFrontendHandler(bootnodeService *bootnode.Service, ipNames *ipnames.Resolver) *FrontendHandler {
	return &FrontendHandler{
		bootnodeService: bootnodeService,
		ipNames:         ipNames,
	}
}

// ipName returns the configured display name for an IP, or "" if none.
func (fh *FrontendHandler) ipName(ip string) string {
	if fh.ipNames == nil {
		return ""
	}
	return fh.ipNames.Lookup(ip)
}
