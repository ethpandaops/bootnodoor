package handlers

import "github.com/ethpandaops/bootnodoor/bootnode"

type FrontendHandler struct {
	bootnodeService *bootnode.Service
}

func NewFrontendHandler(bootnodeService *bootnode.Service) *FrontendHandler {
	return &FrontendHandler{
		bootnodeService: bootnodeService,
	}
}
