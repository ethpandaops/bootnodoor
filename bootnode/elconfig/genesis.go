package elconfig

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// Genesis represents an Execution Layer genesis specification.
// This is a minimal version focused on extracting metadata needed for bootnode operation.
type Genesis struct {
	Config    *ChainConfig       `json:"config"`
	Timestamp uint64             `json:"timestamp,string"`
	Alloc     map[string]interface{} `json:"alloc,omitempty"`
}

// LoadGenesis loads a genesis file and parses both the config and metadata.
//
// The genesis file should be in geth's genesis format (JSON).
//
// Example:
//
//	genesis, err := LoadGenesis("/path/to/genesis.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadGenesis(path string) (*Genesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read genesis file: %w", err)
	}

	return ParseGenesis(data)
}

// ParseGenesis parses a genesis specification from JSON bytes.
func ParseGenesis(data []byte) (*Genesis, error) {
	var genesis Genesis

	// Parse as map first to get raw config
	var rawGenesis map[string]interface{}
	if err := json.Unmarshal(data, &rawGenesis); err != nil {
		return nil, fmt.Errorf("failed to parse genesis JSON: %w", err)
	}

	// Parse into struct
	if err := json.Unmarshal(data, &genesis); err != nil {
		return nil, fmt.Errorf("failed to parse genesis: %w", err)
	}

	// Parse the config if present
	if configData, ok := rawGenesis["config"]; ok {
		configBytes, err := json.Marshal(configData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal config: %w", err)
		}
		config, err := ParseChainConfig(configBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chain config: %w", err)
		}
		genesis.Config = config
	}

	if genesis.Config == nil {
		return nil, fmt.Errorf("genesis has no chain configuration")
	}

	return &genesis, nil
}

// GetTimestamp returns the genesis timestamp.
func (g *Genesis) GetTimestamp() uint64 {
	return g.Timestamp
}

// GetChainConfig returns the chain configuration.
func (g *Genesis) GetChainConfig() *ChainConfig {
	return g.Config
}

// GetChainID returns the chain ID from the config.
func (g *Genesis) GetChainID() *big.Int {
	if g.Config == nil {
		return nil
	}
	return g.Config.ChainID
}
