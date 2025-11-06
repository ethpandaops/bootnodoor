package elconfig

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// LoadChainConfig loads a chain config from a JSON file.
//
// The file should be in geth's chain config format.
//
// Example:
//
//	config, err := LoadChainConfig("/path/to/mainnet.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadChainConfig(path string) (*ChainConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return ParseChainConfig(data)
}

// ParseChainConfig parses a chain config from JSON bytes.
func ParseChainConfig(data []byte) (*ChainConfig, error) {
	// First parse as map to extract fork data dynamically
	var rawConfig map[string]interface{}
	if err := json.Unmarshal(data, &rawConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config as map: %w", err)
	}

	// Create config and store raw data
	config := &ChainConfig{
		rawConfig: rawConfig,
	}

	// Extract ChainID if present
	if chainIDValue, ok := rawConfig["chainId"]; ok {
		switch v := chainIDValue.(type) {
		case float64:
			config.ChainID = big.NewInt(int64(v))
		case int:
			config.ChainID = big.NewInt(int64(v))
		case int64:
			config.ChainID = big.NewInt(v)
		case string:
			if chainID, ok := new(big.Int).SetString(v, 0); ok {
				config.ChainID = chainID
			}
		}
	}

	// Extract fork data dynamically
	config.extractForkData()

	return config, nil
}

// MarshalChainConfig serializes a chain config to JSON.
func MarshalChainConfig(config *ChainConfig) ([]byte, error) {
	if config.rawConfig != nil {
		return json.MarshalIndent(config.rawConfig, "", "  ")
	}
	// Fallback: create a minimal config with chainId
	output := make(map[string]interface{})
	if config.ChainID != nil {
		output["chainId"] = config.ChainID.Uint64()
	}
	return json.MarshalIndent(output, "", "  ")
}

// WriteChainConfig writes a chain config to a JSON file.
func WriteChainConfig(path string, config *ChainConfig) error {
	data, err := MarshalChainConfig(config)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
