package elconfig

import "testing"

// TestParseGenesisTimestamp accepts both encodings seen in the wild: geth and
// eth-clients publish hex (Sepolia's genesis.json), kurtosis and older files decimal.
func TestParseGenesisTimestamp(t *testing.T) {
	cases := []struct {
		name, timestamp string
	}{
		{"hex", `"0x6159af19"`},
		{"decimal", `"1633267481"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := []byte(`{"config":{"chainId":11155111,"amsterdamTime":1791294816},"timestamp":` + c.timestamp + `}`)
			g, err := ParseGenesis(data)
			if err != nil {
				t.Fatalf("ParseGenesis: %v", err)
			}
			if got := g.GetTimestamp(); got != sepoliaGenesisTime {
				t.Fatalf("GetTimestamp() = %d, want %d", got, sepoliaGenesisTime)
			}
		})
	}
}

func TestParseGenesisMissingTimestamp(t *testing.T) {
	if _, err := ParseGenesis([]byte(`{"config":{"chainId":1}}`)); err == nil {
		t.Fatal("expected error for genesis without timestamp")
	}
	g, err := ParseGenesis([]byte(`{"config":{"chainId":1},"timestamp":"0x0"}`))
	if err != nil {
		t.Fatalf("zero timestamp: %v", err)
	}
	if got := g.GetTimestamp(); got != 0 {
		t.Fatalf("GetTimestamp() = %d, want 0", got)
	}
}
