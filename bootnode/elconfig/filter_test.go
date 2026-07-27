package elconfig

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// mainnetGenesisHash is the Ethereum mainnet genesis block hash, so the
// checksums below can be verified against go-ethereum's forkid test vectors.
var mainnetGenesisHash = mustHash32("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")

func mustHash32(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("bad hash literal")
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// mainnetConfig mirrors go-ethereum's params.MainnetChainConfig fork
// schedule. Mainnet's genesis block timestamp is 0.
func mainnetConfig() *ChainConfig {
	return &ChainConfig{rawConfig: map[string]interface{}{
		"homesteadBlock":      1150000,
		"daoForkBlock":        1920000,
		"eip150Block":         2463000,
		"eip155Block":         2675000,
		"eip158Block":         2675000,
		"byzantiumBlock":      4370000,
		"constantinopleBlock": 7280000,
		"petersburgBlock":     7280000,
		"istanbulBlock":       9069000,
		"muirGlacierBlock":    9200000,
		"berlinBlock":         12244000,
		"londonBlock":         12965000,
		"arrowGlacierBlock":   13773000,
		"grayGlacierBlock":    15050000,
		"shanghaiTime":        1681338455,
		"cancunTime":          1710338135,
		"pragueTime":          1746612311,
		"osakaTime":           1764798551,
		"bpo1Time":            1765290071,
		"bpo2Time":            1767747671,
	}}
}

// devnetConfig models a kurtosis-style devnet: every fork active at genesis.
func devnetConfig(genesisTime uint64) *ChainConfig {
	return &ChainConfig{rawConfig: map[string]interface{}{
		"homesteadBlock": 0,
		"londonBlock":    0,
		"shanghaiTime":   int(genesisTime),
		"cancunTime":     int(genesisTime),
		"pragueTime":     int(genesisTime),
	}}
}

func sum32(hash uint32) [4]byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], hash)
	return out
}

func TestGatherForksGenesisCutoff(t *testing.T) {
	byBlock, byTime := GatherForks(mainnetConfig(), 0)
	if len(byBlock) != 12 {
		t.Fatalf("block forks = %d (%v), want 12 deduplicated boundaries", len(byBlock), byBlock)
	}
	if len(byTime) != 6 {
		t.Fatalf("time forks = %d (%v), want 6", len(byTime), byTime)
	}
	for i := 1; i < len(byBlock); i++ {
		if byBlock[i] <= byBlock[i-1] {
			t.Fatalf("block forks not strictly ascending: %v", byBlock)
		}
	}

	_, byTime = GatherForks(mainnetConfig(), 1710338135)
	if len(byTime) != 4 || byTime[0] != 1746612311 {
		t.Fatalf("cutoff at cancun kept %v, want time forks strictly after the cutoff", byTime)
	}

	byBlock, byTime = GatherForks(devnetConfig(1700000000), 1700000000)
	if len(byBlock) != 0 || len(byTime) != 0 {
		t.Fatalf("all-at-genesis devnet gathered %v/%v, want none (genesis ruleset)", byBlock, byTime)
	}
}

// TestComputeForkIDNextSelection pins go-ethereum's mainnet TestCreation
// vectors at era boundaries.
func TestComputeForkIDNextSelection(t *testing.T) {
	byBlock, byTime := GatherForks(mainnetConfig(), 0)
	cases := []struct {
		head, time uint64
		wantHash   uint32
		wantNext   uint64
	}{
		{0, 0, 0xfc64ec04, 1150000},
		{1149999, 0, 0xfc64ec04, 1150000},
		{1150000, 0, 0x97c2c34c, 1920000},
		{15050000, 1681338454, 0xf0afd0e3, 1681338455},
		{20000000, 1681338455, 0xdce96c2d, 1710338135},
		{30000000, 1710338134, 0xdce96c2d, 1710338135},
		{30000000, 1710338135, 0x9f3d2254, 1746612311},
		{30000000, 1746612311, 0xc376cf8b, 1764798551},
		{30000000, 1767747671, 0x07c9462e, 0},
		{50000000, 2000000000, 0x07c9462e, 0},
	}
	for _, c := range cases {
		got := ComputeForkID(mainnetGenesisHash, byBlock, byTime, c.head, c.time)
		if got.Hash != sum32(c.wantHash) || got.Next != c.wantNext {
			t.Errorf("ComputeForkID(head=%d, time=%d) = %v, want {%#x %d}", c.head, c.time, got, c.wantHash, c.wantNext)
		}
	}
}

func TestComputeAllForkIDsConsistentWithComputeForkID(t *testing.T) {
	byBlock, byTime := GatherForks(mainnetConfig(), 0)
	all := ComputeAllForkIDs(mainnetGenesisHash, byBlock, byTime)
	if len(all) != len(byBlock)+len(byTime)+1 {
		t.Fatalf("enumerated %d ids, want %d", len(all), len(byBlock)+len(byTime)+1)
	}
	boundaries := append(append([]uint64{}, byBlock...), byTime...)
	for i, boundary := range boundaries {
		var head, time uint64
		if i < len(byBlock) {
			head = boundary
			time = 0
		} else {
			head = byBlock[len(byBlock)-1]
			time = boundary
		}
		got := ComputeForkID(mainnetGenesisHash, byBlock, byTime, head, time)
		if got != all[i+1] {
			t.Errorf("boundary %d: walked id %v != enumerated %v", boundary, got, all[i+1])
		}
	}
}

// TestGetCurrentForkIDUsesGenesisTime is the regression pin for the hardcoded
// genesisTime=0 bug: an all-at-genesis devnet must report the genesis-era id
// with no upcoming fork, and the result must be in the admission set.
func TestGetCurrentForkIDUsesGenesisTime(t *testing.T) {
	const genesisTime = 1700000000
	genesisHash := mustHash32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	f := NewForkFilter(genesisHash, devnetConfig(genesisTime), genesisTime)

	got := f.GetCurrentForkID(999999999, genesisTime+600)
	byBlock, byTime := GatherForks(devnetConfig(genesisTime), genesisTime)
	want := ComputeForkID(genesisHash, byBlock, byTime, 0, 0)
	if got != want || got.Next != 0 {
		t.Fatalf("devnet current fork id = %v, want genesis-era %v with Next 0", got, want)
	}
	found := false
	for _, id := range f.GetAllForkIDs() {
		if id == got {
			found = true
		}
	}
	if !found {
		t.Fatal("current fork id is not in the filter's own admission set")
	}

	mf := NewForkFilter(mainnetGenesisHash, mainnetConfig(), 0)
	if got := mf.GetCurrentForkID(999999999, 1710338135); got.Hash != sum32(0x9f3d2254) || got.Next != 1746612311 {
		t.Fatalf("mainnet current-era id = %v, want {0x9f3d2254 1746612311}", got)
	}
}

// TestForkFilterValidation ports the static-stance-relevant subset of
// go-ethereum's validation rules: the time head is pinned mid-Cancun.
func TestForkFilterValidation(t *testing.T) {
	f := NewForkFilter(mainnetGenesisHash, mainnetConfig(), 0)
	const now = 1720000000 // between cancun (1710338135) and prague (1746612311)

	cases := []struct {
		name   string
		id     ForkID
		accept bool
	}{
		{"current era, correct next", ForkID{sum32(0x9f3d2254), 1746612311}, true},
		{"current era, no next", ForkID{sum32(0x9f3d2254), 0}, true},
		{"current era, stale next already passed (rule 1a)", ForkID{sum32(0x9f3d2254), 1710338135}, false},
		{"subset syncing peer, correct next (rule 2)", ForkID{sum32(0xdce96c2d), 1710338135}, true},
		{"subset stale peer, wrong next (rule 2)", ForkID{sum32(0xdce96c2d), 0}, false},
		{"deep subset syncing peer, correct next", ForkID{sum32(0xfc64ec04), 1150000}, true},
		{"superset future peer (rule 3)", ForkID{sum32(0xc376cf8b), 1764798551}, true},
		{"unknown chain (rule 4)", ForkID{sum32(0xdeadbeef), 0}, false},
	}
	for _, c := range cases {
		err := f.validate(c.id, now)
		if (err == nil) != c.accept {
			t.Errorf("%s: validate(%v) = %v, want accept=%v", c.name, c.id, err, c.accept)
		}
	}

	f.RecordAdmission(true, cases[0].id)
	f.RecordAdmission(false, cases[7].id)
	stats := f.GetStats()
	if stats.TotalChecks != 2 || stats.Accepted != 1 || stats.Rejected != 1 || stats.LastRejectedID != cases[7].id {
		t.Fatalf("admission stats = %+v", stats)
	}
}

// TestGetAllForkIDsWithNamesAlignment covers duplicate activations: two
// upgrades sharing one timestamp must collapse to one named row per fork id.
func TestGetAllForkIDsWithNamesAlignment(t *testing.T) {
	cfg := &ChainConfig{rawConfig: map[string]interface{}{
		"homesteadBlock": 1000,
		"shanghaiTime":   5000,
		"cancunTime":     5000,
		"pragueTime":     6000,
	}}
	genesisHash := mustHash32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	f := NewForkFilter(genesisHash, cfg, 100)

	rows := f.GetAllForkIDsWithNames()
	if len(rows) != len(f.GetAllForkIDs()) {
		t.Fatalf("rows = %d, want one per fork id (%d)", len(rows), len(f.GetAllForkIDs()))
	}
	for i, row := range rows {
		if row.ForkID != f.GetAllForkIDs()[i] {
			t.Errorf("row %d id %v misaligned with enumerated %v", i, row.ForkID, f.GetAllForkIDs()[i])
		}
	}
	if rows[0].Name != "Genesis" || rows[1].Name != "Homestead" || rows[3].Name != "Prague" {
		t.Fatalf("row names = %q, %q, _, %q", rows[0].Name, rows[1].Name, rows[3].Name)
	}
	if !strings.Contains(rows[2].Name, "Shanghai") || !strings.Contains(rows[2].Name, "Cancun") || rows[2].Activation != 5000 || !rows[2].IsTime {
		t.Fatalf("shared-activation row = %+v, want both upgrade names at @5000", rows[2])
	}
}
