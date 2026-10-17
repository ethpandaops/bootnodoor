package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	testHoodiGenesis = `{"config":{"chainId":560048,"shanghaiTime":0,"pragueTime":1742999832},"timestamp":"0x67d80ec0"}`
	testHoodiConfig  = "CONFIG_NAME: hoodi\nGENESIS_FORK_VERSION: 0x10000910\nALTAIR_FORK_VERSION: 0x20000910\nALTAIR_FORK_EPOCH: 0\nELECTRA_FORK_VERSION: 0x60000910\nELECTRA_FORK_EPOCH: 2048\n"
)

type testServer struct {
	mu       sync.Mutex
	files    map[string]string
	status   int
	requests atomic.Int32
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	s := &testServer{
		status: http.StatusOK,
		files: map[string]string{
			"/hoodi/main/metadata/genesis.json": testHoodiGenesis,
			"/hoodi/main/metadata/config.yaml":  testHoodiConfig,
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		body, ok := s.files[r.URL.Path]
		if !ok || s.status != http.StatusOK {
			w.WriteHeader(max(s.status, http.StatusNotFound))
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	oldURL := networkConfigBaseURL
	networkConfigBaseURL = srv.URL
	t.Cleanup(func() { networkConfigBaseURL = oldURL })
	return s
}

func (s *testServer) set(path, body string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path != "" {
		s.files[path] = body
	}
	s.status = status
}

// newNetworkCmd rebinds the package flag globals to their defaults, then
// parses args, so each case starts clean and Changed reflects only args.
func newNetworkCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	f := cmd.Flags()
	f.StringVar(&network, "network", "", "")
	f.StringVar(&nodeDBPath, "nodedb", "", "")
	f.BoolVar(&enableEL, "enable-el", true, "")
	f.BoolVar(&enableCL, "enable-cl", true, "")
	f.StringVar(&elConfigPath, "el-config", "", "")
	f.StringVar(&elGenesisHash, "el-genesis-hash", "", "")
	f.StringVar(&clConfigPath, "cl-config", "", "")
	f.StringVar(&genesisValidatorsRoot, "genesis-validators-root", "", "")
	f.Uint64Var(&clGenesisTime, "cl-genesis-time", 0, "")
	if err := cmd.ParseFlags(append([]string{"--nodedb", filepath.Join(t.TempDir(), "nodes.db")}, args...)); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	return cmd
}

func quietLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestResolveNetwork_FillsFlagsAndCache(t *testing.T) {
	newTestServer(t)
	cmd := newNetworkCmd(t, "--network", "hoodi")
	if err := resolveNetwork(cmd, quietLogger()); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	wantDir := filepath.Join(filepath.Dir(nodeDBPath), "network-hoodi")
	if elConfigPath != filepath.Join(wantDir, "genesis.json") || clConfigPath != filepath.Join(wantDir, "config.yaml") {
		t.Fatalf("config paths = %q, %q; want under %q", elConfigPath, clConfigPath, wantDir)
	}
	if got := readFile(t, elConfigPath); got != testHoodiGenesis {
		t.Fatalf("cached genesis = %q", got)
	}
	nw := knownNetworks["hoodi"]
	if elGenesisHash != nw.elGenesisHash || genesisValidatorsRoot != nw.genesisValidatorsRoot || clGenesisTime != nw.clGenesisTime {
		t.Fatalf("filled values = %q, %q, %d", elGenesisHash, genesisValidatorsRoot, clGenesisTime)
	}
}

func TestResolveNetwork_FallsBackToCache(t *testing.T) {
	const (
		genesisPath = "/hoodi/main/metadata/genesis.json"
		configPath  = "/hoodi/main/metadata/config.yaml"
	)
	elOnly := []string{"--network", "hoodi", "--enable-cl=false"}
	clOnly := []string{"--network", "hoodi", "--enable-el=false"}
	elPath := func() string { return elConfigPath }
	clPath := func() string { return clConfigPath }
	cases := []struct {
		name     string
		args     []string
		path     string
		body     string
		status   int
		original string
		got      func() string
	}{
		{"el server error", elOnly, genesisPath, "", http.StatusInternalServerError, testHoodiGenesis, elPath},
		{"el bad json", elOnly, genesisPath, "{", http.StatusOK, testHoodiGenesis, elPath},
		{"el null config", elOnly, genesisPath, `{"config":null,"timestamp":"0x0"}`, http.StatusOK, testHoodiGenesis, elPath},
		{"el no timestamp or forks", elOnly, genesisPath, `{"config":{"chainId":560048}}`, http.StatusOK, testHoodiGenesis, elPath},
		{"el no forks", elOnly, genesisPath, `{"config":{"chainId":560048},"timestamp":"0x0"}`, http.StatusOK, testHoodiGenesis, elPath},
		{"el wrong chain", elOnly, genesisPath, `{"config":{"chainId":1,"pragueTime":1742999832},"timestamp":"0x0"}`, http.StatusOK, testHoodiGenesis, elPath},
		{"cl server error", clOnly, configPath, "", http.StatusInternalServerError, testHoodiConfig, clPath},
		{"cl bad yaml", clOnly, configPath, "CONFIG_NAME: [", http.StatusOK, testHoodiConfig, clPath},
		{"cl wrong name", clOnly, configPath, strings.Replace(testHoodiConfig, "hoodi", "sepolia", 1), http.StatusOK, testHoodiConfig, clPath},
		{"cl no forks after genesis", clOnly, configPath, strings.Replace(testHoodiConfig, "EPOCH: 2048", "EPOCH: 0", 1), http.StatusOK, testHoodiConfig, clPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			cmd := newNetworkCmd(t, tc.args...)
			if err := resolveNetwork(cmd, quietLogger()); err != nil {
				t.Fatalf("first resolve: %v", err)
			}
			cached := tc.got()
			db := nodeDBPath

			srv.set(tc.path, tc.body, tc.status)
			cmd = newNetworkCmd(t, append(tc.args, "--nodedb", db)...)
			if err := resolveNetwork(cmd, quietLogger()); err != nil {
				t.Fatalf("resolve with cache: %v", err)
			}
			if tc.got() != cached {
				t.Fatalf("config path = %q, want cached %q", tc.got(), cached)
			}
			if got := readFile(t, cached); got != tc.original {
				t.Fatalf("cache was replaced: %q", got)
			}
		})
	}
}

func TestResolveNetwork_InvalidCacheRejected(t *testing.T) {
	srv := newTestServer(t)
	args := []string{"--network", "hoodi", "--enable-cl=false"}
	if err := resolveNetwork(newNetworkCmd(t, args...), quietLogger()); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	db := nodeDBPath
	if err := os.WriteFile(elConfigPath, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv.set("", "", http.StatusInternalServerError)
	if err := resolveNetwork(newNetworkCmd(t, append(args, "--nodedb", db)...), quietLogger()); err == nil {
		t.Fatal("expected error for an invalid cached copy")
	}
}

func TestResolveNetwork_CacheIsWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows does not keep unix permission bits")
	}
	newTestServer(t)
	if err := resolveNetwork(newNetworkCmd(t, "--network", "hoodi"), quietLogger()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, path := range []string{elConfigPath, clConfigPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o644 {
			t.Fatalf("%s mode = %o, want 644", path, mode)
		}
	}
}

func TestResolveNetwork_FetchFailsWithoutCache(t *testing.T) {
	srv := newTestServer(t)
	srv.set("", "", http.StatusInternalServerError)
	cmd := newNetworkCmd(t, "--network", "hoodi")
	if err := resolveNetwork(cmd, quietLogger()); err == nil {
		t.Fatal("expected error without a cached copy")
	}
}

func TestResolveNetwork_ExplicitFlagsWin(t *testing.T) {
	newTestServer(t)
	cmd := newNetworkCmd(t, "--network", "hoodi",
		"--el-genesis-hash", "0x01",
		"--genesis-validators-root", "0x02",
		"--cl-genesis-time", "0")
	if err := resolveNetwork(cmd, quietLogger()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if elGenesisHash != "0x01" || genesisValidatorsRoot != "0x02" || clGenesisTime != 0 {
		t.Fatalf("explicit flags overwritten: %q, %q, %d", elGenesisHash, genesisValidatorsRoot, clGenesisTime)
	}
}

func TestResolveNetwork_ConfigFlagOwnsLayer(t *testing.T) {
	srv := newTestServer(t)
	cmd := newNetworkCmd(t, "--network", "hoodi", "--el-config", "custom.json", "--cl-config", "custom.yaml")
	if err := resolveNetwork(cmd, quietLogger()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n := srv.requests.Load(); n != 0 {
		t.Fatalf("fetched %d files, want none", n)
	}
	if elConfigPath != "custom.json" || elGenesisHash != "" {
		t.Fatalf("EL layer changed: %q, %q", elConfigPath, elGenesisHash)
	}
	if clConfigPath != "custom.yaml" || genesisValidatorsRoot != "" || clGenesisTime != 0 {
		t.Fatalf("CL layer changed: %q, %q, %d", clConfigPath, genesisValidatorsRoot, clGenesisTime)
	}
}

func TestResolveNetwork_Rejects(t *testing.T) {
	newTestServer(t)
	for name, args := range map[string][]string{
		"unknown network": {"--network", "holesky"},
		"no layers":       {"--network", "hoodi", "--enable-el=false", "--enable-cl=false"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := resolveNetwork(newNetworkCmd(t, args...), quietLogger()); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFetchNetworkFile_Concurrent(t *testing.T) {
	newTestServer(t)
	network = "hoodi"
	path := filepath.Join(t.TempDir(), "genesis.json")
	validate := func(p string) error { return validateNetworkGenesis(p, knownNetworks["hoodi"].chainID) }

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- fetchNetworkFile(quietLogger(), networkFileURL("genesis.json"), path, validate)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent fetch: %v", err)
		}
	}
	if got := readFile(t, path); got != testHoodiGenesis {
		t.Fatalf("cached genesis = %q", got)
	}
	leftovers, _ := filepath.Glob(path + ".*.tmp")
	if len(leftovers) != 0 {
		t.Fatalf("temp files left: %v", leftovers)
	}
}

func TestResolveNetwork_CacheWithoutNodeDB(t *testing.T) {
	newTestServer(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", t.TempDir())
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := resolveNetwork(newNetworkCmd(t, "--network", "hoodi", "--nodedb", ""), quietLogger()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := filepath.Join(cache, "bootnodoor", "network-hoodi", "genesis.json"); elConfigPath != want {
		t.Fatalf("config path = %q, want %q", elConfigPath, want)
	}
}

func TestResolveNetwork_RejectsSymlinkedCacheDir(t *testing.T) {
	newTestServer(t)
	base := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(base, "network-hoodi")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	cmd := newNetworkCmd(t, "--network", "hoodi", "--nodedb", filepath.Join(base, "nodes.db"))
	if err := resolveNetwork(cmd, quietLogger()); err == nil {
		t.Fatal("expected error for a symlinked cache directory")
	}
}

func TestResolveNetwork_NoCacheDirWithoutFetch(t *testing.T) {
	newTestServer(t)
	base := t.TempDir()
	cmd := newNetworkCmd(t, "--network", "hoodi", "--nodedb", filepath.Join(base, "nodes.db"),
		"--el-config", "custom.json", "--cl-config", "custom.yaml")
	if err := resolveNetwork(cmd, quietLogger()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "network-hoodi")); !os.IsNotExist(err) {
		t.Fatalf("cache dir created without a fetch: %v", err)
	}
}

func TestResolveNetwork_NoCacheLocation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.UserCacheDir uses %LocalAppData%, not HOME, on windows")
	}
	newTestServer(t)
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	if err := resolveNetwork(newNetworkCmd(t, "--network", "hoodi", "--nodedb", ""), quietLogger()); err == nil {
		t.Fatal("expected error without --nodedb or a user cache directory")
	}
}
