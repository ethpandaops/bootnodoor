# bootnodoor - Universal Ethereum Bootnode

A comprehensive Ethereum bootnode implementation supporting both Execution Layer (EL) and Consensus Layer (CL) peer discovery with intelligent fork-aware filtering.

> **Note**: This project is under active development and not yet production-ready. Use at your own risk.

## Project Structure

bootnodoor provides a unified bootnode service with multiple protocol implementations:

### 1. Universal Bootnode Service (`bootnode/`)

A complete dual-stack bootnode supporting both EL and CL networks:

- **Dual Layer Support**: Run EL-only, CL-only, or both simultaneously
- **Dual Protocol Support**: Discovery v4 (discv4) and Discovery v5 (discv5)
- **Protocol Multiplexing**: Both protocols share a single UDP port
- **Fork-Aware Filtering**:
  - EL: EIP-2124 fork ID validation via `eth` ENR field
  - CL: Fork digest validation via `eth2` ENR field with grace periods
- **Separate Routing Tables**: Independent tables for EL and CL nodes (500 nodes each by default)
- **Intelligent Node Routing**: Only serves compatible nodes to requesters
- **LAN-Aware Filtering**: Prevents leaking private network topology
- **IP Discovery**: Automatic external IP detection from PONG consensus
- **Web UI**: Real-time statistics dashboard with EL/CL breakdowns

### 2. Discovery v4 Implementation (`discv4/`)

Legacy protocol for Execution Layer discovery:

- **Full Wire Protocol**: PING/PONG, FINDNODE/NEIGHBORS, ENRREQUEST/ENRRESPONSE
- **Bond Mechanism**: Bidirectional PING/PONG required before serving nodes
- **Storm Prevention**: Protection against ping-pong amplification attacks
- **ENR Support**: Supports both modern ENR and legacy enode URLs
- **EL-Specific**: Only used for Execution Layer nodes

### 3. Discovery v5 Implementation (`discv5/`)

Modern encrypted protocol for both EL and CL:

- **Protocol Handler**: Full discv5 wire protocol (PING/PONG, FINDNODE/NODES, TALKREQ/TALKRESP)
- **Session Management**: Encrypted messaging with WHOAREYOU handshakes
- **UDP Transport**: Network communication with per-IP rate limiting
- **ENR Support**: Full Ethereum Node Records implementation
- **DoS Protection**: Bounded pending maps with LRU eviction and per-IP limits
- **Cross-Layer**: Used by both EL and CL nodes

## Key Benefits

### Universal Ethereum Support

Single bootnode binary supporting all Ethereum network types:

- **Execution Layer**: Ethereum mainnet and testnets (EL nodes)
- **Consensus Layer**: Beacon chain nodes (CL nodes)
- **Dual-Stack Mode**: Serve both EL and CL simultaneously on the same port
- **Protocol Agnostic**: Supports both discv4 (EL) and discv5 (EL+CL)

### Fork-Aware Filtering

#### Execution Layer (EIP-2124)
- **Fork ID Validation**: Validates nodes based on `eth` ENR field
- **Chain Compatibility**: Ensures nodes are on the correct chain and fork
- **Historical Acceptance**: Accepts any valid fork from chain history
- **Network Isolation**: Mainnet nodes won't be served to testnet peers

#### Consensus Layer
- **Fork Digest Validation**: Validates nodes based on `eth2` ENR field
- **Grace Period Support**: Accepts nodes from previous forks during transitions (default: 60 minutes)
- **Fork Awareness**: Automatically updates accepted fork digests based on beacon chain schedule
- **Quality Assurance**: Only serves nodes that have been validated and pinged successfully

This ensures that peers connecting to the bootnode receive **only valid, reachable nodes from their specific network and fork**.

### Architecture Advantages

- **Context-Driven**: Graceful shutdown via context cancellation
- **Memory Efficient**: Bounded data structures with configurable limits (500 nodes per table by default)
- **Attack Resistant**: Multi-layer DoS protection (per-IP limits, rate limiting, bond mechanism, storm prevention)
- **Observable**: Comprehensive statistics and web UI for monitoring
- **Database Persistence**: SQLite storage with automatic migrations
- **Self-Configuring**: Automatic external IP discovery from PONG consensus

## Usage

### Building

```bash
go build -o bootnodoor ./cmd/bootnodoor
```

### Quick Start Examples

#### Dual-Stack Bootnode (EL + CL)

```bash
./bootnodoor \
  --private-key "$(openssl rand -hex 32)" \
  --bind-port 30303 \
  --enr-ip $(curl -s ifconfig.me) \
  --el-config ./config-mainnet-el.json \
  --el-genesis-hash 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3 \
  --el-genesis-time 1438269988 \
  --cl-config ./config-mainnet-cl.yaml \
  --genesis-validators-root 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95 \
  --nodedb ./data/mainnet.db \
  --web-ui
```

#### Execution Layer Only (e.g., for Ethereum mainnet/testnets)

```bash
./bootnodoor \
  --private-key "$(openssl rand -hex 32)" \
  --bind-port 30303 \
  --enr-ip $(curl -s ifconfig.me) \
  --el-config ./config-mainnet-el.json \
  --el-genesis-hash 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3 \
  --el-genesis-time 1438269988 \
  --el-bootnodes "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303" \
  --nodedb ./data/mainnet-el.db \
  --web-ui
```

#### Consensus Layer Only (e.g., for Beacon chain)

```bash
./bootnodoor \
  --private-key "$(openssl rand -hex 32)" \
  --bind-port 9000 \
  --enr-ip $(curl -s ifconfig.me) \
  --cl-config ./config-mainnet-cl.yaml \
  --genesis-validators-root 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95 \
  --cl-bootnodes "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg" \
  --nodedb ./data/mainnet-cl.db \
  --web-ui
```

### Configuration Parameters

#### Required Parameters (At Least One Layer)

**For Execution Layer:**
- `--el-config <path>`: Path to EL chain config file (JSON)
  - Contains fork schedule and network parameters
  - Example: Mainnet, Sepolia, Holesky configs

- `--el-genesis-hash <hex>`: Genesis block hash (0x-prefixed hex)
  - Used to compute fork IDs
  - Example: `0xd4e56740...` for Ethereum mainnet

- `--el-genesis-time <unix>`: Genesis block timestamp (Unix time)
  - Example: `1438269988` for Ethereum mainnet

**For Consensus Layer:**
- `--cl-config <path>`: Path to CL beacon config file (YAML)
  - Contains fork schedule, genesis config, and network parameters
  - Example files: `config-mainnet.yaml`, `config-sepolia.yaml`

- `--genesis-validators-root <hex>`: Genesis validators root (0x-prefixed hex)
  - Used to compute fork digests
  - Unique per network (mainnet, sepolia, holesky, etc.)

**Common Required:**
- `--private-key <hex>`: Node private key (64 hex characters, optional 0x prefix)
  - Used for node identity and ENR signing
  - **Keep this secret!** Anyone with this key can impersonate your node

- `--enr-ip <ip>`: Public IPv4 address to advertise in ENR
  - This is the address other nodes will use to connect to you
  - Must be reachable from the internet
  - Can be omitted for automatic discovery from PONG responses

#### Network Binding

- `--bind-addr <ip>`: IP address to bind UDP socket (default: `0.0.0.0`)
- `--bind-port <port>`: UDP port to bind (default: `30303`)
- `--enr-ip6 <ip>`: Optional IPv6 address to advertise
- `--enr-port <port>`: UDP port to advertise (default: use `--bind-port`)

#### Protocol Selection

- `--enable-el`: Enable execution bootnode (default: `true`)
- `--enable-cl`: Enable consensus bootnode (default: `true`)

#### Node Database

- `--nodedb <path>`: Path to persistent SQLite database file
  - Stores discovered nodes across restarts with automatic migrations
  - Leave empty for in-memory database (no persistence)
  - Database contains separate tables for EL and CL nodes

#### Discovery (Bootnodes)

- `--el-bootnodes <enr1,enr2,...>`: Comma-separated list of EL bootnode ENRs or enode URLs
  - Used for initial EL peer discovery
  - Supports both ENR and legacy enode format

- `--cl-bootnodes <enr1,enr2,...>`: Comma-separated list of CL bootnode ENRs
  - Used for initial CL peer discovery
  - Only ENR format supported

#### Routing Table Configuration

- `--max-active-nodes <count>`: Maximum active nodes per table (default: `500`)
  - Separate limit for EL and CL tables

- `--max-nodes-per-ip <count>`: Maximum nodes to track per IP address (default: `10`)
  - Prevents single IPs from dominating the routing table

#### Fork Filtering (CL Only)

- `--grace-period <duration>`: Grace period for old CL fork digests (default: `60m`)
  - How long to accept nodes from previous forks after transition
  - Format: `60m`, `2h`, `30s`
  - EL fork IDs accept any historical fork without grace period

#### Web UI

- `--web-ui`: Enable web UI dashboard
- `--web-host <ip>`: Web UI host (default: `0.0.0.0`)
- `--web-port <port>`: Web UI port (default: `8080`)
- `--web-sitename <name>`: Web UI site name (default: `bootnodoor`)
- `--pprof`: Enable pprof performance profiling endpoints

#### Logging

- `--log-level <level>`: Log level: `debug`, `info`, `warn`, `error` (default: `info`)

## Example Configurations

### Mainnet Dual-Stack Bootnode (EL + CL)

```bash
./bootnodoor \
  --private-key "$(openssl rand -hex 32)" \
  --bind-port 30303 \
  --enr-ip $(curl -s ifconfig.me) \
  --el-config ./configs/mainnet-el.json \
  --el-genesis-hash 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3 \
  --el-genesis-time 1438269988 \
  --cl-config ./configs/mainnet-cl.yaml \
  --genesis-validators-root 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95 \
  --nodedb ./data/mainnet.db \
  --web-ui \
  --web-port 8080
```

### Sepolia Testnet CL Bootnode

```bash
./bootnodoor \
  --cl-config ./configs/sepolia-cl.yaml \
  --genesis-validators-root 0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078 \
  --private-key "$(openssl rand -hex 32)" \
  --bind-port 9000 \
  --enr-ip $(curl -s ifconfig.me) \
  --nodedb ./data/sepolia-cl.db \
  --web-ui
```

### Holesky Testnet EL Bootnode

```bash
./bootnodoor \
  --el-config ./configs/holesky-el.json \
  --el-genesis-hash 0xb5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4 \
  --el-genesis-time 1695902100 \
  --private-key "$(openssl rand -hex 32)" \
  --bind-port 30303 \
  --enr-ip $(curl -s ifconfig.me) \
  --nodedb ./data/holesky-el.db \
  --web-ui
```

### Development Setup (No Persistence, Localhost)

```bash
./bootnodoor \
  --cl-config ./configs/holesky-cl.yaml \
  --genesis-validators-root 0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1 \
  --private-key "1234567890123456789012345678901212345678901234567890123456789012" \
  --bind-addr 127.0.0.1 \
  --bind-port 9000 \
  --enr-ip 127.0.0.1 \
  --log-level debug
```

## Using the discv5 Library

The generic discv5 library can be used independently:

```go
package main

import (
    "context"
    "crypto/ecdsa"
    "log"

    ethcrypto "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethpandaops/bootnodoor/discv5"
    "github.com/ethpandaops/bootnodoor/discv5/protocol"
)

func main() {
    // Generate private key
    privKey, _ := ethcrypto.GenerateKey()

    // Create configuration
    cfg := discv5.DefaultConfig()
    cfg.PrivateKey = privKey
    cfg.BindPort = 9000

    // Set callbacks for protocol events
    cfg.OnHandshakeComplete = func(n *node.Node, incoming bool) {
        log.Printf("Handshake complete with %s", n.PeerID())
    }

    cfg.OnFindNode = func(msg *protocol.FindNode) []*node.Node {
        // Return nodes from your routing table
        return myTable.FindClosest(msg.Distances)
    }

    // Create service
    service, err := discv5.New(cfg)
    if err != nil {
        log.Fatal(err)
    }

    // Start service
    if err := service.Start(); err != nil {
        log.Fatal(err)
    }
    defer service.Stop()

    // Use the service
    nodes, err := service.FindNode(targetNode, []uint{256})
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Discovered %d nodes", len(nodes))
}
```

## Monitoring

### Web UI

When `--web-ui` is enabled, access the dashboard at `http://localhost:8080` (or your configured port).

The dashboard shows:
- **Overview**: Real-time EL and CL node counts, database statistics
- **EL Nodes Page**: List of all EL nodes with fork IDs, protocol support, and quality metrics
- **CL Nodes Page**: List of all CL nodes with fork digests and statistics
- **Fork Information**: Current and historical fork data for both layers
- **Protocol Metrics**: Packets sent/received, handshakes, sessions
- **Database Stats**: Node counts, quality metrics, protocol support distribution

### HTTP API Endpoints

- `GET /` - Web dashboard overview
- `GET /el-nodes` - EL nodes list page
- `GET /cl-nodes` - CL nodes list page
- `GET /enr` - Local ENR in base64 format
- `GET /enode` - Local enode URL (EL format)
- `GET /metrics` - Prometheus metrics (when enabled)
- `GET /debug/pprof/` - Performance profiling (when `--pprof` enabled)

## Fork Configuration

### Execution Layer Fork IDs (EIP-2124)

Fork IDs are computed from the EL chain config (JSON):

```json
{
  "chainId": 1,
  "homesteadBlock": 1150000,
  "daoForkBlock": 1920000,
  "eip150Block": 2463000,
  ...
  "shanghaiTime": 1681338455,
  "cancunTime": 1710338135,
  "pragueTime": 1746612311
}
```

The bootnode automatically:
1. Computes fork ID from genesis hash and all fork blocks/timestamps
2. Validates `eth` ENR field against chain history
3. Accepts any valid historical fork ID
4. No grace period needed (all historical forks are valid)

### Consensus Layer Fork Digests

Fork digests are computed from the CL beacon config (YAML):

```yaml
# config-mainnet-cl.yaml
CONFIG_NAME: "mainnet"

# Fork schedule
ALTAIR_FORK_EPOCH: 74240
BELLATRIX_FORK_EPOCH: 144896
CAPELLA_FORK_EPOCH: 194048
DENEB_FORK_EPOCH: 269568

# Fork versions
GENESIS_FORK_VERSION: 0x00000000
ALTAIR_FORK_VERSION: 0x01000000
BELLATRIX_FORK_VERSION: 0x02000000
CAPELLA_FORK_VERSION: 0x03000000
DENEB_FORK_VERSION: 0x04000000

# Network parameters
SECONDS_PER_SLOT: 12
SLOTS_PER_EPOCH: 32
```

The bootnode automatically:
1. Computes fork digests: `compute_fork_digest(fork_version, genesis_validators_root)[:4]`
2. Determines current fork based on network time
3. Accepts nodes with current fork digest
4. Accepts nodes with old fork digests within grace period (default: 60 minutes)
5. Deprioritizes but accepts historical fork digests

## Security Considerations

### DoS Protection

The bootnode implements multiple layers of DoS protection:

- **Rate Limiting**: 100 packets/second per IP at transport layer
- **Pending Limits**: Bounded pending maps for handshakes and challenges
- **Per-IP Limits**: Max 10 nodes per IP address to prevent Sybil attacks
- **LRU Eviction**: Oldest entries evicted when limits reached
- **Session Limits**: Max 1024 concurrent discv5 sessions with 12-hour lifetime
- **Bond Mechanism**: Discv4 requires bidirectional PING/PONG before serving nodes
- **Storm Prevention**: Protection against ping-pong amplification attacks
- **Bad Node Caching**: Tracks rejected nodes to avoid repeated validation

### LAN Awareness

- WAN clients don't receive LAN nodes (RFC1918 filtering)
- Prevents disclosure of private network topology
- Separate handling for LAN and WAN requesters

### Best Practices

1. **Private Key**: Generate a unique key for each bootnode, never reuse keys
2. **Firewall**: Allow only UDP traffic on your configured port
3. **Monitoring**: Enable web UI on localhost only or behind authentication/firewall
4. **Database**: Backup node database periodically for faster restarts
5. **Updates**: Keep bootnode updated for latest fork schedule changes
6. **IP Discovery**: Use `--enr-ip` to manually set public IP, or rely on automatic discovery

## Troubleshooting

### No Peers Discovered

**For both layers:**
- Check `--enr-ip` is your **public** IP, not `0.0.0.0` or `127.0.0.1`
- Verify UDP port is open in firewall: `nc -u -z -v <ip> <port>`
- Ensure system time is synchronized (use NTP)
- Check bootnode configuration (--el-bootnodes or --cl-bootnodes)

**For EL:**
- Verify `--el-genesis-hash` matches your network
- Check `--el-genesis-time` is correct
- Ensure EL config has correct fork schedule
- Verify discv4 is enabled if using enode bootnodes

**For CL:**
- Verify `--genesis-validators-root` is correct for your network
- Ensure CL config has correct fork schedule
- Check `GENESIS_FORK_VERSION` in config file

### Wrong Fork Errors

**EL fork ID errors:**
- Verify genesis hash and time match the network
- Check EL chain config has correct fork blocks and timestamps
- Ensure config matches the network you're trying to join

**CL fork digest errors:**
- Verify genesis validators root is correct
- Check CL config file has correct fork versions
- Ensure fork schedule matches the network

### High Memory Usage

- Reduce `--max-active-nodes` (default: 500 per table)
- Reduce `--max-nodes-per-ip` (default: 10)
- Enable database persistence with `--nodedb`
- Disable unused layer (don't configure both EL and CL if only one is needed)

### Slow Peer Discovery

- Add more bootnodes (`--el-bootnodes` and/or `--cl-bootnodes`)
- Check network connectivity to initial bootnodes
- Verify protocol settings (--enable-discv4, --enable-discv5)
- For CL: reduce grace period if too permissive: `--grace-period 30m`

## Development

### Running Tests

```bash
go test ./...
```

### Building for Production

```bash
make build
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## References

### Discovery Protocols
- [Discovery v4 Specification](https://github.com/ethereum/devp2p/blob/master/discv4.md)
- [Discovery v5 Specification](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md)

### Standards & EIPs
- [EIP-778: Ethereum Node Records (ENR)](https://eips.ethereum.org/EIPS/eip-778)
- [EIP-868: Node Discovery v4 ENR Extension](https://eips.ethereum.org/EIPS/eip-868)
- [EIP-2124: Fork identifier for chain compatibility checks](https://eips.ethereum.org/EIPS/eip-2124)

### Ethereum Specifications
- [Ethereum Consensus Layer Specs](https://github.com/ethereum/consensus-specs)
- [Ethereum Execution Layer Specs](https://github.com/ethereum/execution-specs)
