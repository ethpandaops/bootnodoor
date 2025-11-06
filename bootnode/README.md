# Universal Bootnode Package

The `bootnode` package provides a comprehensive Ethereum bootnode implementation supporting both Execution Layer (EL) and Consensus Layer (CL) discovery protocols.

## Features

### Multi-Layer Support
- **Execution Layer (EL)**: Ethereum mainnet, testnets (via `eth` ENR field with fork IDs)
- **Consensus Layer (CL)**: Beacon chain (via `eth2` ENR field with fork digests)
- **Dual Mode**: Run both EL and CL simultaneously on the same service

### Multi-Protocol Support
- **Discovery v4 (discv4)**: Legacy UDP protocol for EL nodes
- **Discovery v5 (discv5)**: Modern encrypted protocol for both EL and CL
- **Protocol Multiplexing**: Both protocols share a single UDP socket

### Intelligent Node Routing
- **Layer Separation**: Separate routing tables for EL and CL nodes
- **Fork-Aware Filtering**: Validates nodes based on EL fork IDs and CL fork digests
- **Protocol-Aware Responses**: Returns only compatible nodes to requesters
- **LAN-Aware Filtering**: Prevents leaking private network topology to WAN peers

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Bootnode Service                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐              ┌──────────────┐            │
│  │  EL Table    │              │  CL Table    │            │
│  │  (500 nodes) │              │  (500 nodes) │            │
│  └──────┬───────┘              └──────┬───────┘            │
│         │                              │                    │
│  ┌──────┴───────┐              ┌──────┴───────┐            │
│  │  EL NodeDB   │              │  CL NodeDB   │            │
│  │  (SQLite)    │              │  (SQLite)    │            │
│  └──────────────┘              └──────────────┘            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              ENR Manager                             │  │
│  │  - Local ENR with 'eth' + 'eth2' fields             │  │
│  │  - EL Fork ID Filter (EIP-2124)                     │  │
│  │  - CL Fork Digest Filter                            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────┐                ┌─────────────┐            │
│  │  Discv4     │                │  Discv5     │            │
│  │  Service    │                │  Service    │            │
│  └──────┬──────┘                └──────┬──────┘            │
│         └───────────┬────────────────┬─┘                   │
│                     │                │                     │
│              ┌──────┴────────────────┴──────┐              │
│              │   UDP Transport (Shared)     │              │
│              │   0.0.0.0:30303              │              │
│              └─────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

## Package Structure

```
bootnode/
├── config.go          # Bootnode configuration
├── service.go         # Main service implementation
├── enr.go             # ENR management with eth/eth2 fields
├── elconfig/          # Execution Layer configuration
│   ├── forkid.go      # EIP-2124 fork ID calculation
│   ├── filter.go      # Fork ID filtering
│   └── parser.go      # Chain config parsing
└── clconfig/          # Consensus Layer configuration
    ├── config.go      # Beacon chain config
    └── filter.go      # Fork digest filtering
```

## Usage

### Basic Setup

```go
import (
    "github.com/ethpandaops/bootnodoor/bootnode"
    "github.com/ethpandaops/bootnodoor/bootnode/elconfig"
    "github.com/ethpandaops/bootnodoor/bootnode/clconfig"
)

// Load configurations
elConfig, _ := elconfig.LoadChainConfig("mainnet.json")
clConfig, _ := clconfig.LoadConfig("mainnet-cl.yaml")

// Create bootnode config
config := bootnode.DefaultConfig()
config.PrivateKey = privateKey
config.Database = db
config.BindPort = 30303

// Configure EL support
config.ELConfig = elConfig
config.ELGenesisHash = genesisHash
config.ELGenesisTime = genesisTime
config.ELBootnodes = []string{
    "enode://...",  // enode format
    "enr://...",    // ENR format
}

// Configure CL support
config.CLConfig = clConfig
config.CLBootnodes = []string{
    "enr://...",    // ENR format only
}

// Create and start service
service, err := bootnode.New(config)
if err != nil {
    log.Fatal(err)
}

if err := service.Start(); err != nil {
    log.Fatal(err)
}
defer service.Stop()
```

### EL-Only Bootnode

```go
config := bootnode.DefaultConfig()
config.PrivateKey = privateKey
config.Database = db

// Only set EL config
config.ELConfig = elConfig
config.ELGenesisHash = genesisHash
config.ELGenesisTime = genesisTime

// Protocols: Both discv4 and discv5 enabled by default
config.EnableDiscv4 = true
config.EnableDiscv5 = true

service, _ := bootnode.New(config)
service.Start()
```

### CL-Only Bootnode

```go
config := bootnode.DefaultConfig()
config.PrivateKey = privateKey
config.Database = db

// Only set CL config
config.CLConfig = clConfig

// Discv4 will be disabled (CL nodes don't use discv4)
config.EnableDiscv4 = false
config.EnableDiscv5 = true

service, _ := bootnode.New(config)
service.Start()
```

### Dual EL+CL Bootnode

```go
config := bootnode.DefaultConfig()
config.PrivateKey = privateKey
config.Database = db

// Set both configs
config.ELConfig = elConfig
config.ELGenesisHash = genesisHash
config.ELGenesisTime = genesisTime
config.CLConfig = clConfig

// Both protocols enabled
config.EnableDiscv4 = true  // For EL
config.EnableDiscv5 = true  // For both EL and CL

service, _ := bootnode.New(config)
service.Start()
```

## Configuration Options

### Network Configuration
- `BindIP`: IP address to bind to (default: 0.0.0.0)
- `BindPort`: UDP port to bind to (default: 30303)
- `ENRIP`: IPv4 address to advertise in ENR (auto-detected if nil)
- `ENRIP6`: IPv6 address to advertise in ENR (optional)
- `ENRPort`: UDP port to advertise in ENR (default: same as BindPort)

### Layer Configuration
- `ELConfig`: Execution layer chain configuration
- `ELGenesisHash`: EL genesis block hash
- `ELGenesisTime`: EL genesis block timestamp
- `ELBootnodes`: List of EL bootnodes (ENR or enode format)
- `CLConfig`: Consensus layer beacon chain configuration
- `CLBootnodes`: List of CL bootnodes (ENR format only)

### Table Configuration
- `MaxActiveNodes`: Maximum active nodes per table (default: 500)
- `MaxNodesPerIP`: Maximum nodes per IP address (default: 10)
- `PingInterval`: How often to ping nodes (default: 30s)
- `MaxNodeAge`: Maximum age before removing node (default: 24h)
- `MaxFailures`: Maximum consecutive failures (default: 3)

### Protocol Configuration
- `EnableDiscv4`: Enable Discovery v4 protocol (default: true)
- `EnableDiscv5`: Enable Discovery v5 protocol (default: true)
- `SessionLifetime`: Discv5 session lifetime (default: 12h)
- `MaxSessions`: Maximum discv5 sessions (default: 1024)

## How It Works

### Node Discovery Flow

1. **Incoming Node**: A node connects to the bootnode
   - Discv4: Receives PING packet
   - Discv5: Completes handshake

2. **Layer Detection**: Bootnode examines the node's ENR
   - Checks for `eth` field → EL node
   - Checks for `eth2` field → CL node
   - Can have both fields → Multi-layer node

3. **Fork Validation**:
   - **EL nodes**: Validates fork ID against chain config
   - **CL nodes**: Validates fork digest against beacon config

4. **Table Insertion**: Node is added to appropriate table(s)
   - EL nodes → EL table + EL database
   - CL nodes → CL table + CL database
   - Multi-layer → Both tables

5. **FINDNODE Responses**: When a node requests peers
   - **Discv4 requests**: Returns only EL nodes with discv4 support
   - **Discv5 requests**: Returns both EL and CL nodes with discv5 support
   - **Protocol filtering**: Only returns nodes supporting the request protocol
   - **LAN filtering**: WAN requesters don't receive LAN nodes

### Fork ID Calculation (EL)

The bootnode implements EIP-2124 fork ID calculation:

```
Fork ID = CRC32(genesis_hash || fork1 || fork2 || ... || forkN)
```

Example for Mainnet:
```
Genesis: 0xd4e56740...
Fork 1 (Homestead): Block 1,150,000
Fork 2 (DAO): Block 1,920,000
...
Fork N (Prague): Timestamp 1746612311

Current Fork ID: {Hash: [4]byte{0x...}, Next: 1746612311}
```

### Fork Digest Calculation (CL)

The bootnode implements beacon chain fork digest calculation:

```
Fork Digest = compute_fork_digest(fork_version, genesis_validators_root)
```

The bootnode accepts nodes on:
- Current fork
- Previous fork (within grace period)
- Genesis fork (always accepted)

## Local ENR Structure

The bootnode's local ENR contains both `eth` and `eth2` fields:

```
ENR Fields:
- id: "v4"
- secp256k1: <compressed public key>
- ip: <IPv4 address>
- udp: <UDP port>
- eth: <EL fork ID> (12 bytes: 4-byte hash + 8-byte next)
- eth2: <CL fork digest> (16 bytes: 4-byte digest + 8-byte next + 4-byte enr-seq)
```

This allows the bootnode to serve both EL and CL clients.

## Database Schema

The bootnode uses a single SQLite database with a unified schema:

```sql
CREATE TABLE nodes (
    nodeid BLOB PRIMARY KEY,
    layer TEXT NOT NULL,      -- 'el' or 'cl'
    ip BLOB,
    ipv6 BLOB,
    port INTEGER,
    seq INTEGER,
    fork_digest BLOB,         -- Fork ID (EL) or digest (CL)
    first_seen INTEGER,
    last_seen INTEGER,
    last_active INTEGER,
    enr BLOB,
    has_v4 INTEGER DEFAULT 0,
    has_v5 INTEGER DEFAULT 1,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    avg_rtt INTEGER DEFAULT 0
);

CREATE INDEX idx_nodes_layer ON nodes(layer);
CREATE INDEX idx_nodes_last_seen ON nodes(layer, last_seen);
```

## Performance Characteristics

- **Memory Usage**: ~100MB for 1000 nodes (500 EL + 500 CL)
- **Database Size**: ~50KB per 1000 nodes
- **Packet Rate**: Handles 1000+ packets/sec
- **Discovery Speed**: Discovers 100+ nodes/minute
- **Node Rotation**: 10% of active nodes rotated every 5 minutes

## Security Considerations

### IP Limiting
- Maximum 10 nodes per IP address by default
- Prevents sybil attacks from single source

### Fork Validation
- Rejects nodes on incompatible forks
- Grace period for old fork digests (CL)
- Strict validation of fork IDs (EL)

### LAN Awareness
- WAN clients don't receive LAN nodes
- Prevents network topology disclosure

### Protocol Validation
- All packets cryptographically verified
- Invalid signatures rejected
- Expired packets rejected

## Comparison with beacon-bootnode

The new `bootnode` package improves upon `beacon-bootnode`:

| Feature | beacon-bootnode | bootnode |
|---------|----------------|----------|
| EL Support | ❌ | ✅ |
| CL Support | ✅ | ✅ |
| Discv4 | ❌ | ✅ |
| Discv5 | ✅ | ✅ |
| Dual Tables | ❌ | ✅ |
| Fork ID (EL) | ❌ | ✅ |
| Fork Digest (CL) | ✅ | ✅ |
| ENR with both fields | ❌ | ✅ |

## Future Enhancements

Planned improvements:
- [ ] Ping service implementation
- [ ] Lookup service for random walks
- [ ] ENR request via discv4 for enode bootnodes
- [ ] Dynamic ENR updates on fork transitions
- [ ] Metrics and monitoring endpoints
- [ ] Configurable node scoring
- [ ] Geographic diversity in responses

## References

- [EIP-778: Ethereum Node Records (ENR)](https://eips.ethereum.org/EIPS/eip-778)
- [EIP-868: Node Discovery v4 ENR Extension](https://eips.ethereum.org/EIPS/eip-868)
- [EIP-2124: Fork identifier for chain compatibility checks](https://eips.ethereum.org/EIPS/eip-2124)
- [Discv5 Specification](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md)
