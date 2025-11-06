# Universal Bootnode Package

The `bootnode` package provides a production-ready, comprehensive Ethereum bootnode implementation supporting both Execution Layer (EL) and Consensus Layer (CL) discovery protocols with intelligent fork-aware filtering.

## Overview

This package serves as the main orchestration layer for a universal Ethereum bootnode that can:
- Serve EL nodes (Ethereum mainnet and testnets)
- Serve CL nodes (Beacon chain)
- Serve both simultaneously on the same port (dual-stack mode)
- Support both Discovery v4 (discv4) and Discovery v5 (discv5) protocols
- Automatically filter nodes based on fork compatibility
- Prevent network topology leaks with LAN-aware filtering

## Features

### Multi-Layer Support
- **Execution Layer (EL)**: Full support for Ethereum execution layer networks
  - Fork ID validation via `eth` ENR field (EIP-2124)
  - Accepts any valid historical fork
  - Supports both mainnet and all testnets
- **Consensus Layer (CL)**: Full support for Ethereum beacon chain
  - Fork digest validation via `eth2` ENR field
  - Grace period support for fork transitions (configurable, default 60 minutes)
  - Automatic fork schedule awareness
- **Dual Mode**: Run both EL and CL simultaneously
  - Separate routing tables (500 nodes each by default)
  - Independent fork filtering per layer
  - Shared protocols and transport

### Multi-Protocol Support
- **Discovery v4 (discv4)**: Legacy UDP protocol for EL nodes
  - Full wire protocol: PING/PONG, FINDNODE/NEIGHBORS, ENRREQUEST/ENRRESPONSE
  - Bond mechanism with storm prevention
  - Supports ENR and legacy enode URLs
  - EL-only (CL nodes don't use discv4)
- **Discovery v5 (discv5)**: Modern encrypted protocol
  - Supports both EL and CL nodes
  - Session management with encryption
  - Full wire protocol: PING/PONG, FINDNODE/NODES, TALKREQ/TALKRESP
- **Protocol Multiplexing**: Both protocols share a single UDP socket
  - Transport layer routes packets to correct protocol handler
  - Per-IP rate limiting at transport layer

### Intelligent Node Routing
- **Layer Separation**: Separate routing tables for EL and CL nodes
  - Each table maintains up to 500 active nodes (configurable)
  - Independent quality tracking and statistics
  - Separate database persistence
- **Fork-Aware Filtering**:
  - **EL**: Validates fork IDs against chain config (accepts any valid historical fork)
  - **CL**: Validates fork digests with grace period support
- **Protocol-Aware Responses**:
  - Only returns nodes supporting the requested protocol (v4 or v5)
  - Discv4 requests only receive EL nodes with v4 support
  - Discv5 requests receive both EL and CL nodes with v5 support
- **LAN-Aware Filtering**: Prevents leaking private network topology to WAN peers
  - RFC1918 address detection
  - WAN clients don't receive LAN nodes

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                       Universal Bootnode Service                   │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌────────────────────┐              ┌────────────────────┐        │
│  │   EL Routing       │              │   CL Routing       │        │
│  │   Table            │              │   Table            │        │
│  │   - 500 nodes      │              │   - 500 nodes      │        │
│  │   - IP limiting    │              │   - IP limiting    │        │
│  │   - Quality track  │              │   - Quality track  │        │
│  └─────────┬──────────┘              └─────────┬──────────┘        │
│            │                                   │                   │
│  ┌─────────┴──────────┐              ┌─────────┴──────────┐        │
│  │  EL Database       │              │  CL Database       │        │
│  │  (SQLite - layer   │              │  (SQLite - layer   │        │
│  │   'el')            │              │   'cl')            │        │
│  │  - nodes table     │              │  - nodes table     │        │
│  │  - bad_nodes table │              │  - bad_nodes table │        │
│  └────────────────────┘              └────────────────────┘        │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    ENR Manager                               │  │
│  │  - Local ENR with 'eth' + 'eth2' fields                      │  │
│  │  - EL Fork ID Computation (EIP-2124)                         │  │
│  │  - CL Fork Digest Computation                                │  │
│  │  - Automatic IP discovery from PONG consensus                │  │
│  │  - Dynamic ENR updates                                       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   Maintenance Services                       │  │
│  │  - Lookup Service (random walks, iterative lookups)          │  │
│  │  - Ping Service (aliveness checks, protocol detection)       │  │
│  │  - IP Discovery Service (external IP consensus)              │  │
│  │  - Table Sweep (10% rotation every 5 minutes)                │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌──────────────┐                      ┌──────────────┐            │
│  │  Discv4      │                      │  Discv5      │            │
│  │  Service     │                      │  Service     │            │
│  │  - EL only   │                      │  - EL + CL   │            │
│  │  - Bonding   │                      │  - Sessions  │            │
│  │  - Storm     │                      │  - Encrypted │            │
│  │    prevention│                      │    messaging │            │
│  └──────┬───────┘                      └──────┬───────┘            │
│         │                                     │                    │
│         └──────────┬──────────────────────────┘                    │
│                    │                                               │
│         ┌──────────┴─────────────────────────┐                     │
│         │   UDP Transport (Shared)           │                     │
│         │   - Protocol multiplexing          │                     │
│         │   - Per-IP rate limiting (100/s)   │                     │
│         │   - Packet routing (v4/v5)         │                     │
│         │   - Bind: 0.0.0.0:30303            │                     │
│         └────────────────────────────────────┘                     │
└────────────────────────────────────────────────────────────────────┘
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

1. **Incoming Node**: A node initiates contact with the bootnode
   - **Discv4**: Receives PING packet, validates bond mechanism
   - **Discv5**: Completes WHOAREYOU handshake, establishes encrypted session

2. **Layer Detection**: Bootnode examines the node's ENR fields
   - Checks for `eth` field → EL node detected
   - Checks for `eth2` field → CL node detected
   - Both fields present → Multi-layer node (serves both networks)

3. **Fork Validation**:
   - **EL nodes**: Validates fork ID from `eth` field against chain config
     - Computes expected fork ID from genesis hash and chain config
     - Accepts any valid historical fork ID
     - No grace period needed
   - **CL nodes**: Validates fork digest from `eth2` field against beacon config
     - Computes current fork digest from current fork version + genesis validators root
     - Accepts current fork digest
     - Accepts previous fork digest within grace period (default: 60 minutes)
     - Accepts but deprioritizes historical fork digests

4. **Bad Node Check**: Before accepting, checks bad_nodes table
   - If node was previously rejected, skips ENR request and validation
   - Automatic cleanup of old bad node entries
   - Prevents repeated validation overhead

5. **Table Insertion**: Node is added to appropriate table(s)
   - **EL nodes** → EL routing table + EL database (layer='el')
   - **CL nodes** → CL routing table + CL database (layer='cl')
   - **Multi-layer** → Both tables with independent tracking
   - IP limiting enforced (max 10 nodes per IP by default)
   - Quality metrics initialized (success/failure counts, RTT)

6. **FINDNODE Responses**: When a node requests peers
   - **Discv4 requests**: Returns only EL nodes with v4 support
     - Maximum 16 nodes per response (protocol limit)
     - Only nodes that have been pinged successfully
   - **Discv5 requests**: Returns appropriate nodes based on layer
     - If requester has `eth` field: returns EL nodes with v5 support
     - If requester has `eth2` field: returns CL nodes with v5 support
     - Can return both if requester supports both layers
   - **Protocol filtering**: Only returns nodes supporting the request protocol
   - **LAN filtering**: WAN requesters don't receive RFC1918 nodes
   - **Quality-based selection**: Prioritizes nodes with better success rates

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

The bootnode uses SQLite with WAL mode and automatic schema migrations (goose). The database contains three main tables:

### Nodes Table

Stores discovered nodes with quality metrics:

```sql
CREATE TABLE nodes (
    nodeid BLOB PRIMARY KEY,        -- Node ID (32 bytes)
    layer TEXT NOT NULL,             -- 'el' or 'cl'
    ip BLOB,                         -- IPv4 address (4 bytes)
    ipv6 BLOB,                       -- IPv6 address (16 bytes, optional)
    port INTEGER,                    -- UDP port
    seq INTEGER,                     -- ENR sequence number
    fork_digest BLOB,                -- Fork ID (EL, 12 bytes) or digest (CL, 4 bytes)
    first_seen INTEGER,              -- Unix timestamp (first discovery)
    last_seen INTEGER,               -- Unix timestamp (last seen)
    last_active INTEGER,             -- Unix timestamp (last successful ping)
    enr BLOB,                        -- Full ENR record
    has_v4 INTEGER DEFAULT 0,        -- Supports Discovery v4
    has_v5 INTEGER DEFAULT 1,        -- Supports Discovery v5
    success_count INTEGER DEFAULT 0, -- Successful ping count
    failure_count INTEGER DEFAULT 0, -- Failed ping count
    avg_rtt INTEGER DEFAULT 0        -- Average round-trip time (ms)
);

CREATE INDEX idx_nodes_layer ON nodes(layer);
CREATE INDEX idx_nodes_last_seen ON nodes(layer, last_seen);
```

### Bad Nodes Table

Optimization table to avoid repeated validation of rejected nodes:

```sql
CREATE TABLE bad_nodes (
    nodeid BLOB PRIMARY KEY,    -- Node ID (32 bytes)
    reason TEXT,                -- Rejection reason
    first_rejected INTEGER,     -- Unix timestamp (first rejection)
    last_rejected INTEGER,      -- Unix timestamp (last rejection)
    rejection_count INTEGER     -- Number of times rejected
);

CREATE INDEX idx_bad_nodes_last_rejected ON bad_nodes(last_rejected);
```

### State Table

Stores runtime state and configuration:

```sql
CREATE TABLE state (
    key TEXT PRIMARY KEY,       -- State key
    value BLOB                  -- State value (e.g., local ENR)
);
```

### Migration Management

The database uses goose for schema migrations:
- Migrations in `db/migrations/`
- Automatic migration on startup
- Version tracking in `goose_db_version` table

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

## Key Features Summary

| Feature | Status | Description |
|---------|--------|-------------|
| **EL Support** | ✅ | Full Execution Layer support with fork ID validation |
| **CL Support** | ✅ | Full Consensus Layer support with fork digest validation |
| **Discv4** | ✅ | Full Discovery v4 with bonding and storm prevention |
| **Discv5** | ✅ | Full Discovery v5 with encryption and sessions |
| **Protocol Multiplexing** | ✅ | Both protocols on same UDP port |
| **Dual Tables** | ✅ | Separate routing tables for EL and CL |
| **Fork ID (EL)** | ✅ | EIP-2124 fork ID validation |
| **Fork Digest (CL)** | ✅ | Fork digest with grace period |
| **ENR with both fields** | ✅ | Single ENR with `eth` + `eth2` fields |
| **Bad Node Caching** | ✅ | Avoid repeated validation of rejected nodes |
| **IP Discovery** | ✅ | Automatic external IP detection from PONG consensus |
| **LAN Filtering** | ✅ | WAN clients don't receive LAN nodes |
| **Quality Metrics** | ✅ | Success/failure tracking, RTT measurement |
| **Protocol Detection** | ✅ | Automatic v4/v5 capability testing |
| **Database Persistence** | ✅ | SQLite with WAL mode and migrations |
| **Web UI** | ✅ | Real-time statistics and node lists |

## Implementation Status

### Fully Implemented
- ✅ Dual-stack bootnode service (EL + CL)
- ✅ Fork-aware filtering for both layers
- ✅ Protocol multiplexing (discv4 + discv5)
- ✅ Separate routing tables with IP limiting
- ✅ Bad node caching and optimization
- ✅ IP discovery service
- ✅ Lookup service (random walks, iterative lookups)
- ✅ Ping service (aliveness checks, protocol detection)
- ✅ ENR management with dynamic updates
- ✅ Database persistence with migrations
- ✅ Web UI with EL/CL breakdowns
- ✅ LAN-aware filtering

### Known Limitations
- Table is flat (not bucket-based Kademlia), which is simpler but less optimal for very large networks
- No geographic diversity optimization in node selection
- No advanced node scoring beyond success/failure counts

## References

- [EIP-778: Ethereum Node Records (ENR)](https://eips.ethereum.org/EIPS/eip-778)
- [EIP-868: Node Discovery v4 ENR Extension](https://eips.ethereum.org/EIPS/eip-868)
- [EIP-2124: Fork identifier for chain compatibility checks](https://eips.ethereum.org/EIPS/eip-2124)
- [Discv5 Specification](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md)
