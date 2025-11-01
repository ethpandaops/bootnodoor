# Bootoor - Ethereum Discovery v5 Bootnode

An Ethereum Discovery v5 (discv5) bootnode implementation with intelligent fork digest filtering for the Ethereum consensus layer.

> **Note**: This project is under active development and not yet production-ready. Use at your own risk.

## Project Structure

Bootoor consists of two main components:

### 1. Generic discv5 Library (`discv5/`)

A minimal, reusable discv5 protocol implementation:

- **Protocol Handler**: Full discv5 wire protocol (PING/PONG, FINDNODE/NODES, TALKREQ/TALKRESP)
- **Session Management**: Encrypted messaging with WHOAREYOU handshakes
- **UDP Transport**: Network communication with per-IP rate limiting
- **ENR Support**: Ethereum Node Records encoding/decoding
- **Callback Interface**: Protocol event hooks (handshake complete, node updates, incoming requests)
- **DoS Protection**: Bounded pending maps with LRU eviction and per-IP limits

The discv5 library is protocol-agnostic and can be used for any discv5-based application.

### 2. Beacon Bootnode (`beacon-bootnode/`)

Ethereum consensus layer bootnode with intelligent filtering:

- **Fork Digest Filtering**: Only serve nodes from the correct network fork
- **Grace Period Support**: Accept nodes from recent forks during transitions
- **Node Quality Tracking**: Persistent database with success/failure statistics
- **IP-Based Limits**: Prevent Sybil attacks with configurable per-IP node limits
- **Routing Table**: Kademlia-based DHT with 256 distance buckets
- **Active Discovery**: Periodic random walks and liveness checks
- **Web UI**: Real-time statistics dashboard (optional)

## Key Benefits

### Fork Digest Filtering

The bootnode uses the consensus layer's fork schedule to validate nodes before serving them to peers:

- **Network Isolation**: Nodes from mainnet won't be served to testnet peers (and vice versa)
- **Fork Awareness**: Automatically updates accepted fork digests based on network schedule
- **Grace Period**: Continues accepting nodes from old forks for a configurable duration (default: 60 minutes)
- **Quality Assurance**: Only serves nodes that have been validated and pinged successfully

This ensures that peers connecting to the bootnode receive **only valid, reachable nodes from their specific network**.

### Architecture Advantages

- **Context-Driven**: Graceful shutdown via context cancellation (no WaitGroups)
- **Memory Efficient**: Bounded data structures with configurable limits
- **Attack Resistant**: Per-IP limits and rate limiting prevent resource exhaustion
- **Observable**: Comprehensive statistics for monitoring and debugging

## Usage

### Building

```bash
go build -o bootnode ./cmd/bootnode
```

### Running the Bootnode

```bash
./bootnode \
  --cl-config ./config-hoodi.yaml \
  --genesis-validators-root 0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f \
  --private-key "1234567890123456789012345678901212345678901234567890123456789012" \
  --bind-addr 0.0.0.0 \
  --bind-port 9010 \
  --enr-ip 10.16.10.174 \
  --enr-port 9010 \
  --nodedb ./nodes.db \
  --web-ui \
  --bootnodes "enr:-Mq4QLkmu..."
```

### Configuration Parameters

#### Required Parameters

- `--cl-config <path>`: Path to consensus layer config file (YAML)
  - Contains fork schedule, genesis config, and network parameters
  - Example files: `config-mainnet.yaml`, `config-sepolia.yaml`

- `--genesis-validators-root <hex>`: Genesis validators root (0x-prefixed hex)
  - Used to compute fork digests
  - Unique per network (mainnet, sepolia, holesky, etc.)

- `--private-key <hex>`: Node private key (64 hex characters, optional 0x prefix)
  - Used for node identity and ENR signing
  - **Keep this secret!** Anyone with this key can impersonate your node

- `--enr-ip <ip>`: Public IPv4 address to advertise in ENR
  - This is the address other nodes will use to connect to you
  - Must be reachable from the internet

#### Network Binding

- `--bind-addr <ip>`: IP address to bind UDP socket (default: `0.0.0.0`)
- `--bind-port <port>`: UDP port to bind (default: `9000`)
- `--enr-ip6 <ip>`: Optional IPv6 address to advertise
- `--enr-port <port>`: UDP port to advertise (default: use `--bind-port`)

#### Node Database

- `--nodedb <path>`: Path to persistent node database directory
  - Stores discovered nodes across restarts
  - Leave empty for in-memory database (no persistence)

#### Discovery

- `--bootnodes <enr1,enr2,...>`: Comma-separated list of bootnode ENRs
  - Used for initial peer discovery
  - Can be ENR records from other bootnodes

#### Fork Filtering

- `--grace-period <duration>`: Grace period for old fork digests (default: `60m`)
  - How long to accept nodes from previous forks after transition
  - Format: `60m`, `2h`, `30s`

#### Rate Limiting

- `--max-nodes-per-ip <count>`: Maximum nodes to track per IP address (default: `100`)
  - Prevents single IPs from dominating the routing table

#### Web UI

- `--web-ui`: Enable web UI dashboard
- `--web-host <ip>`: Web UI host (default: `0.0.0.0`)
- `--web-port <port>`: Web UI port (default: `8080`)
- `--web-sitename <name>`: Web UI site name (default: `Bootoor`)

#### Logging

- `--log-level <level>`: Log level: `debug`, `info`, `warn`, `error` (default: `info`)

## Example Configurations

### Mainnet Bootnode

```bash
./bootnode \
  --cl-config ./config-mainnet.yaml \
  --genesis-validators-root 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95 \
  --private-key "$(openssl rand -hex 32)" \
  --bind-port 9000 \
  --enr-ip $(curl -s ifconfig.me) \
  --nodedb ./data/mainnet-nodes.db \
  --web-ui \
  --web-port 8080
```

### Sepolia Testnet Bootnode

```bash
./bootnode \
  --cl-config ./config-sepolia.yaml \
  --genesis-validators-root 0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078 \
  --private-key "$(openssl rand -hex 32)" \
  --bind-port 9000 \
  --enr-ip $(curl -s ifconfig.me) \
  --nodedb ./data/sepolia-nodes.db \
  --web-ui
```

### Development Setup (No Persistence)

```bash
./bootnode \
  --cl-config ./config-holesky.yaml \
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
    "github.com/pk910/bootoor/discv5"
    "github.com/pk910/bootoor/discv5/protocol"
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
- Real-time node count and bucket statistics
- Fork digest filtering statistics
- Protocol handler metrics (packets sent/received, handshakes, etc.)
- Session statistics
- Per-bucket node lists with fork digest information

### Statistics via API

The service exposes various statistics through the `GetStats()` method:

```go
stats := service.GetStats()
fmt.Printf("Table size: %d nodes\n", stats.TableSize)
fmt.Printf("Buckets filled: %d/256\n", stats.BucketsFilled)
fmt.Printf("Packets received: %d\n", stats.HandlerStats.PacketsReceived)
fmt.Printf("Current fork: %s\n", stats.ForkFilter.CurrentFork)
```

## Fork Digest Configuration

Fork digests are computed from the fork schedule in the CL config file:

```yaml
# config-mainnet.yaml
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
1. Computes fork digests: `hash(fork_version, genesis_validators_root)[:4]`
2. Determines current fork based on network time
3. Accepts nodes with current fork digest
4. Accepts nodes with old fork digests within grace period
5. Rejects nodes with invalid or expired fork digests

## Security Considerations

### DoS Protection

The bootnode implements multiple layers of DoS protection:

- **Rate Limiting**: 100 packets/second per IP at transport layer
- **Pending Limits**: Max 2000 pending handshakes, 500 pending challenges
- **Per-IP Limits**: Max 10 pending entries per IP address
- **LRU Eviction**: Oldest entries evicted when limits reached
- **Session Limits**: Max 1000 concurrent sessions with 12-hour lifetime

### Best Practices

1. **Private Key**: Generate a unique key for each bootnode, never reuse keys
2. **Firewall**: Allow only UDP traffic on your configured port
3. **Monitoring**: Enable web UI on localhost only or behind authentication
4. **Database**: Backup node database periodically for faster restarts
5. **Updates**: Keep bootnode updated for latest fork schedule changes

## Troubleshooting

### No Peers Discovered

- Check `--enr-ip` is your **public** IP, not `0.0.0.0` or `127.0.0.1`
- Verify UDP port is open in firewall: `nc -u -z -v <ip> <port>`
- Check genesis validators root matches your network
- Ensure CL config has correct fork schedule for your network

### Wrong Fork Digest Errors

- Verify `--genesis-validators-root` is correct for your network
- Check CL config file has correct `GENESIS_FORK_VERSION`
- Ensure system time is synchronized (use NTP)

### High Memory Usage

- Reduce `--max-nodes-per-ip` (default: 100)
- Enable database persistence with `--nodedb` to reduce memory

### Slow Peer Discovery

- Add more `--bootnodes` for initial peer discovery
- Reduce grace period: `--grace-period 30m`
- Check network connectivity to bootnodes

## Development

### Running Tests

```bash
go test ./...
```

### Building for Production

```bash
make build
```

### Project Layout

```
bootoor/
├── beacon-bootnode/      # Beacon-specific bootnode implementation
│   ├── config/          # Fork digest filtering and CL config
│   ├── discover/        # Lookup and ping services
│   ├── nodedb/          # Persistent node storage
│   ├── table/           # Routing table with IP limits
│   └── service.go       # Main bootnode service
├── discv5/              # Generic discv5 library
│   ├── crypto/          # Cryptographic primitives
│   ├── enr/             # Ethereum Node Record implementation
│   ├── node/            # Node identity and management
│   ├── protocol/        # Protocol handler and messages
│   ├── session/         # Session management and encryption
│   ├── transport/       # UDP transport with rate limiting
│   ├── config.go        # Configuration
│   └── service.go       # Core discv5 service
├── cmd/bootnode/        # Bootnode CLI application
├── webui/               # Web dashboard
└── README.md
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

- [Ethereum Discovery v5 Specification](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md)
- [Ethereum Node Records (ENR)](https://eips.ethereum.org/EIPS/eip-778)
- [Ethereum Consensus Layer Specs](https://github.com/ethereum/consensus-specs)
