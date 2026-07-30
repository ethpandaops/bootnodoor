# Testing bootnodoor against a Kurtosis devnet

This is the end-to-end test for the bootnode itself: does it discover real clients,
classify them into the right layer tables, keep its advertised fork fields correct
across transitions, persist what it learns, and generate no traffic it should not.

The procedure below is deliberately independent of client versions and open branches.
Put short-lived image pins and known interop failures in
[Current validation notes](#current-validation-notes), not in the procedure.

## What only a devnet can tell you

Unit tests cover the logic. A devnet is the only place that produces:

- a **fork actually activating** while the daemon runs, with real clients reacting to it;
- **real peers on the other end** of discv4/discv5, including clients that are slow,
  wrong, or aggressive;
- **wire evidence** — what bootnodoor actually sends, which is the only way to catch a
  self-inflicted traffic loop;
- **restart behaviour** against a database with real contents.

Every serious defect found in this component to date came from one of those four, not
from the unit suite.

## Scratch layout

Keep devnet state outside the repository:

```text
/path/to/bootnodoor-devnet/
├── network_params.yaml          # steady state, all forks at genesis
├── network_params.forks.yaml    # scheduled transitions
├── network_params.devnet7.yaml  # pinned public-devnet images
├── sample.sh                    # 30s counter + ENR sampler
├── burst.sh                     # 5s high-resolution sampler
└── config/                      # optional: ENRScout bundle
```

## 1. Define the client matrix

Seven EL/CL pairs give full client coverage:

```yaml
participants:
  - { el_type: geth, cl_type: lighthouse, count: 1 }
  - { el_type: nethermind, cl_type: teku, count: 1 }
  - { el_type: reth, cl_type: prysm, count: 1 }
  - { el_type: erigon, cl_type: caplin, count: 1 }
  - { el_type: besu, cl_type: nimbus, count: 1 }
  - { el_type: nimbus, cl_type: grandine, count: 1 }
  - { el_type: ethrex, cl_type: lodestar, count: 1 }

network_params:
  network: kurtosis
  network_id: "3151908"
  seconds_per_slot: 12
  deneb_fork_epoch: 0
  electra_fork_epoch: 0

bootnodoor_params:
  image: ethpandaops/bootnodoor:your-build

additional_services:
  - bootnodoor
```

Build the image under test locally and reference it by tag; the package uses it as-is if
it exists in the local Docker daemon.

```bash
docker build -t ethpandaops/bootnodoor:my-test .
```

## 2. Launch

```bash
cd /path/to/bootnodoor-devnet
kurtosis run --enclave bootnodoor-devnet \
  github.com/ethpandaops/ethereum-package --args-file network_params.yaml
```

Then resolve the ports and genesis, which everything else keys off:

```bash
BN=$(kurtosis port print bootnodoor-devnet bootnodoor http | grep -oE '[0-9]+$')
CL=$(kurtosis port print bootnodoor-devnet cl-1-lighthouse-geth http | grep -oE '[0-9]+$')
GEN=$(curl -s "http://127.0.0.1:$CL/eth/v1/beacon/genesis" \
      | grep -oE '"genesis_time":"[0-9]+"' | grep -oE '[0-9]+')
```

## 3. Sample continuously, not at the end

bootnodoor's interesting behaviour is transient. A counter read after the fact tells you
almost nothing; a timestamped series tells you when something started and what it
correlated with. Two samplers, both scraping the web UI:

- **30s sampler** — fork name, digest, ENR hashes for `/enr`, `/el-enr`, `/cl-enr`, plus
  node/session/packet counters. Enough to see a run's shape.
- **5s sampler** — the same counters around a transition, where a 30s gap can hide the
  entire event.

Scrape the fields by label from `/`, and note the parsing gotchas in
[Harness gotchas](#harness-gotchas).

## 4. What to check, and what "good" looks like

### Fork discipline

The core invariant. Per scheduled fork:

- exactly **one** `fork transition: re-published ENR fork fields` log line;
- the ENR sequence steps **exactly once** — flat between transitions;
- all three of `/enr`, `/el-enr`, `/cl-enr` change together;
- the fork name and `Current Digest` on the UI both advance.

A step per refresh tick means change detection is broken. No step means the refresh is
not firing. Both are why `UpdateENR` is a no-op when nothing changed.

A BPO changes the digest without changing the CL fork _name_ — `Fulu` stays while the
digest moves. That is correct, not a missed transition.

### Refresh lag

Time from the epoch boundary to the re-publish log line. This should be within about one
slot. If it varies wildly between transitions on the same run, the refresh is being
carried by a periodic backstop rather than by the boundary, which is a defect even when
the average looks acceptable — see the 2026-07-29 notes.

### Self-inflicted traffic

**Watch `Packets Sent`, not just `Packets Received`.** A bootnode answering queries is
normal; a bootnode _originating_ thousands of packets is not. Across a transition, the
received rate should stay at its baseline. A spike of several hundred per second means
something is looping.

Aggregate counters cannot tell you who is talking or which direction. Capture the wire:

```bash
C=$(docker ps --format '{{.ID}}\t{{.Names}}' | grep 'bootnodoor--' | cut -f1)
docker run --rm --net=container:$C nicolaka/netshoot \
  tcpdump -n -q -c 20000 'udp port 9000' > capture.txt
```

`--net=container:` shares the target's network namespace, which is what makes another
container's traffic visible at all. Then count discv4 packet types by size and direction:

| size    | type              |
| ------- | ----------------- |
| 138     | PING              |
| 154     | PONG              |
| 104     | ENRREQUEST        |
| 292–298 | ENRRESPONSE       |
| 436–800 | NEIGHBORS / NODES |

```bash
grep -oE '172\.16\.0\.11\.9000 > 172\.16\.0\.[0-9]+\.[0-9]+: UDP, length (138|104)' capture.txt \
  | awk '{split($3,a,"."); print a[4], $NF}' | sort | uniq -c | sort -rn
```

Healthy is single digits per peer per minute. Thousands means a retry loop.

**Byte ratio is not packet ratio.** Outbound is dominated by NEIGHBORS/NODES replies that
are far larger than the queries provoking them, so sent/received bytes sits around 3:1 in
normal operation. That is inherent to serving discovery. The protection against
reflection is the bond/session gate on FINDNODE, not the ratio — do not read a ratio
above 1 as an amplification bug.

### Counter sanity

- **`Invalid Packets` should be near-zero and flat.** discv5 is registered first and
  rejects anything it cannot decode, so every ordinary discv4 packet on the shared socket
  falls through to discv4. Those land in `Other Protocol`. If `Invalid Packets` tracks
  your traffic volume, the dispatcher accounting has regressed.
- **`Inactive Nodes` must never be negative**, and `Active` must never exceed `Total`.
  Those come from different populations (memory vs database) and a negative value means
  the set arithmetic broke.

### Persistence

Restart the container mid-run and confirm the tables reload:

```bash
docker restart "$C"
docker logs "$C" 2>&1 | grep "loaded random nodes into active pool"
```

Both layers should report counts. Zero means organic discoveries were never written.

### `--serve-all`

This is the highest-value single test and it needs its own node, because the package
exposes no way to pass extra arguments to the packaged bootnodoor. Run a second instance
joined to the enclave network:

```bash
GH=$(curl -s -X POST -H 'content-type: application/json' \
     --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0",false],"id":1}' \
     "http://127.0.0.1:$RPC" | grep -oE '"hash":"0x[0-9a-f]+"' | grep -oE '0x[0-9a-f]+')

docker run -d --name sa --network kt-bootnodoor-devnet \
  -v /tmp/gendata:/network-configs:ro -p 38080:8080 \
  ethpandaops/bootnodoor:my-test \
  --cl-config /network-configs/config.yaml \
  --genesis-validators-root "$(cat /tmp/gendata/genesis_validators_root.txt)" \
  --el-config /network-configs/genesis.json --el-genesis-hash "$GH" \
  --private-key "$(openssl rand -hex 32)" \
  --bind-addr 0.0.0.0 --web-ui --nodedb /nodes.db --serve-all \
  --el-bootnodes "$(curl -s http://127.0.0.1:$BN/el-enr)" \
  --cl-bootnodes "$(curl -s http://127.0.0.1:$BN/cl-enr)"
```

`--serve-all` pools every discovered peer into **every** enabled table, so one node ID
occupies both layers. That makes it the only configuration that exercises the
`(nodeid, layer)` composite key against real peers — a normal run cannot, because no real
client advertises both `eth` and `eth2`. EL and CL are separate identities with separate
keys; not even a unified binary publishes one record for both.

Expect most peers in both layers, each row carrying its own layer's fork digest with the
other empty, and every `lookup complete` showing `rejected_fork=0 rejected_layer=0`.

## 5. Fork-transition testing

Copy the whole steady-state file and replace only `network_params`. Kurtosis takes one
`--args-file` and does not merge, so the fork file must still carry `participants` and
`additional_services: [bootnodoor]`.

```yaml
network_params:
  network: kurtosis
  network_id: "3151908"
  seconds_per_slot: 12
  deneb_fork_epoch: 0
  electra_fork_epoch: 1
  fulu_fork_epoch: 3
  bpo_1_epoch: 5
  bpo_1_max_blobs: 12
```

Mainnet preset, 32 slots per epoch, 12s slots — one epoch is 384s, so that schedule
transitions at roughly T+6m, T+19m and T+32m and wants ~50 minutes. Include a BPO: it
moves the digest through the blob schedule rather than a fork version, reaching code an
ordinary fork does not.

Compute the wall-clocks before you start so log lines can be correlated:

```bash
for e in 1 3 5; do
  t=$((GEN + e*32*12))
  echo "epoch $e -> $(date -r "$t" '+%H:%M:%S' 2>/dev/null || date -d "@$t" '+%H:%M:%S')"
done
```

### Testing against a public devnet's images

Pin every client to the target devnet's tags, taken from that devnet's ansible inventory
(`images.yaml`). Pull them first — this is network-bound and can be done while other work
proceeds.

Public devnets schedule their real fork far out (gloas at epoch 38 is ~4h at 12s slots).
Pull it forward to something like epoch 4 so the transition lands inside the run, and say
so in the file — the deviation matters when reading results.

## Harness gotchas

Every one of these cost real time.

**SQLite is in WAL mode.** `docker cp` of `nodes.db` alone shows _no tables_ — it looks
like total data loss. Copy `nodes.db`, `nodes.db-wal` and `nodes.db-shm` together.

**Kurtosis reassigns host ports on `docker restart`.** After restarting the bootnodoor
container, re-resolve with `kurtosis port print`; samplers pointed at the old port
silently write empty rows.

**Kurtosis refuses to schedule when the host is busy.** "requires 100 millicores but we
will only have 0 available" means something else is consuming the box — a concurrent hive
run will do it. Never run fork-timing tests on a loaded host: missed slots look exactly
like bootnodoor bugs.

**Scrape hyphenated fork names.** `BPO-1` contains a hyphen; a `[A-Za-z0-9]+` character
class silently skips it and matches the _next_ field, which is the digest. Symptom: the
fork column fills with hex.

**`bootnodoor_params` has no extra-args hook.** Non-default flags such as `--serve-all`
need a standalone container on the enclave network.

**Caplin has no separate image pin.** It ships inside erigon, so a devnet inventory has no
caplin entry and the package falls back to its default tag. Leave `cl_image` unset for the
erigon pair and note the gap.

**Arm packet captures with care.** A shell loop building filenames from positional
parameters inside `nohup bash -c` is easy to get wrong; all three of my captures ended up
sharing one filename and firing early. Verify each armed job's command line before
walking away.

**ENRScout needs `GENESIS_TIME`.** Kurtosis emits only `MIN_GENESIS_TIME`; append the
derived key if you run the crawler alongside. See the [ENRScout guide][enrscout-doc].

## Interpreting results

- **A transition is not a fork name change.** A BPO moves the digest while the name holds.
  Compare digests, not labels.
- **Rejection counters are not fork health.** On a dual-layer network most records an EL
  lookup sees are consensus records; that is `rejected_layer`, not `rejected_fork`.
- **A quiet counter can still be wrong.** `Invalid Packets` sitting at 84% of received
  traffic looked like an attack signal for an entire run before it turned out to be
  ordinary discv4 load being miscounted. Check what a counter _means_ before treating its
  value as evidence.
- **Correlate direction before assigning blame.** A traffic spike involving one peer says
  nothing about which side started it. The packet sizes above resolve it in seconds.

## Cleanup

```bash
docker rm -f sa
cd /path/to/bootnodoor-devnet && docker compose down -v
kurtosis enclave rm -f bootnodoor-devnet
```

## Current validation notes

Dated and disposable. Update as fixes land; the procedure above should stay valid.

### Runs on 2026-07-29 / 07-30

Baselines from a full validation sweep — steady state, the Electra/Fulu/BPO1 schedule, and
glamsterdam devnet-7 images (13 of 14 pinned; caplin fell back to its default tag).

Organic coverage was 5/7 EL (besu, erigon, ethrex, geth, reth) and 7/7 CL. nimbus-eth1 is
the standing EL gap. Nethermind joins but is identified only outbound.

**A packet storm was found and fixed.** A PONG advertising a newer ENR sequence spawned an
unguarded ENR refresh; each refresh PINGs and sleeps before its ENRREQUEST, so the PONG it
provoked re-entered the same trigger with the cached sequence still stale. Peak was
~980 packets/s, with 2575 PINGs and 2574 ENRREQUESTs sent to a single geth peer in 51s.
Post-fix that peer sees a maximum of 14 and 7 over 60s.

Two things about that defect are worth remembering as method:

- It looked fork-correlated because forks bump many peers' sequences at once. **The actual
  trigger is any ENR sequence bump**, which is a far broader exposure than the fork window
  it appeared in.
- The direction was initially read backwards from aggregate counters alone. Only the
  packet capture showed bootnodoor was the originator.

**A regression was caught by the devnet after code review missed it.** A first fix armed
the fork refresh at the boundary but skipped a boundary that had just passed, falling back
to a 60s backstop; lag came out 75s / 16s / 0s — the 75s _worse_ than the ticker it
replaced. The fix polls after a boundary; re-run gave 0s / 0s / 4s. Reviewing the code
found none of this.

Also fixed in the same sweep: organic nodes were never written to the database (`Add`
marked them dirty but nothing enqueued them); the `nodes` and `bad_nodes` tables were keyed
on `nodeid` alone despite being per-layer, so under `--serve-all` 10 of 11 peers lost a
layer on every restart; and `Invalid Packets` conflated other-protocol traffic with
malformed packets.

### Confirmation run on 2026-07-30

devnet-7 images plus a standalone `--serve-all` node, both on the same build.

Three transitions, `seq` 3→4→5, one log line each, zero errors or warnings. Six distinct
`(fork, digest)` states across the series. Storm-free throughout: ~11–13 packets/s across
every boundary, and a peak of 9 PINGs / 5 ENRREQUESTs to any single peer in the 60s around
gloas. `Invalid Packets` sat at 6 for the entire run while `Other Protocol` absorbed 8,800.
`Inactive Nodes` was 0 at every sample. Under `--serve-all`, 12 of 14 peers occupied both
layers with no errors.

**Refresh lags were 2s, 8s and 25s.** The third exceeds one slot and is worth knowing how
to read. The UI's `Current Fork` is computed live from the wall clock, while
`Current Digest` returns a value cached until `clFilter.Update()` runs inside the refresh
(`bootnode/clconfig/filter.go` — compare `GetCurrentFork` with `GetCurrentDigest`). So a
window where the name has advanced but the digest has not *is* the refresh lag, displayed
in two fields rather than a second defect. Here the boundary timer fired on time and the
digest was simply not derivable for ~25s. Candidate follow-up, not a blocker: it is well
inside the backstop and far better than the 8/20/22s and 2/22/51s measured before the
boundary-armed refresh landed.

### Not yet covered

- **BPO blob semantics.** BPO-1/BPO-2 change `MAX_BLOBS_PER_BLOCK`, but both runs carried
  no blob transactions, so only the digest change was exercised. Adding `spamoor` with blob
  load would close this.
- **Dead nodes are still served.** `PerformSweep` demotes only when the table is over
  capacity, and FINDNODE responses are not filtered on liveness.
- **DB-restored v4 pointers are detached.** `buildNodeFromDB` reconstructs its own discv4
  node rather than the handler's, so proven-address promotion never reaches it.

[enrscout-doc]: https://github.com/mysticryuujin/enrscout/blob/main/docs/testing-with-kurtosis.md
