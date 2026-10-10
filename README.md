# Markout Oracle

Signed crypto prices from independent nodes, checked by a quorum.

Each node reads live exchange feeds, calculates one price for each feed, and
signs it with its own key. The nodes do not talk to each other. A consumer takes
the median of several nodes, so one wrong or dishonest node cannot move the
price.

This repository holds the node, the Rust SDK for consumers, and the registry
canister on the Internet Computer that lists the nodes.

## Contents

- [How it works](#how-it-works)
- [What the oracle serves](#what-the-oracle-serves)
- [Run a node](#run-a-node)
- [Use the prices](#use-the-prices)
- [Security model](#security-model)
- [Repository layout](#repository-layout)
- [Development](#development)
- [License](#license)

## How it works

```text
exchanges ──▶ node 1 ──┐
          ──▶ node 2 ──┼──▶ consumer: checks each signature, takes the median
          ──▶ node 3 ──┘
                ▲
                └── registry canister: lists the node keys, signed by governance
```

1. **Ingest.** Each node keeps WebSocket connections to six venues: Binance,
   Bybit, OKX, Coinbase, Kraken and Deribit.
2. **Aggregate.** For each feed, the node removes stale and outlier sources, and
   takes a weighted median of the rest. Deeper and tighter order books weigh
   more.
3. **Sign.** The node signs each price with its key. It publishes when the price
   moves by 1 basis point or more, and at least once a second.
4. **Resolve.** The consumer checks each signature against the registry, and
   takes the median of the nodes. A quorum of three is the minimum.

**A signature proves who signed, not that the price is true.** One node's
signature tells you which node sent the price. It does not tell you that the
price is right. The protection against a bad node is the median of several
independent nodes. Use a quorum of three or more.

## What the oracle serves

| Feed | Example | Sources |
|---|---|---|
| Spot, in USD | `CRYPTO.BTC/USD` | Coinbase and Kraken in USD; Binance, Bybit and OKX in USDT, converted at the USDT/USD peg |
| Spot, in USDT | `CRYPTO.BTC/USDT` | Binance, Bybit, OKX |
| Perpetual mark | `CRYPTO.ETH/USDT.PERP_MARK` | the venues' own mark prices |
| Perpetual index | `CRYPTO.BTC/USD.PERP_INDEX` | the venues' own index prices |
| Perpetual mid | `CRYPTO.BTC/USDT.PERP_MID` | the mid of the perpetual order books |
| Funding | `CRYPTO.BTC/USD.FUNDING_8H` | Deribit's 8-hour funding rate |

The default set has about 225 feeds for about 145 assets. A feed uses only venue
markets that trade $1M or more a day. `scripts/asset-feeds.py` makes the list
from live venue data.

Each price has a confidence interval and a status:

| Status | Meaning |
|---|---|
| `ok` | Enough sources agree. |
| `degraded` | The price is published, with a warning. For example, two sources disagree, or the USDT/USD peg is not available. |
| `halted` | Too few sources. No price is published. |

Nodes also sign three other streams: a venue report (what each venue showed,
and how it counted), order book snapshots, and each venue's funding.

## Run a node

### Requirements

| Item | Requirement |
|---|---|
| System | Linux on amd64 or arm64, with glibc 2.28 or newer (Debian 10, Ubuntu 20.04, RHEL 8, or later) |
| CPU | 1 to 2 vCPUs. A node with 225 feeds uses about a quarter of one core. |
| Memory | 1 GB for the machine. The node itself uses about 50 MB. |
| Disk | 20 GB. A node keeps no history. |
| Network | About 300 KB/s from the venues, plus about 0.3 MB/s for each client. One port open to clients. |

### Install

The install script downloads the release binary and checks it against the
release's `SHA256SUMS`:

```bash
curl -fsSL https://github.com/markoutlabs/oracle-node/releases/latest/download/install.sh | sh
```

| Option | Effect |
|---|---|
| `--version v0.1.0` | Installs this release, not the latest. |
| `--to <dir>` | Installs into this directory. The default is `/usr/local/bin`, or `~/.local/bin` without root. |

On other systems, build from source with `make node`.

### Create the node

```bash
oracle-node init
```

At a terminal, `init` is a wizard. It asks:

1. Where to write the node's files.
2. The public endpoint that clients connect to, such as `wss://node1.example.com/v2/ws`.
3. How the node opens its key: with a passphrase in a `0600` file, which systemd
   needs, or with a passphrase that you type at each start.
4. Whether to write a systemd unit.

It writes nothing until you confirm. Then it writes:

| File | Contents |
|---|---|
| `signing.key` | The node's secret seed, encrypted with `age`. Keep it on this machine. |
| `passphrase` | The key's passphrase, if you chose a file. Mode `0600`. |
| `config.toml` | The node's config, with absolute paths. |
| `node-entry.json` | The registry entry for governance: the node's address and endpoint. It holds no secret. |
| `oracle-node.service` | The systemd unit, if you asked for it. |

For scripts, `init --out DIR` takes every value from flags. `init` never
overwrites a key.

### Register with governance

A node that is not in the registry signs prices that no client accepts. The node
also refuses to start until the registry lists its address.

Send `node-entry.json` to governance. Governance adds the node to the registry
canister:

```bash
scripts/add-node.sh --identity <governance identity> --json node-entry.json
```

### Run under systemd

```bash
sudo install -m 0644 oracle-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now oracle-node
journalctl -u oracle-node -f
```

The unit:

- starts the node as `Type=notify`, so `systemctl start` returns when the node
  serves;
- stops the node with SIGTERM, for a clean shutdown;
- restarts the node after a failure, but not after exit code 78, which is a
  config error;
- turns off core dumps and swap, because the key is in memory;
- limits the node to what it needs: its files, its port and outbound
  connections.

To keep the passphrase encrypted on disk, use `systemd-creds encrypt` and
`LoadCredentialEncrypted=` in the unit.

### Logs

Each minute the node writes a `status` line: feeds published, clients
connected, venue connections, and the latency from venue data to signed price.
A `venue lag` line follows, with the delay of each venue.

To see what each venue sends, start the node with `--tail`:

```bash
oracle-node start config.toml --tail
```

### Rotate the key

```bash
oracle-node rotate --dir <node dir>
```

`rotate` writes the next key beside the live one, and prints the
`replace_node` call for governance. When governance runs it, move the new key
into place and restart the node. Rotate one node at a time, so that consumers
never lose two nodes at once. Keys have no expiry; rotate when you suspect a
problem.

## Use the prices

### From Rust

The SDK `oracle-client` connects to the nodes in the registry, checks each
signature, and resolves the median.

1. Make a client key:

   ```bash
   cargo run -p oracle-client --example client_key -- --out client.key
   ```

2. Ask governance to list its address (`scripts/add-client.sh`). Nodes answer
   only listed clients.

3. Subscribe:

   ```bash
   cargo run -p oracle-client --example subscribe -- \
     https://<canister-id>.raw.icp0.io/registry.json 0x<governance-address> \
     CRYPTO.BTC/USD --canister-id <canister-id> --client-key client.key
   ```

The builder refuses a quorum below three, unless you call
`i_understand_this_provides_no_protection_against_a_bad_node()`.

Add the SDK to a project:

```toml
[dependencies]
oracle-client = { git = "https://github.com/markoutlabs/oracle-node", tag = "v0.1.0" }
```

### From a browser

A web page cannot keep a client key secret, so browsers do not connect to the
nodes. They connect to `oracle-proxy`: one listed client that checks every
signature and the quorum, and serves the result as JSON over a WebSocket.

## Security model

| Part | How it is protected |
|---|---|
| Node keys | Each node makes its own key. The key stays on the node's machine, encrypted at rest with `age`. There is no cloud key service. |
| Registry | A canister on the Internet Computer lists the node keys and the client keys. It signs each version with a threshold ECDSA key. Only governance can change it. |
| Freshness of the registry | Clients and nodes check the Internet Computer certificate on each fetch. |
| Client access | A client signs a challenge with its key. The node checks that the registry lists the client. |
| Data in transit | The node encrypts its stream for the listed clients. |
| Wrong prices | The median of the nodes, with a quorum of three or more. |

## Repository layout

| Crate | Purpose |
|---|---|
| `oracle-types` | Shared types: symbols, venues, fixed-point numbers, observations. |
| `oracle-ingest` | Venue connections and decoders, reconnects, local order books. |
| `oracle-agg` | Aggregation: staleness, outliers, weights, the publish policy. |
| `oracle-wire` | Byte layouts, signatures, the registry document. |
| `oracle-transport` | Client authentication and stream encryption. |
| `oracle-server` | The node's WebSocket server. |
| `oracle-client` | The consumer SDK. |
| `oracle-node` | The node binary: `init`, `start`, `rotate`. |
| `oracle-registry-canister` | The registry canister. |
| `oracle-replay` | Replays recorded venue data through the pipeline. |

Other folders:

| Folder | Contents |
|---|---|
| `node/` | `all-feeds.toml`, the feed set, and `assets.toml`, the generated asset feeds. |
| `scripts/` | The local stack, registry calls, the asset list. |
| `release/` | The release build and the install script. |

## Development

### Tools

- Rust, with the `wasm32-unknown-unknown` target
- [icp-cli](https://cli.internetcomputer.org/) 1.6 or newer, `ic-wasm` and `candid-extractor`, for the canister
- Docker, for `make release`

### Build and test

`make help` lists every target.

| Command | Does |
|---|---|
| `make test` | Runs every test, PocketIC included. |
| `make lint` | Checks formatting and runs clippy. |
| `make node` | Builds `oracle-node` for this machine. |
| `make canister` | Builds the canister wasm and its `.did`. |
| `make e2e` | Runs the whole system on PocketIC. |
| `make smoke` | Deploys the canister on a local network with icp-cli. |
| `make latency` | Measures live latency from the venues to the SDK. |

### Local stack

`scripts/dev-stack.sh` runs a whole oracle on this machine: the registry
canister on a local network, three nodes on ports 8801 to 8803, and one listed
client key. Nothing on mainnet changes.

```bash
scripts/dev-stack.sh            # 3 nodes; Ctrl-C stops everything
NODES=1 scripts/dev-stack.sh    # 1 node
ASSETS=1 scripts/dev-stack.sh   # also the feeds of node/assets.toml
```

Keys, configs and logs are in `target/dev-stack/`.

### Asset list

```bash
scripts/asset-feeds.py           # writes node/assets.toml from live venue data
```

The script keeps assets that three or more venues trade with $1M or more a
day. It leaves out stablecoins, wrapped tokens, leveraged tokens, and stock or
commodity perpetuals. Volumes change each day, so each run gives a new list.

### Release

`make release` builds the release files in a pinned Docker image, so anyone can
rebuild them and get the same bytes:

```text
target/release-artifacts/oracle_registry_canister.wasm
target/release-artifacts/oracle-node-linux-{amd64,arm64}
target/release-artifacts/SHA256SUMS
```

To publish a release:

```bash
make release
git tag v0.1.0 && git push origin v0.1.0
make publish        # uploads the files and install.sh as GitHub release v0.1.0
```

`make publish` refuses unless the tree is clean and the tag points at `HEAD`.

### Registry canister on mainnet

The identity that deploys the canister becomes its controller, and so its
governance.

```bash
make deploy ENV=ic IDENTITY=<identity>        # the release wasm, then icp deploy
make governance ENV=ic IDENTITY=<identity>    # prints the canister id and governance address
```

The canister signs with the `key_1` threshold key. Each signature costs cycles,
so keep the canister funded.

## License

MIT or Apache-2.0, at your option.
