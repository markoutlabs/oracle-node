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
| System | Linux on amd64 or arm64. The installer supports Debian, Ubuntu, RHEL, Fedora, Alpine, openSUSE and Arch. |
| CPU | 1 to 2 vCPUs. A node with 225 feeds uses about a quarter of one core. |
| Memory | 4 GB to build; 2 GB with swap works, more slowly. The node itself uses about 50 MB. |
| Disk | 20 GB. A node keeps no history. |
| Network | About 300 KB/s from the venues, plus about 0.3 MB/s for each client. One port open to clients. |

### Install

Run these two commands on the node's machine:

```bash
curl -fsSL https://raw.githubusercontent.com/markoutlabs/oracle-node/main/release/install.sh | sh
sudo oracle-node init
```

The first command builds the node from source. The second asks one question,
the URL that clients connect to. Then it sets up and starts the node. The node
serves when governance adds it to the registry.

#### The install script

1. If there is no C compiler, it installs one with the system's package
   manager: apt, dnf, yum, apk, zypper or pacman.
2. If there is no Rust 1.85 or newer, it installs Rust with `rustup`. It does
   not change your shell profile.
3. It builds `oracle-node` with `cargo install --locked`. This takes about 5 to
   10 minutes. With less than 3.5 GB of memory, it builds one job at a time.
4. It installs the binary to `/usr/local/bin`, with sudo if necessary.

Put options after `sh -s --`:

| Option | Effect |
|---|---|
| `--version v0.1.0` | Builds this tag. A branch or a commit also works. The default is `main`. |
| `--to <dir>` | Installs into this directory. Without root or sudo, the default is `~/.local/bin`. |

#### `sudo oracle-node init`

1. It creates the system user `oracle-node`, with no login.
2. It writes the node's files to `/var/lib/oracle-node`. Only the `oracle-node`
   user can open this directory.
3. It installs the systemd unit `/etc/systemd/system/oracle-node.service`,
   enables it at boot, and starts it.
4. If ufw or firewalld is active, it opens the node's port.
5. It prints the `add_node` call for governance.

| File | Contents |
|---|---|
| `signing.key` | The node's secret seed, encrypted with `age`. It is the only copy. Keep it on this machine. |
| `passphrase` | The passphrase of the key. Mode `0600`. |
| `config.toml` | The node's config, with every feed of the network. |
| `node-entry.json` | The registry entry for governance: the node's address and endpoint. It holds no secret. |

The endpoint is the URL that clients dial, such as `ws://203.0.113.7:8791/v2/ws`.
The node listens on the port of the URL. Behind a TLS proxy, use a `wss://` URL
without a port. The node then listens on port 8791.

For a script, give the endpoint as a flag:

```bash
sudo oracle-node init --endpoint ws://203.0.113.7:8791/v2/ws
```

`init` never overwrites a key. On a machine that already has a node, it stops
before it writes anything.

### Register with governance

A node that is not in the registry signs prices that no client accepts. So until
the registry lists the node, the node waits. It does not connect to the venues
or serve clients. It checks the registry every 30 seconds.

Send the `add_node` call that `init` printed to governance. The same entry is in
`/var/lib/oracle-node/node-entry.json`. Governance adds the node to the registry
canister:

```bash
scripts/add-node.sh --identity <governance identity> --json node-entry.json
```

The node starts to serve at its next check.

### The service

```bash
journalctl -u oracle-node -f        # the log
systemctl status oracle-node        # "activating" until the registry lists the node
sudo systemctl restart oracle-node  # after a config edit
```

The unit:

- starts the node as `Type=notify`, so systemd knows when the node serves;
- stops the node with SIGTERM, for a clean shutdown;
- restarts the node after a failure, but not after exit code 78, which is a
  config error;
- turns off core dumps and swap, because the key is in memory;
- limits the node to what it needs: its files, its port and outbound
  connections.

To keep the passphrase encrypted on disk, use `systemd-creds encrypt` and
`LoadCredentialEncrypted=` in the unit.

### Without root

Without sudo, `oracle-node init` writes the files only, to a directory that you
choose. At a terminal, it is a wizard. It can also write a systemd unit for you
to install. For scripts, `init --out DIR` takes every value from flags. Start
the node with:

```bash
oracle-node start <dir>/config.toml
```

### Logs

Each minute the node writes a `status` line: feeds published, clients
connected, venue connections, and the latency from venue data to signed price.
A `venue lag` line follows, with the delay of each venue.

To see what each venue sends, start the node with `--tail`:

```bash
oracle-node start config.toml --tail
```

### Update the feeds

`init` writes the feeds of its own version into the config. After you install a
new version, write its feeds into the config, and restart the node:

```bash
sudo oracle-node update-feeds /var/lib/oracle-node/config.toml
sudo systemctl restart oracle-node
```

The old config stays as `config.toml.prev`.

### Rotate the key

```bash
sudo -u oracle-node oracle-node rotate --dir /var/lib/oracle-node
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

### From a canister

The nodes push their signed prices to the registry canister, which checks each
signature and serves the median of the nodes. A canister calls `get_price` with
the feed's 32-byte id, keccak256 of its symbol:

```rust
use candid::{CandidType, Deserialize, Principal};
use ic_cdk::call::Call;
use serde_bytes::ByteBuf;

#[derive(CandidType, Deserialize)]
enum PriceStatus { Ok, Degraded, Halted }

/// The fields you need. Candid ignores the others.
#[derive(CandidType, Deserialize)]
struct PriceRecord { status: PriceStatus, price: Option<i64>, expo: i32, publish_time_ns: u64 }

// CRYPTO.BTC/USD
let feed_id = hex::decode("0523e79c7ed211911a19afaa4def68c896bc72d674bf33c5c64d4d7089e320e2")?;
let oracle = Principal::from_text("xb5gv-diaaa-aaaaf-qg5qa-cai")?;
let reply = Call::bounded_wait(oracle, "get_price")
    .with_arg(ByteBuf::from(feed_id))
    .await?;
let btc: Option<PriceRecord> = reply.candid()?;
```

The price is `price × 10^expo`. Use it only when the status is `Ok` or
`Degraded`. A feed whose nodes stop pushing goes `Halted` after 75 s.
`get_feeds` lists the priced feeds and their ids.

### Certified, over HTTPS

```bash
curl https://xb5gv-diaaa-aaaaf-qg5qa-cai.icp0.io/prices.json
```

The gateway checks the canister's certificate before it serves the document.
To check it yourself, fetch from the `raw` domain and verify it with
`ic-response-verification`, as the SDK does for `/registry.json`. The document
is resolved when the last frame arrived, so also check `resolved_at_ns`.
`/frames.json` holds the nodes' signed frames, for a client that checks the
nodes itself.

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
and so does each push from a node: about 12T cycles a month for each node on a
quiet market (SPEC §3.7). Keep the canister funded.

On an installed canister, `make deploy` upgrades it and keeps every node,
client and price. After the first upgrade with prices, governance lists the
priced feeds. The 14 defaults are in the install arguments in `icp.yaml`:

```bash
icp canister call oracle_registry set_feeds '(vec { "CRYPTO.BTC/USD"; "CRYPTO.ETH/USD" })' -e ic
```

## License

Copyright 2026 Markout Labs.

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, change
and distribute this code under its terms. It comes with no warranty. The
license gives no right to use the Markout Labs name.
