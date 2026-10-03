# price-oracle

A network of independent Rust nodes that ingest exchange WebSocket feeds, aggregate them into signed price updates, and serve them to subscribers. Nodes do not talk to each other; each is an independent attestor, and the consumer takes a median across M-of-N.

Full design in [`SPEC.md`](SPEC.md). Threat model and known pitfalls in [§12](SPEC.md#12-threat-model-and-pitfalls) — read that before building anything on top of this.

## The one thing to understand

**A signature proves authorship, not truth.** It says node X asserted this price at this time. It says nothing about whether the price is right, or even whether the node ever connected to an exchange — `num_sources` is inside the signed payload, but nothing binds that claim to reality.

The defence against a lying or malfunctioning node is not cryptographic. It is the median across N independently-keyed nodes plus divergence monitoring. A consumer verifying signatures from a single node has confirmed who is talking and learned nothing about whether to believe them.

## Status

| Milestone | Scope | State |
|---|---|---|
| M0 | `oracle-types`, `oracle-wire` | **done** |
| M1 | Binance adapter + normalization | **done** (see caveat below) |
| M2 | `oracle-agg` + halt/degrade | **done** |
| M3 | WS/REST server + client SDK | **done** |
| M3.5 | `oracle-node` binary wiring the pipeline | **done** |
| M4 | Remaining venues + USDT/USD conversion | **done** |
| M5 | Multi-node deploy + registry rotation | **done** |
| M5.5 | Registry canister, one live key per node | **done** |
| M6 | Hardening | in progress: keys encrypted at rest, replay harness, adversarial suite, metrics and alerts |

## Crates

### `oracle-types`

Pure data. No I/O, no clock, no cryptography.

- `Fixed` — `i128` fixed-point at `10^-12`. No floating point anywhere in the pricing path, so a recorded observation set replays to a bit-identical price.
- `Symbol` / `FeedId` — canonical feed identity. A `Symbol` cannot be constructed in a non-canonical form, which is what makes hash-derived feed IDs safe without a coordinating registry.
- `Venue` / `VenueSet` — wire-stable venue numbering for the `source_bitmap`.
- `Flags` — status bits. Reserved bits are **rejected**, not masked: an old client that cannot read a new warning must not conclude there is no warning.
- `Observation` — one venue's view of one instrument, with mid/microprice/spread derivations.
- `PriceUpdate` — the logical payload that gets signed.

### `oracle-ingest`

Exchange WebSocket ingest. Every venue sits behind `ExchangeAdapter`, so the
aggregator never learns anything venue-specific.

- `binance::decode` — pure: bytes and a receipt timestamp in, observations out.
  Tested against captured payloads, not a live exchange.
- `Session` — the connect/decode/reconnect loop, generic over `Connector` so
  reconnect behaviour is tested with a mock in microseconds. Reconnect logic only
  exercised against a live venue is logic only exercised during an outage.
- `Backoff` — `backon`'s exponential ladder with jitter, plus a reset once a
  connection proved stable. Jitter is seeded from OS entropy per connection, so
  sibling connections and sibling nodes never re-synchronise after a shared
  outage. Tests pass a seed and assert the exact schedule.
- `MonotonicClock` — forward-only unix nanoseconds. `SystemTime::now()` can step
  backwards under NTP, which makes in-flight observations look like they arrived
  from the future and read as age zero forever.

Binance encodes subscriptions in the URL; every other venue connects, sends a
subscribe frame, and needs an application keepalive, so they share a
`VenueAdapter` and supply only their naming and their decoder. The decoder is
attached **per connection**, not per venue — Kraken spot and Kraken Futures share
a brand and nothing else.

| Venue | Spot | Mark | Index | Funding |
|---|:--:|:--:|:--:|:--:|
| Binance | ✅ | ✅ | ✅ | ✅ (raw interval) |
| Bybit | ✅ | ✅ | ✅ | ✅ (raw interval) |
| OKX | ✅ | ✅ | — | ✅ (raw interval) |
| Coinbase | ✅ | — | — | — |
| Kraken | ✅ | ✅ | ✅ | ✅ (1h) |
| Deribit | — | ✅ | ✅ | ✅ (**8h, normalised**) |

Two venues are deliberately absent from that table:

- **Coinbase perpetuals.** They live on Coinbase International, whose market-data
  socket authenticates every subscription with an API key, passphrase and HMAC
  signature. This build has no credential path for ingest, so configuring one is
  a startup error naming the reason rather than a socket that gets dropped three
  seconds after connecting.
- **Binance coin-margined futures.** A different host with its own contract
  catalogue. `base_url` returns `None` for `inverse_perp` rather than falling
  back to the USD-margined host, which would stream a different contract under a
  name that looks right.

**Deribit is the only funding source that is currently safe to aggregate.** It
publishes `funding_8h`, a fraction over a fixed eight-hour window. Every other
venue publishes a fraction over its own interval — 1h on Kraken Futures, 8h or 4h
on Binance depending on the contract, and the message does not say which. See
[the funding caveat](#funding-is-not-normalised).

`MarketKind` now distinguishes `InversePerp` from `LinearPerp`, because the
distinction is load-bearing: on Deribit's `BTC-PERPETUAL` the order sizes are
quoted in **USD**, not BTC. They are divided by price on the way in so every
venue reports base units. Nothing today would notice if that were wrong —
`microprice` is scale-invariant within one observation and depth weighting is
inert — which is exactly why it is a distinct market kind rather than a comment.

Two invariants the code enforces rather than documents:

- **Staleness uses our clock, never the venue's.** `exchange_time_ns` is an
  `Option` because Binance spot `bookTicker` genuinely sends no timestamp, and
  live futures data shows venue stamps arriving *ahead* of our receipt clock.
- **A reconnect invalidates state; it does not resume it.** Every session emits
  `IngestEvent::Disconnected` before any post-reconnect quote, and consumers must
  drop that venue's book rather than carry a pre-gap quote across the hole.

### `oracle-agg`

Aggregation: many venues' observations into one price and confidence.

`Aggregator` holds no clock, opens no socket, spawns nothing. Time arrives as a
`now_ns` argument and results are returned rather than sent — so a recorded
observation sequence replays bit-for-bit, months later, on another machine. Every
production incident becomes a unit test instead of an argument.

```text
observations ──▶ per-venue quote     (microprice, staleness, crossed books)
             ──▶ outlier rejection   (MAD, unweighted, never below quorum)
             ──▶ weight cap          (no source may buy the median)
             ──▶ weighted median
             ──▶ confidence          (disagreement ∨ spread ∨ floor)
             ──▶ circuit breakers    (jump corroboration, sanity band)
             ──▶ publication policy  (rate cap, then deviation ∨ heartbeat)
```

**The governing bias: degrade loudly, halt rarely, never silently narrow.** An
oracle that goes dark breaks its consumers; one that publishes a confident wrong
number liquidates them. Widening the confidence interval is the pressure-release
valve. Halting is reserved for the two cases with no honest price to widen
around: too few live sources, and a price outside the sanity band.

`conf` is the widest of three floors — venue disagreement, actual book spreads,
and an absolute minimum. It is not decoration; it is how the oracle says "markets
are dislocated" without either lying or going dark, and it is the number a
consumer should key off.

**Why the weight cap exists.** A weighted median offers no protection against
weight itself: a sample holding more than half the total *is* the answer,
whatever its value. The weight inputs — spread and freshness — are exactly what a
manipulating venue controls. So outlier rejection runs first and is deliberately
**unweighted**, and surviving weights are then capped to a multiple of the median
weight. `stats::a_dominant_weight_captures_the_weighted_median` documents the
underlying hazard so nobody removes those two defences by accident.

### `oracle-server`

The subscriber-facing node: WebSocket fanout and REST.

Fanout is **conflating** — one slot per feed per subscriber, newer replaces
pending older. A stale price delivered from behind a backlog is worse than no
price, because the consumer acts on it as though it were current. Frames are
signed and encoded once and shared as `Bytes` across every subscriber; the JSON
view is built lazily, since most subscribers take binary.

The consequence consumers must internalise: **you observe state, not
transitions.** A sub-second halt can be conflated away. Every frame carries
complete state and the heartbeat makes any sustained halt unmissable, but code
that accumulates transitions rather than reading state will eventually be wrong.

`GET /v1/registry` serves this node's registry as a **hint, never a trust root**.
A consumer that accepted it as authoritative would let the node vouch for itself,
and therefore add itself.

### `oracle-client`

The consumer SDK, and the answer to "so how do I actually use this safely".

Two pure, synchronous halves with a thin async layer on top:

- `Verifier` — one update at a time: signature, registry membership, certificate
  validity **at publish time**, sequence monotonicity, staleness, coherence.
  Replay and staleness are the consumer's job because signatures say nothing
  about freshness: a relay that withholds new updates and rebroadcasts an old one
  passes every cryptographic check flawlessly.
- `FeedView` — the cross-node step: median price, with confidence floored at half
  the inter-node spread. **That floor is the crux.** A disagreeing node cannot
  move the median, and its disagreement automatically widens the band — so a
  consumer keying off `conf` reacts correctly with no extra logic.

`OracleClientBuilder::build` **refuses a quorum below three** unless you call
`i_understand_this_provides_no_protection_against_a_bad_node()`. Verifying
signatures from one node confirms who is talking and nothing else, and that is
the mistake most likely to be made during integration and then never revisited.

#### How a rotation reaches the consumer

A node holds one live signing key at a time (SPEC §3.5). When its operator
rotates it, the registry canister swaps the key atomically, and the consumer
finds out from the first frame it cannot verify:

1. An unknown signer triggers one fetch from the `RegistrySource`, at most once
   per `refresh_interval` (10s by default). Anyone who can inject a frame can
   trigger the fetch, so the floor is what keeps a hostile relay from turning
   the client into a load generator against the registry.
2. `refresh_registry` adopts the document in place if it is strictly newer and
   signed by the pinned governance address. No reconnect, no lost feed state.
   Nodes the new version de-lists are dropped from the quorum **on adoption**,
   not once their last update ages out.
3. The frame is retried. The node is back with its new key, and it kept its seat
   and its replay floor, because both are keyed by `NodeId` and not by address.
4. The old key is now **retired**, not unknown. Frames it signed are refused as
   `RetiredKey` and never trigger another fetch. A few right after a rotation
   are frames that were in flight. A steady stream is a stolen key in use.

The canister re-signs the document daily even when nothing changed, so a
registry older than `max_registry_age` (48h by default) means the fetch path is
broken or newer versions are being withheld. Every feed is then reported
`Degraded` with `Concern::RegistryStale`. The prices are still verified; the
membership may not be current.

`HttpRegistrySource::canister(id)` fetches `/registry.json` from the canister.
The canister answers through an update call, so the gateway's response
verification passes without the canister building certification trees. The
document carries its own governance signature either way, which is the check
every consumer runs.

Stored frames are a separate path. `verify_historical` checks a frame against
the key that was live at its publish time, using the node's key history from the
canister, bounded by when that key was retired.

### `oracle-node`

The binary. One config file describes the whole node; ingest subscriptions are
**derived** from the feed definitions rather than listed separately, because two
lists would drift and the failure mode of that drift is a feed that quietly loses
a venue.

`Pipeline` is synchronous and owned by a single task. That is deliberate: the
ordering guarantee `oracle-ingest` provides — a disconnect notice reaching the
aggregator before any post-reconnect quote — only means something if nothing
downstream reorders it. Fanning events across workers would break it silently.

```sh
oracle-node init [--out DIR] [--canister ID]   # generate this node's keys
oracle-node rotate --dir DIR [--canister ID]   # generate the next signing key
oracle-node start <config.toml>                # ingest, aggregate, sign, serve
oracle-node start <config.toml> --tail         # ...and log the stream as it flows
```

`--tail` logs every decoded observation going into the aggregator and every
signed update coming out, under the `tail` target. It is the fastest way to see
what a venue is actually sending — normalised, but before anything is weighted,
filtered, or aggregated:

```text
INFO tail: observation venue=deribit market=inverse_perp symbol=BTC-PERPETUAL
           kind="book_top" price=64972.25 bid="64972" ask="64972.5"
           bid_qty="2.292679923659" ask_qty="1.610373619608" lag_ms="49"
INFO tail: observation venue=kraken market=linear_perp symbol=PF_XBTUSD
           kind="mark_price" price=64971.86250214206 lag_ms="81"
INFO tail: published status="ok" price="64971.86250214" conf="6.49718625"
           seq=1 sources=2 venues={Kraken, Deribit}
```

That output is also the quickest demonstration of the funding caveat below:
Deribit reports `funding=0.00000012` and Kraken `funding=0.000002992933` for the
same contract at the same instant, because one is an 8h rate and the other is
hourly. `lag_ms` is `local_recv − exchange_time` and is diagnostic only —
staleness is always measured with our own clock, never the venue's.

`init` generates **both** keys — the two-tier split from §3.5 is the design, not
a suggestion — issues the signing certificate, and prints the registry entry to
hand to governance. That entry carries no secret: an identity public key, the
endpoints, and a certificate anyone can check. Nothing the node publishes
verifies for anyone until governance signs it into a new registry version.

Secrets go to stdout by default, which puts them in terminal scrollback and shell
history; `--out DIR` writes them to `0600` files instead, along with a starter
config. It refuses to overwrite existing keys — silently replacing an identity
key would orphan every certificate it ever issued.

Keys come from the OS CSPRNG (`Signer::generate`). The seeded keys in the
examples and test helpers are derived from small integers and guessable by
construction; they exist so fixtures reproduce.

```sh
cargo run -p oracle-node -- start crates/oracle-node/config/example.toml
```

The signing key comes from a file or an environment variable, never a
command-line argument: arguments are visible in `ps` to every user on the box.

**Keys are encrypted at rest.** `init --out` and `rotate` write `age` files,
encrypted with a passphrase from `--passphrase-file` or a terminal prompt, and
record the passphrase file in the starter config as `signing.passphrase_file`.
At startup the node opens the key with that file, or prompts when the line is
absent, and refuses to start when it has neither and no terminal. Plaintext hex
is still accepted in a key file or `key_env` so the local playground can hand a
seeded key to the node; a real key never goes there. There is no KMS and no HSM
by design (SPEC §9.2): a cloud key service is a third party in the signing path.

The registry comes from `registry.path`, a file, or `registry.url`, usually the
registry canister's `/registry.json`. A file is pinned
until the node restarts. Either way the document is verified against the pinned
`governance_address` before anything else happens.

At startup the node checks that the registry actually authorises its own signing
address, and **refuses to start** if not. This is a hard failure rather than a
warning because it is otherwise the quietest way for a node to fail: it goes on
ingesting, aggregating and signing, every node-local metric reads healthy, and
every subscriber silently discards the output. The certificate expiry countdown
is logged at startup and re-checked hourly, warning under seven days (§9.3) —
a 30-day certificate lapses mid-flight long before anything else prompts a
restart.

#### Funding is not normalised

`FeedKind::Funding8h` claims a rate "normalised to an 8-hour interval".
`ObsKind::Funding` carries "a fraction over the venue's own interval". Nothing
converts between them, because the interval is not in the WebSocket message — it
needs an instrument-metadata fetch (Binance `/fapi/v1/fundingInfo`, Bybit
`fundingInterval`, OKX `fundingTime` deltas), and that has not been built.

The consequence: a `FUNDING_8H` feed whose sources sit on different intervals
takes a **median across incomparable numbers**. A 1h rate and an 8h rate are off
by 8×, and nothing halts or degrades — it publishes a confidently wrong number,
which is the one failure mode the rest of this codebase works to prevent.

Safe today: Deribit alone, which publishes a genuine `funding_8h`; or a single
venue; or several venues on a contract you have confirmed shares an interval
(BTC and ETH majors are 8h on Binance, Bybit and OKX). Treat multi-venue funding
as unsupported until the metadata fetch lands. SPEC.md §13, open question 3.

#### USDT is not USD

Binance, Bybit, and OKX quote in USDT. Coinbase and Kraken are the only
native-USD venues in scope, which makes losing both a distinct failure class
rather than "two of five sources down".

`CRYPTO.USDT/USD` is therefore a feed like any other, priced from the native-USD
venues, and stablecoin-quoted sources of a `/USD` feed are converted through it.
The peg's own uncertainty propagates in quadrature, so a wobbling peg widens the
whole catalogue instead of silently mispricing it. Confirmed live: with the peg
at 1.0bp and the aggregate floor at 1.0bp, BTC/USD published 1.414bp — exactly
√2 × 1bp.

If the peg goes away, dependent feeds **halt**. Publishing a USDT-quoted number
under a `/USD` symbol would be wrong by however far the peg had drifted, and
nobody would notice.

### `oracle-wire`

Byte layouts and cryptography.

- Canonical 96-byte price update payload — this layout *is* the protocol.
- secp256k1 recoverable ECDSA over a keccak256 digest, EIP-712-shaped domain separation. `v` is offset by 27, so the bytes are Ethereum's exactly and an on-chain verifier is a port rather than a redesign.
- Two curve backends behind one private module: `libsecp256k1` on native targets, `k256` on wasm32 (or anywhere with `--features pure-rust`). Nothing outside the module names a backend type. The split exists so the registry canister can reuse the exact encoding and verification code instead of a port. `k256` recovers about five times slower, which is why it is not the default.
- `SigningKeyCert` — identity key authorises a hot signing key for a window.
- `Registry` / `VerifiedRegistry` — the trust root.
- `UnverifiedFrame` → `VerifiedUpdate` typestate.

## The verification path

The types enforce the order of operations, so the dangerous shortcut — treating successful key recovery as successful verification — is not expressible by accident:

```text
bytes ──parse──▶ UnverifiedFrame ──verify(&VerifiedRegistry)──▶ VerifiedUpdate
                       │
                       └─ recover_signer() yields an address for ANY well-formed
                          signature, including one an attacker just forged
```

`VerifiedRegistry` is itself only obtainable by checking a `Registry` against a governance address the caller pins *and* against a version floor — so a node cannot vouch for its own registry, and an old registry cannot be replayed to reinstate a revoked key.

Verification stops at "a registered node really signed this". Sequence monotonicity, staleness, and cross-node quorum are consumer policy and belong to the client SDK (M3). **A signed update is a bearer token that never expires on its own**: a relay that withholds new updates and rebroadcasts an old one passes every check in `oracle-wire`.

### `oracle-registry-canister`

The node registry as an Internet Computer canister (SPEC §3.6). It is the
trust root for membership: who the nodes are, which signing key each one holds
right now, and which keys it held before.

- **The canister signs the registry.** Every version is signed with a
  threshold ECDSA key on secp256k1, so the governance address consumers pin is
  the address of that key and `Registry::verify` is unchanged. No governance
  private key exists anywhere. Consumers need no Internet Computer agent; they
  fetch `/registry.json` and verify the signature they already verify.
- **One live key per node.** `rotate_key` is an atomic swap. The old key gets a
  `retired_at` and stays in `get_key_history` for stored-frame verification,
  but it never verifies a live frame again, and its address can never be listed
  again by anyone.
- **Rules are code, not policy.** One rotation fleet-wide per window, never
  below `min_nodes`, a heartbeat re-sign so a withheld document is detectable
  by age. Each rule is a unit test in `state.rs`, with no canister runtime.
- **Governance is the controller set.** A single-controller canister is a
  single governance key with extra steps; put it under a multisig or an SNS
  with timelocked upgrades.

`state.rs` is the whole state machine and has no IC dependency. `lib.rs` adds
the caller, the clock, stable memory, and the signing round. Entries,
certificates and documents cross the Candid boundary as JSON strings in the
protocol's own format, so there is one schema rather than a Candid mirror.

`tests/pocket_ic.rs` runs the real wasm on PocketIC with real threshold
signing. It needs the PocketIC server: set `POCKET_IC_BIN`, or have a `dfx`
install whose cache bundles it. The test builds the canister wasm itself.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all --check

# The two secp256k1 backends must agree byte for byte. The golden vectors
# run under k256 here, and the wasm32 build is what the registry canister needs.
cargo test -p oracle-wire --features pure-rust
cargo clippy --target wasm32-unknown-unknown -p oracle-wire -p oracle-registry-canister \
  --no-default-features --lib -- -D warnings

# The canister wasm and its Candid interface.
cargo build -p oracle-registry-canister --target wasm32-unknown-unknown --release
candid-extractor target/wasm32-unknown-unknown/release/oracle_registry_canister.wasm \
  > crates/oracle-registry-canister/oracle-registry-canister.did
```

### Running a node locally

```sh
# One-node registry plus keys, generated with the real tooling.
cargo run -p oracle-node --example gen_local_registry > registry.json

cargo run -p oracle-node -- start node.toml      # ingest, sign, serve
cargo run -p oracle-client --example subscribe \
  -- registry.json 0x<governance> CRYPTO.BTC/USDT
```

To run a node you generated with `init`, governance has to sign its entry in —
`gen_local_registry` plays that part with `--entry`:

```sh
cargo run -p oracle-node -- init --out node1
cargo run -p oracle-node --example gen_local_registry -- \
  --nodes 0 --entry node1/node-entry.json > node1/registry.json
# then pin the printed GOVERNANCE address in node1/config.toml
cargo run -p oracle-node -- start node1/config.toml
```

Confirmed live against Binance: exchange → node → signed frame → WebSocket → SDK
verification, with prices resolving `Ok` and zero rejected frames.

### Recording and replay

`oracle-node start --record FILE` writes every raw venue frame, with the time it
arrived, as JSON lines. The recorder sits at the transport, under every decoder,
so what it keeps is what the venue sent. `oracle-replay` plays a recording back
through the same adapters, decoders, session loop and aggregator the node runs:

```sh
oracle-node start node.toml --record capture.jsonl      # on the node
oracle-replay node.toml capture.jsonl                    # anywhere, later
oracle-replay node.toml capture.jsonl --json > updates.jsonl
oracle-replay node.toml capture.jsonl --realtime         # sleep the recorded gaps
```

Two substitutions make it deterministic. The transport reads the recording
instead of a socket, releasing frames in recorded order across every connection.
The session clock reads the recording instead of the wall, so each observation
carries the receipt time it really had, and the pipeline ticks at recorded-time
boundaries. The last line `oracle-replay` prints is a digest over every published
update. Two replays of one recording print the same digest, on any machine. That
is SPEC §10's cross-node conformance check, and it is also how an incident gets
reproduced months later and how an aggregation constant gets tuned against a real
dislocation instead of a guess.

The replay binary is single-threaded on purpose: the driven clock is only
coherent when nothing runs between a transport returning a frame and the session
stamping it.

#### The adversarial suite

`oracle_replay::adversarial` turns a clean recording into an attack by rewriting
one venue's frames: `scale_prices` for a jump or a spoof window, `drift_prices`
for a slow pull, `cross_book`, `silence`, and `freeze`. Prices are rewritten
inside each venue's own JSON, in fixed point, so a transform is exact.
`crates/oracle-replay/tests/adversarial.rs` replays each attack against the
clean recording and compares the published prices tick by tick:

| Attack on one of three venues | What must hold |
|---|---|
| 10% jump, held | price within 20 bps of clean, outliers rejected, no halt |
| 50% spoof for one second | same |
| drift of 25 bps per second | price within 15 bps, the venue is shed once outside the band |
| crossed book | price within 20 bps, no halt |
| silence on an open connection | shed by staleness, feed carries on with two sources |
| frozen quote in a quiet market | within the band, and nothing flags it: a documented limitation |
| the whole market jumps 150% | the sanity band halts, and anything published at the new level carries the halt flag |

The fixture is a committed twelve-second recording of Binance, Bybit, and OKX
spot BTC/USDT, with the config it was recorded under beside it. The Binance URL
embeds the subscribed streams, so a fixture is only valid with its own config.

### Metrics and alerts

Every node serves Prometheus text at `/metrics` (SPEC §9.3). The node installs
the exporter; `oracle-server` only renders what it is handed, so a server built
without one answers 404 rather than inventing an exporter.

| Family | What |
|---|---|
| `oracle_ingest_*` | per stream: connected, connects, disconnects, connect failures, messages, decode errors, observations, lag |
| `oracle_feed_*` | per feed: status (0 ok, 1 degraded, 2 halted), sources, conf in bps, signed updates, outliers rejected, halted and degraded polls, invalidations |
| `oracle_pipeline_tick_seconds` | how long one aggregate-and-sign pass takes |
| `oracle_server_*` | subscribers, updates published, lagged disconnects |
| `oracle_cert_expiry_seconds`, `oracle_registry_version`, `oracle_registry_age_seconds` | the node's own key and registry |

No node can see its own divergence. `oracle-monitor` is the internal consumer
the spec asks for: it subscribes to every node exactly as the SDK does, resolves
every feed, and exports per feed the status, node count, inter-node spread and
confidence, and per node its signed distance from the resolved price in basis
points. That last gauge is the highest-signal metric in the system. It catches a
subtly wrong node that every node-local metric reports as perfectly healthy.

```sh
oracle-monitor https://<canister>.icp0.io/registry.json 0x<governance> \
  CRYPTO.BTC/USD CRYPTO.ETH/USD --listen 127.0.0.1:9108
```

`ops/prometheus-alerts.yml` holds the spec's alert list as Prometheus rules:
feed halted over thirty seconds, confidence over fifty basis points for a
minute, a node over twenty-five basis points from the median for thirty seconds,
certificate expiry under seven days, registry older than two days, both
USD-native venues down, decode errors, lagging subscribers, and a registry
refresh storm on the consumer side.

### End to end on a local replica

`scripts/e2e-dfx.sh` is the M5.5 exit criterion as one command. It starts a
clean local replica, deploys the registry canister, generates a node with
`init`, submits and approves it through the canister, starts the node against
the canister URL, and runs the SDK client. Then, with the client still running,
it rotates the node's key through the canister, restarts the node on the new
key, and checks the client's counters: exactly one registry refresh, no
untrusted frames, no replays. It ends by printing the canister's key history.

```sh
scripts/e2e-dfx.sh                 # about three minutes; stops the replica after
KEEP_REPLICA=1 scripts/e2e-dfx.sh  # leave the replica and the node running
```

It uses a throwaway `dfx` identity named `oracle-e2e`, never your default, and
needs internet access for the venue connections. The first run found a real bug:
a restarted node began its sequence numbers at zero and was refused as a replay
for every frame until it caught up, which is why `Aggregator::with_sequence_floor`
exists.

The local gateway, like the mainnet one, verifies responses. The canister answers
`/registry.json` through an update call rather than building certification trees,
so the same URL shape works in both places and no `raw` domain is involved.

### Rotating a signing key

A rotation is one canister call, not a registry edit. The node generates the
key, the operator submits it, the canister swaps it atomically (SPEC §3.5):

```sh
# 1. A new key beside the live one. Nothing on the node changes yet.
oracle-node rotate --dir node1 --canister <CANISTER_ID>
#    writes node1/signing.key.next and node1/rotation-cert.json, and prints:
#    dfx canister call <CANISTER_ID> rotate_key '("oracle-eu-1", "{...cert...}")'

# 2. Run that call as the node's operator principal. The canister checks the
#    certificate against the node's identity key, refuses an address it has ever
#    seen, and refuses a second rotation inside the fleet-wide window.

# 3. The registry now lists only the new key. Move it into place and restart.
mv node1/signing.key.next node1/signing.key
oracle-node start node1/config.toml
```

The node is out of each consumer's quorum from step 2 until its first frame
under the new key triggers that consumer's one registry fetch. The other nodes
carry the feed through it, exactly as through a restart. The old key is retired
on the canister and can never be listed again, by anyone.

The local generator does not model rotation. It stands in for the canister only
to sign a document; the rules a rotation needs live in the canister.

`crates/oracle-client/tests/rotation.rs` covers the ways a rotation can go wrong
from the consumer's side: never learning about the new key, fetching on every
unknown frame, a retired key that keeps verifying, the replay floor resetting
with the new key, a de-listed node counting until its last update ages out, and a
stale document reported as healthy.

### End to end

`crates/oracle-server/tests/end_to_end.rs` runs the real axum server over a real
TCP listener and drives it with the real SDK — no mocks on either side of the
wire. The scenarios that matter are the ones where something is wrong: a forged
frame, a captured frame replayed, a node reporting itself halted, one node lying
among three, and a node-served registry that still demands the pinned governance
key.

### Adversarial replay

`crates/oracle-agg/tests/adversarial.rs` drives manipulated venues through the
full aggregator. Every scenario asserts one contract: the aggregator prices
honestly, degrades loudly, or halts — but never publishes a confidently wrong
number. Covered: spoofed prints, frozen feeds, one-sided and crossed books, slow
drift, implausibly tight books bidding for weight, quorum loss, market-wide
dislocation, mid-second disconnects, rate-cap behaviour under volatility,
sequence monotonicity across halt/recover cycles, and replay determinism.

### Running against live venues

```sh
cargo run -p oracle-ingest --example binance_tail        # tail live Binance
cargo run -p oracle-ingest --example binance_tail -- 30  # stop after 30s

# Dump raw frames from one stream URL, for diagnosing decode gaps.
cargo run -p oracle-ingest --example raw_probe -- \
  'wss://fstream.binance.com/stream?streams=btcusdt@bookTicker' 3
```

#### Known caveat: Binance futures streams other than `bookTicker`

From this network, `fstream.binance.com` delivers `bookTicker` normally but sends
**nothing** for `aggTrade`, `markPrice`, or `ticker` — the `SUBSCRIBE` is
acknowledged with `{"result":null}` and no data follows, on both the combined
(`/stream?streams=`) and single (`/ws/`) endpoint forms. Binance futures REST is
reachable and returns live data over the same path, so this sits upstream of this
codebase rather than inside it.

Consequence: the `MarkPrice` / `IndexPrice` / `Funding` decode path is covered by
unit tests against the documented payload shape, but has **not** been confirmed
against a live frame. Re-run `raw_probe` from a different network before relying
on perpetual feeds. Everything else — spot `bookTicker` and `aggTrade`, futures
`bookTicker`, reconnect, and clean shutdown — is confirmed live.

### Golden vectors

`crates/oracle-wire/tests/vectors/golden.json` freezes the protocol: payload bytes, digests, signatures, frames, feed IDs, certificates, and the registry encoding. A diff there means the wire format changed and previously-issued signatures no longer verify.

Regenerate deliberately, and read the diff:

```sh
REGENERATE_GOLDEN=1 cargo test -p oracle-wire --test golden
```

Self-generated vectors only prove behaviour has not drifted, not that it was ever right. The independent evidence is separate:

- published Keccak-256 vectors, distinguishing Keccak-256 from SHA3-256 (they differ only in padding);
- the canonical Ethereum address for secret key `1`;
- the domain separator, recomputed by `foundry` from the EIP-712 definition alone;
- full signatures cross-checked against `cast wallet sign --no-hash`, confirming the `r ‖ s ‖ v` layout is byte-identical to Ethereum's.

The `foundry` cross-check skips itself when `cast` is not on `PATH`, so a clean checkout still passes.
