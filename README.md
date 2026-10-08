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
| M5.5 | Registry canister, one key per node | **done** |
| M6 | Hardening | in progress: keys encrypted at rest, replay harness, adversarial suite, authenticated and encrypted transport |

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
venue reports base units. The microprice would not notice if that were wrong,
being scale-invariant within one observation, but the impact price from a depth
snapshot would — which is exactly why it is a distinct market kind rather than a
comment.

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
             ──▶ weighted median     (plain median when venues disagree and none can go)
             ──▶ confidence          (disagreement ∨ spread ∨ floor)
             ──▶ circuit breakers    (jump corroboration, sanity band)
             ──▶ publication policy  (rate cap, then deviation ∨ heartbeat)
```

A feed is evaluated when one of its inputs changes, so a move publishes when it
arrives; a 25 ms timer catches heartbeats and stale venues. `deviation_bps` (1 by
default), `heartbeat_ms` and `min_interval_ms` are set per feed. A move held back
by the rate cap publishes the moment the cap expires.

With `impact_notional` set on a feed, each venue is priced at the average fill
for that notional instead of its microprice, moved by the live top of book
between book updates. One large order at the top can lean a microprice; it
cannot lean an impact price. The node keeps each venue's book from a snapshot
and the changes after it, and proves continuity with the venue's checksum or
sequence numbers. A failed proof drops the connection for a fresh snapshot.
SPEC §5.1 lists each venue's stream and proof.

Two venues that disagree beyond the 10 bp outlier floor leave no majority to say
which is wrong. The feed degrades, keeps the venue nearer its last price, and
widens the confidence to cover the other: one moved venue cannot move the price.

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

The subscriber-facing node: `/v2/ws` for listed clients only (SPEC §6.1), and
open info routes (`/v2/feeds`, `/v2/registry`, `/v2/health`) that carry no
price.

Fanout is **conflating** — one slot per feed per subscriber, newer replaces
pending older. A stale price delivered from behind a backlog is worse than no
price, because the consumer acts on it as though it were current. Frames are
signed, encoded and sealed once and shared as `Bytes` across every subscriber.
Venue reports (SPEC §3.3.1) have their own subscription and their own slot per
feed, so a report never replaces a price. Book deltas (SPEC §3.3.2) cannot
replace one another, so each client has a bounded queue for each book, and a
client that falls behind waits for the next snapshot.

The consequence consumers must internalise: **you observe state, not
transitions.** A sub-second halt can be conflated away. Every frame carries
complete state and the heartbeat makes any sustained halt unmissable, but code
that accumulates transitions rather than reading state will eventually be wrong.

`GET /v2/registry` serves this node's registry as a **hint, never a trust root**.
A consumer that accepted it as authoritative would let the node vouch for itself,
and therefore add itself.

### `oracle-client`

The consumer SDK, and the answer to "so how do I actually use this safely".

Two pure, synchronous halves with a thin async layer on top:

- `Verifier` — one update at a time: signature, registry membership, sequence
  monotonicity, staleness, coherence.
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

`Resolved` serializes with serde. `symbol` names the feed; the client sets it
for every subscribed feed. Decimals and `publish_time_ns` are strings, because a
JavaScript number loses precision on a nanosecond timestamp:

```json
{"feed_id":"0x0523…20e2","symbol":"CRYPTO.BTC/USD","status":"ok",
 "price":"86599.95","conf":"19.71359135","nodes":3,"halted_nodes":0,
 "concerns":[],"publish_time_ns":"1791299498663252000","spread_bps":"0"}
```

`OracleClient::latency` reports p50, p90, p99 and max for three spans of each
accepted update. The client stamps each frame when it arrives, before it
decrypts the frame.

| Span | From | To |
|---|---|---|
| `delivery` | the node signs | the client receives |
| `data_age` | the node receives the newest venue data | the client receives |
| `processing` | the client receives | `next()` returns the resolved price |

`delivery` compares two clocks, so it is exact only on one machine or with
clocks in sync. `data_age` includes heartbeats, which send old data on purpose.
`reset_latency` starts the report again after a warm-up.

#### Venue reports

A venue report (SPEC §3.3.1) shows what one node saw for each source of a
feed, signed with the node key:

- the best bid and ask, with their sizes;
- the impact prices for the feed's `impact_notional`;
- the mark, the index and the funding rate, when the venue sends them;
- the status in the price (used, outlier, stale, crossed, no data, invalid or
  feed halted) and the weight.

```rust
client.subscribe_venues(&["CRYPTO.BTC/USDT"]).await?;
while let Some(event) = client.next_event().await {
    match event {
        Event::Price(resolved) => { /* as from next() */ }
        Event::Venues(report) => { /* report.signer, report.report.entries */ }
    }
}
```

The SDK verifies each report like a price: the signature, the registry, its
own `seq`, and the clock. It does not combine reports across nodes, because
each node reports what it saw. `next()` skips reports.

#### Books

The node also sends each venue book it keeps (SPEC §3.3.2): a snapshot of the
top 50 levels every second, and the changed levels in between, at most every
50 ms. The format is the same for every venue, because the node computes the
deltas from its own book.

```rust
client.subscribe_books(&["CRYPTO.BTC/USDT"]).await?;
// `next_event()` yields Event::Book as frames arrive; the SDK applies them.
let binance = InstrumentId::new(Venue::Binance, MarketKind::Spot, "BTCUSDT");
if let Some(book) = client.book(&binance, now_unix_nanos()) {
    let top = book.best_bid();
}
```

The SDK keeps one book per node. A missed frame makes that node's book invalid
until its next snapshot. `book()` returns the freshest valid book, from one
node.

#### Client auth

Nodes serve prices only to listed clients, over `/v2/ws`, encrypted (SPEC
§6.1). The consumer must pass its API key; `subscribe` refuses without one:

```rust
let client = OracleClient::builder_from_source(source, GOVERNANCE_ADDRESS)
    .await?
    .client_key(api_key) // a secp256k1 `Signer`; governance listed its address
    .build()?;
```

The SDK runs the handshake on each connection and checks that the node's
`auth_ok` is signed by the address it dialled. Only after that does it send the
subscription. Every opened frame then goes through the same `Verifier` as
before. Decryption proves nothing, because every listed client holds the
broadcast key. `scripts/client-key.sh --out client.key` makes a key with
`examples/client_key.rs` and prints its address. Governance registers it with
`scripts/add-client.sh --identity <controller> --address 0x… --expires
2027-01-01`.

#### How a rotation reaches the consumer

A node has one secret seed, and the address of its secp256k1 key is the node's
id (SPEC §3.5). A rotation is
governance's `replace_node`: in one registry version the new address takes the
old one's place, at the same endpoint. The consumer finds out from the first
frame it cannot verify, or from a handshake challenge that names the new
address:

1. An unknown signer, or a `WrongNode` challenge, triggers one fetch from the
   `RegistrySource`, at most once
   per `refresh_interval` (10s by default). Anyone who can inject a frame can
   trigger the fetch, so the floor is what keeps a hostile relay from turning
   the client into a load generator against the registry.
2. `refresh_registry` adopts the document in place if it is strictly newer and
   signed by the pinned governance address. No reconnect, no lost feed state.
   Nodes the new version de-lists are dropped from the quorum **on adoption**,
   not once their last update ages out.
3. The frame is retried. The quorum seat moves to the new address in the same
   adoption that drops the old one, so the node never counts twice. The new
   address starts a fresh replay floor, which is safe: the new key never signed
   before.
4. The old key is now **retired**, not unknown. Frames it signed are refused as
   `RetiredKey` and never trigger another fetch. A few right after a rotation
   are frames that were in flight. A steady stream is a stolen key in use.

The canister publishes only when something changes, so a document's age says
nothing. Instead, every fetch checks the canister's IC certificate, which is at
most five minutes old, and confirms the registry. A registry unconfirmed for
longer than `max_registry_age` (48h by default) means the fetch path is broken or
newer versions are being withheld. Every feed is then reported `Degraded` with
`Concern::RegistryStale`. The prices are still verified; the membership may not
be current.

`HttpRegistrySource::canister(id)` fetches `/registry.json` from the canister's
`raw` domain and checks the certificate against the mainnet root key. On another
network, pass `Certification::new(id, root_key)` to `HttpRegistrySource::new`.
The governance signature is checked on top: the certificate says the document is
current, the signature says it is genuine.

Stored frames are a separate path. `verify_historical` checks a frame against
the canister's listing of its signer: when the address was listed, and when it
was replaced or removed.

### `oracle-proxy`

Verified oracle data for web clients (SPEC §6.5). A browser cannot hold a
client API key, so it cannot use the node transport. The proxy is one listed
client: it runs the SDK, with the signature checks and the quorum, and serves
the result as JSON over one plain WebSocket, `/v1/ws`. A reverse proxy in front
of it terminates TLS. `proxy/proxy.toml` is a commented example.

```sh
scripts/client-key.sh --out proxy.key          # the proxy's own client key
scripts/add-client.sh --identity <controller> --address <its address> --expires <date>
make proxy && target/release/oracle-proxy proxy/proxy.toml
```

A web client then does this:

```js
const socket = new WebSocket("wss://oracle.example.com/v1/ws");
socket.onopen = () => socket.send(JSON.stringify({
  op: "subscribe",
  prices: ["CRYPTO.BTC/USD"],
  venues: ["CRYPTO.BTC/USDT"],
  books: ["binance:spot:BTCUSDT"],
}));
socket.onmessage = (event) => {
  const message = JSON.parse(event.data);
  // message.type: "subscribed", "price", "venues", "book", "pong" or "error"
};
```

| Message | Contents |
|---|---|
| `price` | `symbol`, `status`, `price`, `conf`, `nodes`, `concerns`, `publish_time_ns`, `spread_bps` |
| `venues` | `symbol`, `node`, and the node's venue report (SPEC §3.3.1) |
| `book` | `book`, `seq`, `snapshot`, `available`, `node`, `bids` and `asks` as `[price, size]` |

Every 64-bit time and every decimal is a string, so JavaScript loses no
precision. For a book, apply a snapshot, then each delta in `seq` order; a size
of `"0"` removes the level. `GET /v1/catalog` lists what the proxy serves, and
`GET /health` shows the upstream client.

The socket is open to anyone, within `[limits]`. Behind a reverse proxy, set
`trust_forwarded_for = true`, so that the limits see each client's address
rather than the reverse proxy's.

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
oracle-node init                               # the wizard, at a terminal
oracle-node init --out DIR [--canister ID ...] # the same, from flags, for scripts
oracle-node rotate --dir DIR [--canister ID]   # generate the next key
oracle-node start <config.toml>                # ingest, aggregate, sign, serve
oracle-node start <config.toml> --tail         # ...and log the stream as it flows
```

`--tail` logs every decoded observation going into the aggregator and every
signed update coming out, under the `tail` target. It is the fastest way to see
what a venue is actually sending — normalised, but before anything is weighted,
filtered, or aggregated:

```text
12:03:04  INFO observation venue=deribit market=inverse_perp symbol=BTC-PERPETUAL
               kind="book_top" price=64972.25 bid="64972" ask="64972.5"
               bid_qty="2.292679923659" ask_qty="1.610373619608" lag_ms="49"
12:03:04  INFO observation venue=kraken market=linear_perp symbol=PF_XBTUSD
               kind="mark_price" price=64971.86250214206 lag_ms="81"
12:03:04  INFO published status="ok" price="64971.86250214" conf="6.49718625"
               seq=1 sources=2 venues={Kraken, Deribit}
```

That output is also the quickest demonstration of the funding caveat below:
Deribit reports `funding=0.00000012` and Kraken `funding=0.000002992933` for the
same contract at the same instant, because one is an 8h rate and the other is
hourly. `lag_ms` is `local_recv − exchange_time` and is diagnostic only —
staleness is always measured with our own clock, never the venue's.

`init` generates the node's secret seed and prints the two public keys it
derives (SPEC §3.5): the secp256k1 address, which is the node's id, and the
ed25519 key for venues that verify ed25519, such as tapray-perps. It also prints
the registry entry to hand to governance. That entry carries no secret: the
address and the endpoints. Nothing the node publishes verifies for anyone until
governance signs it into a new registry version.

At a terminal, `init` is a wizard. Its first note names the registry canister
and the governance address. Then it asks, one question at a time:
- where the files go: the default is shown as an absolute path, and a leading
  `~` is your home directory;
- the public endpoint: on mainnet, a loopback address such as `127.0.0.1` gets a
  warning at once, because no client elsewhere can dial it;
- how the node opens its key at start: a generated passphrase in a `0600` file,
  which systemd needs, or a passphrase typed at each start;
- whether to write a systemd unit.

It writes nothing until you confirm the summary, and Esc leaves nothing behind.
The answers are checked with the canister's own rules, so the registry accepts
the entry it writes. `--out` and `--passphrase-file` also expand a leading `~`.

It does not ask where the registry comes from. A node always fetches from the
registry canister, and the mainnet canister id and governance address are built
in (`oracle_client::mainnet`, next to the mainnet root key). For another
network, such as the local network, pass `--canister` and `--governance`
together, and `--gateway` and `--root-key` as well.

With `--out DIR`, every value comes from flags (also `--passphrase-file` and
`--service-user`), and the output is plain text a script can read. Without
`--out`, and not at a terminal, the secret goes to stdout, which puts it in
scrollback and shell history. `init` never overwrites an existing key:
replacing it would drop the node out of the registry while it kept running. The
config it writes holds absolute paths and needs no edit.

Until the registry canister is deployed on mainnet, the built-in values are
empty, and `init` asks for `--canister` and `--governance`.

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
absent, and refuses to start when it has neither and no terminal. The scrypt
work factor is fixed at 2^18 (256 MiB, about a second), so a key made on a fast
machine opens on a slow server; a key file may ask for up to 2^20. A key file
holds the seed as `oracle-node-seed-v1:<hex>`. Bare hex is still accepted, as a
secp256k1 key with no ed25519 key, so the local playground can hand a seeded key
to the node; a real key never goes there. There is no KMS and no HSM
by design (SPEC §9.2): a cloud key service is a third party in the signing path.

The registry comes from `registry.path`, a file, or `registry.url`, the
registry canister's `/registry.json`. A file is pinned until the node restarts. A
URL response must carry the certificate of `registry.canister_id`, checked
against `registry.root_key` off mainnet; `clients.url` must too. Either way the
document is verified against the pinned `governance_address` before anything
else happens.

`[[endpoints]]` puts another WebSocket URL in place of a venue market's built-in
one: a regional host, a proxy, or a local feed for tests. The node refuses an
endpoint that no feed reads. For Binance the URL is the combined-stream base, and
the node adds the stream names:

```toml
[[endpoints]]
venue = "binance"
market = "spot"
url = "wss://data-stream.binance.vision/stream"
```

At startup the node checks that the registry actually lists its own address, and
**refuses to start** if not. This is a hard failure rather than a
warning because it is otherwise the quietest way for a node to fail: it goes on
ingesting, aggregating and signing, every node-local metric reads healthy, and
every subscriber silently discards the output. Keys have no expiry (SPEC §3.5),
so once a node is listed it stays so until governance replaces or removes it.

#### Logs

Logs go to stderr. `--log-format` picks how they look; `auto`, the default,
picks from where stderr goes:

| Format | Chosen when | Looks like |
|---|---|---|
| `journald` | stderr is the journal stream systemd connected | `<6> INFO status feeds=12/12 ...`: no time, no colour, a syslog priority |
| `pretty` | stderr is a terminal | local time, colour, compact, and a banner once the node serves |
| `plain` | anything else, such as a file | UTC time, no colour |
| `json` | only when asked | one JSON object per line, for log shippers |

`RUST_LOG` filters as usual. Once a minute the node logs a `status` line:
feeds published, clients connected, venue connections up, updates in the last
minute, and p50 and p99 from venue data to signed update. Only updates that a
move or a flag change caused count, from the data at the first evaluation that
fired; a wait in the rate cap counts too. A heartbeat repeats old data, so it
does not count. Under systemd the same line shows in `systemctl status`. A
`venue lag` line follows: p50 and p99 from each venue's own timestamp to our
receipt. It also holds the offset between the venue clock and ours, and it shows
the share of venue timestamps ahead of our clock. A large share means that our
clock is behind.

#### Running under systemd

`init` writes `oracle-node.service` when asked (`--service-user USER`, or yes in
the wizard). The unit:
- is `Type=notify`: `systemctl start` returns once the node serves, and
  `systemctl status` shows what it is doing;
- stops the node with SIGTERM, which the node handles with a clean shutdown;
- restarts it on failure, but not on exit code 78, a config error that only an
  edit fixes;
- turns off core dumps and swap, because the key is in memory (SPEC §9.2);
- sandboxes the node to what it uses: a read-only system, its port, and
  outbound connections.

```sh
sudo install -m 0644 node1/oracle-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now oracle-node
journalctl -u oracle-node -f            # add -p warning for warnings only
```

Nobody can type at a service, so it reads its passphrase from a `0600` file.
That file protects the key against someone who copies the key file alone. For
more, keep the passphrase encrypted with `systemd-creds encrypt`, give it to the
unit with `LoadCredentialEncrypted=passphrase:/etc/oracle-node/passphrase.cred`,
and set `passphrase_file = "/run/credentials/oracle-node.service/passphrase"`.
`rotate` then needs `--passphrase-file` with the plain passphrase.

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
- `Registry` / `VerifiedRegistry` — the trust root.
- `UnverifiedFrame` → `VerifiedUpdate` typestate.
- `ClientList` / `VerifiedClientList`: the governance-signed allow-list, plus the
  handshake transcripts (kinds `0x83`, `0x84`, `0x85`).

### `oracle-transport`

The transport (SPEC §6.1), pure and without I/O. Callers pass the RNG and
`now`, so every rule is a unit test.

- **Handshake.** The client signs a transcript that binds the node's address, a
  fresh challenge, its own nonce and a fresh X25519 key. The node answers
  through HPKE (RFC 9180) and signs the result with its key.
- **Control channel.** One AES-256-GCM-SIV key per direction per session, with
  strict counters.
- **Broadcast keys.** One per node per 60 s epoch. Each is derived from its
  node's address, epoch and generation, so it cannot be used out of context. The node
  seals each price frame **once**, and every subscriber gets the same bytes.
- **Expiry and revocation.** Session deadlines snap to the epoch grid, so no
  client holds a key past its deadline. A revocation forces a rotation off the
  grid.

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
trust root for membership: which addresses are nodes and clients now, and which
were before.

- **The canister signs the registry.** Every version is signed with a
  threshold ECDSA key on secp256k1, so the governance address consumers pin is
  the address of that key and `Registry::verify` is unchanged. No governance
  private key exists anywhere. Consumers need no Internet Computer agent; they
  fetch `/registry.json`, check its IC certificate, and verify the signature
  they already verify.
- **One key per node.** `replace_node` is an atomic swap of addresses. The old
  address gets a `removed_at` and stays in `get_node_listing` for stored-frame
  verification, but it never verifies a live frame again.
- **Rules are code, not policy.** An address is listed once, ever, as a node or
  as a client; a removal never goes below `min_nodes`. Each rule is a unit test
  in `state.rs`, with no canister runtime.
- **Publication only on change.** Each change signs one new version; nothing
  re-signs on a timer. A failed signing round changes nothing. Freshness is
  the IC certificate on each fetch, not the document's age.
- **Governance is the controller set, and the only caller.** Nodes never call
  the canister. An operator sends `node-entry.json`, or the two addresses
  `oracle-node rotate` prints, to governance, which runs `add_node` or
  `replace_node`. `scripts/add-node.sh --identity <controller> --json
  node-entry.json` runs `add_node`; `--json` also takes the entry inline.
  `scripts/add-client.sh` runs `add_client`. Both target mainnet, ask before
  they publish, and take `ENV=local` for the local network.
  `inspect_message` drops
  every other principal's ingress, so spam costs the canister nothing. A
  single-controller canister is a single governance key with extra steps; put
  it under a multisig or an SNS with timelocked upgrades.

`state.rs` is the whole state machine and has no IC dependency. `lib.rs` adds
the caller, the clock, stable memory, and the signing round. Entries, listings
and documents cross the Candid boundary as JSON strings in the protocol's own
format, so there is one schema rather than a Candid mirror. Addresses cross as
`0x` hex.

`tests/pocket_ic.rs` runs the real wasm on PocketIC with real threshold
signing. The `pocket-ic` crate downloads the PocketIC server it needs on the
first run, unless `POCKET_IC_BIN` names it. The test builds the canister wasm
itself; `oracle_registry_canister::testing` holds the harness, which the
node's end-to-end test shares.

## Development

The `Makefile` drives the build; `make help` lists every target.

```sh
make test lint        # every test, PocketIC included; fmt and clippy
make canister         # the canister wasm: builds it, writes its .did, bakes
                      # the .did into the wasm as public candid:service
make node             # the oracle-node binary for this machine
make proxy            # the oracle-proxy binary for web clients
make e2e              # the whole system on PocketIC; also part of make test
make latency          # live latency from the venues to the SDK (below)
make smoke            # the icp-cli path on a local network (below)

# The two secp256k1 backends must agree byte for byte. The golden vectors
# run under k256 here.
cargo test -p oracle-wire --features pure-rust
```

Tools: Rust with the `wasm32-unknown-unknown` target, [icp-cli][icp-cli] 1.6
or newer, `ic-wasm`, `candid-extractor`, and Docker for `make release`.

[icp-cli]: https://cli.internetcomputer.org/

### Local network

`icp.yaml` describes the canister. Its local network has a fiduciary subnet,
which holds the threshold ECDSA key the canister signs with.

```sh
make network                          # icp network start -d, on port 8000
make deploy IDENTITY=<icp identity>   # builds, then installs on the local network
make governance IDENTITY=<icp identity>
make network-stop
```

### Release

`make release` builds the release artifacts in a pinned Docker image (Rust,
`ic-wasm` and `candid-extractor` at fixed versions), so anyone can rebuild them
and get the same bytes:

```text
target/release-artifacts/oracle_registry_canister.wasm
target/release-artifacts/oracle-node-linux-amd64
target/release-artifacts/SHA256SUMS
```

### Deploying the registry canister to mainnet

The deploying identity becomes the canister's controller, and so its
governance (SPEC §3.6). It must be an icp-cli identity with cycles, never
`anonymous`:

```sh
icp cycles balance -n ic --identity <you>
make deploy ENV=ic IDENTITY=<you>       # make release, then icp deploy -e ic
make deploy ENV=ic IDENTITY=<you> REPRODUCIBLE=0   # build here, no Docker
make governance ENV=ic IDENTITY=<you>   # prints the canister id and governance address
```

Mainnet gets the release build: `scripts/icp-wasm.sh` refuses a wasm built
on your machine there, unless you set `REPRODUCIBLE=0`. Then nobody can
rebuild the installed module and get its hash. After the first deploy:

1. Commit `.icp/data/mappings/ic.ids.json`, the canister id icp-cli keeps.
2. Put both printed values into `crates/oracle-client/src/mainnet.rs`, in one
   reviewed commit: every node and consumer that uses the defaults then trusts
   them.
3. Publish the first client list (`republish_clients`), or nodes refuse to
   start.

The canister signs with the `key_1` threshold key. Each signing round costs
cycles, so keep the canister topped up.

### Running a node locally

```sh
# One-node registry, the client list every node needs, and one local client.
cargo run -p oracle-node --example gen_local_registry -- \
  --clients node/clients.json > node/registry.json
#   prints ORACLE_LOCAL_1_SIGNING_KEY=… and LOCAL_CLIENT_KEY=… on stderr

ORACLE_SIGNING_KEY=<signing key> cargo run -p oracle-node -- start node/all-feeds.toml
echo <LOCAL_CLIENT_KEY> > client.key
cargo run -p oracle-client --example subscribe -- node/registry.json 0x<governance> \
  CRYPTO.BTC/USDT --client-key client.key
```

A node made with `init` fetches from a registry canister. To run one locally,
point it at the canister on the local network, as `scripts/smoke.sh` does.
`icp network status --json` prints the gateway URL and the root key:

```sh
oracle-node init --canister <CANISTER_ID> --governance <GOVERNANCE> \
  --gateway http://127.0.0.1:8000 --root-key <root_key from icp network status --json>
```

Confirmed live against Binance: exchange → node → signed, sealed frame →
WebSocket → SDK decryption and verification, with prices resolving `Ok` and zero
rejected frames.

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
carries the receipt time it really had. The pipeline evaluates each changed feed
after each observation, and runs its timers at recorded time. Binance's REST book
snapshots are recorded as frames too, so a replay rebuilds every book without
calling a venue. The last line `oracle-replay` prints is a digest over every published
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

### End to end on PocketIC

`crates/oracle-node/tests/e2e.rs` (`make e2e`, also part of `make test`) runs
the whole system in one test, over the authenticated, encrypted transport:

1. Installs the registry canister on PocketIC, behind a live HTTP gateway.
2. Generates a node with `oracle-node init`, which governance adds through the
   canister. Starts the `oracle-node` binary against the canister URLs.
3. Lists a client and runs the SDK as that client.
4. With the client still running, rotates the node's key with `oracle-node
   rotate` and `replace_node`, and restarts the node with SIGTERM. The client
   must adopt the new registry with at most one refresh, no untrusted frames
   and no replays.
5. Removes the client. The node must close its session and rotate its
   broadcast key, and the client must get no more prices.
6. Lists a second client for 15 s. It must get prices, then lose its session
   at the last epoch boundary before it expires.
7. Checks that the canister keeps the old address as retired.

A local Binance-shaped feed stands in for the venues through the node's
`[[endpoints]]`, so the test needs no internet. The node logs JSON to a file,
and the test reads its events. The test takes about 45 s.

The SDK and the node check the canister's certificate themselves, against the
network's root key. The PocketIC gateway, like the local network's gateway and
the mainnet `raw` domain, passes the certificate headers through.

The first version of this test, a shell script against live venues, found a
real bug: a restarted node began its sequence numbers at zero and was refused as
a replay for every frame until it caught up. That is why
`Aggregator::with_sequence_floor` exists.

### Live latency

`crates/oracle-node/tests/latency.rs` (`make latency`) measures the latency
from the venues to the SDK on this machine. It needs the internet, so `make
test` skips it. It sets up the system as the end-to-end test does, but the node
serves every feed in `node/all-feeds.toml` from the live venues. After a 15 s
warm-up, it measures for `LATENCY_SECS` (default 60) and prints:

```text
venue to node (venue clocks)  p50/p99 binance 0.0/215.6 ms (97% ahead), bybit 0.0/0.0 ms (100% ahead), ...
venue data to signed (node)   p50 0.12 ms, p99 51.74 ms
signed to SDK (delivery)      p50 0.28 ms, p90 0.59 ms, p99 1.51 ms, max 6.33 ms (n=1059)
venue data to SDK (data age)  p50 0.46 ms, p90 136.57 ms, p99 1073.15 ms, max 1994.75 ms (n=945)
SDK processing                p50 0.12 ms, p90 0.25 ms, p99 0.57 ms, max 4.87 ms (n=1059)
```

The node rows come from the node's second `status` and `venue lag` lines,
because the first one includes the startup. SPEC §9.1 explains each row.

The venue line above is from a machine whose clock was 144 ms behind NTP.
Most venue timestamps were ahead of its clock, and a lag below zero reads as
zero. Check the host clock with `sntp time.apple.com` (macOS) or `chronyc
tracking` (Linux) before you read that line.

### Smoke test on the local network

`scripts/smoke.sh` (`make smoke`) covers what the Rust test does not: `icp.yaml`
and its build step, `icp deploy`, `make governance`, and the `icp canister call`
lines that `init` and `rotate` print for governance. It runs each printed line
as it is and checks the version that the line publishes. No node runs.

```sh
scripts/smoke.sh                 # about 30 s; stops the network after
KEEP_NETWORK=1 scripts/smoke.sh  # leave the network running
```

It uses a throwaway icp identity named `oracle-e2e`, never your default.

### Rotating a node's key

A rotation is one canister call, not a registry edit. The operator generates
the next key, sends both addresses to governance, and governance's call swaps
them atomically (SPEC §3.5):

```sh
# 1. A new key beside the live one. Nothing on the node changes yet.
oracle-node rotate --dir node1
#    writes node1/signing.key.next and prints, for the config's canister:
#    icp canister call <CANISTER_ID> replace_node '("0xOLD…", "0xNEW…")' -n ic

# 2. Governance runs that call. The canister refuses an address it has ever
#    seen. Stagger rotations, so a consumer never loses two seats at once.

# 3. The registry now lists only the new address. Move the key into place and
#    restart.
mv node1/signing.key.next node1/signing.key
oracle-node start node1/config.toml
```

The node is out of each consumer's quorum from step 2 until its first frame
under the new key, or its first challenge, triggers that consumer's one
registry fetch. The other nodes carry the feed through it, exactly as through a
restart. The old address is retired on the canister and can never be listed
again, by anyone.

The local generator does not model rotation. It stands in for the canister only
to sign a document; the rules a rotation needs live in the canister.

`crates/oracle-client/tests/rotation.rs` covers the ways a rotation can go wrong
from the consumer's side: never learning about the new key, fetching on every
unknown frame, a retired key that keeps verifying, the old and the new address
both counting, a de-listed node counting until its last update ages out, and a
registry the source stops confirming reported as healthy.

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

`crates/oracle-wire/tests/vectors/golden.json` freezes the protocol: payload bytes, digests, signatures, frames, feed IDs, the registry encoding, venue reports and book updates. A diff there means the wire format changed and previously-issued signatures no longer verify.

Regenerate deliberately, and read the diff:

```sh
REGENERATE_GOLDEN=1 cargo test -p oracle-wire --test golden
```

Self-generated vectors only prove behaviour has not drifted, not that it was ever right. The independent evidence is separate:

- published Keccak-256 vectors, distinguishing Keccak-256 from SHA3-256 (they differ only in padding);
- the canonical Ethereum address for secret key `1`;
- the domain separator, recomputed by `foundry` from the EIP-712 definition alone;
- full signatures cross-checked against `cast wallet sign --no-hash`, confirming the `r ‖ s ‖ v` layout is byte-identical to Ethereum's;
- every payload built again by `tests/vectors/check_layout.py`, a second implementation in Python. It packs each payload from its JSON fields with `struct`, from the SPEC tables, and hashes with `cast keccak`. Thus neither the layout nor the hash comes from the Rust encoder.

The `foundry` and Python checks skip themselves when `cast` or `python3` is not on `PATH`, so a clean checkout still passes.
