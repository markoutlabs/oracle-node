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
| M4 | Remaining venues + USDT/USD conversion | not started |
| M5 | Multi-node deploy + registry rotation | not started |
| M6 | Hardening | not started |

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
- `Backoff` — exponential with seeded jitter. Deterministic, so the schedule is
  asserted rather than observed. Sibling connections get different seeds so they
  do not re-synchronise after a shared outage.
- `MonotonicClock` — forward-only unix nanoseconds. `SystemTime::now()` can step
  backwards under NTP, which makes in-flight observations look like they arrived
  from the future and read as age zero forever.

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

### `oracle-wire`

Byte layouts and cryptography.

- Canonical 96-byte price update payload — this layout *is* the protocol.
- secp256k1 recoverable ECDSA over a keccak256 digest, EIP-712-shaped domain separation. `v` is offset by 27, so the bytes are Ethereum's exactly and an on-chain verifier is a port rather than a redesign.
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

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all --check
```

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
