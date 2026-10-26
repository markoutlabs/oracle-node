# price-oracle

## Dependencies

- **Never hand-roll logic that a maintained crate provides.** Before writing
  arithmetic, parsing, retry, encoding, crypto-adjacent, or command-line code,
  check the dependency tree and crates.io first. Use the crate.
- A deliberate exception needs a comment that says why. The current ones:
  `Fixed` i128 fixed point and the i128 statistics in `oracle-agg` (exact,
  deterministic replay), the wire-format bit types `Flags` and `VenueSet`,
  the EIP-55 rendering in `oracle-wire` (alloy is too heavy for wasm32), and
  the `HALF_CURVE_ORDER` byte compare (backend-independent).
- Code that must build for `wasm32-unknown-unknown` (`oracle-wire`,
  `oracle-quorum`, `oracle-registry-canister`) chooses pure-Rust crates.

## Code comments

- Do not put a doc comment over every method, field, or test.
- Private items: no comment, unless the reason is not clear from the code.
- Public items: one line. The workspace `missing_docs` lint requires it.
- A comment says why, not what. Two sentences at most.
