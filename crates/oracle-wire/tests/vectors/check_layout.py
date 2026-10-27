#!/usr/bin/env python3
"""Checks golden.json with a second implementation of the wire format.

Every payload is built again from its JSON fields with `struct`, from the
tables in SPEC §3.3, §3.3.1, §3.3.2, §3.3.3 and §3.8, and hashed with foundry's `cast keccak`.
Nothing here shares code with the Rust encoder.

    python3 check_layout.py golden.json
"""

import json
import struct
import subprocess
import sys

VENUES = ["binance", "bybit", "okx", "coinbase", "kraken", "deribit", "hyperliquid", "bitfinex", "mexc", "kucoin"]
MARKETS = ["spot", "linear_perp", "inverse_perp"]
STATUSES = ["used", "outlier", "stale", "crossed", "no_data", "invalid", "feed_halted", "peg_unavailable"]
FRAME_TYPES = {"price": 1, "venues": 2, "book": 3, "funding": 4, "batch": 5}
BASES = ["interval", "eight_hours"]
UNITS = ["base", "contracts", "quote"]


def keccak(data: bytes) -> bytes:
    out = subprocess.run(
        ["cast", "keccak", "0x" + data.hex()], capture_output=True, text=True, check=True
    )
    return bytes.fromhex(out.stdout.strip()[2:])


def unhex(text: str) -> bytes:
    return bytes.fromhex(text[2:] if text.startswith("0x") else text)


def price_update(u: dict) -> bytes:
    """SPEC §3.3: 96 bytes."""
    return struct.pack(
        ">BBH32sqQiQQQQII",
        1,
        1,
        u["flags"],
        unhex(u["feed_id"]),
        int(u["price"]),
        int(u["conf"]),
        u["expo"],
        int(u["publish_time_ns"]),
        int(u["observation_time_ns"]),
        int(u["prev_publish_time_ns"]),
        int(u["seq"]),
        u["num_sources"],
        u["sources"],
    )


def price_batch(updates: list) -> bytes:
    """SPEC §3.4: a 4-byte header, then each update's 96 bytes."""
    return struct.pack(">BBH", 1, 2, len(updates)) + b"".join(price_update(u) for u in updates)


SLOTS = [
    ("bid", "q"),
    ("ask", "q"),
    ("bid_qty", "Q"),
    ("ask_qty", "Q"),
    ("impact_bid", "q"),
    ("impact_ask", "q"),
    ("mark", "q"),
    ("index", "q"),
    ("funding", "q"),
    ("exchange_time_ns", "Q"),
]


def venue_report(r: dict) -> bytes:
    """SPEC §3.3.1: 55 bytes, then 96 + L bytes for each entry."""
    out = struct.pack(
        ">BB32sQQiB",
        1,
        3,
        unhex(r["feed_id"]),
        int(r["publish_time_ns"]),
        int(r["seq"]),
        r["expo"],
        len(r["entries"]),
    )
    for e in r["entries"]:
        present = sum(1 << i for i, (name, _) in enumerate(SLOTS) if e[name] is not None)
        symbol = e["symbol"].encode("ascii")
        out += struct.pack(
            ">BBB", VENUES.index(e["venue"]), MARKETS.index(e["market"]), len(symbol)
        )
        out += symbol
        out += struct.pack(">BHH", STATUSES.index(e["status"]), present, e["weight_bps"])
        for name, kind in SLOTS:
            out += struct.pack(">" + kind, int(e[name]) if e[name] is not None else 0)
        out += struct.pack(">Q", int(e["local_recv_ns"]))
    return out


def book_update(u: dict) -> bytes:
    """SPEC §3.3.2."""
    symbol = u["symbol"].encode("ascii")
    out = struct.pack(
        ">BBBBB", 1, 4, VENUES.index(u["venue"]), MARKETS.index(u["market"]), len(symbol)
    )
    out += symbol
    flags = (1 if u["snapshot"] else 0) | (2 if u["venue_seq"] is not None else 0)
    out += struct.pack(
        ">QQBiiQQQBB",
        int(u["publish_time_ns"]),
        int(u["seq"]),
        flags,
        -8,
        -8,
        int(u["exchange_time_ns"] or 0),
        int(u["local_recv_ns"]),
        int(u["venue_seq"] or 0),
        len(u["bids"]),
        len(u["asks"]),
    )
    for level in u["bids"] + u["asks"]:
        out += struct.pack(">qQ", int(level["price"]), int(level["qty"]))
    return out


def funding_update(u: dict) -> bytes:
    """SPEC §3.3.3."""
    symbol = u["symbol"].encode("ascii")
    out = struct.pack(
        ">BBBBB", 1, 5, VENUES.index(u["venue"]), MARKETS.index(u["market"]), len(symbol)
    )
    out += symbol
    settled = u["settled"] or {"rate": 0, "time_ns": 0}
    oi = u["open_interest"]
    flags = 0
    for bit, present in enumerate(
        [
            u["predicted_rate"] is not None,
            u["interval_ns"] is not None,
            u["next_funding_time_ns"] is not None,
            u["settled"] is not None,
            oi is not None,
        ]
    ):
        flags |= int(present) << bit
    out += struct.pack(
        ">QQBBBiiqqQQqQQQQ",
        int(u["publish_time_ns"]),
        int(u["seq"]),
        flags,
        BASES.index(u["basis"]),
        UNITS.index(oi["unit"]) if oi else 0,
        -12,
        -8,
        int(u["rate"]),
        int(u["predicted_rate"] or 0),
        int(u["interval_ns"] or 0),
        int(u["next_funding_time_ns"] or 0),
        int(settled["rate"]),
        int(settled["time_ns"]),
        int(oi["amount"]) if oi else 0,
        int(u["exchange_time_ns"] or 0),
        int(u["local_recv_ns"]),
    )
    return out


def text(value: str) -> bytes:
    data = value.encode()
    return struct.pack(">H", len(data)) + data


def opt_text(value) -> bytes:
    return b"\x00" if value is None else b"\x01" + text(value)


def opt_u64(value) -> bytes:
    return b"\x00" if value is None else b"\x01" + struct.pack(">Q", value)


def feed_set(s: dict) -> bytes:
    out = struct.pack(">BBQQ", 1, 0x86, s["version"], s["effective_from"])
    out += text(s["min_node_version"])
    push = s["push"]
    if push is None:
        out += b"\x00"
    else:
        out += b"\x01" + struct.pack(
            ">QIQ", push["heartbeat_secs"], push["deviation_bps"], push["min_interval_secs"]
        )
    out += struct.pack(">I", len(s["feeds"]))
    for feed in s["feeds"]:
        out += text(feed["symbol"])
        out += opt_text(feed.get("peg"))
        out += opt_text(feed.get("max_peg_conf_bps"))
        out += opt_u64(feed.get("min_sources"))
        out += opt_text(feed.get("deviation_bps"))
        out += opt_u64(feed.get("min_interval_ms"))
        out += opt_u64(feed.get("max_age_ms"))
        out += opt_text(feed.get("impact_notional"))
        out += struct.pack(">H", len(feed["sources"]))
        for source in feed["sources"]:
            out += text(source["venue"]) + text(source["market"]) + text(source["symbol"])
            kinds = source.get("kinds")
            if kinds is None:
                out += b"\x00"
            else:
                out += b"\x01" + struct.pack(">H", len(kinds)) + b"".join(text(k) for k in kinds)
            out += opt_text(source.get("weight"))
            out += bytes([1 if source.get("converted") else 0])
            out += opt_text(source.get("contract_size"))
    return out


def check(kind: str, vector: dict, payload: bytes, separator: bytes) -> list:
    name = f"{kind} `{vector['name']}`"
    errors = []
    if payload != unhex(vector["payload"]):
        errors.append(f"{name}: payload differs\n  ours   0x{payload.hex()}\n  stored {vector['payload']}")
    digest = keccak(b"\x19\x01" + separator + keccak(payload))
    if digest != unhex(vector["digest"]):
        errors.append(f"{name}: digest differs: ours 0x{digest.hex()}, stored {vector['digest']}")
    frame = (
        bytes([FRAME_TYPES[kind]])
        + unhex(vector["signer"])
        + payload
        + unhex(vector["signature"])
    )
    if frame != unhex(vector["frame"]):
        errors.append(f"{name}: frame differs")
    return errors


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as file:
        golden = json.load(file)
    separator = unhex(golden["domain"]["separator"])
    errors = []
    count = 0
    for vector in golden["price_updates"]:
        errors += check("price", vector, price_update(vector["update"]), separator)
        count += 1
    for vector in golden["venue_reports"]:
        errors += check("venues", vector, venue_report(vector["report"]), separator)
        count += 1
    for vector in golden["book_updates"]:
        errors += check("book", vector, book_update(vector["update"]), separator)
        count += 1
    for vector in golden["funding_updates"]:
        errors += check("funding", vector, funding_update(vector["update"]), separator)
        count += 1
    for vector in golden["price_batches"]:
        errors += check("batch", vector, price_batch(vector["updates"]), separator)
        count += 1
    vector = golden["feed_set"]
    payload = feed_set(vector["feed_set"])
    if payload != unhex(vector["signing_bytes"]):
        errors.append(f"feed set: bytes differ\n  ours   0x{payload.hex()}\n  stored {vector['signing_bytes']}")
    digest = keccak(b"\x19\x01" + separator + keccak(payload))
    if digest != unhex(vector["digest"]):
        errors.append(f"feed set: digest differs: ours 0x{digest.hex()}, stored {vector['digest']}")
    count += 1
    for error in errors:
        print(error)
    print(f"{count} vectors checked, {len(errors)} differences")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
