#!/usr/bin/env python3
"""Writes node/assets.toml: feeds for the most traded crypto assets.

    scripts/asset-feeds.py [--top 150] [--out node/assets.toml]
    scripts/asset-feeds.py --merge hyperliquid    # only adds that venue's markets to the current feeds

It reads each venue's public 24 h tickers, the venues the node supports, and
keeps an asset when at least three venues trade it with $1M or more a day.
Stablecoins, fiat, wrapped and staked copies, leveraged tokens, and stock or
commodity perpetuals are left out. The top assets by 24 h volume get:

  CRYPTO.<ASSET>/USD             spot: Coinbase and Kraken in USD, Binance,
                                 Bybit and OKX in USDT through the peg, and
                                 Hyperliquid in USDC at par
  CRYPTO.<ASSET>/USDT.PERP_MARK  the mark of Binance, Bybit, OKX and
                                 Hyperliquid perpetuals

Each feed takes only venue markets with $1M or more a day. A spot feed needs
three, so that one venue that stops cannot halt it. A perpetual's mark moves
each second, so two do. A perpetual priced per 1000 units
(1000PEPEUSDT) is left out, so that no feed mixes two scales. Feeds that node/all-feeds.toml has already are skipped.
Volumes move each day, so a new run gives a new list.
"""

import argparse
import datetime
import json
import re
import sys
import time
import urllib.request
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIN_MARKET_USD = 1_000_000
MIN_VENUES = 3
MIN_SPOT_SOURCES = 3
MIN_PERP_SOURCES = 2
UA = {"User-Agent": "price-oracle asset-feeds"}

ALIASES = {"XBT": "BTC", "XDG": "DOGE"}
STABLE = set("""USDT USDC FDUSD DAI TUSD USDP BUSD USDE USDS PYUSD USD1 RLUSD USDD FRAX LUSD GUSD
EURC EURT EURI AEUR EUR GBP AUD TRY BRL JPY CAD CHF MXN ARS ZAR PLN UAH RUB IDR COP CZK BFUSD USDG
USDQ USDR XUSD USDX GHO CRVUSD DOLA MIM EURQ EUROP USDO USDF USDA USD0 LISUSD SUSDE SUSDS USDB
USDTB USDAI FXUSD DEUSD SUSD AUSD USDM USDY BUIDL USTB""".split())
WRAPPED = set("""WBTC WETH STETH WSTETH CBBTC CBETH RETH WBETH BETH BNSOL JITOSOL MSOL LBTC SOLVBTC
TBTC WEETH EZETH EETH OSETH METH CMETH BBSOL JUPSOL STHYPE WBNB WAVAX WPOL WMATIC WSOL KBTC FBTC
UNIBTC PUMPBTC ENZOBTC XSOLVBTC BBTC LSETH SWETH ANKRETH OETH SFRXETH FRXETH""".split())
LEVERAGED = re.compile(r"^[A-Z]+[2-5][LS]$")
MULTIPLIER = re.compile(r"^(1000000|100000|10000|1000|1M)([A-Z].*)$")
QUOTES = ["FDUSD", "USDT", "USDC", "USD"]


def get(url):
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def norm(base):
    """The asset's common name, without a price multiplier."""
    base = ALIASES.get(base.upper(), base.upper())
    match = MULTIPLIER.match(base)
    return ALIASES.get(match.group(2), match.group(2)) if match else base


def split_suffix(symbol):
    for quote in QUOTES:
        if symbol.endswith(quote) and len(symbol) > len(quote):
            return symbol[: -len(quote)], quote
    return None, None


def markets():
    """Each market: venue, kind, venue symbol, raw base, quote, 24 h USD volume."""
    rows = []

    def add(venue, kind, symbol, base, quote, usd, contract=None):
        if base and usd > 0:
            rows.append(dict(venue=venue, kind=kind, symbol=symbol, raw=base.upper(), quote=quote, usd=usd,
                             contract=contract))

    # A halted Binance market keeps its last day's ticker; its close time shows it.
    recent_ms = (time.time() - 3600) * 1000
    for t in get("https://api.binance.com/api/v3/ticker/24hr"):
        base, quote = split_suffix(t["symbol"])
        if quote == "USDT" and number(t.get("closeTime")) > recent_ms:
            add("binance", "spot", t["symbol"], base, quote, number(t["quoteVolume"]))
    for t in get("https://fapi.binance.com/fapi/v1/ticker/24hr"):
        base, quote = split_suffix(t["symbol"])
        if "_" not in t["symbol"] and quote == "USDT" and number(t.get("closeTime")) > recent_ms:
            add("binance", "perp", t["symbol"], base, quote, number(t["quoteVolume"]))
    for category, kind in (("spot", "spot"), ("linear", "perp")):
        for t in get(f"https://api.bybit.com/v5/market/tickers?category={category}")["result"]["list"]:
            base, quote = split_suffix(t["symbol"])
            if "-" not in t["symbol"] and quote == "USDT":
                add("bybit", kind, t["symbol"], base, quote, number(t["turnover24h"]))
    for t in get("https://www.okx.com/api/v5/market/tickers?instType=SPOT")["data"]:
        base, quote = t["instId"].split("-")[:2]
        if quote == "USDT":
            add("okx", "spot", t["instId"], base, quote, number(t["volCcy24h"]))
    # An OKX swap counts in contracts; the node needs the coins in one to report coins.
    contracts = {i["instId"]: Decimal(i["ctVal"]) * Decimal(i["ctMult"])
                 for i in get("https://www.okx.com/api/v5/public/instruments?instType=SWAP")["data"]}
    for t in get("https://www.okx.com/api/v5/market/tickers?instType=SWAP")["data"]:
        base, quote = t["instId"].split("-")[:2]
        if quote == "USDT" and t["instId"] in contracts:
            # A swap's volCcy24h is in the base currency.
            add("okx", "perp", t["instId"], base, quote, number(t["volCcy24h"]) * number(t["last"]),
                contract=contracts[t["instId"]])
    # The node reads Coinbase's Exchange feed, which refuses a whole
    # subscription for one unknown product, so only its live USD products count.
    exchange = {p["id"] for p in get("https://api.exchange.coinbase.com/products")
                if p.get("status") == "online" and not p.get("trading_disabled")}
    for p in get("https://api.coinbase.com/api/v3/brokerage/market/products?limit=1000")["products"]:
        if p.get("product_type") == "SPOT" and p["quote_currency_id"] == "USD" and p["product_id"] in exchange:
            add("coinbase", "spot", p["product_id"], p["base_currency_id"], "USD",
                number(p.get("volume_24h")) * number(p.get("price")))
    pairs = get("https://api.kraken.com/0/public/AssetPairs")["result"]
    tickers = get("https://api.kraken.com/0/public/Ticker")["result"]
    for key, pair in pairs.items():
        ws = pair.get("wsname")
        if ws and key in tickers and ws.endswith("/USD") and pair.get("status", "online") == "online":
            base = ws.split("/")[0]
            # Kraken's v2 socket names BTC and DOGE as such, not XBT and XDG.
            t = tickers[key]
            add("kraken", "spot", f"{ALIASES.get(base, base)}/USD", base, "USD",
                number(t["v"][1]) * number(t["p"][1]))
    for t in get("https://futures.kraken.com/derivatives/api/v3/tickers")["tickers"]:
        symbol = t.get("symbol", "")
        if symbol.startswith("PF_") and symbol.endswith("USD"):
            add("kraken", "perp", symbol, symbol[3:-3], "USD", number(t.get("volumeQuote")))
    # Hyperliquid quotes in USDC, taken at par: the node has no USDC peg, and the
    # venue's weight is small. A perp is named by its coin; `kPEPE` and the like
    # are priced per 1000 coins and left out. A spot pair is named by its index,
    # `@142`, the only name its socket takes; a Unit token is the coin itself,
    # bridged, so `UBTC` is BTC.
    perp_meta, perp_ctxs = hyperliquid({"type": "metaAndAssetCtxs"})
    for u, c in zip(perp_meta["universe"], perp_ctxs):
        if not u.get("isDelisted") and not re.match(r"^k[A-Z]", u["name"]):
            add("hyperliquid", "perp", u["name"], u["name"], "USDC", number(c.get("dayNtlVlm")))
    spot_meta, spot_ctxs = hyperliquid({"type": "spotMetaAndAssetCtxs"})
    tokens = {t["index"]: t for t in spot_meta["tokens"]}
    volumes = {c["coin"]: number(c.get("dayNtlVlm")) for c in spot_ctxs}
    for pair in spot_meta["universe"]:
        base, quote = (tokens[i] for i in pair["tokens"])
        if quote["name"] != "USDC":
            continue
        unit = (base.get("fullName") or "").startswith("Unit ")
        if unit or base.get("isCanonical"):
            name = base["name"][1:] if unit else base["name"]
            add("hyperliquid", "spot", pair["name"], name, "USDC", volumes.get(pair["name"], 0.0))
    return rows


def hyperliquid(body):
    request = urllib.request.Request("https://api.hyperliquid.xyz/info", data=json.dumps(body).encode(),
                                     headers={**UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def tradfi():
    """Assets that the venues list as stocks, ETFs or commodities."""
    found = set()
    for s in get("https://fapi.binance.com/fapi/v1/exchangeInfo")["symbols"]:
        if s.get("underlyingType") in ("EQUITY", "COMMODITY"):
            found.add(norm(s["baseAsset"]))
    linear = get("https://api.bybit.com/v5/market/instruments-info?category=linear&limit=1000")
    for i in linear["result"]["list"]:
        if i.get("symbolType") in ("stock", "ETF", "commodity", "forex"):
            found.add(norm(i["baseCoin"]))
    return found


def merge(path, venue, rows):
    """Adds `venue`'s deep markets as sources to the feeds that `path` has, and nothing else."""
    deep = {}
    for m in rows:
        if m["venue"] == venue and m["usd"] >= MIN_MARKET_USD:
            deep[(norm(m["raw"]), m["kind"])] = m
    text = path.read_text()
    out, added = [], 0
    symbol = None
    for line in text.splitlines():
        found = re.match(r'^symbol = "CRYPTO\.([A-Z0-9]+)/(USD|USDT\.PERP_MARK)"$', line)
        if found:
            symbol = (found.group(1), "perp" if found.group(2).endswith("PERP_MARK") else "spot")
        if line == "]" and symbol and symbol in deep and f'venue = "{venue}"' not in "\n".join(out[-12:]):
            m = deep[symbol]
            market = "linear_perp" if symbol[1] == "perp" else "spot"
            extra = ', kinds = ["mark_price"]' if symbol[1] == "perp" else ""
            note = f'  # {m["raw"]}/USDC' if venue == "hyperliquid" and m["symbol"].startswith("@") else ""
            out.append(f'  {{ venue = "{venue}", market = "{market}", symbol = "{m["symbol"]}"{extra} }},{note}')
            added += 1
        out.append(line)
    path.write_text("\n".join(out) + ("\n" if text.endswith("\n") else ""))
    print(f"{added} {venue} sources added to {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}",
          file=sys.stderr)


def existing_symbols():
    text = (ROOT / "node/all-feeds.toml").read_text()
    return set(re.findall(r'^symbol = "([^"]+)"', text, re.M))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--top", type=int, default=150)
    parser.add_argument("--out", type=Path, default=ROOT / "node/assets.toml")
    parser.add_argument("--merge", metavar="VENUE",
                        help="keep the feeds of --out as they are; add this venue's deep markets to them")
    args = parser.parse_args()

    rows = markets()
    if args.merge:
        merge(args.out, args.merge, rows)
        return
    excluded = tradfi()
    assets = {}
    for row in rows:
        base = norm(row["raw"])
        if base in STABLE or base in WRAPPED or base in excluded or LEVERAGED.match(base):
            continue
        assets.setdefault(base, []).append(row)

    ranked = []
    for base, markets_of in assets.items():
        deep = [m for m in markets_of if m["usd"] >= MIN_MARKET_USD]
        if len({m["venue"] for m in deep}) >= MIN_VENUES:
            ranked.append((sum(m["usd"] for m in markets_of), base, deep))
    ranked.sort(reverse=True)
    top = ranked[: args.top]

    have = existing_symbols()
    feeds, skipped = [], []
    for rank, (total, base, deep) in enumerate(top, 1):
        spot = sorted(
            (m for m in deep if m["kind"] == "spot"),
            # USD venues first: they price the feed without the peg.
            key=lambda m: (m["quote"] != "USD", m["venue"]),
        )
        # A perpetual priced per 1000 units would sit 1000 times away.
        perp = sorted(
            (m for m in deep if m["kind"] == "perp" and m["venue"] != "kraken" and norm(m["raw"]) == m["raw"]),
            key=lambda m: m["venue"],
        )
        header = f"# {base}: rank {rank}, ${total / 1e6:,.0f}M a day"
        for symbol, sources, perpetual in (
            (f"CRYPTO.{base}/USD", spot, False),
            (f"CRYPTO.{base}/USDT.PERP_MARK", perp, True),
        ):
            if symbol in have:
                continue
            if len(sources) < (MIN_PERP_SOURCES if perpetual else MIN_SPOT_SOURCES):
                skipped.append(f"{symbol} ({len(sources)} source)")
                continue
            feeds.append((header, symbol, sources, perpetual))
            header = None

    today = datetime.date.today().isoformat()
    lines = [
        "# The most traded assets, by scripts/asset-feeds.py on " + today + ". The rules",
        "# are at the top of the script. Run it again for a new list.",
        "",
    ]
    for header, symbol, sources, perpetual in feeds:
        if header:
            lines.append(header)
        lines.append("[[feeds]]")
        lines.append(f'symbol = "{symbol}"')
        if not perpetual and any(m["quote"] == "USDT" for m in sources):
            lines.append('peg = "CRYPTO.USDT/USD"')
        lines.append("min_sources = 2")
        lines.append("sources = [")
        for m in sources:
            market = "linear_perp" if perpetual else "spot"
            extra = ', kinds = ["mark_price"]' if perpetual else (
                ", converted = true" if m["quote"] == "USDT" else "")
            if m["contract"] is not None:
                extra += f', contract_size = "{m["contract"].normalize():f}"'
            # A Hyperliquid spot pair's index says nothing to a reader; name the coin.
            note = f'  # {m["raw"]}/USDC' if m["venue"] == "hyperliquid" and m["symbol"].startswith("@") else ""
            lines.append(f'  {{ venue = "{m["venue"]}", market = "{market}", symbol = "{m["symbol"]}"{extra} }},{note}')
        lines.append("]")
        lines.append("")
    args.out.write_text("\n".join(lines))
    spot_count = sum(1 for f in feeds if not f[3])
    out = args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out
    print(f"{len(top)} assets: {spot_count} spot feeds, {len(feeds) - spot_count} perp feeds "
          f"-> {out}", file=sys.stderr)
    print(f"skipped for too few deep markets: {len(skipped)}", file=sys.stderr)


if __name__ == "__main__":
    main()
