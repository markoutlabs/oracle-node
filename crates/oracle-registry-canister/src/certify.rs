//! HTTP certification of `/registry.json`, `/clients.json`, `/feeds.json`,
//! `/prices.json`, `/frames.json` and a 404 for every other path. The
//! certificate is what proves a fetched document is current.

use std::cell::RefCell;

use ic_http_certification::{
    CERTIFICATE_EXPRESSION_HEADER_NAME, DefaultCelBuilder, DefaultResponseCertification,
    DefaultResponseOnlyCelExpression, HttpCertification, HttpCertificationPath,
    HttpCertificationTree, HttpCertificationTreeEntry, HttpResponse, StatusCode,
};

use crate::prices::{FeedPrice, PriceEntry, Prices};
use crate::runtime::{now_ns, read_prices};
use crate::{get_clients, get_feed_set, get_registry};

const REGISTRY_PATH: &str = "/registry.json";
const CLIENTS_PATH: &str = "/clients.json";
const FEEDS_PATH: &str = "/feeds.json";
const PRICES_PATH: &str = "/prices.json";
const FRAMES_PATH: &str = "/frames.json";

thread_local! {
    // Not in stable memory: rebuilt from `STATE` in `post_upgrade`.
    pub(crate) static CERTIFIED: RefCell<Option<Certified>> = const { RefCell::new(None) };
}

pub(crate) struct Certified {
    pub(crate) tree: HttpCertificationTree,
    /// The signed documents, which change only at a publish.
    signed: Vec<CertifiedResponse>,
    /// The prices and frames, which change at each accepted push.
    live: Vec<CertifiedResponse>,
    not_found: CertifiedResponse,
}

pub(crate) struct CertifiedResponse {
    pub(crate) path: HttpCertificationPath<'static>,
    pub(crate) entry: HttpCertificationTreeEntry<'static>,
    pub(crate) response: HttpResponse<'static>,
}

impl Certified {
    /// The response for `request_path`: its document, or the 404.
    pub(crate) fn lookup(&self, request_path: &str) -> &CertifiedResponse {
        let path = HttpCertificationPath::exact(request_path);
        self.signed
            .iter()
            .chain(&self.live)
            .find(|document| document.path == path)
            .unwrap_or(&self.not_found)
    }
}

fn cel() -> DefaultResponseOnlyCelExpression<'static> {
    // An allow-list, not exclusions: gateways add their own headers, and a
    // client that checks the certificate itself must still match.
    DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::certified_response_headers(
            vec!["content-type", "cache-control"],
        ))
        .build()
}

fn response(status: StatusCode, content_type: &str, body: Vec<u8>) -> HttpResponse<'static> {
    HttpResponse::builder()
        .with_status_code(status)
        .with_headers(vec![
            ("content-type".to_owned(), content_type.to_owned()),
            ("cache-control".to_owned(), "no-cache".to_owned()),
            (
                CERTIFICATE_EXPRESSION_HEADER_NAME.to_owned(),
                cel().to_string(),
            ),
        ])
        .with_body(body)
        .build()
}

fn document(json: Option<String>, missing: &[u8]) -> HttpResponse<'static> {
    match json {
        Some(json) => response(StatusCode::OK, "application/json", json.into_bytes()),
        None => response(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            missing.to_vec(),
        ),
    }
}

fn certified(
    path: HttpCertificationPath<'static>,
    response: HttpResponse<'static>,
) -> CertifiedResponse {
    let certification = HttpCertification::response_only(&cel(), &response, None)
        .expect("the response carries its own CEL expression");
    CertifiedResponse {
        entry: HttpCertificationTreeEntry::new(path.clone(), certification),
        path,
        response,
    }
}

/// `/prices.json`: each feed resolved at `now_ns`, the time of the last accepted batch.
pub(crate) fn prices_document(prices: &Prices, now_ns: u64) -> String {
    let resolved = prices.resolve_all(now_ns);
    let entries: Vec<PriceEntry<'_>> = resolved.iter().map(FeedPrice::entry).collect();
    serde_json::json!({ "resolved_at_ns": now_ns.to_string(), "prices": entries }).to_string()
}

/// `/frames.json`: each batch that holds a node's latest update of a feed, for
/// clients that verify the nodes themselves.
pub(crate) fn frames_document(prices: &Prices) -> String {
    let frames: Vec<serde_json::Value> = prices
        .sources()
        .into_iter()
        .map(|source| {
            let symbols: Vec<String> = source.symbols.iter().map(ToString::to_string).collect();
            serde_json::json!({
                "node": source.node.to_checksummed(),
                // Readers of the document read the kind; the canister takes batches only.
                "kind": "batch",
                "symbols": symbols,
                "bytes": format!("0x{}", hex::encode(source.bytes)),
            })
        })
        .collect();
    serde_json::json!({ "frames": frames }).to_string()
}

fn live_documents() -> Vec<CertifiedResponse> {
    let (prices, frames) =
        read_prices(|prices| (prices_document(prices, now_ns()), frames_document(prices)));
    vec![
        certified(
            HttpCertificationPath::exact(PRICES_PATH),
            document(Some(prices), b""),
        ),
        certified(
            HttpCertificationPath::exact(FRAMES_PATH),
            document(Some(frames), b""),
        ),
    ]
}

/// Certifies every document, and a 404 for every other path, in one tree. It
/// runs at install, at upgrade and after each change of a signed document.
pub(crate) fn certify_documents() {
    let signed = vec![
        certified(
            HttpCertificationPath::exact(REGISTRY_PATH),
            document(
                get_registry(),
                b"no registry version has been published yet",
            ),
        ),
        certified(
            HttpCertificationPath::exact(CLIENTS_PATH),
            document(
                get_clients(),
                b"no client list version has been published yet",
            ),
        ),
        certified(
            HttpCertificationPath::exact(FEEDS_PATH),
            document(
                get_feed_set(),
                b"no feed set version has been published yet",
            ),
        ),
    ];
    // A gateway rejects an uncertified response, a 404 included.
    let not_found = certified(
        HttpCertificationPath::wildcard("/"),
        response(StatusCode::NOT_FOUND, "text/plain", b"not found".to_vec()),
    );
    let live = live_documents();
    let mut tree = HttpCertificationTree::default();
    for document in signed.iter().chain(&live).chain([&not_found]) {
        tree.insert(&document.entry);
    }
    ic_cdk::api::certified_data_set(tree.root_hash());
    CERTIFIED.with(|cell| {
        *cell.borrow_mut() = Some(Certified {
            tree,
            signed,
            live,
            not_found,
        });
    });
}

/// Certifies the prices and frames again, and leaves the signed documents as
/// they are. A push runs it, so it does not hash the feed set each time.
pub(crate) fn certify_prices() {
    let renewed = CERTIFIED.with(|cell| {
        let mut cell = cell.borrow_mut();
        let Some(certified) = cell.as_mut() else {
            return false;
        };
        for old in &certified.live {
            certified.tree.delete(&old.entry);
        }
        certified.live = live_documents();
        for new in &certified.live {
            certified.tree.insert(&new.entry);
        }
        ic_cdk::api::certified_data_set(certified.tree.root_hash());
        true
    });
    if !renewed {
        certify_documents();
    }
}

#[cfg(test)]
mod tests {
    use oracle_quorum::testing::{REGISTRY_ISSUED_AT, TestNode, registry_with, update_at};
    use oracle_types::{NANOS_PER_SEC, PriceUpdate, Symbol};
    use oracle_wire::feed_id;

    use super::*;
    use crate::testing::usd;

    /// `/prices.json` as the canister served it before its own price schema.
    const GOLDEN: &str = include_str!("../tests/fixtures/prices.json");
    const PUBLISHED_NS: u64 = (REGISTRY_ISSUED_AT + 600) * NANOS_PER_SEC;
    const RESOLVED_NS: u64 = PUBLISHED_NS + 2 * NANOS_PER_SEC;

    /// A fixed time and `seq`, not `TestNode::next`: the golden document came from these.
    fn update(feed: &str, price: i64) -> PriceUpdate {
        let symbol: Symbol = feed.parse().expect("a valid symbol");
        let mut update = update_at(PUBLISHED_NS, 1);
        update.feed_id = feed_id(&symbol);
        update.price = price;
        update
    }

    /// SPEC §3.7: proxies and the JS SDK read this document, so its shape is
    /// frozen, key order and number spelling too.
    #[test]
    fn the_prices_document_keeps_its_shape() {
        let nodes = [TestNode::new(1), TestNode::new(2), TestNode::new(3)];
        let mut prices = Prices::default();
        prices.set_feeds(&[
            "CRYPTO.BTC/USD".parse().expect("a symbol"),
            "CRYPTO.ETH/USD".parse().expect("a symbol"),
        ]);
        prices.set_registry(registry_with(&[&nodes[0], &nodes[1], &nodes[2]]));
        let batches = [
            nodes[0].sign_batch(&[
                update("CRYPTO.BTC/USD", usd(64_000)),
                update("CRYPTO.ETH/USD", usd(2_300)),
            ]),
            nodes[1].sign_batch(&[update("CRYPTO.BTC/USD", usd(64_010))]),
            nodes[2].sign_batch(&[update("CRYPTO.BTC/USD", usd(64_025))]),
        ];
        prices
            .push(&batches, PUBLISHED_NS)
            .expect("passes the push rules");

        let golden: serde_json::Value = serde_json::from_str(GOLDEN).expect("JSON");
        assert_eq!(
            prices_document(&prices, RESOLVED_NS),
            golden.to_string(),
            "the served bytes are the golden document"
        );
    }
}
