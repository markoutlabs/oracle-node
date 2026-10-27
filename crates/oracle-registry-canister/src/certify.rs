//! HTTP certification of `/registry.json`, `/clients.json`, `/feeds.json`,
//! `/prices.json`, `/frames.json` and a 404 for every other path. The
//! certificate is what proves a fetched document is current.

use std::cell::RefCell;

use ic_http_certification::{
    CERTIFICATE_EXPRESSION_HEADER_NAME, DefaultCelBuilder, DefaultResponseCertification,
    DefaultResponseOnlyCelExpression, HttpCertification, HttpCertificationPath,
    HttpCertificationTree, HttpCertificationTreeEntry, HttpResponse, StatusCode,
};

use crate::{frames_document, get_clients, get_feed_set, get_registry, prices_document};

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

fn live_documents() -> Vec<CertifiedResponse> {
    vec![
        certified(
            HttpCertificationPath::exact(PRICES_PATH),
            document(Some(prices_document()), b""),
        ),
        certified(
            HttpCertificationPath::exact(FRAMES_PATH),
            document(Some(frames_document()), b""),
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
