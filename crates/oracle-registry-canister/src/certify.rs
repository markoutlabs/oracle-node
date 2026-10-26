//! HTTP certification of `/registry.json`, `/clients.json`, `/prices.json`,
//! `/frames.json` and a 404 for every other path. The certificate is what
//! proves a fetched document is current.

use std::cell::RefCell;

use ic_http_certification::{
    CERTIFICATE_EXPRESSION_HEADER_NAME, DefaultCelBuilder, DefaultResponseCertification,
    HttpCertification, HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry,
    HttpResponse, StatusCode,
};

use crate::{frames_document, get_clients, get_registry, prices_document};

const REGISTRY_PATH: &str = "/registry.json";
const CLIENTS_PATH: &str = "/clients.json";
const PRICES_PATH: &str = "/prices.json";
const FRAMES_PATH: &str = "/frames.json";

thread_local! {
    // Not in stable memory: rebuilt from `STATE` in `post_upgrade`.
    pub(crate) static CERTIFIED: RefCell<Option<Certified>> = const { RefCell::new(None) };
}

pub(crate) struct Certified {
    pub(crate) tree: HttpCertificationTree,
    documents: Vec<CertifiedResponse>,
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
        self.documents
            .iter()
            .find(|document| document.path == HttpCertificationPath::exact(request_path))
            .unwrap_or(&self.not_found)
    }
}

/// Certifies the current documents, and a 404 for every other path, in one tree.
pub(crate) fn certify_documents() {
    // An allow-list, not exclusions: gateways add their own headers, and a
    // client that checks the certificate itself must still match.
    let cel = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::certified_response_headers(
            vec!["content-type", "cache-control"],
        ))
        .build();
    let build = |status: StatusCode, content_type: &str, body: Vec<u8>| {
        HttpResponse::builder()
            .with_status_code(status)
            .with_headers(vec![
                ("content-type".to_owned(), content_type.to_owned()),
                ("cache-control".to_owned(), "no-cache".to_owned()),
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.to_owned(),
                    cel.to_string(),
                ),
            ])
            .with_body(body)
            .build()
    };
    let document = |json: Option<String>, missing: &[u8]| match json {
        Some(json) => build(StatusCode::OK, "application/json", json.into_bytes()),
        None => build(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            missing.to_vec(),
        ),
    };
    let mut tree = HttpCertificationTree::default();
    let mut certify = |path: HttpCertificationPath<'static>, response: HttpResponse<'static>| {
        let certification = HttpCertification::response_only(&cel, &response, None)
            .expect("the response carries its own CEL expression");
        let entry = HttpCertificationTreeEntry::new(path.clone(), certification);
        tree.insert(&entry);
        CertifiedResponse {
            path,
            entry,
            response,
        }
    };
    let documents = vec![
        certify(
            HttpCertificationPath::exact(REGISTRY_PATH),
            document(
                get_registry(),
                b"no registry version has been published yet",
            ),
        ),
        certify(
            HttpCertificationPath::exact(CLIENTS_PATH),
            document(
                get_clients(),
                b"no client list version has been published yet",
            ),
        ),
        certify(
            HttpCertificationPath::exact(PRICES_PATH),
            document(Some(prices_document()), b""),
        ),
        certify(
            HttpCertificationPath::exact(FRAMES_PATH),
            document(Some(frames_document()), b""),
        ),
    ];
    // A gateway rejects an uncertified response, a 404 included.
    let not_found = certify(
        HttpCertificationPath::wildcard("/"),
        build(StatusCode::NOT_FOUND, "text/plain", b"not found".to_vec()),
    );
    ic_cdk::api::certified_data_set(tree.root_hash());
    CERTIFIED.with(|cell| {
        *cell.borrow_mut() = Some(Certified {
            tree,
            documents,
            not_found,
        });
    });
}
