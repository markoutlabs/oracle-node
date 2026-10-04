//! HTTP certification of `/registry.json` and `/clients.json`. The certificate
//! is what proves a fetched document is current.

use std::cell::RefCell;

use ic_http_certification::{
    CERTIFICATE_EXPRESSION_HEADER_NAME, DefaultCelBuilder, DefaultResponseCertification,
    HttpCertification, HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry,
    HttpResponse, StatusCode,
};

use crate::{get_clients, get_registry};

const REGISTRY_PATH: &str = "/registry.json";
const CLIENTS_PATH: &str = "/clients.json";

thread_local! {
    // Not in stable memory: rebuilt from `STATE` in `post_upgrade`.
    pub(crate) static CERTIFIED: RefCell<Option<Certified>> = const { RefCell::new(None) };
}

pub(crate) struct Certified {
    pub(crate) tree: HttpCertificationTree,
    pub(crate) documents: Vec<CertifiedDocument>,
}

pub(crate) struct CertifiedDocument {
    pub(crate) path: &'static str,
    pub(crate) entry: HttpCertificationTreeEntry<'static>,
    pub(crate) response: HttpResponse<'static>,
}

/// Certifies the current `/registry.json` and `/clients.json` responses in one
/// tree, so the query path can serve either.
pub(crate) fn certify_documents() {
    // An allow-list, not exclusions: gateways add their own headers, and a
    // client that checks the certificate itself must still match.
    let cel = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::certified_response_headers(
            vec!["content-type", "cache-control"],
        ))
        .build();
    let headers = |content_type: &str| {
        vec![
            ("content-type".to_owned(), content_type.to_owned()),
            ("cache-control".to_owned(), "no-cache".to_owned()),
            (
                CERTIFICATE_EXPRESSION_HEADER_NAME.to_owned(),
                cel.to_string(),
            ),
        ]
    };
    let response = |json: Option<String>, missing: &'static [u8]| match json {
        Some(json) => HttpResponse::ok(json.into_bytes(), headers("application/json")).build(),
        None => HttpResponse::builder()
            .with_status_code(StatusCode::SERVICE_UNAVAILABLE)
            .with_headers(headers("text/plain"))
            .with_body(missing.to_vec())
            .build(),
    };
    let mut tree = HttpCertificationTree::default();
    let documents: Vec<CertifiedDocument> = [
        (
            REGISTRY_PATH,
            response(
                get_registry(),
                b"no registry version has been published yet",
            ),
        ),
        (
            CLIENTS_PATH,
            response(
                get_clients(),
                b"no client list version has been published yet",
            ),
        ),
    ]
    .into_iter()
    .map(|(path, response)| {
        let certification = HttpCertification::response_only(&cel, &response, None)
            .expect("the response carries its own CEL expression");
        let entry =
            HttpCertificationTreeEntry::new(HttpCertificationPath::exact(path), certification);
        tree.insert(&entry);
        CertifiedDocument {
            path,
            entry,
            response,
        }
    })
    .collect();
    ic_cdk::api::certified_data_set(tree.root_hash());
    CERTIFIED.with(|cell| *cell.borrow_mut() = Some(Certified { tree, documents }));
}
