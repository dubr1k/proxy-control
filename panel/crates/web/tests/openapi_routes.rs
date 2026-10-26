//! The route table against the served OpenAPI document: every (method, path) the router lists in
//! the schema must be an operation of the document, and — once every package has landed — the two
//! sets must be equal (`router_matches_the_openapi_document`, ignored until the cutover, WP14).

use std::collections::BTreeSet;

use serde_json::Value;

fn document_operations() -> BTreeSet<(String, String)> {
    let document: Value = serde_json::from_slice(panel_web::routes::openapi::DOCUMENT).unwrap();
    let mut out = BTreeSet::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            if ["get", "post", "put", "patch", "delete", "head", "options"].contains(&method.as_str()) {
                out.insert((method.to_ascii_uppercase(), path.clone()));
            }
        }
    }
    out
}

fn router_operations() -> BTreeSet<(String, String)> {
    let routes = panel_web::routes::all();
    let mut out = BTreeSet::new();
    for route in routes.routes().iter().filter(|route| route.in_schema()) {
        for method in route.methods() {
            out.insert((method.to_string(), route.template().to_string()));
        }
    }
    out
}

#[test]
fn every_router_operation_is_documented() {
    let extra: Vec<_> = router_operations().difference(&document_operations()).cloned().collect();
    assert!(extra.is_empty(), "routes missing from the OpenAPI document: {extra:?}");
}

#[test]
#[ignore = "until every work package registered its routes (WP14 removes this attribute)"]
fn router_matches_the_openapi_document() {
    assert_eq!(router_operations(), document_operations());
}
