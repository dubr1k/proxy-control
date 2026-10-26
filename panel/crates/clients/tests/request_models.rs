//! The client API's request models against what pydantic reported for the same bodies
//! (`tests/fixtures/request_models.json`, recorded by `record_request_models.py`).

mod common;

use panel_clients::models::{
    ClientCreate, ClientImport, ClientRename, ClientStateBody, GrantAdoptBatch, GrantLabel, GrantsCreate,
};
use panel_model::validate::Model;
use panel_model::ValidationError;
use serde_json::Value;

fn issues<M: Model>(body: &Value) -> Option<Value> {
    let result: Result<M, ValidationError> = M::validate_body(body);
    result.err().map(|error| serde_json::to_value(&error.issues).unwrap())
}

#[test]
fn request_models_report_like_pydantic() {
    let records: Value =
        serde_json::from_str(&std::fs::read_to_string(common::fixture_path("request_models.json")).unwrap()).unwrap();
    for record in records.as_array().unwrap() {
        let body = &record["body"];
        let actual = match record["model"].as_str().unwrap() {
            "ClientImport" => issues::<ClientImport>(body),
            "GrantsCreate" => issues::<GrantsCreate>(body),
            "GrantAdoptBatch" => issues::<GrantAdoptBatch>(body),
            "GrantLabel" => issues::<GrantLabel>(body),
            "ClientState" => issues::<ClientStateBody>(body),
            "ClientCreate" => issues::<ClientCreate>(body),
            "ClientRename" => issues::<ClientRename>(body),
            other => panic!("{other}"),
        };
        assert_eq!(actual.unwrap_or(Value::Null), record["issues"], "{} {body}", record["model"]);
    }
}
