//! Consumer regressions from `test_xray_routing_compiler.py`, not manager-renderer tests.

use super::support::*;
use crate::compiler::{self, Options};
use crate::store::{self, Mark};
use panel_core::migrations::{self, MIGRATIONS};
use panel_model::protocols::AppliedDocument;
use panel_model::routing::document::{attach_document, document_digest};
use panel_model::routing::models::{
    Action, CompileStatus, DefaultAction, Fallback, PolicyInput, PolicyState, LANE_SERVICE,
};
use panel_model::Backend;
use serde_json::{json, Value};

fn compile(
    policy: &panel_model::routing::models::RoutingPolicy,
    router: Option<&panel_model::protocols::RouterTarget>,
) -> panel_model::routing::models::Compiled {
    compiler::compile(
        policy,
        Some(&attached_target(policy.protocol.as_str())),
        Options { router, ..Options::default() },
    )
    .unwrap()
}

fn warp() -> panel_model::routing::models::RoutingPolicy {
    let mut policy = router_policy("naive");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    policy
}

#[test]
fn compile_router_whole_warp_intent() {
    let compiled = compile(&warp(), Some(&router("naive")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert!(compiled.reasons.is_empty());
    assert_eq!(document(&compiled), &json!({"schema":1,"default":{"action":"egress","egress":"warp"},"rules":[]}));
    assert_eq!(compiled.digest.as_deref(), Some(document_digest(document(&compiled)).as_str()));
    assert_eq!(compiled.attach, attach_document("naive"));
    assert_eq!(compiled.backend.as_deref(), Some("xray_router"));
    assert!(compiled.restart_required);
    assert_eq!(compiled.runtime_version.as_deref(), Some("Xray 26.3.27"));
    assert_eq!(compiled.compiler_version, "3");
    assert!(compiled.rollback.is_none());
}

#[test]
fn compile_router_block_beside_warp_default_is_supported() {
    let policy = with_rules(warp(), vec![rule(Action::Block, json!({"domains":["example.com","*.example.com"]}))]);
    let compiled = compile(&policy, Some(&router("naive")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(
        document(&compiled)["rules"],
        json!([{"domains":["example.com"],"geosites":[],"cidrs":[],"geoips":[],"ports":[],"action":"block","egress":null}])
    );
}

#[test]
fn compile_router_geosite_geoip_ports_in_order() {
    let mut disabled = rule(Action::Block, json!({"domains":["x.example"]}));
    disabled.enabled = false;
    let policy = with_rules(
        router_policy("naive"),
        vec![
            rule(Action::Block, json!({"geosites":["category-ads-all"]})),
            rule(Action::Direct, json!({"geoips":["cn"],"cidrs":["1.1.1.0/24"]})),
            egress_rule(json!({"ports":[443,"1000-2000"]}), "warp"),
            disabled,
        ],
    );
    let compiled = compile(&policy, Some(&router("naive")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    let rules = document(&compiled)["rules"].as_array().unwrap();
    assert_eq!(
        rules.iter().map(|rule| rule["action"].as_str().unwrap()).collect::<Vec<_>>(),
        ["block", "direct", "egress"]
    );
    assert_eq!(rules[0]["geosites"], json!(["category-ads-all"]));
    assert_eq!(rules[1]["geoips"], json!(["cn"]));
    assert_eq!(rules[1]["cidrs"], json!(["1.1.1.0/24"]));
    assert_eq!(rules[2]["ports"], json!([443, "1000-2000"]));
    assert_eq!(rules[2]["egress"], "warp");
}

#[test]
fn compile_router_unavailable_and_not_attached() {
    let policy = router_policy("naive");
    assert_eq!(codes(&compile(&policy, None)), ["router_unavailable"]);
    let mut unavailable = router("naive");
    unavailable.available = false;
    unavailable.reason = Some("artifact_mismatch".into());
    assert_eq!(codes(&compile(&policy, Some(&unavailable))), ["artifact_mismatch"]);
    let compiled = compiler::compile(
        &policy,
        Some(&native_target("naive")),
        Options { router: Some(&router("naive")), ..Options::default() },
    )
    .unwrap();
    assert_eq!(codes(&compiled), ["not_attached"]);
}

#[test]
fn compile_router_capability_missing_from_status() {
    let mut router = router("naive");
    router.capabilities.remove("block_geosite");
    let mut matched = rule(Action::Block, json!({"geosites":["cn"]}));
    matched.id = Some("11111111-0000-4000-8000-111111111111".into());
    let compiled = compile(&with_rules(router_policy("naive"), vec![matched.clone()]), Some(&router));
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["backend_capability_missing"]);
    assert_eq!(compiled.reasons[0].rule_id, matched.id);
    assert!(compiled.reasons[0].message.contains("block_geosite"));
}

#[test]
fn compile_router_private_destination_rejected_but_block_allowed() {
    for matcher in [json!({"cidrs":["10.0.0.0/8"]}), json!({"domains":["localhost"]}), json!({"cidrs":["::1/128"]})] {
        let mut matched = rule(Action::Direct, matcher.clone());
        matched.id = Some("11111111-0000-4000-8000-111111111111".into());
        let denied = compile(&with_rules(router_policy("naive"), vec![matched.clone()]), Some(&router("naive")));
        assert_eq!(codes(&denied), ["private_destination"]);
        assert_eq!(denied.reasons[0].rule_id, matched.id);
        assert_eq!(
            compile(&with_rules(router_policy("naive"), vec![rule(Action::Block, matcher)]), Some(&router("naive")))
                .status,
            CompileStatus::Supported
        );
    }
}

#[test]
fn compile_router_provider_unreachable_fail_closed_and_approved_direct() {
    let mut down = router("naive");
    down.providers = providers(&[("warp", Some(false))]);
    assert_eq!(codes(&compile(&warp(), Some(&down))), ["provider_unreachable"]);
    let mut approved = with_rules(warp(), vec![egress_rule(json!({"domains":["a.example"]}), "warp")]);
    approved.intent.fallback = Fallback::ApprovedDirect;
    let compiled = compile(&approved, Some(&down));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert!(compiled.warnings.iter().any(|warning| warning == "provider_unreachable"));
    assert_eq!(document(&compiled)["default"], json!({"action":"direct","egress":null}));
    assert_eq!(document(&compiled)["rules"][0]["action"], "direct");
    assert!(document(&compiled)["rules"][0]["egress"].is_null());
    down.providers.clear();
    assert_eq!(codes(&compile(&warp(), Some(&down))), ["provider_unavailable"]);
}

#[test]
fn compile_router_diff_against_applied_intent_and_rollback_target() {
    let document = json!({"schema":1,"default":{"action":"egress","egress":"warp"},"rules":[]});
    let mut router = router("naive");
    router.applied = Some(applied("rev-router", &document));
    let same = compile(&warp(), Some(&router));
    assert!(same.diff.is_empty());
    assert_eq!(same.rollback, Some(json!({"to_revision":"rev-router","to_digest":document_digest(&document)})));
    let changed = compile(&router_policy("naive"), Some(&router));
    assert!(changed.diff.iter().any(|line| line.contains("\"action\": \"direct\"")));
    assert!(changed.warnings.iter().any(|warning| warning == "policy_empty"));
    router.applied =
        Some(AppliedDocument { revision: "r".into(), digest: document_digest(&document), document: Value::Null });
    assert!(compile(&warp(), Some(&router)).diff.is_empty());
    assert!(!compile(&router_policy("naive"), Some(&router)).diff.is_empty());
}

#[test]
fn compile_router_document_size_limit() {
    let domains = (0..64).map(|i| format!("{}{i:03}.{}.example", "x".repeat(60), "y".repeat(60))).collect::<Vec<_>>();
    let policy =
        with_rules(router_policy("naive"), (0..3).map(|_| rule(Action::Block, json!({"domains":domains}))).collect());
    let compiled = compile(&policy, Some(&router("naive")));
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["document_too_large"]);
    assert!(compiled.document.is_none());
}

#[test]
fn compile_router_attach_document_per_protocol() {
    let mut policy = router_policy("mieru");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let compiled = compile(&policy, Some(&router("mieru")));
    assert_eq!(compiled.attach, attach_document("mieru"));
    assert_eq!(compiled.attach.unwrap()["rules"][0]["proxy"], "router");
}

#[test]
fn compile_native_geo_and_port_rules_are_unsupported_naming_the_router() {
    let mut geo = rule(Action::Block, json!({"geoips":["cn"]}));
    geo.id = Some("eeeeeeee-0000-4000-8000-eeeeeeeeeeee".into());
    let mut port = rule(Action::Block, json!({"ports":[25]}));
    port.id = Some("ffffffff-0000-4000-8000-ffffffffffff".into());
    let compiled = compile_native(
        &with_rules(native_policy("naive"), vec![geo.clone(), port.clone()]),
        Some(&native_target("naive")),
    );
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(
        compiled.reasons.iter().map(|reason| (reason.code.as_str(), reason.rule_id.clone())).collect::<Vec<_>>(),
        [("rule_kind_unsupported", geo.id), ("rule_kind_unsupported", port.id)]
    );
    assert!(compiled.reasons.iter().all(|reason| reason.message.contains("xray_router")));
}

#[test]
fn compile_native_policy_on_attached_service_is_unsupported() {
    let mut policy = native_policy("naive");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let attached = compile(&policy, Some(&router("naive")));
    assert_eq!(codes(&attached), ["backend_capability_missing"]);
    assert!(attached.reasons[0].message.contains("attached"));
    assert_eq!(compile_native(&policy, Some(&native_target("naive"))).status, CompileStatus::Supported);
}

#[test]
fn routing_v15_rebuilds_policies_keeping_rows_and_foreign_keys() {
    let scratch = Scratch::new("migration15");
    let database = scratch.database();
    assert_eq!(migrations::apply(&database, &MIGRATIONS[..14]).unwrap(), (1..=14).collect::<Vec<_>>());
    database.transaction::<_,panel_core::db::DbError>(|db| {
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,revision,state,created_at,updated_at) VALUES('p1','local','naive','naive_native','egress','fail_closed',3,'applied',1,1)",[])?;
        db.execute("INSERT INTO routing_rules(id,policy_id,position,enabled,match_json,action,created_at,updated_at) VALUES('11111111-0000-4000-8000-111111111111','p1',0,1,'{\"domains\":[\"a.example\"],\"cidrs\":[],\"ports\":[]}','block',1,1)",[])?;
        db.execute("INSERT INTO routing_applies(policy_id,revision,digest,backend,compiler_version,outcome,actor,created_at) VALUES('p1',3,'d','naive_native','1','applied','owner',1)",[])?;
        assert!(db.execute("UPDATE routing_policies SET backend='xray_router' WHERE id='p1'",[]).is_err());
        Ok(())
    }).unwrap();
    assert_eq!(migrations::apply(&database, &MIGRATIONS[..15]).unwrap(), [15]);
    database.transaction::<_,panel_core::db::DbError>(|db| {
        assert_eq!(db.query_row("SELECT id,backend,revision,state FROM routing_policies",[],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,String>(3)?)))?,("p1".into(),"naive_native".into(),3,"applied".into()));
        for table in ["routing_rules","routing_applies"] {
            assert_eq!(db.query_row(&format!("SELECT count(*) FROM {table} WHERE policy_id='p1'"),[],|row| row.get::<_,i64>(0))?,1);
        }
        assert!(!db.prepare("PRAGMA foreign_key_check")?.exists([])?);
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name='routing_policies_old'",[],|row|row.get::<_,i64>(0))?,0);
        db.execute("UPDATE routing_policies SET backend='xray_router' WHERE id='p1'",[])?;
        db.execute("DELETE FROM routing_policies WHERE id='p1'",[])?;
        for table in ["routing_rules","routing_applies"] {
            assert_eq!(db.query_row(&format!("SELECT count(*) FROM {table}"),[],|row| row.get::<_,i64>(0))?,0);
        }
        let columns = db.prepare("PRAGMA table_info(managed_egress)")?.query_map([],|row|row.get::<_,String>(1))?.collect::<Result<Vec<_>,_>>()?;
        assert!(columns.contains(&"router_revision".into()) && columns.contains(&"router_digest".into()));
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,revision,state,created_at,updated_at) VALUES('p2','local','naive','naive_native','direct','fail_closed',1,'draft',1,1)",[])?;
        db.execute("INSERT INTO routing_rules(id,policy_id,position,enabled,match_json,action,created_at,updated_at) VALUES('22222222-0000-4000-8000-222222222222','p2',0,1,'{\"domains\":[\"a.example\"],\"cidrs\":[],\"ports\":[]}','block',1,1)",[])?;
        Ok(())
    }).unwrap();
    assert_eq!(migrations::apply_migrations(&database).unwrap(), (16..=26).collect::<Vec<_>>());
    let db = database.connect().unwrap();
    let policy = store::get(&db, "local", "naive", LANE_SERVICE).unwrap().unwrap();
    assert!(policy.intent.rules[0].matcher.geosites.is_empty() && policy.intent.rules[0].matcher.geoips.is_empty());
}

#[test]
fn store_keeps_or_switches_the_backend_and_retargets() {
    let (_scratch, database) = database("retarget");
    let db = database.connect().unwrap();
    let policy = store::upsert(&db, "local", "naive", &PolicyInput::default(), None, 1, LANE_SERVICE).unwrap();
    assert_eq!((policy.backend, policy.revision), (Backend::NaiveNative, 1));
    let policy = store::upsert(
        &db,
        "local",
        "naive",
        &input(vec![rule(Action::Block, json!({"geoips":["cn"]}))]),
        Some(1),
        2,
        LANE_SERVICE,
    )
    .unwrap();
    assert_eq!(policy.backend, Backend::NaiveNative);
    assert_eq!(policy.intent.rules[0].matcher.geoips, ["cn"]);
    let switched = PolicyInput { backend: Some(Backend::XrayRouter), ..PolicyInput::default() };
    let policy = store::upsert(&db, "local", "naive", &switched, Some(2), 3, LANE_SERVICE).unwrap();
    assert_eq!((policy.backend, policy.revision), (Backend::XrayRouter, 3));
    let invalid = PolicyInput { backend: Some(Backend::MieruNative), ..PolicyInput::default() };
    assert!(store::upsert(&db, "local", "naive", &invalid, Some(3), 4, LANE_SERVICE).is_err());
    store::mark(
        &db,
        &policy.id,
        PolicyState::Applied,
        Mark { applied_revision: Some(3), applied_digest: Some("d".into()), ..Mark::default() },
        4,
    )
    .unwrap();
    let retargeted = store::retarget(&db, &policy.id, Backend::NaiveNative, 5).unwrap();
    assert_eq!(
        (retargeted.backend, retargeted.revision, retargeted.state),
        (Backend::NaiveNative, 4, PolicyState::Draft)
    );
    assert!(store::retarget(&db, &policy.id, Backend::MieruNative, 6).is_err());
    assert_eq!(
        store::upsert(&db, "local", "mieru", &switched, None, 7, LANE_SERVICE).unwrap().backend,
        Backend::XrayRouter
    );
}
