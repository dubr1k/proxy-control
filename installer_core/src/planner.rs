//! The deterministic install plan and its digest (`installer/planner.py`): audit facts, actions,
//! evidence, the release identity, adapter selection and order, the topological sort, the secret
//! scanner, and the canonical JSON whose SHA-256 the operator confirms.
//!
//! Every byte of [`InstallPlan::to_canonical_json`] counts: the digest is recomputed at
//! `install --accept-plan` and whenever a journal's `plan.json` is read back
//! (`InstallPlan::from_value`), so a Python-written plan must re-digest identically.
//! JSON goes through `pc_host::json::canonical` (sorted keys, `,`/`:`, raw UTF-8).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

use serde_json::{json, Map, Number, Value};

use crate::model::{InstallerConfig, ThreeXuiMode};
use crate::pystr::nonempty;
use crate::secret::{plan_key_is_secret, plan_text_has_secret};

pub const PLAN_SCHEMA: i64 = 1;

/// `PlanError` and its subclass `StalePlanError`; adapters' own planning refusals carry their
/// Python class name (they reach the operator as `BLOCKED: <message>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Plan(String),
    /// Security-relevant host facts changed after planning.
    Stale(String),
    /// An adapter refused to plan (`PackagesError`, `NginxError`, …).
    Adapter {
        class: String,
        message: String,
    },
}

impl PlanError {
    pub fn new(message: impl Into<String>) -> PlanError {
        PlanError::Plan(message.into())
    }

    pub fn adapter(class: impl Into<String>, message: impl Into<String>) -> PlanError {
        PlanError::Adapter { class: class.into(), message: message.into() }
    }

    /// `str(exc)`.
    pub fn message(&self) -> &str {
        match self {
            PlanError::Plan(message) | PlanError::Stale(message) => message,
            PlanError::Adapter { message, .. } => message,
        }
    }

    /// `type(exc).__name__`.
    pub fn python_class_name(&self) -> &str {
        match self {
            PlanError::Plan(_) => "PlanError",
            PlanError::Stale(_) => "StalePlanError",
            PlanError::Adapter { class, .. } => class,
        }
    }

    pub fn is_stale(&self) -> bool {
        matches!(self, PlanError::Stale(_))
    }
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for PlanError {}

type Result<T> = std::result::Result<T, PlanError>;

/// A fact value as the audit produces it. `Set` is a Python set: canonically it becomes a list
/// sorted by each item's compact JSON text (`{9, 10}` → `[10, 9]`). Map keys are already
/// `str(key)` (an int key `443` is `"443"`, a bool key `True` is `"True"`).
#[derive(Debug, Clone, PartialEq)]
pub enum Fact {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Fact>),
    Set(Vec<Fact>),
    Map(BTreeMap<String, Fact>),
}

impl Fact {
    /// `_canonical_fact_value`: maps sorted, sets ordered by compact JSON, lists kept.
    pub fn canonical(&self) -> Result<Value> {
        Ok(match self {
            Fact::Null => Value::Null,
            Fact::Bool(flag) => Value::Bool(*flag),
            Fact::Int(number) => Value::Number((*number).into()),
            Fact::Float(number) => Value::Number(
                Number::from_f64(*number)
                    .ok_or_else(|| PlanError::new("non-finite float is forbidden in canonical data"))?,
            ),
            Fact::Str(text) => Value::String(text.clone()),
            Fact::List(items) => Value::Array(items.iter().map(Fact::canonical).collect::<Result<_>>()?),
            Fact::Set(items) => {
                let mut values: Vec<(String, Value)> = items
                    .iter()
                    .map(|item| item.canonical().map(|value| (pc_host::json::canonical(&value), value)))
                    .collect::<Result<_>>()?;
                values.sort_by(|a, b| a.0.cmp(&b.0));
                values.dedup_by(|a, b| a.0 == b.0);
                Value::Array(values.into_iter().map(|(_, value)| value).collect())
            }
            Fact::Map(map) => Value::Object(
                map.iter().map(|(key, value)| Ok((key.clone(), value.canonical()?))).collect::<Result<_>>()?,
            ),
        })
    }
}

impl From<Value> for Fact {
    fn from(value: Value) -> Fact {
        match value {
            Value::Null => Fact::Null,
            Value::Bool(flag) => Fact::Bool(flag),
            Value::Number(number) => match number.as_i64() {
                Some(int) => Fact::Int(int),
                None => Fact::Float(number.as_f64().unwrap_or(f64::NAN)),
            },
            Value::String(text) => Fact::Str(text),
            Value::Array(items) => Fact::List(items.into_iter().map(Fact::from).collect()),
            Value::Object(map) => Fact::Map(map.into_iter().map(|(k, v)| (k, Fact::from(v))).collect()),
        }
    }
}

/// `AuditFacts`: the stable groups (canonical JSON objects) and the transient group, which
/// never enters the plan or the freshness check (`compare=False`).
#[derive(Debug, Clone, Default)]
pub struct AuditFacts {
    pub platform: Map<String, Value>,
    pub listeners: Map<String, Value>,
    pub ownership: Map<String, Value>,
    pub topology: Map<String, Value>,
    pub prerequisites: Map<String, Value>,
    pub transient: Map<String, Value>,
}

/// Python's `==` ignores `transient`.
impl PartialEq for AuditFacts {
    fn eq(&self, other: &AuditFacts) -> bool {
        self.stable_dict() == other.stable_dict()
    }
}

/// The five stable groups in `assert_fresh` order with their messages.
const FRESHNESS: [(&str, &str); 5] = [
    ("platform", "platform facts changed"),
    ("listeners", "listener facts changed"),
    ("ownership", "ownership facts changed"),
    ("topology", "topology facts changed"),
    ("prerequisites", "prerequisite facts changed"),
];

fn group(name: &str, fact: Fact) -> Result<Map<String, Value>> {
    match fact {
        Fact::Map(_) => match fact.canonical()? {
            Value::Object(map) => Ok(map),
            _ => unreachable!("a map canonicalises to an object"),
        },
        _ => Err(PlanError::new(format!("{name} facts must be a mapping"))),
    }
}

impl AuditFacts {
    /// `AuditFacts(platform=…, …)` from audit values (sets ordered, floats checked).
    pub fn from_groups(
        platform: Fact,
        listeners: Fact,
        ownership: Fact,
        topology: Fact,
        prerequisites: Fact,
        transient: Fact,
    ) -> Result<AuditFacts> {
        Ok(AuditFacts {
            platform: group("platform", platform)?,
            listeners: group("listeners", listeners)?,
            ownership: group("ownership", ownership)?,
            topology: group("topology", topology)?,
            prerequisites: group("prerequisites", prerequisites)?,
            transient: group("transient", transient)?,
        })
    }

    /// `stable_dict()`.
    pub fn stable_dict(&self) -> Value {
        json!({
            "listeners": self.listeners,
            "ownership": self.ownership,
            "platform": self.platform,
            "prerequisites": self.prerequisites,
            "topology": self.topology,
        })
    }

    fn stable_group(&self, name: &str) -> &Map<String, Value> {
        match name {
            "platform" => &self.platform,
            "listeners" => &self.listeners,
            "ownership" => &self.ownership,
            "topology" => &self.topology,
            _ => &self.prerequisites,
        }
    }
}

/// `Action`: one secret-free, owned, reversible adapter mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub id: String,
    pub adapter: String,
    pub owner: String,
    pub mutations: Vec<String>,
    pub preconditions: Vec<String>,
    pub verification: Vec<String>,
    pub inverse: Vec<String>,
    pub credentials_required: bool,
}

const ACTION_FIELDS: [&str; 8] =
    ["adapter", "credentials_required", "id", "inverse", "mutations", "owner", "preconditions", "verification"];

impl Action {
    /// `Action(...)` with its `__post_init__` checks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        adapter: &str,
        owner: &str,
        mutations: Vec<String>,
        preconditions: Vec<String>,
        verification: Vec<String>,
        inverse: Vec<String>,
        credentials_required: bool,
    ) -> Result<Action> {
        let action = Action {
            id: id.into(),
            adapter: adapter.into(),
            owner: owner.into(),
            mutations,
            preconditions,
            verification,
            inverse,
            credentials_required,
        };
        action.validate()?;
        Ok(action)
    }

    /// `Action.__post_init__`: what [`Action::new`] checks, for an action built as a struct
    /// literal.
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [("id", &self.id), ("adapter", &self.adapter), ("owner", &self.owner)] {
            if !nonempty(value) {
                return Err(PlanError::new(format!("action {name} must be a non-empty string")));
            }
        }
        for (name, values) in [
            ("mutations", &self.mutations),
            ("preconditions", &self.preconditions),
            ("verification", &self.verification),
            ("inverse", &self.inverse),
        ] {
            if values.is_empty() || values.iter().any(|value| !nonempty(value)) {
                return Err(PlanError::new(format!("action {} must declare non-empty {name}", self.id)));
            }
        }
        assert_secret_free(&self.to_value(), "plan")
    }

    /// [`validate`](Self::validate), then the action itself.
    pub fn checked(self) -> Result<Action> {
        self.validate()?;
        Ok(self)
    }

    /// `Action(**item)` from a stored plan: exactly the eight fields, Python's checks and texts.
    pub fn from_value(value: &Value) -> Result<Action> {
        let Value::Object(map) = value else {
            return Err(PlanError::new("action must be a mapping"));
        };
        if let Some(key) = map.keys().find(|key| !ACTION_FIELDS.contains(&key.as_str())) {
            return Err(PlanError::new(format!("action got an unexpected field: {key}")));
        }
        if let Some(key) = ACTION_FIELDS.iter().find(|key| !map.contains_key(**key)) {
            return Err(PlanError::new(format!("action is missing the field: {key}")));
        }
        let text = |name: &str| match &map[name] {
            Value::String(text) if nonempty(text) => Ok(text.clone()),
            _ => Err(PlanError::new(format!("action {name} must be a non-empty string"))),
        };
        let id = text("id")?;
        let adapter = text("adapter")?;
        let owner = text("owner")?;
        let mut lists = Vec::new();
        for name in ["mutations", "preconditions", "verification", "inverse"] {
            let Value::Array(items) = &map[name] else {
                return Err(PlanError::new(format!("action {id} {name} must be a non-string sequence")));
            };
            let values: Vec<String> = items
                .iter()
                .map(|item| match item {
                    Value::String(text) if nonempty(text) => Some(text.clone()),
                    _ => None,
                })
                .collect::<Option<_>>()
                .filter(|values: &Vec<String>| !values.is_empty())
                .ok_or_else(|| PlanError::new(format!("action {id} must declare non-empty {name}")))?;
            lists.push(values);
        }
        let Value::Bool(credentials_required) = map["credentials_required"] else {
            return Err(PlanError::new(format!("action {id} credentials_required must be a boolean")));
        };
        let mut lists = lists.into_iter();
        let mut next = || lists.next().expect("four lists");
        let action = Action {
            id,
            adapter,
            owner,
            mutations: next(),
            preconditions: next(),
            verification: next(),
            inverse: next(),
            credentials_required,
        };
        assert_secret_free(&action.to_value(), "plan")?;
        Ok(action)
    }

    /// `to_dict()`.
    pub fn to_value(&self) -> Value {
        json!({
            "adapter": self.adapter,
            "credentials_required": self.credentials_required,
            "id": self.id,
            "inverse": self.inverse,
            "mutations": self.mutations,
            "owner": self.owner,
            "preconditions": self.preconditions,
            "verification": self.verification,
        })
    }
}

/// `Evidence`: the sanitized result of verifying or rolling back an action. `details` is a
/// canonical JSON object (what the journal stores).
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub action_id: String,
    pub success: bool,
    pub observations: Vec<String>,
    pub details: Map<String, Value>,
}

impl Evidence {
    pub fn new(action_id: &str, success: bool, observations: Vec<String>, details: Fact) -> Result<Evidence> {
        if !nonempty(action_id) {
            return Err(PlanError::new("evidence action_id must be a non-empty string"));
        }
        if observations.iter().any(|item| !nonempty(item)) {
            return Err(PlanError::new("evidence observations must be non-empty strings"));
        }
        let details = match details {
            Fact::Map(_) => match details.canonical()? {
                Value::Object(map) => map,
                _ => unreachable!("a map canonicalises to an object"),
            },
            _ => return Err(PlanError::new("evidence details must be a mapping")),
        };
        let evidence = Evidence { action_id: action_id.into(), success, observations, details };
        assert_secret_free(
            &json!({"action_id": evidence.action_id, "details": evidence.details, "observations": evidence.observations}),
            "plan",
        )?;
        Ok(evidence)
    }

    /// Successful evidence without details.
    pub fn ok(action_id: &str, observations: &[&str]) -> Result<Evidence> {
        Evidence::new(action_id, true, observations.iter().map(|s| s.to_string()).collect(), Fact::Map(BTreeMap::new()))
    }

    /// Failed evidence without details.
    pub fn failed(action_id: &str, observations: &[&str]) -> Result<Evidence> {
        Evidence::new(
            action_id,
            false,
            observations.iter().map(|s| s.to_string()).collect(),
            Fact::Map(BTreeMap::new()),
        )
    }

    /// Evidence with JSON details (a checkpoint's `details` object; checked like [`Evidence::new`]).
    pub fn with_details(
        action_id: &str,
        success: bool,
        observations: Vec<String>,
        details: Map<String, Value>,
    ) -> Result<Evidence> {
        Evidence::new(action_id, success, observations, Fact::from(Value::Object(details)))
    }

    /// `_evidence_to_dict`: what a checkpoint stores as `evidence` / `rollback_evidence`.
    pub fn to_map(&self) -> Map<String, Value> {
        match json!({
            "action_id": self.action_id,
            "details": self.details,
            "observations": self.observations,
            "success": self.success,
        }) {
            Value::Object(map) => map,
            _ => unreachable!("an object literal"),
        }
    }

    /// Evidence back from a stored checkpoint record (exactly `{action_id, details,
    /// observations, success}` with their types; `evidence is invalid` otherwise), e.g. to replay
    /// a recorded run. The `report` command's lenient reader is
    /// [`crate::report::evidence_from_checkpoint`].
    pub fn from_map(map: &Map<String, Value>) -> Result<Evidence> {
        let invalid = || PlanError::new("evidence is invalid");
        let observations = map
            .get("observations")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or_else(invalid))
            .collect::<Result<Vec<_>>>()?;
        Evidence::with_details(
            map.get("action_id").and_then(Value::as_str).ok_or_else(invalid)?,
            map.get("success").and_then(Value::as_bool).ok_or_else(invalid)?,
            observations,
            map.get("details").and_then(Value::as_object).cloned().ok_or_else(invalid)?,
        )
    }
}

/// `planner.ReleaseIdentity`: what the plan records about the release tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseIdentity {
    pub tag: String,
    pub commit: String,
    pub manifest_sha256: String,
    pub components: BTreeMap<String, String>,
    pub artifacts: BTreeMap<String, String>,
}

const RELEASE_FIELDS: [&str; 5] = ["artifacts", "commit", "components", "manifest_sha256", "tag"];

impl ReleaseIdentity {
    pub fn new(
        tag: &str,
        commit: &str,
        manifest_sha256: &str,
        components: BTreeMap<String, String>,
        artifacts: BTreeMap<String, String>,
    ) -> Result<ReleaseIdentity> {
        let identity = ReleaseIdentity {
            tag: tag.into(),
            commit: commit.into(),
            manifest_sha256: manifest_sha256.into(),
            components,
            artifacts,
        };
        for (name, value) in
            [("tag", &identity.tag), ("commit", &identity.commit), ("manifest_sha256", &identity.manifest_sha256)]
        {
            if !nonempty(value) {
                return Err(PlanError::new(format!("release {name} must be a non-empty string")));
            }
        }
        for (name, map) in [("components", &identity.components), ("artifacts", &identity.artifacts)] {
            if map.iter().any(|(key, value)| !nonempty(key) || !nonempty(value)) {
                return Err(PlanError::new(format!("release {name} must contain non-empty strings")));
            }
        }
        assert_secret_free(&identity.to_value(), "plan")?;
        Ok(identity)
    }

    /// `release_identity(tree)` → the plan's identity (`schema`, `version` and the 4.0 keys of
    /// `release.json` are not part of it).
    pub fn from_tree(tree: &pc_host::archive::ReleaseIdentity) -> Result<ReleaseIdentity> {
        ReleaseIdentity::new(
            &tree.tag,
            &tree.commit,
            &tree.manifest_sha256,
            tree.components.clone(),
            tree.artifacts.clone(),
        )
    }

    /// `ReleaseIdentity(**release)` from a stored plan.
    pub fn from_value(value: &Value) -> Result<ReleaseIdentity> {
        let Value::Object(map) = value else {
            return Err(PlanError::new("release must be a mapping"));
        };
        if let Some(key) = map.keys().find(|key| !RELEASE_FIELDS.contains(&key.as_str())) {
            return Err(PlanError::new(format!("release got an unexpected field: {key}")));
        }
        let text = |name: &str| match map.get(name) {
            Some(Value::String(text)) => Ok(text.clone()),
            Some(_) => Err(PlanError::new(format!("release {name} must be a non-empty string"))),
            None => Err(PlanError::new(format!("release is missing the field: {name}"))),
        };
        let strings = |name: &str| -> Result<BTreeMap<String, String>> {
            match map.get(name) {
                None => Ok(BTreeMap::new()),
                Some(Value::Object(items)) => items
                    .iter()
                    .map(|(key, value)| match value {
                        Value::String(text) => Ok((key.clone(), text.clone())),
                        _ => Err(PlanError::new(format!("release {name} must contain non-empty strings"))),
                    })
                    .collect(),
                Some(_) => Err(PlanError::new(format!("release {name} must be a mapping"))),
            }
        };
        ReleaseIdentity::new(
            &text("tag")?,
            &text("commit")?,
            &text("manifest_sha256")?,
            strings("components")?,
            strings("artifacts")?,
        )
    }

    /// `to_dict()`.
    pub fn to_value(&self) -> Value {
        json!({
            "artifacts": self.artifacts,
            "commit": self.commit,
            "components": self.components,
            "manifest_sha256": self.manifest_sha256,
            "tag": self.tag,
        })
    }
}

/// `InstallPlan`: canonical, secret-free, approved and applied by digest.
#[derive(Debug, Clone, PartialEq)]
pub struct InstallPlan {
    /// The canonical configuration (`config.canonical_dict()`, or what a stored plan holds).
    pub config: Value,
    pub facts: AuditFacts,
    pub release: ReleaseIdentity,
    pub adapter_order: Vec<String>,
    pub adapter_dependencies: BTreeMap<String, Vec<String>>,
    pub actions: Vec<Action>,
    pub schema: i64,
}

const PLAN_FIELDS: [&str; 7] =
    ["actions", "adapter_dependencies", "adapter_order", "audit_facts", "config", "release", "schema"];

impl InstallPlan {
    pub fn new(
        config: Value,
        facts: AuditFacts,
        release: ReleaseIdentity,
        adapter_order: Vec<String>,
        adapter_dependencies: BTreeMap<String, Vec<String>>,
        actions: Vec<Action>,
        schema: i64,
    ) -> Result<InstallPlan> {
        if schema != PLAN_SCHEMA {
            return Err(PlanError::new(format!("unsupported plan schema: {schema}")));
        }
        let plan = InstallPlan { config, facts, release, adapter_order, adapter_dependencies, actions, schema };
        assert_secret_free(&plan.canonical_value(), "plan")?;
        Ok(plan)
    }

    /// `_plan_from_dict(value)`: a stored `plan.json` back into a plan (WP2 maps any error to
    /// `transaction plan is invalid`).
    pub fn from_value(value: &Value) -> Result<InstallPlan> {
        let Value::Object(map) = value else {
            return Err(PlanError::new("plan must be a mapping"));
        };
        if map.len() != PLAN_FIELDS.len() || PLAN_FIELDS.iter().any(|key| !map.contains_key(*key)) {
            return Err(PlanError::new("plan keys are not the plan schema"));
        }
        let (Value::Object(facts), Value::Object(_), Value::Array(actions), Value::Object(dependencies)) =
            (&map["audit_facts"], &map["release"], &map["actions"], &map["adapter_dependencies"])
        else {
            return Err(PlanError::new("plan sections have the wrong types"));
        };
        let fact_group = |name: &str| match facts.get(name) {
            None => Ok(Map::new()),
            Some(Value::Object(group)) => Ok(group.clone()),
            Some(_) => Err(PlanError::new(format!("{name} facts must be a mapping"))),
        };
        let facts = AuditFacts {
            platform: fact_group("platform")?,
            listeners: fact_group("listeners")?,
            ownership: fact_group("ownership")?,
            topology: fact_group("topology")?,
            prerequisites: fact_group("prerequisites")?,
            transient: Map::new(),
        };
        let strings = |value: &Value| -> Result<Vec<String>> {
            match value {
                Value::Array(items) => items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string).ok_or_else(|| PlanError::new("not a string")))
                    .collect(),
                _ => Err(PlanError::new("not a sequence")),
            }
        };
        let adapter_dependencies = dependencies
            .iter()
            .map(|(name, requires)| Ok((name.clone(), strings(requires)?)))
            .collect::<Result<_>>()?;
        let Some(schema) = map["schema"].as_i64() else {
            return Err(PlanError::new(format!("unsupported plan schema: {}", map["schema"])));
        };
        InstallPlan::new(
            map["config"].clone(),
            facts,
            ReleaseIdentity::from_value(&map["release"])?,
            strings(&map["adapter_order"])?,
            adapter_dependencies,
            actions.iter().map(Action::from_value).collect::<Result<_>>()?,
            schema,
        )
    }

    /// Parses `plan.json` bytes (any JSON formatting) with [`InstallPlan::from_value`].
    pub fn from_json(data: &[u8]) -> Result<InstallPlan> {
        let value = pc_host::json::loads(data).map_err(|err| PlanError::new(err.to_string()))?;
        InstallPlan::from_value(&value)
    }

    /// `_canonical_dict()`.
    pub fn canonical_value(&self) -> Value {
        json!({
            "actions": self.actions.iter().map(Action::to_value).collect::<Vec<_>>(),
            "adapter_dependencies": self.adapter_dependencies,
            "adapter_order": self.adapter_order,
            "audit_facts": self.facts.stable_dict(),
            "config": self.config,
            "release": self.release.to_value(),
            "schema": self.schema,
        })
    }

    /// `to_canonical_json()`: compact, sorted, raw UTF-8, no trailing newline.
    pub fn to_canonical_json(&self) -> String {
        pc_host::json::canonical(&self.canonical_value())
    }

    /// `digest`: SHA-256 hex of the canonical JSON.
    pub fn digest(&self) -> String {
        pc_host::fs::sha256_hex(self.to_canonical_json().as_bytes())
    }

    /// `intent_digest`: the installation independent of the observed host.
    pub fn intent_digest(&self) -> String {
        pc_host::json::canonical_digest(&json!({
            "adapter_order": self.adapter_order,
            "config": self.config,
            "release": self.release.to_value(),
            "schema": self.schema,
        }))
    }

    /// `assert_fresh(current)`: `StalePlanError("<group> facts changed")` in Python's group order.
    pub fn assert_fresh(&self, current: &AuditFacts) -> Result<()> {
        for (name, message) in FRESHNESS {
            if self.facts.stable_group(name) != current.stable_group(name) {
                return Err(PlanError::Stale(message.into()));
            }
        }
        Ok(())
    }
}

/// What the planner needs from an adapter (the transaction engine's adapters implement it).
pub trait PlanAdapter {
    /// The name its actions carry.
    fn name(&self) -> &str;
    /// Adapters that must come before it.
    fn requires(&self) -> Vec<String>;
    /// Its actions for this configuration and host.
    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>>;
}

/// `build_plan(config, facts, adapters, release)`.
pub fn build_plan(
    config: &InstallerConfig,
    facts: &AuditFacts,
    adapters: &[&dyn PlanAdapter],
    release: &ReleaseIdentity,
) -> Result<InstallPlan> {
    let ordered = topologically_sorted(adapters)?;
    let mut actions: Vec<Action> = Vec::new();
    let mut dependencies = BTreeMap::new();
    for adapter in &ordered {
        let mut requires = adapter.requires();
        requires.sort();
        requires.dedup();
        dependencies.insert(adapter.name().to_string(), requires);
        for item in adapter.plan(config, facts)? {
            if item.adapter != adapter.name() {
                return Err(PlanError::new(format!(
                    "action {} names adapter {}, expected {}",
                    item.id,
                    item.adapter,
                    adapter.name()
                )));
            }
            if actions.iter().any(|existing| existing.id == item.id) {
                return Err(PlanError::new(format!("duplicate action id: {}", item.id)));
            }
            actions.push(item);
        }
    }
    InstallPlan::new(
        config.canonical_dict(),
        facts.clone(),
        release.clone(),
        ordered.iter().map(|adapter| adapter.name().to_string()).collect(),
        dependencies,
        actions,
        PLAN_SCHEMA,
    )
}

/// Kahn's sort; among ready adapters the caller's order wins, then the name.
fn topologically_sorted<'a>(adapters: &[&'a dyn PlanAdapter]) -> Result<Vec<&'a dyn PlanAdapter>> {
    let mut by_name: Vec<(String, &'a dyn PlanAdapter)> = Vec::new();
    for adapter in adapters.iter().copied() {
        let name = adapter.name().to_string();
        if !nonempty(&name) {
            return Err(PlanError::new("adapter name must be a non-empty string"));
        }
        if by_name.iter().any(|(known, _)| *known == name) {
            return Err(PlanError::new(format!("duplicate adapter name: {name}")));
        }
        by_name.push((name, adapter));
    }
    let mut dependents: HashMap<String, Vec<String>> =
        by_name.iter().map(|(name, _)| (name.clone(), Vec::new())).collect();
    let mut indegree: BTreeMap<String, usize> = BTreeMap::new();
    for (name, adapter) in &by_name {
        let mut requires = adapter.requires();
        requires.sort();
        requires.dedup();
        if let Some(missing) = requires.iter().find(|r| !by_name.iter().any(|(n, _)| n == *r)) {
            return Err(PlanError::new(format!("adapter {name} requires missing adapter: {missing}")));
        }
        indegree.insert(name.clone(), requires.len());
        for requirement in &requires {
            dependents.get_mut(requirement).expect("checked above").push(name.clone());
        }
    }
    let position: HashMap<String, usize> =
        by_name.iter().enumerate().map(|(index, (name, _))| (name.clone(), index)).collect();
    let mut ready: BinaryHeap<Reverse<(usize, String)>> = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(name, _)| Reverse((position[name], name.clone())))
        .collect();
    let mut ordered = Vec::new();
    while let Some(Reverse((_, name))) = ready.pop() {
        let adapter = by_name.iter().find(|(n, _)| *n == name).expect("known adapter").1;
        ordered.push(adapter);
        let mut next = dependents[&name].clone();
        next.sort();
        for dependent in next {
            let count = indegree.get_mut(&dependent).expect("known adapter");
            *count -= 1;
            if *count == 0 {
                ready.push(Reverse((position[&dependent], dependent)));
            }
        }
    }
    if ordered.len() != by_name.len() {
        let cyclic: Vec<&str> =
            indegree.iter().filter(|(_, count)| **count > 0).map(|(name, _)| name.as_str()).collect();
        return Err(PlanError::new(format!("adapter dependency cycle: {}", cyclic.join(", "))));
    }
    Ok(ordered)
}

/// The adapter registry (`adapter_factories()`), in registration order.
pub const ADAPTER_NAMES: [&str; 14] = [
    "packages",
    "nginx",
    "certificates",
    "firewall",
    "core",
    "naive",
    "mieru",
    "three_xui",
    "warp",
    "xray_router",
    "mcp",
    "amneziawg",
    "trusttunnel",
    "version_agent",
];

/// Each adapter's `requires` (they enter the digest as `adapter_dependencies`).
pub fn adapter_requires(name: &str) -> &'static [&'static str] {
    match name {
        "packages" => &[],
        "nginx" | "firewall" | "warp" => &["packages"],
        "certificates" => &["nginx", "packages"],
        "core" | "three_xui" => &["certificates"],
        _ => &["core"],
    }
}

/// The documented full-profile order; every profile is an order-preserving subset of it.
pub const PROFILE_ORDER: [&str; 14] = [
    "packages",
    "nginx",
    "firewall",
    "certificates",
    "core",
    "warp",
    "xray_router",
    "naive",
    "mieru",
    "three_xui",
    "amneziawg",
    "trusttunnel",
    "mcp",
    "version_agent",
];

/// `adapters_for(config)`: the names of exactly the adapters this configuration needs, in
/// order (the engine maps them to adapter instances).
pub fn adapters_for(config: &InstallerConfig) -> Result<Vec<&'static str>> {
    if config.profile.includes_naive() && config.domains.naive.is_none() {
        return Err(PlanError::new("the selected profile requires a NaiveProxy domain"));
    }
    if config.profile.includes_mieru() && (config.domains.mieru.is_none() || config.mieru.is_none()) {
        return Err(PlanError::new("the selected profile requires Mieru listeners and a host"));
    }
    if !config.profile.includes_mieru() && config.mieru.is_some() {
        return Err(PlanError::new("Mieru listeners are configured outside a Mieru profile"));
    }
    if config.three_xui.mode == ThreeXuiMode::ManagedNew && config.host_mode != crate::model::HostMode::Fresh {
        return Err(PlanError::new("managed 3x-ui requires a fresh host"));
    }
    let egress = config.effective_egress();
    let selected = |name: &str| match name {
        "packages" | "nginx" | "certificates" | "core" | "version_agent" => true,
        "firewall" => config.host_mode == crate::model::HostMode::Fresh && config.firewall.manage_ufw,
        "warp" => egress.warp,
        "xray_router" => egress.router,
        "naive" => config.profile.includes_naive(),
        "mieru" => config.profile.includes_mieru(),
        "three_xui" => config.three_xui.mode != ThreeXuiMode::None,
        "amneziawg" => config.amneziawg.is_some(),
        "trusttunnel" => config.trusttunnel.is_some(),
        "mcp" => config.domains.mcp.is_some(),
        _ => false,
    };
    Ok(PROFILE_ORDER.iter().copied().filter(|name| selected(name)).collect())
}

/// `compose_file_list(config)`: the one canonical Compose file list for a profile.
pub fn compose_file_list(config: &InstallerConfig) -> Vec<&'static str> {
    let mut files = vec!["compose.yaml"];
    if config.profile.includes_naive() {
        files.push("compose.naive.yaml");
    }
    if config.profile.includes_mieru() {
        files.push("compose.mieru.yaml");
    }
    if config.effective_egress().router {
        files.push("compose.xray-router.yaml");
    }
    if config.amneziawg.is_some() {
        files.push("compose.amneziawg.yaml");
    }
    if config.trusttunnel.is_some() {
        files.push("compose.trusttunnel.yaml");
    }
    if config.domains.mcp.is_some() {
        files.push("compose.mcp.yaml");
    }
    files
}

/// `_assert_secret_free(value, path=path)`: no secret-named key, no secret assignment text.
pub fn assert_secret_free(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                if plan_key_is_secret(key) {
                    return Err(PlanError::new(format!("secret field is forbidden at {path}.{key}")));
                }
                assert_secret_free(item, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_secret_free(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::String(text) if plan_text_has_secret(text) => {
            Err(PlanError::new(format!("secret material is forbidden at {path}")))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "planner_tests.rs"]
mod tests;
