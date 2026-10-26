//! The plan types the transaction engine executes (`installer/planner.py:48-310`): actions,
//! evidence, the release identity, the audit facts and the canonical plan with its digests.
//!
//! The plan is approved by its SHA-256, and `plan.json` is re-rendered and re-hashed on every
//! journal read (`transaction.py:1392`), so [`InstallPlan::to_canonical_json`] must produce the
//! exact bytes Python's `json.dumps(…, separators=(",", ":"), sort_keys=True,
//! ensure_ascii=False)` produced. Every value is kept as [`serde_json::Value`] (key-sorted maps),
//! which `pc_host::json::canonical` renders byte for byte.
//!
//! Host WP3 owns building plans (`build_plan`, `adapters_for`, the config model); this module
//! has what the journal and the adapters need.

use std::collections::BTreeMap;
use std::fmt;

use pc_host::json;
use serde_json::{Map, Value};

/// `PLAN_SCHEMA`.
pub const PLAN_SCHEMA: i64 = 1;

/// `PlanError`: a plan, an action or evidence cannot be represented safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanError(pub String);

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlanError {}

fn plan_error(message: impl Into<String>) -> PlanError {
    PlanError(message.into())
}

/// `_nonempty`: a string with a non-whitespace character (`str.strip()` semantics).
pub(crate) fn nonempty(value: &str) -> bool {
    value.chars().any(|c| !py_isspace(c))
}

/// `str.isspace()` for one character: Unicode white space plus the ASCII separators
/// `\x1c`–`\x1f`, which Python counts and Rust's `char::is_whitespace` does not.
pub(crate) fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// One secret-free, owned, reversible adapter mutation (`Action`). The mutation strings and
/// their order are part of the plan digest.
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

impl Action {
    /// `Action.__post_init__`: the checks every action passes before it enters a plan.
    pub fn validate(&self) -> Result<(), PlanError> {
        for (name, value) in [("id", &self.id), ("adapter", &self.adapter), ("owner", &self.owner)] {
            if !nonempty(value) {
                return Err(plan_error(format!("action {name} must be a non-empty string")));
            }
        }
        for (name, values) in [
            ("mutations", &self.mutations),
            ("preconditions", &self.preconditions),
            ("verification", &self.verification),
            ("inverse", &self.inverse),
        ] {
            if values.is_empty() || values.iter().any(|value| !nonempty(value)) {
                return Err(plan_error(format!("action {} must declare non-empty {name}", self.id)));
            }
        }
        assert_secret_free(&self.to_value(), "plan")
    }

    /// `validate`, then the action itself.
    pub fn checked(self) -> Result<Action, PlanError> {
        self.validate()?;
        Ok(self)
    }

    /// `Action.to_dict()`.
    pub fn to_value(&self) -> Value {
        let strings = |values: &[String]| Value::Array(values.iter().cloned().map(Value::String).collect());
        let mut map = Map::new();
        map.insert("adapter".into(), Value::String(self.adapter.clone()));
        map.insert("credentials_required".into(), Value::Bool(self.credentials_required));
        map.insert("id".into(), Value::String(self.id.clone()));
        map.insert("inverse".into(), strings(&self.inverse));
        map.insert("mutations".into(), strings(&self.mutations));
        map.insert("owner".into(), Value::String(self.owner.clone()));
        map.insert("preconditions".into(), strings(&self.preconditions));
        map.insert("verification".into(), strings(&self.verification));
        Value::Object(map)
    }

    /// `Action(**item)`: exactly the eight keys, each of its type, then [`validate`](Self::validate).
    pub fn from_value(value: &Value) -> Result<Action, PlanError> {
        let invalid = || plan_error("action is invalid");
        let map = value.as_object().ok_or_else(invalid)?;
        const KEYS: [&str; 8] =
            ["adapter", "credentials_required", "id", "inverse", "mutations", "owner", "preconditions", "verification"];
        if map.len() != KEYS.len() || KEYS.iter().any(|key| !map.contains_key(*key)) {
            return Err(invalid());
        }
        let text = |key: &str| map[key].as_str().map(str::to_owned).ok_or_else(invalid);
        let list = |key: &str| -> Result<Vec<String>, PlanError> {
            map[key]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|item| item.as_str().map(str::to_owned).ok_or_else(invalid))
                .collect()
        };
        let action = Action {
            id: text("id")?,
            adapter: text("adapter")?,
            owner: text("owner")?,
            mutations: list("mutations")?,
            preconditions: list("preconditions")?,
            verification: list("verification")?,
            inverse: list("inverse")?,
            credentials_required: map["credentials_required"].as_bool().ok_or_else(invalid)?,
        };
        action.checked()
    }
}

/// The sanitized result of verifying or rolling back an action (`Evidence`).
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    action_id: String,
    success: bool,
    observations: Vec<String>,
    details: Map<String, Value>,
}

impl Evidence {
    /// `Evidence(action_id, success, observations, details)` with its checks.
    pub fn new(
        action_id: impl Into<String>,
        success: bool,
        observations: Vec<String>,
        details: Map<String, Value>,
    ) -> Result<Evidence, PlanError> {
        let action_id = action_id.into();
        if !nonempty(&action_id) {
            return Err(plan_error("evidence action_id must be a non-empty string"));
        }
        if observations.iter().any(|item| !nonempty(item)) {
            return Err(plan_error("evidence observations must be non-empty strings"));
        }
        let evidence = Evidence { action_id, success, observations, details };
        let mut checked = Map::new();
        checked.insert("action_id".into(), Value::String(evidence.action_id.clone()));
        checked.insert("details".into(), Value::Object(evidence.details.clone()));
        checked.insert(
            "observations".into(),
            Value::Array(evidence.observations.iter().cloned().map(Value::String).collect()),
        );
        assert_secret_free(&Value::Object(checked), "plan")?;
        Ok(evidence)
    }

    /// Successful evidence without details.
    pub fn ok(action_id: impl Into<String>, observations: &[&str]) -> Result<Evidence, PlanError> {
        Evidence::new(action_id, true, observations.iter().map(|s| s.to_string()).collect(), Map::new())
    }

    /// Failed evidence without details.
    pub fn failed(action_id: impl Into<String>, observations: &[&str]) -> Result<Evidence, PlanError> {
        Evidence::new(action_id, false, observations.iter().map(|s| s.to_string()).collect(), Map::new())
    }

    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub fn success(&self) -> bool {
        self.success
    }

    pub fn observations(&self) -> &[String] {
        &self.observations
    }

    pub fn details(&self) -> &Map<String, Value> {
        &self.details
    }

    /// `_evidence_to_dict`: what a checkpoint stores.
    pub fn to_map(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("action_id".into(), Value::String(self.action_id.clone()));
        map.insert("details".into(), Value::Object(self.details.clone()));
        map.insert("observations".into(), Value::Array(self.observations.iter().cloned().map(Value::String).collect()));
        map.insert("success".into(), Value::Bool(self.success));
        map
    }

    /// Evidence back from a stored checkpoint record (`{action_id, details, observations,
    /// success}`), e.g. to replay a recorded run.
    pub fn from_map(map: &Map<String, Value>) -> Result<Evidence, PlanError> {
        let invalid = || plan_error("evidence is invalid");
        let observations = map
            .get("observations")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or_else(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        Evidence::new(
            map.get("action_id").and_then(Value::as_str).ok_or_else(invalid)?,
            map.get("success").and_then(Value::as_bool).ok_or_else(invalid)?,
            observations,
            map.get("details").and_then(Value::as_object).cloned().ok_or_else(invalid)?,
        )
    }
}

/// The identity and public digests of the release a plan installs (`ReleaseIdentity`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseIdentity {
    pub tag: String,
    pub commit: String,
    pub manifest_sha256: String,
    pub components: BTreeMap<String, String>,
    pub artifacts: BTreeMap<String, String>,
}

impl ReleaseIdentity {
    /// A release without component or artifact digests.
    pub fn new(tag: &str, commit: &str, manifest_sha256: &str) -> ReleaseIdentity {
        ReleaseIdentity {
            tag: tag.into(),
            commit: commit.into(),
            manifest_sha256: manifest_sha256.into(),
            components: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        }
    }

    /// `ReleaseIdentity.__post_init__`.
    pub fn validate(&self) -> Result<(), PlanError> {
        for (name, value) in [("tag", &self.tag), ("commit", &self.commit), ("manifest_sha256", &self.manifest_sha256)]
        {
            if !nonempty(value) {
                return Err(plan_error(format!("release {name} must be a non-empty string")));
            }
        }
        for (name, map) in [("components", &self.components), ("artifacts", &self.artifacts)] {
            if map.iter().any(|(key, value)| !nonempty(key) || !nonempty(value)) {
                return Err(plan_error(format!("release {name} must contain non-empty strings")));
            }
        }
        assert_secret_free(&self.to_value(), "plan")
    }

    /// `ReleaseIdentity.to_dict()`.
    pub fn to_value(&self) -> Value {
        let strings = |map: &BTreeMap<String, String>| {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect())
        };
        let mut map = Map::new();
        map.insert("artifacts".into(), strings(&self.artifacts));
        map.insert("commit".into(), Value::String(self.commit.clone()));
        map.insert("components".into(), strings(&self.components));
        map.insert("manifest_sha256".into(), Value::String(self.manifest_sha256.clone()));
        map.insert("tag".into(), Value::String(self.tag.clone()));
        Value::Object(map)
    }

    /// `ReleaseIdentity(**release)`: `tag`, `commit`, `manifest_sha256` required, `components`
    /// and `artifacts` optional string maps, nothing else.
    pub fn from_value(value: &Value) -> Result<ReleaseIdentity, PlanError> {
        let invalid = || plan_error("release is invalid");
        let map = value.as_object().ok_or_else(invalid)?;
        const ALLOWED: [&str; 5] = ["artifacts", "commit", "components", "manifest_sha256", "tag"];
        if map.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
            return Err(invalid());
        }
        let text = |key: &str| map.get(key).and_then(Value::as_str).map(str::to_owned).ok_or_else(invalid);
        let strings = |key: &str| -> Result<BTreeMap<String, String>, PlanError> {
            match map.get(key) {
                None => Ok(BTreeMap::new()),
                Some(Value::Object(items)) => items
                    .iter()
                    .map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())).ok_or_else(invalid))
                    .collect(),
                Some(_) => Err(plan_error(format!("release {key} must be a mapping"))),
            }
        };
        let identity = ReleaseIdentity {
            tag: text("tag")?,
            commit: text("commit")?,
            manifest_sha256: text("manifest_sha256")?,
            components: strings("components")?,
            artifacts: strings("artifacts")?,
        };
        identity.validate()?;
        Ok(identity)
    }
}

/// The audit snapshot a plan carries (`AuditFacts`). Only the five stable groups enter the plan
/// and its digest; `transient` never does.
///
/// The values must already be canonical JSON (Python's `_canonical_fact_value`: sets as lists
/// sorted by their canonical JSON); the audit (host WP4) builds them that way.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditFacts {
    pub platform: Map<String, Value>,
    pub listeners: Map<String, Value>,
    pub ownership: Map<String, Value>,
    pub topology: Map<String, Value>,
    pub prerequisites: Map<String, Value>,
    pub transient: Map<String, Value>,
}

impl AuditFacts {
    /// `stable_dict()`.
    pub fn stable_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("listeners".into(), Value::Object(self.listeners.clone()));
        map.insert("ownership".into(), Value::Object(self.ownership.clone()));
        map.insert("platform".into(), Value::Object(self.platform.clone()));
        map.insert("prerequisites".into(), Value::Object(self.prerequisites.clone()));
        map.insert("topology".into(), Value::Object(self.topology.clone()));
        Value::Object(map)
    }
}

/// The canonical, secret-free plan approved and applied by digest (`InstallPlan`).
#[derive(Debug, Clone, PartialEq)]
pub struct InstallPlan {
    pub config: Value,
    pub facts: AuditFacts,
    pub release: ReleaseIdentity,
    pub adapter_order: Vec<String>,
    pub adapter_dependencies: BTreeMap<String, Vec<String>>,
    pub actions: Vec<Action>,
    pub schema: i64,
}

impl InstallPlan {
    /// `InstallPlan.__post_init__`: the schema, then no secret anywhere in the canonical form.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.schema != PLAN_SCHEMA {
            return Err(plan_error(format!("unsupported plan schema: {}", self.schema)));
        }
        assert_secret_free(&self.canonical_value(), "plan")
    }

    /// `validate`, then the plan itself.
    pub fn checked(self) -> Result<InstallPlan, PlanError> {
        self.validate()?;
        Ok(self)
    }

    /// `_canonical_dict()`.
    pub fn canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("actions".into(), Value::Array(self.actions.iter().map(Action::to_value).collect()));
        map.insert(
            "adapter_dependencies".into(),
            Value::Object(
                self.adapter_dependencies
                    .iter()
                    .map(|(name, requires)| {
                        (name.clone(), Value::Array(requires.iter().cloned().map(Value::String).collect()))
                    })
                    .collect(),
            ),
        );
        map.insert(
            "adapter_order".into(),
            Value::Array(self.adapter_order.iter().cloned().map(Value::String).collect()),
        );
        map.insert("audit_facts".into(), self.facts.stable_value());
        map.insert("config".into(), self.config.clone());
        map.insert("release".into(), self.release.to_value());
        map.insert("schema".into(), Value::from(self.schema));
        Value::Object(map)
    }

    /// The bytes of `plan.json` and of the digest.
    pub fn to_canonical_json(&self) -> String {
        json::canonical(&self.canonical_value())
    }

    /// The SHA-256 the operator approves.
    pub fn digest(&self) -> String {
        pc_host::fs::sha256_hex(self.to_canonical_json().as_bytes())
    }

    /// What the operator asked for, independent of the audited host: re-applying the same
    /// intent to an active installation is a no-op (`intent_digest`).
    pub fn intent_digest(&self) -> String {
        let mut map = Map::new();
        map.insert(
            "adapter_order".into(),
            Value::Array(self.adapter_order.iter().cloned().map(Value::String).collect()),
        );
        map.insert("config".into(), self.config.clone());
        map.insert("release".into(), self.release.to_value());
        map.insert("schema".into(), Value::from(self.schema));
        pc_host::fs::sha256_hex(json::canonical(&Value::Object(map)).as_bytes())
    }

    /// `_plan_from_dict` (`transaction.py:1616`): exactly the seven top-level keys, then each
    /// part as its constructor accepts it. Unknown keys inside `audit_facts` are ignored and
    /// a missing group is empty, as Python's `facts.get(group, {})`; a re-render then no longer
    /// matches the stored digest, which the journal reader refuses.
    pub fn from_value(value: &Value) -> Result<InstallPlan, PlanError> {
        let invalid = || plan_error("transaction plan is invalid");
        let map = value.as_object().ok_or_else(invalid)?;
        const KEYS: [&str; 7] =
            ["actions", "adapter_dependencies", "adapter_order", "audit_facts", "config", "release", "schema"];
        if map.len() != KEYS.len() || KEYS.iter().any(|key| !map.contains_key(*key)) {
            return Err(invalid());
        }
        let facts = map["audit_facts"].as_object().ok_or_else(invalid)?;
        let group = |name: &str| -> Result<Map<String, Value>, PlanError> {
            match facts.get(name) {
                None => Ok(Map::new()),
                Some(Value::Object(items)) => Ok(items.clone()),
                Some(_) => Err(invalid()),
            }
        };
        let names = |value: &Value| -> Result<Vec<String>, PlanError> {
            value
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|item| item.as_str().map(str::to_owned).ok_or_else(invalid))
                .collect()
        };
        let dependencies = map["adapter_dependencies"]
            .as_object()
            .ok_or_else(invalid)?
            .iter()
            .map(|(name, requires)| Ok((name.clone(), names(requires)?)))
            .collect::<Result<BTreeMap<_, _>, PlanError>>()?;
        let actions = map["actions"]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .map(Action::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let schema = match &map["schema"] {
            Value::Number(number) => number.as_i64().ok_or_else(invalid)?,
            _ => return Err(invalid()),
        };
        let plan = InstallPlan {
            config: map["config"].clone(),
            facts: AuditFacts {
                platform: group("platform")?,
                listeners: group("listeners")?,
                ownership: group("ownership")?,
                topology: group("topology")?,
                prerequisites: group("prerequisites")?,
                transient: Map::new(),
            },
            release: ReleaseIdentity::from_value(&map["release"])?,
            adapter_order: names(&map["adapter_order"])?,
            adapter_dependencies: dependencies,
            actions,
            schema,
        };
        plan.checked()
    }
}

// ------------------------------------------------------------------------------------------
// The secret scanner (`_assert_secret_free`, `planner.py:608`)
// ------------------------------------------------------------------------------------------

const SECRET_KEY_PARTS: [&str; 6] = ["password", "passwd", "secret", "token", "privatekey", "apikey"];

/// `_assert_secret_free(value, path=…)`: no key that names a secret, no string that assigns
/// one. Keys are visited in sorted order, as Python visited the frozen (sorted) mappings.
pub fn assert_secret_free(value: &Value, path: &str) -> Result<(), PlanError> {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                let compact: String =
                    key.to_lowercase().chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect();
                if SECRET_KEY_PARTS.iter().any(|part| compact.contains(part)) {
                    return Err(plan_error(format!("secret field is forbidden at {path}.{key}")));
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
        Value::String(text) if has_secret_assignment(text) => {
            Err(plan_error(format!("secret material is forbidden at {path}")))
        }
        _ => Ok(()),
    }
}

/// `_SECRET_ASSIGNMENT.search(text)` (`re.IGNORECASE | re.VERBOSE`):
///
/// ```text
/// --NAME(?:=|\s+)(?:"[^"]*"|'[^']*'|\S+)
/// | ["']?NAME["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,}\]]+)
/// NAME = password|passwd|secret|token|private[_ -]?key|api[_ -]?key
/// ```
///
/// Worked out without backtracking: the first branch matches when `--NAME` is followed by `=`
/// or white space and then a non-space character; the second when `NAME`, an optional quote,
/// white space, `:` or `=`, white space are followed by a character other than `,`, `}`, `]`.
pub fn has_secret_assignment(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    (0..chars.len()).any(|start| {
        let long_option = start + 2 <= chars.len()
            && chars[start] == '-'
            && chars[start + 1] == '-'
            && name_ends(&chars, start + 2).into_iter().any(|end| option_value_follows(&chars, end));
        long_option || name_ends(&chars, start).into_iter().any(|end| assignment_follows(&chars, end))
    })
}

fn option_value_follows(chars: &[char], end: usize) -> bool {
    match chars.get(end) {
        Some('=') => chars.get(end + 1).is_some_and(|c| !py_isspace(*c)),
        Some(c) if py_isspace(*c) => {
            let mut index = end;
            while chars.get(index).is_some_and(|c| py_isspace(*c)) {
                index += 1;
            }
            chars.get(index).is_some()
        }
        _ => false,
    }
}

fn assignment_follows(chars: &[char], end: usize) -> bool {
    let mut index = end;
    if matches!(chars.get(index), Some('"') | Some('\'')) {
        index += 1;
    }
    while chars.get(index).is_some_and(|c| py_isspace(*c)) {
        index += 1;
    }
    if !matches!(chars.get(index), Some(':') | Some('=')) {
        return false;
    }
    index += 1;
    while chars.get(index).is_some_and(|c| py_isspace(*c)) {
        index += 1;
    }
    chars.get(index).is_some_and(|c| !matches!(c, ',' | '}' | ']'))
}

/// Every end index of a secret name starting at `start`, case-insensitively.
fn name_ends(chars: &[char], start: usize) -> Vec<usize> {
    let mut ends = Vec::new();
    for word in ["password", "passwd", "secret", "token"] {
        if let Some(end) = literal(chars, start, word) {
            ends.push(end);
        }
    }
    for (head, tail) in [("private", "key"), ("api", "key")] {
        if let Some(middle) = literal(chars, start, head) {
            if let Some(end) = literal(chars, middle, tail) {
                ends.push(end);
            }
            if matches!(chars.get(middle), Some('_') | Some(' ') | Some('-')) {
                if let Some(end) = literal(chars, middle + 1, tail) {
                    ends.push(end);
                }
            }
        }
    }
    ends
}

fn literal(chars: &[char], start: usize, word: &str) -> Option<usize> {
    let mut index = start;
    for expected in word.chars() {
        if !folds_to(*chars.get(index)?, expected) {
            return None;
        }
        index += 1;
    }
    Some(index)
}

/// Python's `re.IGNORECASE` on `str` for an ASCII lowercase letter: the letter, its capital,
/// and the characters whose simple case folding meets it (`ſ` → `s`, `K` (Kelvin) → `k`,
/// `ı`/`İ` → `i`).
fn folds_to(c: char, letter: char) -> bool {
    if c.to_ascii_lowercase() == letter {
        return true;
    }
    matches!((c, letter), ('\u{17f}', 's') | ('\u{212a}', 'k') | ('\u{131}', 'i') | ('\u{130}', 'i'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn action() -> Action {
        Action {
            id: "core.install".into(),
            adapter: "core".into(),
            owner: "proxy-control:core".into(),
            mutations: vec!["write /core.owned".into()],
            preconditions: vec!["/core.owned is absent".into()],
            verification: vec!["/core.owned has the approved content".into()],
            inverse: vec!["remove /core.owned".into()],
            credentials_required: false,
        }
    }

    #[test]
    fn secret_assignments_follow_the_python_pattern() {
        for text in [
            "--password=x",
            "--token abc",
            "--API-KEY  'a b'",
            "password: hunter2",
            "\"secret\" = \"x\"",
            "private_key=abc",
            "privatekey:1",
            "api key = z",
            "TOKEN=a",
            "my_token=a",
            "pa\u{17f}\u{17f}word=x",
        ] {
            assert!(has_secret_assignment(text), "{text}");
        }
        for text in [
            "--password",
            "password:",
            "password: ,",
            "token=}",
            "token=]",
            "write /core.owned",
            "the token file is private",
            "secret",
            "privat key=x",
            "--tokens x",
        ] {
            assert!(!has_secret_assignment(text), "{text}");
        }
    }

    #[test]
    fn secret_keys_and_paths() {
        assert_eq!(
            assert_secret_free(&json!({"a": {"Api-Key": 1}}), "plan"),
            Err(PlanError("secret field is forbidden at plan.a.Api-Key".into()))
        );
        assert_eq!(
            assert_secret_free(&json!({"a": ["ok", "token=x"]}), "plan"),
            Err(PlanError("secret material is forbidden at plan.a[1]".into()))
        );
        assert!(assert_secret_free(&json!({"tokenless": false}), "plan").is_err());
        assert!(assert_secret_free(&json!({"owner": "x", "n": [1, null, true]}), "plan").is_ok());
    }

    #[test]
    fn action_checks_match_post_init() {
        assert!(action().checked().is_ok());
        let mut bad = action();
        bad.owner = "  ".into();
        assert_eq!(bad.validate(), Err(PlanError("action owner must be a non-empty string".into())));
        let mut bad = action();
        bad.inverse = vec![];
        assert_eq!(bad.validate(), Err(PlanError("action core.install must declare non-empty inverse".into())));
        let mut bad = action();
        bad.mutations = vec!["--password=x".into()];
        assert_eq!(bad.validate(), Err(PlanError("secret material is forbidden at plan.mutations[0]".into())));
        assert_eq!(Action::from_value(&action().to_value()).unwrap(), action());
        let mut extra = action().to_value();
        extra["more"] = json!(1);
        assert!(Action::from_value(&extra).is_err());
    }

    #[test]
    fn evidence_checks_and_round_trip() {
        let evidence = Evidence::ok("a", &["verified"]).unwrap();
        assert_eq!(Evidence::from_map(&evidence.to_map()).unwrap(), evidence);
        assert!(Evidence::ok(" ", &["x"]).is_err());
        assert!(Evidence::ok("a", &[""]).is_err());
        assert_eq!(
            json::canonical(&Value::Object(evidence.to_map())),
            r#"{"action_id":"a","details":{},"observations":["verified"],"success":true}"#
        );
    }

    #[test]
    fn plan_bytes_and_digests() {
        let mut facts = AuditFacts::default();
        facts.platform.insert("os".into(), json!("test"));
        let plan = InstallPlan {
            config: json!({"profile": "test"}),
            facts,
            release: ReleaseIdentity::new("v1.2.3", &"a".repeat(40), &"b".repeat(64)),
            adapter_order: vec!["core".into()],
            adapter_dependencies: [("core".to_string(), vec![])].into_iter().collect(),
            actions: vec![action()],
            schema: 1,
        }
        .checked()
        .unwrap();
        let text = plan.to_canonical_json();
        assert!(text.starts_with(r#"{"actions":[{"adapter":"core","credentials_required":false,"id":"core.install""#));
        assert!(text.contains(
            r#""audit_facts":{"listeners":{},"ownership":{},"platform":{"os":"test"},"prerequisites":{},"topology":{}}"#
        ));
        let reread = InstallPlan::from_value(&json::loads(text.as_bytes()).unwrap()).unwrap();
        assert_eq!(reread.to_canonical_json(), text);
        assert_eq!(reread.digest(), plan.digest());
        let mut replanned = plan.clone();
        replanned.facts.platform.insert("changed".into(), json!("1"));
        assert_ne!(replanned.digest(), plan.digest());
        assert_eq!(replanned.intent_digest(), plan.intent_digest());
        let mut wrong = plan.clone();
        wrong.schema = 2;
        assert_eq!(wrong.validate(), Err(PlanError("unsupported plan schema: 2".into())));
    }
}
