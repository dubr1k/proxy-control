//! The typed journal: `state.json`, its checkpoints and the ownership entries
//! (`installer/transaction.py:222-404`, host inventory B.2.2).
//!
//! The readers are as strict as Python's `from_dict`: required keys must be there, unknown keys
//! are refused, so a journal a newer installer extended is never half-understood. The writers
//! omit optional keys instead of writing `null` (`error`, `legacy`, `purge_data`,
//! `rollback_target`, `evidence`, `rollback_evidence`, an ownership entry's `mutable`), so a
//! Python-written journal is written back byte for byte and a 3.x reader accepts a Rust-written
//! one. Checkpoint `data`, `evidence` and the runtime-v2 `legacy` manifest are opaque JSON.

use std::collections::BTreeMap;

use pc_host::TxError;
use serde_json::{Map, Value};

/// `TRANSACTION_SCHEMA`.
pub const TRANSACTION_SCHEMA: i64 = 1;
/// The origin of a transaction the installer applied.
pub const ORIGIN_INSTALLER: &str = "installer-v1";

/// Adapter-defined checkpoint state, passed to and returned by every adapter method.
pub type CheckpointData = Map<String, Value>;

fn invalid(message: &str) -> TxError {
    crate::error::transaction(message)
}

/// `state.json:status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    Applying,
    Active,
    RollingBack,
    RollbackFailed,
    Uninstalling,
    RolledBack,
    Uninstalled,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Applying => "applying",
            Status::Active => "active",
            Status::RollingBack => "rolling_back",
            Status::RollbackFailed => "rollback_failed",
            Status::Uninstalling => "uninstalling",
            Status::RolledBack => "rolled_back",
            Status::Uninstalled => "uninstalled",
        }
    }

    pub fn parse(text: &str) -> Option<Status> {
        Some(match text {
            "applying" => Status::Applying,
            "active" => Status::Active,
            "rolling_back" => Status::RollingBack,
            "rollback_failed" => Status::RollbackFailed,
            "uninstalling" => Status::Uninstalling,
            "rolled_back" => Status::RolledBack,
            "uninstalled" => Status::Uninstalled,
            _ => return None,
        })
    }

    /// A transaction stopped half-way that `resume` must finish before anything else.
    pub fn is_interrupted(self) -> bool {
        matches!(self, Status::Applying | Status::RollingBack | Status::RollbackFailed | Status::Uninstalling)
    }
}

/// A checkpoint's `phase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Prepared,
    Applying,
    Applied,
    Verified,
    RollbackInProgress,
    RolledBack,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Prepared => "prepared",
            Phase::Applying => "applying",
            Phase::Applied => "applied",
            Phase::Verified => "verified",
            Phase::RollbackInProgress => "rollback_in_progress",
            Phase::RolledBack => "rolled_back",
        }
    }

    pub fn parse(text: &str) -> Option<Phase> {
        Some(match text {
            "prepared" => Phase::Prepared,
            "applying" => Phase::Applying,
            "applied" => Phase::Applied,
            "verified" => Phase::Verified,
            "rollback_in_progress" => Phase::RollbackInProgress,
            "rolled_back" => Phase::RolledBack,
            _ => return None,
        })
    }

    /// Phases whose ownership is in the derived journal (`_ownership_for`).
    pub fn owns(self, include_in_progress: bool) -> bool {
        matches!(self, Phase::Applied | Phase::Verified) || (include_in_progress && self == Phase::RollbackInProgress)
    }
}

/// Where a rollback ends (`rollback_target`, and the `rollback_target=` of an adapter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RollbackTarget {
    RolledBack,
    Uninstalled,
}

impl RollbackTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            RollbackTarget::RolledBack => "rolled_back",
            RollbackTarget::Uninstalled => "uninstalled",
        }
    }

    pub fn parse(text: &str) -> Option<RollbackTarget> {
        match text {
            "rolled_back" => Some(RollbackTarget::RolledBack),
            "uninstalled" => Some(RollbackTarget::Uninstalled),
            _ => None,
        }
    }

    /// The final status of a rollback to this target.
    pub fn status(self) -> Status {
        match self {
            RollbackTarget::RolledBack => Status::RolledBack,
            RollbackTarget::Uninstalled => Status::Uninstalled,
        }
    }
}

/// One owned host path: what the installer proved it wrote (`_capture_ownership`).
///
/// `mutable` is absent in entries the runtime-v2 import wrote and is kept absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipEntry {
    pub action_id: String,
    pub adapter: String,
    /// `file` or `symlink`.
    pub kind: String,
    pub mutable: Option<bool>,
    pub preserve: bool,
    pub sha256: String,
}

impl OwnershipEntry {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("action_id".into(), Value::String(self.action_id.clone()));
        map.insert("adapter".into(), Value::String(self.adapter.clone()));
        map.insert("kind".into(), Value::String(self.kind.clone()));
        if let Some(mutable) = self.mutable {
            map.insert("mutable".into(), Value::Bool(mutable));
        }
        map.insert("preserve".into(), Value::Bool(self.preserve));
        map.insert("sha256".into(), Value::String(self.sha256.clone()));
        Value::Object(map)
    }

    /// Exactly `{action_id, adapter, kind, mutable?, preserve, sha256}` with their types.
    pub fn from_value(value: &Value) -> Option<OwnershipEntry> {
        let map = value.as_object()?;
        const REQUIRED: [&str; 5] = ["action_id", "adapter", "kind", "preserve", "sha256"];
        if REQUIRED.iter().any(|key| !map.contains_key(*key))
            || map.keys().any(|key| !REQUIRED.contains(&key.as_str()) && key != "mutable")
        {
            return None;
        }
        let text = |key: &str| map[key].as_str().map(str::to_owned);
        Some(OwnershipEntry {
            action_id: text("action_id")?,
            adapter: text("adapter")?,
            kind: text("kind")?,
            mutable: match map.get("mutable") {
                None => None,
                Some(value) => Some(value.as_bool()?),
            },
            preserve: map["preserve"].as_bool()?,
            sha256: text("sha256")?,
        })
    }

    /// Whether only existence and kind are compared (`mutable is True`).
    pub fn is_mutable(&self) -> bool {
        self.mutable == Some(true)
    }
}

/// Owned host paths, key-sorted like every journal file.
pub type Ownership = BTreeMap<String, OwnershipEntry>;

/// `{path: entry}` as JSON.
pub fn ownership_to_value(ownership: &Ownership) -> Value {
    Value::Object(ownership.iter().map(|(path, entry)| (path.clone(), entry.to_value())).collect())
}

/// `{path: entry}` from JSON; `None` when it is not a map of valid entries.
pub fn ownership_from_value(value: &Value) -> Option<Ownership> {
    value.as_object()?.iter().map(|(path, entry)| Some((path.clone(), OwnershipEntry::from_value(entry)?))).collect()
}

/// Durable progress of one action (`TransactionCheckpoint`).
#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    pub action_id: String,
    pub adapter: String,
    pub phase: Phase,
    pub data: CheckpointData,
    pub ownership: Ownership,
    pub evidence: Option<Map<String, Value>>,
    pub rollback_evidence: Option<Map<String, Value>>,
}

impl Checkpoint {
    /// A new checkpoint without ownership or evidence.
    pub fn new(action_id: &str, adapter: &str, phase: Phase, data: CheckpointData) -> Checkpoint {
        Checkpoint {
            action_id: action_id.into(),
            adapter: adapter.into(),
            phase,
            data,
            ownership: Ownership::new(),
            evidence: None,
            rollback_evidence: None,
        }
    }

    /// `__post_init__`: `checkpoint identity is invalid` for an empty action or adapter.
    pub fn validate(&self) -> Result<(), TxError> {
        if self.action_id.is_empty() || self.adapter.is_empty() {
            return Err(invalid("checkpoint identity is invalid"));
        }
        Ok(())
    }

    /// `to_dict()`.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("action_id".into(), Value::String(self.action_id.clone()));
        map.insert("adapter".into(), Value::String(self.adapter.clone()));
        map.insert("data".into(), Value::Object(self.data.clone()));
        map.insert("ownership".into(), ownership_to_value(&self.ownership));
        map.insert("phase".into(), Value::String(self.phase.as_str().into()));
        if let Some(evidence) = &self.evidence {
            map.insert("evidence".into(), Value::Object(evidence.clone()));
        }
        if let Some(evidence) = &self.rollback_evidence {
            map.insert("rollback_evidence".into(), Value::Object(evidence.clone()));
        }
        Value::Object(map)
    }

    /// `from_dict()`: required `{action_id, adapter, data, ownership, phase}`, optional
    /// `{evidence, rollback_evidence}` (`null` = absent), nothing else.
    pub fn from_value(value: &Value) -> Result<Checkpoint, TxError> {
        let map = value.as_object().ok_or_else(|| invalid("checkpoint is invalid"))?;
        const REQUIRED: [&str; 5] = ["action_id", "adapter", "data", "ownership", "phase"];
        if REQUIRED.iter().any(|key| !map.contains_key(*key))
            || map
                .keys()
                .any(|key| !REQUIRED.contains(&key.as_str()) && key != "evidence" && key != "rollback_evidence")
        {
            return Err(invalid("checkpoint is invalid"));
        }
        let text = |key: &str| map[key].as_str().map(str::to_owned).ok_or_else(|| invalid("checkpoint is invalid"));
        let action_id = text("action_id")?;
        let adapter = text("adapter")?;
        if action_id.is_empty() || adapter.is_empty() {
            return Err(invalid("checkpoint identity is invalid"));
        }
        let phase =
            map["phase"].as_str().and_then(Phase::parse).ok_or_else(|| invalid("checkpoint phase is invalid"))?;
        let evidence = |key: &str| match map.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Object(record)) => Ok(Some(record.clone())),
            Some(_) => Err(invalid("checkpoint is invalid")),
        };
        Ok(Checkpoint {
            action_id,
            adapter,
            phase,
            data: map["data"].as_object().cloned().ok_or_else(|| invalid("checkpoint is invalid"))?,
            ownership: ownership_from_value(&map["ownership"]).ok_or_else(|| invalid("checkpoint is invalid"))?,
            evidence: evidence("evidence")?,
            rollback_evidence: evidence("rollback_evidence")?,
        })
    }
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The authoritative journal (`TransactionState`).
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionState {
    pub transaction_id: String,
    pub status: Status,
    pub plan_digest: String,
    pub accepted_digest: String,
    pub checkpoints: Vec<Checkpoint>,
    pub purge_data: Option<bool>,
    pub rollback_target: Option<RollbackTarget>,
    pub origin: String,
    /// The Python class name of the failure (`type(exc).__name__`).
    pub error: Option<String>,
    /// The runtime-v2 manifest of an imported legacy installation (empty otherwise).
    pub legacy: Map<String, Value>,
    pub schema: i64,
}

impl TransactionState {
    /// A fresh installer transaction for an approved plan digest.
    pub fn new(transaction_id: &str, status: Status, plan_digest: &str) -> TransactionState {
        TransactionState {
            transaction_id: transaction_id.into(),
            status,
            plan_digest: plan_digest.into(),
            accepted_digest: plan_digest.into(),
            checkpoints: Vec::new(),
            purge_data: None,
            rollback_target: None,
            origin: ORIGIN_INSTALLER.into(),
            error: None,
            legacy: Map::new(),
            schema: TRANSACTION_SCHEMA,
        }
    }

    /// `__post_init__`, in Python's order.
    pub fn validate(&self) -> Result<(), TxError> {
        if self.schema != TRANSACTION_SCHEMA {
            return Err(invalid("transaction schema is invalid"));
        }
        if !is_hex(&self.transaction_id, 32) {
            return Err(invalid("transaction identity is invalid"));
        }
        if !is_hex(&self.plan_digest, 64) || self.accepted_digest != self.plan_digest {
            return Err(invalid("transaction plan digest is invalid"));
        }
        for checkpoint in &self.checkpoints {
            checkpoint.validate()?;
        }
        let mut seen = std::collections::BTreeSet::new();
        if !self.checkpoints.iter().all(|checkpoint| seen.insert(checkpoint.action_id.as_str())) {
            return Err(invalid("transaction checkpoint actions are duplicated"));
        }
        if self.origin.is_empty() {
            return Err(invalid("transaction origin is invalid"));
        }
        Ok(())
    }

    /// `to_dict()`.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("accepted_digest".into(), Value::String(self.accepted_digest.clone()));
        map.insert("checkpoints".into(), Value::Array(self.checkpoints.iter().map(Checkpoint::to_value).collect()));
        map.insert("origin".into(), Value::String(self.origin.clone()));
        map.insert("plan_digest".into(), Value::String(self.plan_digest.clone()));
        map.insert("schema".into(), Value::from(self.schema));
        map.insert("status".into(), Value::String(self.status.as_str().into()));
        map.insert("transaction_id".into(), Value::String(self.transaction_id.clone()));
        if let Some(error) = &self.error {
            map.insert("error".into(), Value::String(error.clone()));
        }
        if !self.legacy.is_empty() {
            map.insert("legacy".into(), Value::Object(self.legacy.clone()));
        }
        if let Some(purge) = self.purge_data {
            map.insert("purge_data".into(), Value::Bool(purge));
        }
        if let Some(target) = self.rollback_target {
            map.insert("rollback_target".into(), Value::String(target.as_str().into()));
        }
        Value::Object(map)
    }

    /// `from_dict()`: the strict reader. Checkpoints are read first (their errors win), then the
    /// state's own checks in `__post_init__` order. A key of a newer journal schema is refused
    /// (`transaction state is invalid`), so an older binary never rewrites what it cannot read.
    pub fn from_value(value: &Value) -> Result<TransactionState, TxError> {
        let state_invalid = || invalid("transaction state is invalid");
        let map = value.as_object().ok_or_else(state_invalid)?;
        const REQUIRED: [&str; 7] =
            ["accepted_digest", "checkpoints", "origin", "plan_digest", "schema", "status", "transaction_id"];
        const OPTIONAL: [&str; 4] = ["error", "legacy", "purge_data", "rollback_target"];
        if REQUIRED.iter().any(|key| !map.contains_key(*key))
            || map.keys().any(|key| !REQUIRED.contains(&key.as_str()) && !OPTIONAL.contains(&key.as_str()))
        {
            return Err(state_invalid());
        }
        let raw_checkpoints =
            map["checkpoints"].as_array().ok_or_else(|| invalid("transaction checkpoints are invalid"))?;
        let checkpoints = raw_checkpoints.iter().map(Checkpoint::from_value).collect::<Result<Vec<_>, _>>()?;
        let schema = match &map["schema"] {
            Value::Number(number) => number.as_i64().ok_or_else(|| invalid("transaction schema is invalid"))?,
            _ => return Err(invalid("transaction schema is invalid")),
        };
        if schema != TRANSACTION_SCHEMA {
            return Err(invalid("transaction schema is invalid"));
        }
        let text = |key: &str| map[key].as_str().map(str::to_owned);
        let transaction_id = text("transaction_id").ok_or_else(state_invalid)?;
        if !is_hex(&transaction_id, 32) {
            return Err(invalid("transaction identity is invalid"));
        }
        let status =
            map["status"].as_str().and_then(Status::parse).ok_or_else(|| invalid("transaction status is invalid"))?;
        let plan_digest = text("plan_digest").ok_or_else(|| invalid("transaction plan digest is invalid"))?;
        let accepted_digest = text("accepted_digest").ok_or_else(|| invalid("transaction plan digest is invalid"))?;
        if !is_hex(&plan_digest, 64) || accepted_digest != plan_digest {
            return Err(invalid("transaction plan digest is invalid"));
        }
        let mut seen = std::collections::BTreeSet::new();
        if !checkpoints.iter().all(|checkpoint| seen.insert(checkpoint.action_id.as_str())) {
            return Err(invalid("transaction checkpoint actions are duplicated"));
        }
        let purge_data = match map.get("purge_data") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(value)) => Some(*value),
            Some(_) => return Err(invalid("transaction data policy is invalid")),
        };
        let rollback_target = match map.get("rollback_target") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(RollbackTarget::parse)
                    .ok_or_else(|| invalid("transaction rollback target is invalid"))?,
            ),
        };
        let origin = text("origin").ok_or_else(|| invalid("transaction origin is invalid"))?;
        let error = match map.get("error") {
            None | Some(Value::Null) => None,
            Some(Value::String(error)) => Some(error.clone()),
            Some(_) => return Err(state_invalid()),
        };
        let legacy = match map.get("legacy") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(legacy)) => legacy.clone(),
            Some(_) => return Err(state_invalid()),
        };
        let state = TransactionState {
            transaction_id,
            status,
            plan_digest,
            accepted_digest,
            checkpoints,
            purge_data,
            rollback_target,
            origin,
            error,
            legacy,
            schema,
        };
        state.validate()?;
        Ok(state)
    }

    /// `_with_checkpoint`: replace the checkpoint of the same action, or append it.
    pub fn with_checkpoint(&mut self, replacement: Checkpoint) {
        match self.checkpoints.iter_mut().find(|item| item.action_id == replacement.action_id) {
            Some(slot) => *slot = replacement,
            None => self.checkpoints.push(replacement),
        }
    }

    /// The checkpoint of `action_id`.
    pub fn checkpoint(&self, action_id: &str) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|item| item.action_id == action_id)
    }

    /// `_ownership_for`: the union of the ownership of checkpoints that own their paths
    /// (`applied`, `verified`, and `rollback_in_progress` when `include_in_progress`).
    pub fn ownership(&self, include_in_progress: bool) -> Result<Ownership, TxError> {
        let mut ownership = Ownership::new();
        for checkpoint in &self.checkpoints {
            if checkpoint.phase.owns(include_in_progress) {
                for (path, entry) in &checkpoint.ownership {
                    if ownership.insert(path.clone(), entry.clone()).is_some() {
                        return Err(crate::error::ownership("ownership journal contains duplicate paths"));
                    }
                }
            }
        }
        Ok(ownership)
    }

    /// The engine's `report.json` (`_persist`): phases and evidence, never data or ownership.
    pub fn report_value(&self) -> Value {
        let record = |evidence: &Option<Map<String, Value>>| evidence.clone().map(Value::Object).unwrap_or(Value::Null);
        let checkpoints = self
            .checkpoints
            .iter()
            .map(|checkpoint| {
                let mut map = Map::new();
                map.insert("action_id".into(), Value::String(checkpoint.action_id.clone()));
                map.insert("evidence".into(), record(&checkpoint.evidence));
                map.insert("phase".into(), Value::String(checkpoint.phase.as_str().into()));
                map.insert("rollback_evidence".into(), record(&checkpoint.rollback_evidence));
                Value::Object(map)
            })
            .collect();
        let mut map = Map::new();
        map.insert("checkpoints".into(), Value::Array(checkpoints));
        map.insert("error".into(), self.error.clone().map(Value::String).unwrap_or(Value::Null));
        map.insert("plan_digest".into(), Value::String(self.plan_digest.clone()));
        map.insert("schema".into(), Value::from(TRANSACTION_SCHEMA));
        map.insert("status".into(), Value::String(self.status.as_str().into()));
        map.insert("transaction_id".into(), Value::String(self.transaction_id.clone()));
        Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn state_json() -> Value {
        json!({
            "accepted_digest": "a".repeat(64),
            "checkpoints": [{
                "action_id": "core.runtime", "adapter": "core", "data": {"ownership": {}},
                "ownership": {"/x": {"action_id": "core.runtime", "adapter": "core", "kind": "file",
                                     "preserve": false, "sha256": "b".repeat(64)}},
                "phase": "verified",
                "evidence": {"action_id": "core.runtime", "details": {}, "observations": [], "success": true}
            }],
            "origin": "runtime-v2",
            "plan_digest": "a".repeat(64),
            "schema": 1,
            "status": "active",
            "transaction_id": "0".repeat(32),
            "legacy": {"schema": 2}
        })
    }

    #[test]
    fn round_trip_keeps_absent_optional_keys_absent() {
        let state = TransactionState::from_value(&state_json()).unwrap();
        assert_eq!(state.checkpoints[0].ownership["/x"].mutable, None);
        assert_eq!(state.to_value(), state_json());
    }

    type Mutation = Box<dyn Fn(&mut Value)>;

    #[test]
    fn strict_reader_messages() {
        let cases: Vec<(Mutation, &str)> = vec![
            (Box::new(|v| v["extra"] = json!(1)), "transaction state is invalid"),
            (
                Box::new(|v| v.as_object_mut().unwrap().remove("origin").map(|_| ()).unwrap()),
                "transaction state is invalid",
            ),
            (Box::new(|v| v["checkpoints"] = json!({})), "transaction checkpoints are invalid"),
            (Box::new(|v| v["checkpoints"][0]["extra"] = json!(1)), "checkpoint is invalid"),
            (Box::new(|v| v["checkpoints"][0]["adapter"] = json!("")), "checkpoint identity is invalid"),
            (Box::new(|v| v["checkpoints"][0]["phase"] = json!("done")), "checkpoint phase is invalid"),
            (Box::new(|v| v["checkpoints"][0]["ownership"]["/x"]["extra"] = json!(1)), "checkpoint is invalid"),
            (Box::new(|v| v["schema"] = json!(2)), "transaction schema is invalid"),
            (Box::new(|v| v["transaction_id"] = json!("X".repeat(32))), "transaction identity is invalid"),
            (Box::new(|v| v["status"] = json!("done")), "transaction status is invalid"),
            (Box::new(|v| v["accepted_digest"] = json!("c".repeat(64))), "transaction plan digest is invalid"),
            (Box::new(|v| v["purge_data"] = json!("yes")), "transaction data policy is invalid"),
            (Box::new(|v| v["rollback_target"] = json!("gone")), "transaction rollback target is invalid"),
            (Box::new(|v| v["origin"] = json!("")), "transaction origin is invalid"),
            (
                Box::new(|v| {
                    let first = v["checkpoints"][0].clone();
                    v["checkpoints"].as_array_mut().unwrap().push(first);
                }),
                "transaction checkpoint actions are duplicated",
            ),
        ];
        for (mutate, message) in cases {
            let mut value = state_json();
            mutate(&mut value);
            let err = TransactionState::from_value(&value).unwrap_err();
            assert_eq!(err.message(), message, "{value}");
            assert_eq!(err.python_class_name(), "TransactionError");
        }
    }

    #[test]
    fn null_optionals_read_as_absent() {
        let mut value = state_json();
        value["error"] = Value::Null;
        value["purge_data"] = Value::Null;
        value["checkpoints"][0]["rollback_evidence"] = Value::Null;
        let state = TransactionState::from_value(&value).unwrap();
        assert_eq!(state.to_value(), state_json());
    }

    #[test]
    fn ownership_union_refuses_duplicates() {
        let mut state = TransactionState::from_value(&state_json()).unwrap();
        let mut second = state.checkpoints[0].clone();
        second.action_id = "other".into();
        state.checkpoints.push(second);
        assert_eq!(state.ownership(true).unwrap_err().message(), "ownership journal contains duplicate paths");
        state.checkpoints[1].phase = Phase::Prepared;
        assert_eq!(state.ownership(true).unwrap().len(), 1);
    }
}
