use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestCase {
    pub id: String,
    pub description: String,
    pub network: String,
    pub utxo_set: Vec<Utxo>,
    pub tx_hex: String,
    pub flags: Vec<String>,
    #[serde(default)]
    pub core_template: Option<CoreTemplate>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreTemplate {
    pub kind: String,
    pub spend_type: String,
    #[serde(default)]
    pub feerate_sats_vb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub amount_sats: u64,
    pub script_pubkey_hex: String,
    pub height: u32,
    pub coinbase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: String,
    pub vout: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecResult {
    pub ok: bool,
    pub reason: Option<String>,
    #[serde(default)]
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DivergenceEvent {
    pub testcase_id: String,
    pub core: ExecResult,
    pub rust: ExecResult,
    pub diff_summary: String,
    pub timestamp: DateTime<Utc>,
    pub artifacts: Vec<PathBuf>,
}

impl ExecResult {
    pub fn ok() -> Self {
        Self {
            ok: true,
            reason: None,
            details: BTreeMap::new(),
        }
    }

    pub fn err(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            reason: Some(reason.into()),
            details: BTreeMap::new(),
        }
    }
}
