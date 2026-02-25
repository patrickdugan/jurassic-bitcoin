use anyhow::{Context, Result};
use chrono::Utc;
use jb_model::{DivergenceEvent, TestCase};
use std::fs;
use std::path::{Path, PathBuf};

pub fn load_corpus(dir: &Path) -> Result<Vec<TestCase>> {
    let mut cases = Vec::new();
    if !dir.exists() {
        return Ok(cases);
    }
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let case: TestCase = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing testcase {}", path.display()))?;
        cases.push(case);
    }
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(cases)
}

pub fn write_divergence_event(base_dir: &Path, event: &DivergenceEvent, case: &TestCase) -> Result<PathBuf> {
    let day = Utc::now().format("%Y-%m-%d").to_string();
    let out_dir = base_dir.join(day);
    fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    let event_path = out_dir.join(format!("{}-event.json", event.testcase_id));
    let case_path = out_dir.join(format!("{}-testcase.json", event.testcase_id));

    let mut stable_event = event.clone();
    stable_event.artifacts = vec![case_path.clone()];

    fs::write(&event_path, serde_json::to_vec_pretty(&stable_event)?)
        .with_context(|| format!("writing {}", event_path.display()))?;
    fs::write(&case_path, serde_json::to_vec_pretty(case)?)
        .with_context(|| format!("writing {}", case_path.display()))?;
    Ok(event_path)
}

#[cfg(test)]
mod tests {
    use super::{load_corpus, write_divergence_event};
    use chrono::Utc;
    use jb_model::{DivergenceEvent, ExecResult, OutPoint, TestCase, Utxo};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn sample_case() -> TestCase {
        TestCase {
            id: "tc-001".to_string(),
            description: "roundtrip".to_string(),
            network: "regtest".to_string(),
            utxo_set: vec![Utxo {
                outpoint: OutPoint {
                    txid: "00".repeat(32),
                    vout: 0,
                },
                amount_sats: 5_000_000_000,
                script_pubkey_hex: "51".to_string(),
                height: 101,
                coinbase: false,
            }],
            tx_hex: "00".to_string(),
            flags: vec!["MANDATORY_SCRIPT_VERIFY_FLAGS".to_string()],
            core_template: None,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn json_roundtrip_and_sorted_load() {
        let temp = std::env::temp_dir().join(format!("jb-corpus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("create temp dir");
        let mut a = sample_case();
        a.id = "b".to_string();
        let mut b = sample_case();
        b.id = "a".to_string();
        std::fs::write(temp.join("b.json"), serde_json::to_vec(&a).expect("serialize a")).expect("write b.json");
        std::fs::write(temp.join("a.json"), serde_json::to_vec(&b).expect("serialize b")).expect("write a.json");

        let loaded = load_corpus(&temp).expect("load corpus");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "a");
        assert_eq!(loaded[1].id, "b");
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn writes_event_artifacts() {
        let temp = std::env::temp_dir().join(format!("jb-artifacts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("create artifact dir");

        let case = sample_case();
        let event = DivergenceEvent {
            testcase_id: case.id.clone(),
            core: ExecResult::ok(),
            rust: ExecResult::err("mismatch"),
            diff_summary: "ok mismatch".to_string(),
            timestamp: Utc::now(),
            artifacts: vec![PathBuf::from("placeholder")],
        };
        let path = write_divergence_event(&temp, &event, &case).expect("write event");
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&temp);
    }
}
