use chrono::Utc;
use jb_model::{DivergenceEvent, ExecResult, TestCase};
use std::path::PathBuf;

pub fn diff_results(
    tc: &TestCase,
    core: &ExecResult,
    rust: &ExecResult,
) -> Option<DivergenceEvent> {
    if core.ok == rust.ok && core.reason == rust.reason {
        return None;
    }

    Some(DivergenceEvent {
        testcase_id: tc.id.clone(),
        core: core.clone(),
        rust: rust.clone(),
        core_allowed: core.ok,
        rust_ok: rust.ok,
        core_reason: core.reason.clone(),
        rust_reason: rust.reason.clone(),
        normalized_class: classify(core, rust),
        mutations_applied: Vec::new(),
        diff_summary: format!(
            "core(ok={}, reason={:?}) vs rust(ok={}, reason={:?})",
            core.ok, core.reason, rust.ok, rust.reason
        ),
        timestamp: Utc::now(),
        artifacts: vec![PathBuf::from("pending-write")],
    })
}

fn classify(core: &ExecResult, rust: &ExecResult) -> String {
    let core_reason = core.reason.as_deref().unwrap_or("");
    let rust_reason = rust.reason.as_deref().unwrap_or("");
    let both = format!("{core_reason} {rust_reason}").to_lowercase();
    if both.contains("invalid tx encoding") {
        "PARSE_FAIL".to_string()
    } else if both.contains("wrong prevout") {
        "PREVOUT_MISSING".to_string()
    } else if both.contains("script") || both.contains("checksighook") {
        "SCRIPT_FAIL".to_string()
    } else if both.contains("reject") || both.contains("policy") {
        "POLICY_FAIL".to_string()
    } else if both.contains("sig") {
        "SIG_FAIL".to_string()
    } else {
        "UNCLASSIFIED".to_string()
    }
}
