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
        diff_summary: format!(
            "core(ok={}, reason={:?}) vs rust(ok={}, reason={:?})",
            core.ok, core.reason, rust.ok, rust.reason
        ),
        timestamp: Utc::now(),
        artifacts: vec![PathBuf::from("pending-write")],
    })
}
