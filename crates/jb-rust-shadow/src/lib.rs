use jb_model::{ExecResult, TestCase};

pub fn run_testcase_rust(tc: &TestCase) -> ExecResult {
    if tc.tx_hex.len() % 2 != 0 {
        return ExecResult::err("invalid tx hex length");
    }

    if tc.flags.iter().any(|f| f == "RUST_SHADOW_FAIL") {
        return ExecResult::err("rejected by shadow flag RUST_SHADOW_FAIL");
    }

    let mut result = ExecResult::ok();
    result
        .details
        .insert("validation".to_string(), "minimal-script-placeholder".to_string());
    result
}
