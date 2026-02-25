use jb_core_exec::run_testcase_core;
use jb_diff::diff_results;
use jb_model::TestCase;
use jb_rust_shadow::run_testcase_rust;

pub fn reduce_divergence(case: &TestCase) -> TestCase {
    let mut best = case.clone();
    let reduced_id = format!("{}-reduced", case.id);
    let mut changed = true;

    while changed && best.tx_hex.len() > 2 {
        changed = false;
        let candidate_hex = best.tx_hex[..best.tx_hex.len() - 2].to_string();
        let mut candidate = best.clone();
        candidate.tx_hex = candidate_hex;
        candidate.id = reduced_id.clone();
        let core = run_testcase_core(&candidate);
        let rust = run_testcase_rust(&candidate);
        if diff_results(&candidate, &core, &rust).is_some() {
            best = candidate;
            changed = true;
        }
    }
    best.id = reduced_id;
    best
}
