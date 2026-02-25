use anyhow::{Context, Result};
use jb_model::TestCase;
use std::fs;
use std::path::Path;

pub fn load_tx_hex(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(raw.trim().to_string())
}

pub fn into_testcase(mut tc: TestCase, tx_hex: String) -> TestCase {
    tc.tx_hex = tx_hex;
    tc
}
