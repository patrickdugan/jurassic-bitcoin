use jb_model::{ExecResult, TestCase};
use std::env;

pub fn run_testcase_rust(tc: &TestCase) -> ExecResult {
    let is_txhex_template = tc
        .core_template
        .as_ref()
        .map(|t| t.kind == "testmempoolaccept_tx_hex")
        .unwrap_or(false);

    if is_txhex_template {
        return run_txhex_template(tc);
    }

    if tc.tx_hex.len() % 2 != 0 {
        return ExecResult::err("invalid tx encoding");
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

fn run_txhex_template(tc: &TestCase) -> ExecResult {
    let inputs = match parse_input_outpoints(&tc.tx_hex) {
        Ok(v) => v,
        Err(_) => return ExecResult::err("invalid tx encoding"),
    };

    let mut result = ExecResult::err("unsupported: script not implemented");
    result
        .details
        .insert("mode".to_string(), "txhex-gate".to_string());
    result
        .details
        .insert("planned_spend_type".to_string(), "p2wpkh".to_string());

    match env::var("JB_FUNDING_OUTPOINT") {
        Ok(target) => {
            if !contains_outpoint(&inputs, &target) {
                return ExecResult::err("wrong prevout (not harness funding outpoint)");
            }
            result
                .details
                .insert("funding_check".to_string(), "enforced-via-env".to_string());
        }
        Err(_) => {
            result.details.insert(
                "warning".to_string(),
                "JB_FUNDING_OUTPOINT not set; prevout not enforced".to_string(),
            );
        }
    }
    result
}

#[derive(Debug, Clone)]
struct TxInputOutpoint {
    txid: String,
    vout: u32,
}

fn contains_outpoint(inputs: &[TxInputOutpoint], target: &str) -> bool {
    inputs
        .iter()
        .any(|i| format!("{}:{}", i.txid, i.vout) == target)
}

fn parse_input_outpoints(tx_hex: &str) -> Result<Vec<TxInputOutpoint>, ()> {
    let tx = hex::decode(tx_hex).map_err(|_| ())?;
    if tx.len() < 10 {
        return Err(());
    }
    let mut i = 0usize;
    i = advance(&tx, i, 4)?;
    let has_witness = tx.get(i) == Some(&0x00) && tx.get(i + 1) == Some(&0x01);
    if has_witness {
        i = advance(&tx, i, 2)?;
    }

    let vin_count = read_varint(&tx, &mut i).ok_or(())?;
    let mut outpoints = Vec::with_capacity(vin_count as usize);
    for _ in 0..vin_count {
        let txid_le = read_bytes(&tx, &mut i, 32).ok_or(())?;
        let txid = txid_le.iter().rev().map(|b| format!("{:02x}", b)).collect();
        let vout = read_u32_le(&tx, &mut i).ok_or(())?;
        outpoints.push(TxInputOutpoint { txid, vout });
        let script_len = read_varint(&tx, &mut i).ok_or(())?;
        i = advance(&tx, i, script_len as usize)?;
        i = advance(&tx, i, 4)?;
    }

    let vout_count = read_varint(&tx, &mut i).ok_or(())?;
    for _ in 0..vout_count {
        i = advance(&tx, i, 8)?;
        let spk_len = read_varint(&tx, &mut i).ok_or(())?;
        i = advance(&tx, i, spk_len as usize)?;
    }
    if has_witness {
        for _ in 0..vin_count {
            let item_count = read_varint(&tx, &mut i).ok_or(())?;
            for _ in 0..item_count {
                let item_len = read_varint(&tx, &mut i).ok_or(())?;
                i = advance(&tx, i, item_len as usize)?;
            }
        }
    }
    i = advance(&tx, i, 4)?;
    if i != tx.len() {
        return Err(());
    }
    Ok(outpoints)
}

fn advance(bytes: &[u8], idx: usize, n: usize) -> Result<usize, ()> {
    let next = idx.saturating_add(n);
    if next > bytes.len() {
        return Err(());
    }
    Ok(next)
}

fn read_bytes<'a>(bytes: &'a [u8], idx: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = idx.checked_add(n)?;
    if end > bytes.len() {
        return None;
    }
    let out = &bytes[*idx..end];
    *idx = end;
    Some(out)
}

fn read_u16_le(bytes: &[u8], idx: &mut usize) -> Option<u16> {
    let raw = read_bytes(bytes, idx, 2)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32_le(bytes: &[u8], idx: &mut usize) -> Option<u32> {
    let raw = read_bytes(bytes, idx, 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64_le(bytes: &[u8], idx: &mut usize) -> Option<u64> {
    let raw = read_bytes(bytes, idx, 8)?;
    Some(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn read_varint(bytes: &[u8], idx: &mut usize) -> Option<u64> {
    let first = *read_bytes(bytes, idx, 1)?.first()?;
    match first {
        0x00..=0xfc => Some(first as u64),
        0xfd => Some(read_u16_le(bytes, idx)? as u64),
        0xfe => Some(read_u32_le(bytes, idx)? as u64),
        _ => read_u64_le(bytes, idx),
    }
}
