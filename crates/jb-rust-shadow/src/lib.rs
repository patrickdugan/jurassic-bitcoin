use jb_model::TestCase;
use jb_model::ExecResult;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::env;

pub fn run_testcase_rust(tc: &TestCase) -> ExecResult {
    let is_txhex_template = tc
        .core_template
        .as_ref()
        .map(|t| t.kind == "testmempoolaccept_tx_hex" && t.spend_type == "p2wpkh")
        .unwrap_or(false);
    let is_decode_template = tc
        .core_template
        .as_ref()
        .map(|t| t.kind == "decode_tx_hex")
        .unwrap_or(false);

    if is_txhex_template {
        return run_txhex_p2wpkh_slice(tc);
    }
    if is_decode_template {
        return match parse_transaction(&tc.tx_hex) {
            Ok(_) => ExecResult::ok(),
            Err(_) => ExecResult::err("invalid tx encoding"),
        };
    }

    if tc.tx_hex.len() % 2 != 0 {
        return ExecResult::err("invalid tx encoding");
    }

    let mut result = ExecResult::ok();
    result
        .details
        .insert("validation".to_string(), "minimal-script-placeholder".to_string());
    result
}

fn run_txhex_p2wpkh_slice(tc: &TestCase) -> ExecResult {
    let tx = match parse_transaction(&tc.tx_hex) {
        Ok(v) => v,
        Err(_) => return ExecResult::err("invalid tx encoding"),
    };
    if tx.inputs.len() != 1 {
        return ExecResult::err("unsupported: exactly one input required");
    }
    let input = &tx.inputs[0];
    match env::var("JB_FUNDING_OUTPOINT") {
        Ok(target) => {
            if format!("{}:{}", input.prevout.txid_hex, input.prevout.vout) != target {
                return ExecResult::err("wrong prevout (not harness funding outpoint)");
            }
        }
        Err(_) => {}
    }

    let witness = match &input.witness {
        Some(w) if w.items.len() >= 2 => w,
        _ => return ExecResult::err("script failed: missing witness stack"),
    };
    let signature = witness.items[witness.items.len() - 2].clone();
    let pubkey = witness.items[witness.items.len() - 1].clone();
    let pubkey_hash = hash160(&pubkey);
    let script_code = build_p2wpkh_script_code(&pubkey_hash);

    let mut stack = vec![signature, pubkey];
    let checksig_true = tc
        .metadata
        .get("checksighook")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let exec = execute_script(&script_code, &mut stack, checksig_true);
    match exec {
        Ok(()) => {
            if stack_is_truthy(stack.last()) {
                let mut result = ExecResult::ok();
                result
                    .details
                    .insert("validation".to_string(), "script-slice-p2wpkh".to_string());
                result
                    .details
                    .insert("checksighook".to_string(), checksig_true.to_string());
                result
            } else {
                ExecResult::err("script failed: false top stack")
            }
        }
        Err(e) => {
            let mut result = ExecResult::err(format!("script failed: {}", e.reason));
            result
                .details
                .insert("script_trace".to_string(), format!("op={} depth={}", e.last_opcode, e.stack_depth));
            result
        }
    }
}

fn build_p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76);
    s.push(0xa9);
    s.push(0x14);
    s.extend_from_slice(pubkey_hash);
    s.push(0x88);
    s.push(0xac);
    s
}

fn stack_is_truthy(top: Option<&Vec<u8>>) -> bool {
    match top {
        None => false,
        Some(v) => v.iter().any(|b| *b != 0),
    }
}

#[derive(Debug)]
struct ScriptExecError {
    reason: String,
    last_opcode: String,
    stack_depth: usize,
}

fn execute_script(script: &[u8], stack: &mut Vec<Vec<u8>>, checksig_true: bool) -> Result<(), ScriptExecError> {
    let mut i = 0usize;
    let mut last_opcode: String;
    while i < script.len() {
        let opcode = script[i];
        i += 1;
        last_opcode = format!("0x{opcode:02x}");
        match opcode {
            0x00 => stack.push(Vec::new()),
            0x01..=0x4b => {
                let n = opcode as usize;
                if i + n > script.len() {
                    return Err(script_err("malformed pushdata length", &last_opcode, stack.len()));
                }
                stack.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4c => {
                if i + 1 > script.len() {
                    return Err(script_err("malformed pushdata1 header", &last_opcode, stack.len()));
                }
                let n = script[i] as usize;
                i += 1;
                if i + n > script.len() {
                    return Err(script_err("malformed pushdata1 length", &last_opcode, stack.len()));
                }
                stack.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4d => {
                if i + 2 > script.len() {
                    return Err(script_err("malformed pushdata2 header", &last_opcode, stack.len()));
                }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                if i + n > script.len() {
                    return Err(script_err("malformed pushdata2 length", &last_opcode, stack.len()));
                }
                stack.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4e => {
                if i + 4 > script.len() {
                    return Err(script_err("malformed pushdata4 header", &last_opcode, stack.len()));
                }
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
                i += 4;
                if i + n > script.len() {
                    return Err(script_err("malformed pushdata4 length", &last_opcode, stack.len()));
                }
                stack.push(script[i..i + n].to_vec());
                i += n;
            }
            0x51..=0x60 => {
                let n = opcode - 0x50;
                stack.push(vec![n]);
            }
            0x76 => {
                let top = stack
                    .last()
                    .cloned()
                    .ok_or_else(|| script_err("stack underflow on OP_DUP", &last_opcode, stack.len()))?;
                stack.push(top);
            }
            0xa9 => {
                let v = stack
                    .pop()
                    .ok_or_else(|| script_err("stack underflow on OP_HASH160", &last_opcode, stack.len()))?;
                stack.push(hash160(&v).to_vec());
            }
            0x88 => {
                let a = stack
                    .pop()
                    .ok_or_else(|| script_err("stack underflow on OP_EQUALVERIFY", &last_opcode, stack.len()))?;
                let b = stack
                    .pop()
                    .ok_or_else(|| script_err("stack underflow on OP_EQUALVERIFY", &last_opcode, stack.len()))?;
                if a != b {
                    return Err(script_err("equalverify mismatch", &last_opcode, stack.len()));
                }
            }
            0xac => {
                let _pubkey = stack
                    .pop()
                    .ok_or_else(|| script_err("stack underflow on OP_CHECKSIG", &last_opcode, stack.len()))?;
                let _sig = stack
                    .pop()
                    .ok_or_else(|| script_err("stack underflow on OP_CHECKSIG", &last_opcode, stack.len()))?;
                if checksig_true {
                    stack.push(vec![1]);
                } else {
                    return Err(script_err("checksighook-false", &last_opcode, stack.len()));
                }
            }
            _ => return Err(script_err("unsupported opcode", &last_opcode, stack.len())),
        }
    }
    Ok(())
}

fn script_err(reason: &str, last_opcode: &str, stack_depth: usize) -> ScriptExecError {
    ScriptExecError {
        reason: reason.to_string(),
        last_opcode: last_opcode.to_string(),
        stack_depth,
    }
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

#[derive(Debug, Clone)]
struct Transaction {
    inputs: Vec<TxIn>,
}

#[derive(Debug, Clone)]
struct TxIn {
    prevout: Prevout,
    witness: Option<Witness>,
}

#[derive(Debug, Clone)]
struct Prevout {
    txid_hex: String,
    vout: u32,
}

#[derive(Debug, Clone)]
struct Witness {
    items: Vec<Vec<u8>>,
}

fn parse_transaction(tx_hex: &str) -> Result<Transaction, ()> {
    let bytes = hex::decode(tx_hex).map_err(|_| ())?;
    if bytes.len() < 10 {
        return Err(());
    }
    let mut i = 0usize;
    i = advance(&bytes, i, 4)?; // version
    let has_witness = bytes.get(i) == Some(&0x00) && bytes.get(i + 1) == Some(&0x01);
    if has_witness {
        i = advance(&bytes, i, 2)?;
    }

    let vin_count = read_varint(&bytes, &mut i).ok_or(())? as usize;
    let mut inputs = Vec::with_capacity(vin_count);
    for _ in 0..vin_count {
        let txid_le = read_bytes(&bytes, &mut i, 32).ok_or(())?;
        let txid_hex: String = txid_le.iter().rev().map(|b| format!("{:02x}", b)).collect();
        let vout = read_u32_le(&bytes, &mut i).ok_or(())?;
        let script_len = read_varint(&bytes, &mut i).ok_or(())? as usize;
        i = advance(&bytes, i, script_len)?;
        i = advance(&bytes, i, 4)?; // sequence
        inputs.push(TxIn {
            prevout: Prevout { txid_hex, vout },
            witness: None,
        });
    }

    let vout_count = read_varint(&bytes, &mut i).ok_or(())? as usize;
    for _ in 0..vout_count {
        i = advance(&bytes, i, 8)?;
        let spk_len = read_varint(&bytes, &mut i).ok_or(())? as usize;
        i = advance(&bytes, i, spk_len)?;
    }

    if has_witness {
        for input in &mut inputs {
            let item_count = read_varint(&bytes, &mut i).ok_or(())? as usize;
            let mut items = Vec::with_capacity(item_count);
            for _ in 0..item_count {
                let n = read_varint(&bytes, &mut i).ok_or(())? as usize;
                let item = read_bytes(&bytes, &mut i, n).ok_or(())?.to_vec();
                items.push(item);
            }
            input.witness = Some(Witness { items });
        }
    }
    i = advance(&bytes, i, 4)?; // locktime
    if i != bytes.len() {
        return Err(());
    }

    Ok(Transaction { inputs })
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

#[cfg(test)]
mod tests {
    use super::{execute_script, hash160};

    #[test]
    fn pushdata_direct_success() {
        let mut stack = Vec::new();
        execute_script(&[0x02, 0xaa, 0xbb], &mut stack, true).expect("exec");
        assert_eq!(stack, vec![vec![0xaa, 0xbb]]);
    }

    #[test]
    fn pushdata_malformed_fails() {
        let mut stack = Vec::new();
        let err = execute_script(&[0x4c, 0x02, 0xaa], &mut stack, true).expect_err("must fail");
        assert!(err.reason.contains("malformed pushdata1"));
    }

    #[test]
    fn dup_hash160_equalverify_success() {
        let pubkey = vec![2u8; 33];
        let h = hash160(&pubkey);
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&h);
        script.push(0x88);
        let mut stack = vec![pubkey];
        execute_script(&script, &mut stack, true).expect("exec");
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn stack_underflow_detected() {
        let mut stack = Vec::new();
        let err = execute_script(&[0x76], &mut stack, true).expect_err("underflow");
        assert!(err.reason.contains("stack underflow"));
    }
}
