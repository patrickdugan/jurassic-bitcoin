use jb_model::ExecResult;
use jb_model::TestCase;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::env;

const BIP16_ENFORCEMENT_HEIGHT: u32 = 173_805;

pub fn run_testcase_rust(tc: &TestCase) -> ExecResult {
    let template = tc.core_template.as_ref();
    let is_txhex_template = template
        .map(|t| t.kind == "testmempoolaccept_tx_hex")
        .unwrap_or(false);
    let is_decode_template = template.map(|t| t.kind == "decode_tx_hex").unwrap_or(false);

    if is_txhex_template {
        let spend_type = template.map(|t| t.spend_type.as_str()).unwrap_or("");
        return match spend_type {
            "p2wpkh" => run_txhex_p2wpkh_slice(tc),
            "p2sh" => run_txhex_p2sh_slice(tc),
            other => ExecResult::err(format!("unsupported spend_type in rust_shadow: {other}")),
        };
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
    result.details.insert(
        "validation".to_string(),
        "minimal-script-placeholder".to_string(),
    );
    result
}

fn run_txhex_p2sh_slice(tc: &TestCase) -> ExecResult {
    let tx = match parse_transaction(&tc.tx_hex) {
        Ok(v) => v,
        Err(_) => return ExecResult::err("invalid tx encoding"),
    };
    if tx.inputs.len() != 1 {
        return ExecResult::err("unsupported: exactly one input required");
    }

    let input = &tx.inputs[0];
    let script_pubkey = match resolve_script_pubkey(tc, &tx) {
        Some(v) => v,
        None => return ExecResult::err("missing script_pubkey for p2sh evaluation"),
    };

    let mut trace = Vec::new();
    let checksig_true = tc
        .metadata
        .get("checksighook")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let p2sh_detected = is_p2sh_scriptpubkey(&script_pubkey);
    let bip16_enforced = tc
        .context
        .as_ref()
        .map(|c| c.height >= BIP16_ENFORCEMENT_HEIGHT)
        .unwrap_or(false);

    let mut stack = Vec::new();
    if let Err(e) = execute_script(
        &input.script_sig,
        &mut stack,
        checksig_true,
        ScriptPhase::ScriptSig,
        &mut trace,
    ) {
        return script_error_result(
            &e,
            ScriptPhase::ScriptSig,
            &trace,
            p2sh_detected,
            bip16_enforced,
        );
    }

    let scriptsig_stack = stack.clone();

    if let Err(e) = execute_script(
        &script_pubkey,
        &mut stack,
        checksig_true,
        ScriptPhase::ScriptPubKey,
        &mut trace,
    ) {
        return script_error_result(
            &e,
            ScriptPhase::ScriptPubKey,
            &trace,
            p2sh_detected,
            bip16_enforced,
        );
    }
    if !stack_is_truthy(stack.last()) {
        return reason_result(
            "script failed: false top stack",
            ScriptPhase::ScriptPubKey,
            &trace,
            p2sh_detected,
            bip16_enforced,
            false,
        );
    }

    if p2sh_detected && bip16_enforced {
        let pushes = match decode_push_only_script(&input.script_sig) {
            Ok(p) if !p.is_empty() => p,
            _ => {
                return reason_result(
                    "p2sh missing redeemscript",
                    ScriptPhase::RedeemScript,
                    &trace,
                    p2sh_detected,
                    bip16_enforced,
                    false,
                );
            }
        };

        let redeem_script = match pushes.last() {
            Some(v) => v.clone(),
            None => {
                return reason_result(
                    "p2sh missing redeemscript",
                    ScriptPhase::RedeemScript,
                    &trace,
                    p2sh_detected,
                    bip16_enforced,
                    false,
                );
            }
        };

        let mut redeem_stack = scriptsig_stack;
        if redeem_stack.pop().is_none() {
            return reason_result(
                "p2sh missing redeemscript",
                ScriptPhase::RedeemScript,
                &trace,
                p2sh_detected,
                bip16_enforced,
                false,
            );
        }

        if let Err(e) = execute_script(
            &redeem_script,
            &mut redeem_stack,
            checksig_true,
            ScriptPhase::RedeemScript,
            &mut trace,
        ) {
            return script_error_result(
                &e,
                ScriptPhase::RedeemScript,
                &trace,
                p2sh_detected,
                bip16_enforced,
            );
        }

        if !stack_is_truthy(redeem_stack.last()) {
            return reason_result(
                "script failed: false top stack",
                ScriptPhase::RedeemScript,
                &trace,
                p2sh_detected,
                bip16_enforced,
                false,
            );
        }

        return reason_result(
            "",
            ScriptPhase::RedeemScript,
            &trace,
            p2sh_detected,
            bip16_enforced,
            true,
        );
    }

    reason_result(
        "",
        ScriptPhase::ScriptPubKey,
        &trace,
        p2sh_detected,
        bip16_enforced,
        true,
    )
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
        Some(w) => w,
        None => return ExecResult::err("witness invalid stack"),
    };
    if witness.items.len() != 2 {
        let mut r = ExecResult::err("witness invalid stack");
        r.details.insert("segwit".to_string(), "true".to_string());
        r.details
            .insert("witness_items".to_string(), witness.items.len().to_string());
        r.details
            .insert("script_phase".to_string(), "witness".to_string());
        return r;
    }
    let program = match resolve_p2wpkh_program(tc) {
        Some(p) => p,
        None => return ExecResult::err("missing p2wpkh witness program"),
    };
    let signature = witness.items[0].clone();
    let pubkey = witness.items[1].clone();
    let pubkey_hash = hash160(&pubkey);
    if pubkey_hash != program {
        let mut r = ExecResult::err("witness program mismatch");
        r.details.insert("segwit".to_string(), "true".to_string());
        r.details
            .insert("witness_items".to_string(), "2".to_string());
        r.details
            .insert("script_phase".to_string(), "witness".to_string());
        return r;
    }
    let script_code = build_p2wpkh_script_code(&program);

    let mut stack = vec![signature, pubkey];
    let checksig_true = tc
        .metadata
        .get("checksighook")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut trace = Vec::new();

    let exec = execute_script(
        &script_code,
        &mut stack,
        checksig_true,
        ScriptPhase::ScriptPubKey,
        &mut trace,
    );
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
                    .details
                    .insert("segwit".to_string(), "true".to_string());
                result
                    .details
                    .insert("witness_items".to_string(), "2".to_string());
                result
                    .details
                    .insert("script_phase".to_string(), "witness".to_string());
                result.details.insert(
                    "script_trace".to_string(),
                    trace
                        .last()
                        .cloned()
                        .unwrap_or_else(|| "<none>".to_string()),
                );
                result
            } else {
                ExecResult::err("script failed: false top stack")
            }
        }
        Err(e) => {
            let mut result = ExecResult::err(format!("script failed: {}", e.reason));
            result.details.insert(
                "script_phase".to_string(),
                ScriptPhase::ScriptPubKey.as_str().to_string(),
            );
            result
                .details
                .insert("script_trace".to_string(), trace.join("|"));
            result
        }
    }
}

fn resolve_p2wpkh_program(tc: &TestCase) -> Option<[u8; 20]> {
    let spk_hex = tc.metadata.get("script_pubkey_hex")?;
    let spk = hex::decode(spk_hex).ok()?;
    if spk.len() != 22 || spk[0] != 0x00 || spk[1] != 0x14 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&spk[2..22]);
    Some(out)
}

fn resolve_script_pubkey(tc: &TestCase, tx: &Transaction) -> Option<Vec<u8>> {
    if let Some(spk_hex) = tc.metadata.get("script_pubkey_hex") {
        if let Ok(v) = hex::decode(spk_hex) {
            return Some(v);
        }
    }
    tx.outputs.first().map(|o| o.script_pubkey.clone())
}

fn is_p2sh_scriptpubkey(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

fn decode_push_only_script(script: &[u8]) -> Result<Vec<Vec<u8>>, ScriptExecError> {
    let mut i = 0usize;
    let mut out = Vec::new();
    while i < script.len() {
        let opcode = script[i];
        i += 1;
        match opcode {
            0x00 => out.push(Vec::new()),
            0x01..=0x4b => {
                let n = opcode as usize;
                if i + n > script.len() {
                    return Err(script_err("malformed pushdata length", "0x00", 0));
                }
                out.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4c => {
                if i + 1 > script.len() {
                    return Err(script_err("malformed pushdata1 header", "0x4c", 0));
                }
                let n = script[i] as usize;
                i += 1;
                if i + n > script.len() {
                    return Err(script_err("malformed pushdata1 length", "0x4c", 0));
                }
                out.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4d => {
                if i + 2 > script.len() {
                    return Err(script_err("malformed pushdata2 header", "0x4d", 0));
                }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                if i + n > script.len() {
                    return Err(script_err("malformed pushdata2 length", "0x4d", 0));
                }
                out.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4e => {
                if i + 4 > script.len() {
                    return Err(script_err("malformed pushdata4 header", "0x4e", 0));
                }
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                    as usize;
                i += 4;
                if i + n > script.len() {
                    return Err(script_err("malformed pushdata4 length", "0x4e", 0));
                }
                out.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4f => out.push(vec![0x81]),
            0x51..=0x60 => out.push(vec![opcode - 0x50]),
            _ => return Err(script_err("non-push opcode in scriptsig", "0xff", 0)),
        }
    }
    Ok(out)
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

#[derive(Debug, Clone, Copy)]
enum ScriptPhase {
    ScriptSig,
    ScriptPubKey,
    RedeemScript,
}

impl ScriptPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::ScriptSig => "scriptsig",
            Self::ScriptPubKey => "scriptpubkey",
            Self::RedeemScript => "redeemscript",
        }
    }
}

#[derive(Debug)]
struct ScriptExecError {
    reason: String,
    last_opcode: String,
    stack_depth: usize,
}

fn execute_script(
    script: &[u8],
    stack: &mut Vec<Vec<u8>>,
    checksig_true: bool,
    phase: ScriptPhase,
    trace: &mut Vec<String>,
) -> Result<(), ScriptExecError> {
    let mut i = 0usize;
    let mut last_opcode: String;
    while i < script.len() {
        let opcode = script[i];
        i += 1;
        last_opcode = format!("0x{opcode:02x}");
        trace.push(format!(
            "{}:{}:d{}",
            phase.as_str(),
            last_opcode,
            stack.len()
        ));
        match opcode {
            0x00 => stack.push(Vec::new()),
            0x01..=0x4b => {
                let n = opcode as usize;
                if i + n > script.len() {
                    return Err(script_err(
                        "malformed pushdata length",
                        &last_opcode,
                        stack.len(),
                    ));
                }
                stack.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4c => {
                if i + 1 > script.len() {
                    return Err(script_err(
                        "malformed pushdata1 header",
                        &last_opcode,
                        stack.len(),
                    ));
                }
                let n = script[i] as usize;
                i += 1;
                if i + n > script.len() {
                    return Err(script_err(
                        "malformed pushdata1 length",
                        &last_opcode,
                        stack.len(),
                    ));
                }
                stack.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4d => {
                if i + 2 > script.len() {
                    return Err(script_err(
                        "malformed pushdata2 header",
                        &last_opcode,
                        stack.len(),
                    ));
                }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                if i + n > script.len() {
                    return Err(script_err(
                        "malformed pushdata2 length",
                        &last_opcode,
                        stack.len(),
                    ));
                }
                stack.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4e => {
                if i + 4 > script.len() {
                    return Err(script_err(
                        "malformed pushdata4 header",
                        &last_opcode,
                        stack.len(),
                    ));
                }
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                    as usize;
                i += 4;
                if i + n > script.len() {
                    return Err(script_err(
                        "malformed pushdata4 length",
                        &last_opcode,
                        stack.len(),
                    ));
                }
                stack.push(script[i..i + n].to_vec());
                i += n;
            }
            0x4f => stack.push(vec![0x81]),
            0x51..=0x60 => {
                let n = opcode - 0x50;
                stack.push(vec![n]);
            }
            0x69 => {
                let top = stack.pop().ok_or_else(|| {
                    script_err("stack underflow on OP_VERIFY", &last_opcode, stack.len())
                })?;
                if !stack_is_truthy(Some(&top)) {
                    return Err(script_err("verify false", &last_opcode, stack.len()));
                }
            }
            0x6a => return Err(script_err("op_return", &last_opcode, stack.len())),
            0x75 => {
                let _ = stack.pop().ok_or_else(|| {
                    script_err("stack underflow on OP_DROP", &last_opcode, stack.len())
                })?;
            }
            0x76 => {
                let top = stack.last().cloned().ok_or_else(|| {
                    script_err("stack underflow on OP_DUP", &last_opcode, stack.len())
                })?;
                stack.push(top);
            }
            0x82 => {
                let top = stack.last().ok_or_else(|| {
                    script_err("stack underflow on OP_SIZE", &last_opcode, stack.len())
                })?;
                let n = top.len();
                if n <= 252 {
                    stack.push(vec![n as u8]);
                } else {
                    return Err(script_err(
                        "unsupported size >252",
                        &last_opcode,
                        stack.len(),
                    ));
                }
            }
            0x87 => {
                let a = stack.pop().ok_or_else(|| {
                    script_err("stack underflow on OP_EQUAL", &last_opcode, stack.len())
                })?;
                let b = stack.pop().ok_or_else(|| {
                    script_err("stack underflow on OP_EQUAL", &last_opcode, stack.len())
                })?;
                if a == b {
                    stack.push(vec![1]);
                } else {
                    stack.push(Vec::new());
                }
            }
            0x88 => {
                let a = stack.pop().ok_or_else(|| {
                    script_err(
                        "stack underflow on OP_EQUALVERIFY",
                        &last_opcode,
                        stack.len(),
                    )
                })?;
                let b = stack.pop().ok_or_else(|| {
                    script_err(
                        "stack underflow on OP_EQUALVERIFY",
                        &last_opcode,
                        stack.len(),
                    )
                })?;
                if a != b {
                    return Err(script_err(
                        "equalverify mismatch",
                        &last_opcode,
                        stack.len(),
                    ));
                }
            }
            0xa9 => {
                let v = stack.pop().ok_or_else(|| {
                    script_err("stack underflow on OP_HASH160", &last_opcode, stack.len())
                })?;
                stack.push(hash160(&v).to_vec());
            }
            0xac => {
                let _pubkey = stack.pop().ok_or_else(|| {
                    script_err("stack underflow on OP_CHECKSIG", &last_opcode, stack.len())
                })?;
                let _sig = stack.pop().ok_or_else(|| {
                    script_err("stack underflow on OP_CHECKSIG", &last_opcode, stack.len())
                })?;
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

fn reason_result(
    reason: &str,
    phase: ScriptPhase,
    trace: &[String],
    p2sh_detected: bool,
    bip16_enforced: bool,
    ok: bool,
) -> ExecResult {
    let mut result = if ok {
        ExecResult::ok()
    } else {
        ExecResult::err(reason)
    };
    result
        .details
        .insert("script_phase".to_string(), phase.as_str().to_string());
    result
        .details
        .insert("p2sh_detected".to_string(), p2sh_detected.to_string());
    result
        .details
        .insert("bip16_enforced".to_string(), bip16_enforced.to_string());
    result
        .details
        .insert("script_trace".to_string(), trace.join("|"));
    result
}

fn script_error_result(
    e: &ScriptExecError,
    phase: ScriptPhase,
    trace: &[String],
    p2sh_detected: bool,
    bip16_enforced: bool,
) -> ExecResult {
    let mut result = ExecResult::err(format!("script failed: {}", e.reason));
    result
        .details
        .insert("script_phase".to_string(), phase.as_str().to_string());
    result
        .details
        .insert("p2sh_detected".to_string(), p2sh_detected.to_string());
    result
        .details
        .insert("bip16_enforced".to_string(), bip16_enforced.to_string());
    result.details.insert(
        "script_trace".to_string(),
        if trace.is_empty() {
            format!("{}:{}:d{}", phase.as_str(), e.last_opcode, e.stack_depth)
        } else {
            trace.join("|")
        },
    );
    result
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
    outputs: Vec<TxOut>,
}

#[derive(Debug, Clone)]
struct TxIn {
    prevout: Prevout,
    script_sig: Vec<u8>,
    witness: Option<Witness>,
}

#[derive(Debug, Clone)]
struct TxOut {
    script_pubkey: Vec<u8>,
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
        let script_sig = read_bytes(&bytes, &mut i, script_len).ok_or(())?.to_vec();
        i = advance(&bytes, i, 4)?; // sequence
        inputs.push(TxIn {
            prevout: Prevout { txid_hex, vout },
            script_sig,
            witness: None,
        });
    }

    let vout_count = read_varint(&bytes, &mut i).ok_or(())? as usize;
    let mut outputs = Vec::with_capacity(vout_count);
    for _ in 0..vout_count {
        i = advance(&bytes, i, 8)?;
        let spk_len = read_varint(&bytes, &mut i).ok_or(())? as usize;
        let script_pubkey = read_bytes(&bytes, &mut i, spk_len).ok_or(())?.to_vec();
        outputs.push(TxOut { script_pubkey });
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

    Ok(Transaction { inputs, outputs })
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
    use super::{ScriptPhase, TestCase, execute_script, hash160, run_testcase_rust};
    use jb_model::{CoreTemplate, ValidationContext};
    use std::collections::BTreeMap;

    #[test]
    fn pushdata_direct_success() {
        let mut stack = Vec::new();
        let mut trace = Vec::new();
        execute_script(
            &[0x02, 0xaa, 0xbb],
            &mut stack,
            true,
            ScriptPhase::ScriptSig,
            &mut trace,
        )
        .expect("exec");
        assert_eq!(stack, vec![vec![0xaa, 0xbb]]);
    }

    #[test]
    fn pushdata_malformed_fails() {
        let mut stack = Vec::new();
        let mut trace = Vec::new();
        let err = execute_script(
            &[0x4c, 0x02, 0xaa],
            &mut stack,
            true,
            ScriptPhase::ScriptSig,
            &mut trace,
        )
        .expect_err("must fail");
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
        let mut trace = Vec::new();
        execute_script(
            &script,
            &mut stack,
            true,
            ScriptPhase::ScriptSig,
            &mut trace,
        )
        .expect("exec");
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn stack_underflow_detected() {
        let mut stack = Vec::new();
        let mut trace = Vec::new();
        let err = execute_script(
            &[0x76],
            &mut stack,
            true,
            ScriptPhase::ScriptSig,
            &mut trace,
        )
        .expect_err("underflow");
        assert!(err.reason.contains("stack underflow"));
    }

    #[test]
    fn p2sh_bip16_boundary_flip() {
        let tx_hex = "010000000111111111111111111111111111111111111111111111111111111111111111110000000003517500ffffffff01102700000000000017a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb8700000000";
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "script_pubkey_hex".to_string(),
            "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87".to_string(),
        );

        let tc_pre = TestCase {
            id: "pre".to_string(),
            description: "pre".to_string(),
            network: "mainnet".to_string(),
            utxo_set: Vec::new(),
            tx_hex: tx_hex.to_string(),
            flags: Vec::new(),
            context: Some(ValidationContext {
                height: 173_804,
                median_time_past: None,
                block_time: None,
                epoch: Some("pre-bip16".to_string()),
            }),
            core_template: Some(CoreTemplate {
                kind: "testmempoolaccept_tx_hex".to_string(),
                spend_type: "p2sh".to_string(),
                feerate_sats_vb: None,
            }),
            metadata: metadata.clone(),
        };
        let mut tc_post = tc_pre.clone();
        tc_post.id = "post".to_string();
        tc_post.context = Some(ValidationContext {
            height: 173_805,
            median_time_past: None,
            block_time: None,
            epoch: Some("post-bip16-pre-bip34".to_string()),
        });

        let pre = run_testcase_rust(&tc_pre);
        let post = run_testcase_rust(&tc_post);
        assert!(pre.ok);
        assert!(!post.ok);
        assert_eq!(post.reason.as_deref(), Some("p2sh missing redeemscript"));
    }

    #[test]
    fn p2wpkh_witness_shape_and_program_mismatch() {
        let good = "0100000000010111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01102700000000000016001400000000000000000000000000000000000000000201012102000000000000000000000000000000000000000000000000000000000000000000000000";
        let mut pubkey = vec![0x02u8];
        pubkey.extend_from_slice(&[0u8; 32]);
        let witness_program = hex::encode(hash160(&pubkey));
        let mut tc = TestCase {
            id: "w".to_string(),
            description: "w".to_string(),
            network: "mainnet".to_string(),
            utxo_set: Vec::new(),
            tx_hex: good.to_string(),
            flags: Vec::new(),
            context: Some(ValidationContext {
                height: 700_000,
                median_time_past: None,
                block_time: None,
                epoch: Some("segwit-active".to_string()),
            }),
            core_template: Some(CoreTemplate {
                kind: "testmempoolaccept_tx_hex".to_string(),
                spend_type: "p2wpkh".to_string(),
                feerate_sats_vb: None,
            }),
            metadata: BTreeMap::from([
                ("checksighook".to_string(), "true".to_string()),
                (
                    "script_pubkey_hex".to_string(),
                    format!("0014{}", witness_program),
                ),
            ]),
        };
        let ok = run_testcase_rust(&tc);
        assert!(ok.ok);

        tc.metadata.insert(
            "script_pubkey_hex".to_string(),
            "00141111111111111111111111111111111111111111".to_string(),
        );
        let mismatch = run_testcase_rust(&tc);
        assert_eq!(mismatch.reason.as_deref(), Some("witness program mismatch"));

        tc.tx_hex = "0100000000010111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff011027000000000000160014000000000000000000000000000000000000000001010100000000".to_string();
        let bad_shape = run_testcase_rust(&tc);
        assert_eq!(bad_shape.reason.as_deref(), Some("witness invalid stack"));
    }
}
