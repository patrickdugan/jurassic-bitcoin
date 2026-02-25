use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use jb_model::{CoreTemplate, ExecResult, TestCase};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const HARNESS_WALLET: &str = "jb_harness";

pub fn run_testcase_core(tc: &TestCase) -> ExecResult {
    let rpc = match RpcClient::from_env() {
        Ok(rpc) => rpc,
        Err(_) => return stub_result(tc),
    };

    if let Some(tpl) = &tc.core_template {
        match run_template_case_with_testcase(&rpc, tpl, tc) {
            Ok(result) => result,
            Err(e) => ExecResult::err(format!("core rpc error: {e:#}")),
        }
    } else {
        parse_only_result(tc)
    }
}

pub fn mint_seed_testcase(out_id: impl Into<String>) -> Result<TestCase> {
    let rpc = RpcClient::from_env()?;
    let state = ensure_harness_state(&rpc)?;
    let fee_sats = 2_u64 * 150_u64;
    let signed_hex = build_signed_spend_harness_tx(&state, fee_sats)?;
    Ok(TestCase {
        id: out_id.into(),
        description: "Minted deterministic harness seed tx".to_string(),
        network: "regtest".to_string(),
        utxo_set: Vec::new(),
        tx_hex: signed_hex,
        flags: Vec::new(),
        core_template: Some(CoreTemplate {
            kind: "testmempoolaccept_tx_hex".to_string(),
            spend_type: "p2wpkh".to_string(),
            feerate_sats_vb: Some(2),
        }),
        metadata: BTreeMap::new(),
    })
}

fn stub_result(tc: &TestCase) -> ExecResult {
    let mut result = parse_only_result(tc);
    result.details.insert("mode".to_string(), "stub".to_string());
    result.details.insert(
        "note".to_string(),
        "BITCOIND_RPC_* not set; running deterministic placeholder".to_string(),
    );
    result
}

fn parse_only_result(tc: &TestCase) -> ExecResult {
    if tc.tx_hex.len() % 2 != 0 {
        return ExecResult::err("invalid tx hex length");
    }
    if tc.flags.iter().any(|f| f == "CORE_REJECT") {
        return ExecResult::err("rejected by core flag CORE_REJECT");
    }

    let mut result = ExecResult::ok();
    result
        .details
        .insert("mode".to_string(), "parse-only".to_string());
    result
}

fn run_template_case(rpc: &RpcClient, template: &CoreTemplate) -> Result<ExecResult> {
    match template.kind.as_str() {
        "spend_harness_utxo" => run_spend_harness_template(rpc, template),
        "testmempoolaccept_tx_hex" => Ok(ExecResult::err(
            "internal error: testmempoolaccept_tx_hex requires testcase context",
        )),
        other => Ok(ExecResult::err(format!(
            "unsupported core_template.kind {}",
            other
        ))),
    }
}

fn run_template_case_with_testcase(
    rpc: &RpcClient,
    template: &CoreTemplate,
    tc: &TestCase,
) -> Result<ExecResult> {
    match template.kind.as_str() {
        "testmempoolaccept_tx_hex" => run_testmempoolaccept_tx_hex_template(rpc, template, tc),
        _ => run_template_case(rpc, template),
    }
}

fn run_spend_harness_template(rpc: &RpcClient, template: &CoreTemplate) -> Result<ExecResult> {
    if template.spend_type != "p2wpkh" {
        return Ok(ExecResult::err(format!(
            "unsupported core_template.spend_type {}",
            template.spend_type
        )));
    }
    let state = ensure_harness_state(rpc)?;
    let fee_sats = template.feerate_sats_vb.unwrap_or(2).max(1) * 150;
    let signed_hex = build_signed_spend_harness_tx(&state, fee_sats)?;
    testmempoolaccept_result(
        &state,
        signed_hex.as_str(),
        "spend_harness_utxo",
        template.spend_type.as_str(),
        Some(fee_sats),
    )
}

fn run_testmempoolaccept_tx_hex_template(
    rpc: &RpcClient,
    template: &CoreTemplate,
    tc: &TestCase,
) -> Result<ExecResult> {
    if template.spend_type != "p2wpkh" {
        return Ok(ExecResult::err(format!(
            "unsupported core_template.spend_type {}",
            template.spend_type
        )));
    }
    let state = ensure_harness_state(rpc)?;
    let inputs = match parse_input_outpoints(&tc.tx_hex) {
        Ok(v) => v,
        Err(_) => return Ok(ExecResult::err("invalid tx encoding")),
    };
    let funding_match = inputs
        .iter()
        .any(|i| i.txid == state.funding.txid && i.vout == state.funding.vout);
    if !funding_match {
        return Ok(ExecResult::err(
            "wrong prevout (not harness funding outpoint)",
        ));
    }
    testmempoolaccept_result(
        &state,
        tc.tx_hex.as_str(),
        "testmempoolaccept_tx_hex",
        template.spend_type.as_str(),
        None,
    )
}

fn build_signed_spend_harness_tx(state: &HarnessState, fee_sats: u64) -> Result<String> {
    if state.funding.amount_sats <= fee_sats + 330 {
        return Err(anyhow!(
            "funding outpoint too small: {} sats",
            state.funding.amount_sats
        ));
    }
    let spend_sats = state.funding.amount_sats - fee_sats;
    let spend_btc = sats_to_btc(spend_sats);
    let raw_tx = state.wallet.call(
        "createrawtransaction",
        json!([
            [{ "txid": state.funding.txid, "vout": state.funding.vout }],
            { (state.sink_addr.clone()): spend_btc },
            0,
            false
        ]),
    )?;
    let raw_tx = raw_tx
        .as_str()
        .ok_or_else(|| anyhow!("invalid createrawtransaction response"))?;
    let signed = state
        .wallet
        .call("signrawtransactionwithwallet", json!([raw_tx]))?;
    let signed_hex = signed["hex"]
        .as_str()
        .ok_or_else(|| anyhow!("signrawtransactionwithwallet missing hex"))?;
    if !signed["complete"].as_bool().unwrap_or(false) {
        return Err(anyhow!("signrawtransactionwithwallet returned incomplete=false"));
    }
    Ok(signed_hex.to_string())
}

fn testmempoolaccept_result(
    state: &HarnessState,
    tx_hex: &str,
    kind: &str,
    spend_type: &str,
    fee_sats: Option<u64>,
) -> Result<ExecResult> {
    let accept = state.root.call("testmempoolaccept", json!([[tx_hex]]))?;
    let first = accept
        .as_array()
        .and_then(|arr| arr.first())
        .ok_or_else(|| anyhow!("testmempoolaccept missing result"))?;

    let allowed = first["allowed"].as_bool().unwrap_or(false);
    let reject_reason = first["reject-reason"].as_str().map(ToOwned::to_owned);
    let mut details = BTreeMap::new();
    details.insert("mode".to_string(), "rpc-template".to_string());
    details.insert("kind".to_string(), kind.to_string());
    details.insert("wallet".to_string(), HARNESS_WALLET.to_string());
    details.insert("chain".to_string(), state.chain.clone());
    details.insert("spend_type".to_string(), spend_type.to_string());
    details.insert("state_path".to_string(), state.state_path.display().to_string());
    details.insert(
        "funding_outpoint".to_string(),
        format!("{}:{}", state.funding.txid, state.funding.vout),
    );
    if let Some(fee_sats) = fee_sats {
        details.insert("fee_sats".to_string(), fee_sats.to_string());
        details.insert(
            "spend_sats".to_string(),
            (state.funding.amount_sats.saturating_sub(fee_sats)).to_string(),
        );
    }

    Ok(ExecResult {
        ok: allowed,
        reason: reject_reason,
        details,
    })
}

fn ensure_harness_state(rpc: &RpcClient) -> Result<HarnessState> {
    let info = rpc.call("getblockchaininfo", json!([]))?;
    let chain = info["chain"]
        .as_str()
        .ok_or_else(|| anyhow!("getblockchaininfo missing chain"))?;
    if chain != "regtest" {
        return Err(anyhow!("bitcoind chain is {chain}, expected regtest"));
    }

    let wallets = rpc.call("listwallets", json!([]))?;
    let loaded = wallets
        .as_array()
        .map(|arr| arr.iter().any(|w| w.as_str() == Some(HARNESS_WALLET)))
        .unwrap_or(false);
    if !loaded {
        match rpc.call("loadwallet", json!([HARNESS_WALLET])) {
            Ok(_) => {}
            Err(_) => {
                rpc.call(
                    "createwallet",
                    json!([HARNESS_WALLET, false, false, "", false, false, true]),
                )?;
            }
        }
    }

    let wallet = rpc.for_wallet(HARNESS_WALLET);
    let state_path = resolve_state_path();
    let mut state_disk = load_state(&state_path).unwrap_or_default();

    if state_disk.mining_addr.is_none() {
        let addr = wallet.call("getnewaddress", json!(["jb_mining", "bech32"]))?;
        let addr = addr
            .as_str()
            .ok_or_else(|| anyhow!("invalid mining address response"))?;
        state_disk.mining_addr = Some(addr.to_string());
    }
    if state_disk.sink_addr.is_none() {
        let addr = wallet.call("getnewaddress", json!(["jb_sink", "bech32"]))?;
        let addr = addr
            .as_str()
            .ok_or_else(|| anyhow!("invalid sink address response"))?;
        state_disk.sink_addr = Some(addr.to_string());
    }
    let mining_addr = state_disk
        .mining_addr
        .clone()
        .ok_or_else(|| anyhow!("mining_addr missing from state"))?;
    let sink_addr = state_disk
        .sink_addr
        .clone()
        .ok_or_else(|| anyhow!("sink_addr missing from state"))?;

    let block_count = rpc.call("getblockcount", json!([]))?.as_u64().unwrap_or(0);
    if block_count < 101 {
        wallet.call("generatetoaddress", json!([101 - block_count, mining_addr]))?;
    }

    let mut funding = state_disk.funding.clone();
    if let Some(ref f) = funding {
        let txout = rpc.call("gettxout", json!([f.txid, f.vout, true]))?;
        if txout.is_null() {
            funding = None;
        } else if let Some(value_btc) = txout["value"].as_f64() {
            let sats = btc_to_sats(value_btc);
            if sats > 0 {
                let mut updated = f.clone();
                updated.amount_sats = sats;
                funding = Some(updated);
            }
        }
    }
    if funding.is_none() {
        let txid = wallet.call("sendtoaddress", json!([mining_addr, 1.0]))?;
        let txid = txid
            .as_str()
            .ok_or_else(|| anyhow!("sendtoaddress missing txid"))?
            .to_string();
        wallet.call("generatetoaddress", json!([1, mining_addr]))?;
        let tx = wallet.call("gettransaction", json!([txid, true, true]))?;
        let details = tx["details"]
            .as_array()
            .ok_or_else(|| anyhow!("gettransaction missing details"))?;
        let entry = details
            .iter()
            .find(|d| d["category"].as_str() == Some("receive"))
            .ok_or_else(|| anyhow!("could not find receive entry for funding tx"))?;
        let vout = entry["vout"]
            .as_u64()
            .ok_or_else(|| anyhow!("funding receive entry missing vout"))? as u32;
        let amount_btc = entry["amount"]
            .as_f64()
            .ok_or_else(|| anyhow!("funding receive entry missing amount"))?;
        funding = Some(FundingOutpoint {
            txid,
            vout,
            amount_sats: btc_to_sats(amount_btc),
        });
    }
    let funding = funding.ok_or_else(|| anyhow!("unable to establish funding outpoint"))?;

    lock_other_unspents(&wallet, &funding)?;

    state_disk.bootstrapped = true;
    state_disk.funding = Some(funding.clone());
    write_state(&state_path, &state_disk)?;

    Ok(HarnessState {
        root: rpc.clone(),
        wallet,
        chain: chain.to_string(),
        state_path,
        sink_addr,
        funding,
    })
}

#[derive(Clone)]
struct RpcClient {
    url: String,
    user: String,
    pass: String,
}

#[derive(Clone)]
struct HarnessState {
    root: RpcClient,
    wallet: RpcClient,
    chain: String,
    state_path: PathBuf,
    sink_addr: String,
    funding: FundingOutpoint,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HarnessDiskState {
    mining_addr: Option<String>,
    sink_addr: Option<String>,
    funding: Option<FundingOutpoint>,
    bootstrapped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FundingOutpoint {
    txid: String,
    vout: u32,
    amount_sats: u64,
}

#[derive(Debug, Clone)]
struct TxInputOutpoint {
    txid: String,
    vout: u32,
}

impl RpcClient {
    fn from_env() -> Result<Self> {
        let url = env::var("BITCOIND_RPC_URL").context("missing BITCOIND_RPC_URL")?;
        let user = env::var("BITCOIND_RPC_USER").context("missing BITCOIND_RPC_USER")?;
        let pass = env::var("BITCOIND_RPC_PASS").context("missing BITCOIND_RPC_PASS")?;
        Ok(Self { url, user, pass })
    }

    fn for_wallet(&self, wallet: &str) -> Self {
        Self {
            url: format!("{}/wallet/{}", self.url.trim_end_matches('/'), wallet),
            user: self.user.clone(),
            pass: self.pass.clone(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let req = json!({
            "jsonrpc": "1.0",
            "id": "jb",
            "method": method,
            "params": params,
        });
        let auth = format!("Basic {}", STANDARD.encode(format!("{}:{}", self.user, self.pass)));
        let response: RpcResponse = ureq::post(&self.url)
            .set("content-type", "text/plain")
            .set("authorization", &auth)
            .send_json(req)
            .with_context(|| format!("rpc call failed: {method}"))?
            .into_json()
            .with_context(|| format!("rpc decode failed: {method}"))?;
        if let Some(err) = response.error {
            return Err(anyhow!("rpc {method} error {}: {}", err.code, err.message));
        }
        response
            .result
            .ok_or_else(|| anyhow!("rpc {method} returned null result"))
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

fn sats_to_btc(sats: u64) -> f64 {
    (sats as f64) / 100_000_000.0
}

fn btc_to_sats(value: f64) -> u64 {
    (value * 100_000_000.0).round() as u64
}

fn resolve_state_path() -> PathBuf {
    if let Ok(path) = env::var("JB_STATE_PATH") {
        return PathBuf::from(path);
    }
    let d_drive = Path::new("D:\\jurassic-data");
    if d_drive.exists() {
        return d_drive.join("jb-state.json");
    }
    PathBuf::from("artifacts").join("state.json")
}

fn load_state(path: &Path) -> Result<HarnessDiskState> {
    let bytes = fs::read(path).with_context(|| format!("reading state {}", path.display()))?;
    let state = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing state {}", path.display()))?;
    Ok(state)
}

fn write_state(path: &Path, state: &HarnessDiskState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("writing state {}", path.display()))?;
    Ok(())
}

fn lock_other_unspents(wallet: &RpcClient, funding: &FundingOutpoint) -> Result<()> {
    let unspent = wallet.call("listunspent", json!([1]))?;
    let list = unspent
        .as_array()
        .ok_or_else(|| anyhow!("listunspent response not an array"))?;

    let mut to_lock = Vec::new();
    for u in list {
        let txid = u["txid"].as_str().unwrap_or_default();
        let vout = u["vout"].as_u64().unwrap_or(u64::MAX) as u32;
        if txid == funding.txid && vout == funding.vout {
            continue;
        }
        to_lock.push(json!({ "txid": txid, "vout": vout }));
    }

    wallet.call(
        "lockunspent",
        json!([false, [{ "txid": funding.txid, "vout": funding.vout }]]),
    )?;
    if !to_lock.is_empty() {
        wallet.call("lockunspent", json!([true, to_lock]))?;
    }
    Ok(())
}

fn parse_input_outpoints(tx_hex: &str) -> Result<Vec<TxInputOutpoint>> {
    let tx = hex::decode(tx_hex).map_err(|_| anyhow!("invalid tx encoding"))?;
    if tx.len() < 10 {
        return Err(anyhow!("invalid tx encoding"));
    }
    let mut i = 0usize;
    i = advance(&tx, i, 4)?;

    let has_witness = tx.get(i) == Some(&0x00) && tx.get(i + 1) == Some(&0x01);
    if has_witness {
        i = advance(&tx, i, 2)?;
    }

    let vin_count = read_varint(&tx, &mut i).ok_or_else(|| anyhow!("invalid tx encoding"))?;
    let mut outpoints = Vec::with_capacity(vin_count as usize);
    for _ in 0..vin_count {
        let txid_le = read_bytes(&tx, &mut i, 32).ok_or_else(|| anyhow!("invalid tx encoding"))?;
        let txid = txid_le.iter().rev().map(|b| format!("{:02x}", b)).collect();
        let vout = read_u32_le(&tx, &mut i).ok_or_else(|| anyhow!("invalid tx encoding"))?;
        outpoints.push(TxInputOutpoint { txid, vout });

        let script_len = read_varint(&tx, &mut i).ok_or_else(|| anyhow!("invalid tx encoding"))?;
        i = advance(&tx, i, script_len as usize)?;
        i = advance(&tx, i, 4)?; // sequence
    }

    let vout_count = read_varint(&tx, &mut i).ok_or_else(|| anyhow!("invalid tx encoding"))?;
    for _ in 0..vout_count {
        i = advance(&tx, i, 8)?; // value
        let spk_len = read_varint(&tx, &mut i).ok_or_else(|| anyhow!("invalid tx encoding"))?;
        i = advance(&tx, i, spk_len as usize)?;
    }

    if has_witness {
        for _ in 0..vin_count {
            let item_count = read_varint(&tx, &mut i).ok_or_else(|| anyhow!("invalid tx encoding"))?;
            for _ in 0..item_count {
                let item_len = read_varint(&tx, &mut i).ok_or_else(|| anyhow!("invalid tx encoding"))?;
                i = advance(&tx, i, item_len as usize)?;
            }
        }
    }

    i = advance(&tx, i, 4)?; // locktime
    if i != tx.len() {
        return Err(anyhow!("invalid tx encoding"));
    }
    Ok(outpoints)
}

fn advance(bytes: &[u8], idx: usize, n: usize) -> Result<usize> {
    let next = idx.saturating_add(n);
    if next > bytes.len() {
        return Err(anyhow!("invalid tx encoding"));
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
    use super::{resolve_state_path, run_testcase_core};
    use jb_model::{CoreTemplate, TestCase};
    use std::collections::BTreeMap;

    #[test]
    #[ignore]
    fn rpc_template_path_smoke() {
        let tc = TestCase {
            id: "rpc-smoke".to_string(),
            description: "integration smoke".to_string(),
            network: "regtest".to_string(),
            utxo_set: Vec::new(),
            tx_hex: "00".to_string(),
            flags: Vec::new(),
            core_template: Some(CoreTemplate {
                kind: "spend_harness_utxo".to_string(),
                spend_type: "p2wpkh".to_string(),
                feerate_sats_vb: Some(2),
            }),
            metadata: BTreeMap::new(),
        };
        let _ = run_testcase_core(&tc);
    }

    #[test]
    fn state_path_resolution_has_default() {
        let path = resolve_state_path();
        assert!(!path.as_os_str().is_empty());
    }
}
