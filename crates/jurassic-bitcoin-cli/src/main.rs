use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use jb_consensus_profile::{
    ContextView as ProfileContextView, epoch_for_height, flags_for_context,
};
use jb_core_exec::{doctor_report, mint_seed_testcase, run_testcase_core};
use jb_corpus::{load_corpus, write_divergence_event};
use jb_diff::diff_results;
use jb_fixtures::{
    FetchReport, FixtureOptions, default_cache_dir, fetch_txid_fixtures, load_manifest,
    materialize_fixtures,
};
use jb_model::{CoreTemplate, DivergenceEvent, TestCase, ValidationContext};
use jb_mutator::mutate_testcase_with_trace;
use jb_reducer::reduce_divergence;
use jb_rust_shadow::run_testcase_rust;
use rand::{SeedableRng, rngs::StdRng};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "jurassic-bitcoin")]
#[command(about = "Consensus observability differential harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormat {
    Md,
    Latex,
}

#[derive(Subcommand)]
enum Command {
    Replay {
        #[arg(long, default_value = "corpus")]
        corpus: PathBuf,
        #[arg(long, default_value_t = 100)]
        max: usize,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Fuzz {
        #[arg(long, default_value = "corpus")]
        corpus: PathBuf,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
        #[arg(long, default_value_t = 7)]
        seed: u64,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Reduce {
        #[arg(long)]
        event: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    MintSeed {
        #[arg(long)]
        out: PathBuf,
    },
    Doctor,
    DemoRun {
        #[arg(long, default_value = "artifacts/demo")]
        out_dir: PathBuf,
        #[arg(long, default_value_t = 200)]
        iterations: usize,
        #[arg(long, default_value_t = 7)]
        seed: u64,
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long, default_value = "corpus")]
        corpus: PathBuf,
    },
    Summarize {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long, default_value_t = false)]
        compare: bool,
    },
    FetchFixtures {
        #[arg(long, default_value = "fixtures/manifests/era_2009_2013_poc.json")]
        manifest: PathBuf,
        #[arg(long, default_value = "fixtures/cache/index.json")]
        out_index: PathBuf,
        #[arg(long, default_value_t = false)]
        strict: bool,
    },
    Museum {
        #[arg(long)]
        r#in: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    SuggestLabels {
        #[arg(long)]
        r#in: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    ApplyLabel {
        #[arg(long)]
        specimen: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        labels: PathBuf,
    },
    ReplayEra {
        #[arg(long, default_value = "fixtures/manifests/era_2009_2013_poc.json")]
        manifest: PathBuf,
        #[arg(long, default_value = "artifacts/era-2009-2013")]
        out_dir: PathBuf,
        #[arg(long, default_value_t = 200)]
        limit_per_epoch: usize,
        #[arg(long, default_value_t = false)]
        rpc_fetch: bool,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    ExtractEra {
        #[arg(long)]
        start_height: u32,
        #[arg(long)]
        end_height: u32,
        #[arg(long, default_value_t = 10)]
        limit_per_height: usize,
        #[arg(long, default_value = "corpus/era-mainnet")]
        out_corpus: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    MintP2shSeam {
        #[arg(long, default_value = "fixtures/blobs/p2sh-core-seam.json")]
        out: PathBuf,
    },
    MintP2wpkhSeam {
        #[arg(long, default_value = "fixtures/blobs/p2wpkh-core-seam.json")]
        out: PathBuf,
    },
    MintFindanddeleteSeam {
        #[arg(
            long,
            default_value = "fixtures/blobs/p2sh-findanddelete-core-seam.json"
        )]
        out: PathBuf,
    },
    MintSighashSingleSeam {
        #[arg(long, default_value = "fixtures/blobs/sighash-single-core-seam.json")]
        out: PathBuf,
    },
    MintDummygrindSeam {
        #[arg(long, default_value = "fixtures/blobs/p2sh-dummygrind-core-seam.json")]
        out: PathBuf,
    },
    Report {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, value_enum, default_value_t = ReportFormat::Md)]
        format: ReportFormat,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Replay {
            corpus,
            max,
            artifacts,
        } => replay(&corpus, max, &artifacts),
        Command::Fuzz {
            corpus,
            iterations,
            seed,
            artifacts,
        } => fuzz(&corpus, iterations, seed, &artifacts),
        Command::Reduce { event, artifacts } => reduce(&event, &artifacts),
        Command::MintSeed { out } => mint_seed(&out),
        Command::Doctor => doctor(),
        Command::DemoRun {
            out_dir,
            iterations,
            seed,
            force,
            corpus,
        } => demo_run(&out_dir, iterations, seed, force, &corpus),
        Command::Summarize { dir, json, compare } => summarize(&dir, json, compare),
        Command::FetchFixtures {
            manifest,
            out_index,
            strict,
        } => fetch_fixtures(&manifest, &out_index, strict),
        Command::Museum { r#in, out } => museum(&r#in, &out),
        Command::SuggestLabels { r#in, out } => suggest_labels(&r#in, &out),
        Command::ApplyLabel {
            specimen,
            label,
            labels,
        } => apply_label(&specimen, &label, &labels),
        Command::ReplayEra {
            manifest,
            out_dir,
            limit_per_epoch,
            rpc_fetch,
            force,
        } => replay_era(&manifest, &out_dir, limit_per_epoch, rpc_fetch, force),
        Command::ExtractEra {
            start_height,
            end_height,
            limit_per_height,
            out_corpus,
            force,
        } => extract_era(
            start_height,
            end_height,
            limit_per_height,
            &out_corpus,
            force,
        ),
        Command::MintP2shSeam { out } => mint_p2sh_seam(&out),
        Command::MintP2wpkhSeam { out } => mint_p2wpkh_seam(&out),
        Command::MintFindanddeleteSeam { out } => mint_findanddelete_seam(&out),
        Command::MintSighashSingleSeam { out } => mint_sighash_single_seam(&out),
        Command::MintDummygrindSeam { out } => mint_dummygrind_seam(&out),
        Command::Report { dir, format, out } => report(&dir, format, out.as_deref()),
    }
}

fn replay(corpus_dir: &Path, max: usize, artifacts: &Path) -> Result<()> {
    let corpus = load_corpus(corpus_dir)?;
    let mut checked = 0usize;
    let mut divergences = 0usize;
    for tc in corpus.iter().take(max) {
        checked += 1;
        let core = run_testcase_core(tc);
        let rust = run_testcase_rust(tc);
        if let Some(event) = diff_results(tc, &core, &rust) {
            divergences += 1;
            let path = write_divergence_event(artifacts, &event, tc)?;
            println!("divergence: {} -> {}", tc.id, path.display());
        }
    }
    println!("checked={checked} divergences={divergences}");
    Ok(())
}

fn fuzz(corpus_dir: &Path, iterations: usize, seed: u64, artifacts: &Path) -> Result<()> {
    let corpus = load_corpus(corpus_dir)?;
    if corpus.is_empty() {
        return Ok(());
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let mut divergences = 0usize;
    for _ in 0..iterations {
        let idx = rand::Rng::gen_range(&mut rng, 0..corpus.len());
        let mut_result = mutate_testcase_with_trace(&corpus[idx], &mut rng);
        let mutated = mut_result.testcase;
        let core = run_testcase_core(&mutated);
        let rust = run_testcase_rust(&mutated);
        if let Some(mut event) = diff_results(&mutated, &core, &rust) {
            event.mutations_applied = mut_result.mutations_applied;
            divergences += 1;
            let _ = write_divergence_event(artifacts, &event, &mutated)?;
        }
    }
    println!("iterations={iterations} divergences={divergences}");
    Ok(())
}

fn reduce(event_path: &Path, artifacts: &Path) -> Result<()> {
    let bytes =
        fs::read(event_path).with_context(|| format!("reading event {}", event_path.display()))?;
    let event: jb_model::DivergenceEvent =
        serde_json::from_slice(&bytes).context("parsing event json")?;
    let day_dir = event_path
        .parent()
        .with_context(|| format!("missing parent dir for {}", event_path.display()))?;
    let case_path = day_dir.join(format!("{}-testcase.json", event.testcase_id));
    let case_bytes = fs::read(&case_path)
        .with_context(|| format!("reading testcase {}", case_path.display()))?;
    let case: TestCase = serde_json::from_slice(&case_bytes).context("parsing testcase json")?;
    let reduced = reduce_divergence(&case);
    let out = artifacts.join("reduced");
    fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
    let reduced_path = out.join(format!("{}-reduced.json", reduced.id));
    fs::write(&reduced_path, serde_json::to_vec_pretty(&reduced)?)
        .with_context(|| format!("writing {}", reduced_path.display()))?;
    println!("reduced testcase -> {}", reduced_path.display());
    Ok(())
}

fn mint_seed(out_path: &Path) -> Result<()> {
    let id = out_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("seed-p2wpkh")
        .to_string();
    let tc = mint_seed_testcase(id)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(out_path, serde_json::to_vec_pretty(&tc)?)
        .with_context(|| format!("writing {}", out_path.display()))?;
    println!("minted seed -> {}", out_path.display());
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct SeamAccept {
    allowed: bool,
    reject_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct P2shSeamFixture {
    name: String,
    network: String,
    redeem_script_hex: String,
    context_heights: Vec<u32>,
    funding_outpoint: String,
    missing_redeem_tx_hex: String,
    with_redeem_tx_hex: String,
    missing_redeem_core: SeamAccept,
    with_redeem_core: SeamAccept,
}

#[derive(Debug, Clone, Serialize)]
struct P2wpkhSeamFixture {
    name: String,
    network: String,
    context_heights: Vec<u32>,
    script_pubkey_hex: String,
    good_tx_hex: String,
    bad_witness_shape_tx_hex: String,
    bad_program_mismatch_tx_hex: String,
    good_core: SeamAccept,
    bad_witness_shape_core: SeamAccept,
    bad_program_mismatch_core: SeamAccept,
}

#[derive(Debug, Clone, Serialize)]
struct FindAndDeleteCoreSeamFixture {
    name: String,
    network: String,
    redeem_script_hex: String,
    funding_outpoint: String,
    context_heights: Vec<u32>,
    script_pubkey_hex: String,
    subset_aabb_tx_hex: String,
    subset_aa_tx_hex: String,
    subset_aaaa_tx_hex: String,
    subset_aabb_core: SeamAccept,
    subset_aa_core: SeamAccept,
    subset_aaaa_core: SeamAccept,
}

#[derive(Debug, Clone, Serialize)]
struct SighashSingleSeamFixture {
    name: String,
    network: String,
    funding_outpoints: Vec<String>,
    script_code_hex: String,
    context_heights: Vec<u32>,
    single_bug_tx_hex: String,
    single_bug_anyonecanpay_tx_hex: String,
    single_control_tx_hex: String,
    single_control_anyonecanpay_tx_hex: String,
    single_bug_core: SeamAccept,
    single_bug_anyonecanpay_core: SeamAccept,
    single_control_core: SeamAccept,
    single_control_anyonecanpay_core: SeamAccept,
}

#[derive(Debug, Clone, Serialize)]
struct DummygrindSeamFixture {
    name: String,
    network: String,
    redeem_script_hex: String,
    funding_outpoint: String,
    script_pubkey_hex: String,
    context_heights: Vec<u32>,
    dummy_empty_tx_hex: String,
    dummy_zero_tx_hex: String,
    dummy_32_tx_hex: String,
    dummy_empty_core: SeamAccept,
    dummy_zero_core: SeamAccept,
    dummy_32_core: SeamAccept,
}

fn mint_p2sh_seam(out_path: &Path) -> Result<()> {
    let report = doctor_report().map_err(|e| {
        anyhow!(
            "doctor failed: {e:#}\nSet BITCOIND_RPC_URL/USER/PASS and start regtest bitcoind first."
        )
    })?;
    if report.chain != "regtest" {
        return Err(anyhow!(
            "mint-p2sh-seam requires regtest, got {}",
            report.chain
        ));
    }

    let rpc = SimpleRpc::from_env()?;
    let wallet_name = "jb_legacy_ms";
    ensure_wallet_loaded_simple_with_descriptors(&rpc, wallet_name, false)?;
    let wallet = rpc.for_wallet(wallet_name);

    let mine_addr = wallet.call("getnewaddress", json!(["jb_bootstrap", "bech32"]))?;
    let mine_addr = mine_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing bootstrap addr"))?
        .to_string();
    let block_count = rpc.call("getblockcount", json!([]))?.as_u64().unwrap_or(0);
    if block_count < 101 {
        wallet.call("generatetoaddress", json!([101 - block_count, mine_addr]))?;
    }

    let redeem_script_hex = "5169".to_string(); // OP_1 OP_VERIFY
    let decoded = rpc.call("decodescript", json!([redeem_script_hex]))?;
    let p2sh_addr = decoded["p2sh"]
        .as_str()
        .ok_or_else(|| anyhow!("decodescript missing p2sh address"))?
        .to_string();

    let funding_txid = wallet.call("sendtoaddress", json!([p2sh_addr, 1.0]))?;
    let funding_txid = funding_txid
        .as_str()
        .ok_or_else(|| anyhow!("sendtoaddress missing txid"))?
        .to_string();

    let mining_addr = wallet.call("getnewaddress", json!(["jb_seam_mining", "bech32"]))?;
    let mining_addr = mining_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing mining addr"))?
        .to_string();
    wallet.call("generatetoaddress", json!([1, mining_addr]))?;

    let tx = wallet.call("gettransaction", json!([funding_txid, true, true]))?;
    let funding_hex = tx["hex"]
        .as_str()
        .ok_or_else(|| anyhow!("gettransaction missing hex"))?
        .to_string();
    let decoded_funding = rpc.call("decoderawtransaction", json!([funding_hex]))?;
    let vouts = decoded_funding["vout"]
        .as_array()
        .ok_or_else(|| anyhow!("decoderawtransaction missing vout"))?;
    let mut funding_vout = None::<u32>;
    let mut funding_sats = None::<u64>;
    for v in vouts {
        let addrs = v["scriptPubKey"]["address"]
            .as_str()
            .map(|s| vec![s.to_string()])
            .or_else(|| {
                v["scriptPubKey"]["addresses"].as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .collect()
                })
            })
            .unwrap_or_default();
        if addrs.iter().any(|a| a == &p2sh_addr) {
            funding_vout = v["n"].as_u64().map(|n| n as u32);
            funding_sats = v["value"]
                .as_f64()
                .map(|btc| (btc * 100_000_000.0).round() as u64);
            break;
        }
    }
    let funding_vout =
        funding_vout.ok_or_else(|| anyhow!("could not locate p2sh funding output"))?;
    let funding_sats = funding_sats.ok_or_else(|| anyhow!("missing funding output value"))?;
    if funding_sats <= 1_000 {
        return Err(anyhow!("funding output too small"));
    }

    let sink_addr = wallet.call("getnewaddress", json!(["jb_seam_sink", "bech32"]))?;
    let sink_addr = sink_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing sink addr"))?
        .to_string();
    let sink_info = wallet.call("getaddressinfo", json!([sink_addr]))?;
    let sink_spk = sink_info["scriptPubKey"]
        .as_str()
        .ok_or_else(|| anyhow!("getaddressinfo missing scriptPubKey"))?;
    let sink_spk = hex::decode(sink_spk).context("decode sink scriptPubKey hex")?;

    let spend_sats = funding_sats - 1_000;
    let missing_redeem_sig = vec![0x51];
    let with_redeem_sig = vec![0x51, 0x02, 0x51, 0x69];

    let missing_redeem_tx_hex = build_legacy_tx(
        &funding_txid,
        funding_vout,
        &missing_redeem_sig,
        spend_sats,
        &sink_spk,
    )?;
    let with_redeem_tx_hex = build_legacy_tx(
        &funding_txid,
        funding_vout,
        &with_redeem_sig,
        spend_sats,
        &sink_spk,
    )?;

    let missing_redeem_core = testmempoolaccept_once(&rpc, &missing_redeem_tx_hex)?;
    let with_redeem_core = testmempoolaccept_once(&rpc, &with_redeem_tx_hex)?;

    let fixture = P2shSeamFixture {
        name: "p2sh_core_seam".to_string(),
        network: "regtest".to_string(),
        redeem_script_hex: "5169".to_string(),
        context_heights: vec![173_804, 173_805],
        funding_outpoint: format!("{}:{}", funding_txid, funding_vout),
        missing_redeem_tx_hex,
        with_redeem_tx_hex,
        missing_redeem_core,
        with_redeem_core,
    };

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(out_path, serde_json::to_vec_pretty(&fixture)?)
        .with_context(|| format!("writing {}", out_path.display()))?;
    println!("minted p2sh seam fixture -> {}", out_path.display());
    Ok(())
}

fn mint_p2wpkh_seam(out_path: &Path) -> Result<()> {
    let report = doctor_report().map_err(|e| {
        anyhow!(
            "doctor failed: {e:#}\nSet BITCOIND_RPC_URL/USER/PASS and start regtest bitcoind first."
        )
    })?;
    if report.chain != "regtest" {
        return Err(anyhow!(
            "mint-p2wpkh-seam requires regtest, got {}",
            report.chain
        ));
    }
    let rpc = SimpleRpc::from_env()?;

    let seed = mint_seed_testcase("p2wpkh-seam-seed".to_string())?;
    let good_tx_hex = seed.tx_hex.clone();

    let mut parsed = parse_segwit_tx_one_input(&good_tx_hex)?;
    if parsed.witness_items.len() != 2 {
        return Err(anyhow!(
            "expected 2 witness items in seed tx, got {}",
            parsed.witness_items.len()
        ));
    }
    let pubkey = parsed.witness_items[1].clone();
    let program = hash160_cli(&pubkey);
    let mut script_pubkey = vec![0x00, 0x14];
    script_pubkey.extend_from_slice(&program);
    let script_pubkey_hex = hex::encode(&script_pubkey);

    parsed.witness_items = vec![parsed.witness_items[0].clone()];
    let bad_witness_shape_tx_hex = serialize_segwit_tx_one_input(&parsed);

    let mut parsed_mismatch = parse_segwit_tx_one_input(&good_tx_hex)?;
    if let Some(last) = parsed_mismatch.witness_items.get_mut(1) {
        if let Some(first) = last.first_mut() {
            *first ^= 0x01;
        } else {
            return Err(anyhow!("pubkey witness item empty"));
        }
    } else {
        return Err(anyhow!("missing pubkey witness item"));
    }
    let bad_program_mismatch_tx_hex = serialize_segwit_tx_one_input(&parsed_mismatch);

    let good_core = testmempoolaccept_once(&rpc, &good_tx_hex)?;
    let bad_witness_shape_core = testmempoolaccept_once(&rpc, &bad_witness_shape_tx_hex)?;
    let bad_program_mismatch_core = testmempoolaccept_once(&rpc, &bad_program_mismatch_tx_hex)?;

    let fixture = P2wpkhSeamFixture {
        name: "p2wpkh_core_seam".to_string(),
        network: "regtest".to_string(),
        context_heights: vec![481_823, 700_000],
        script_pubkey_hex: script_pubkey_hex.clone(),
        good_tx_hex,
        bad_witness_shape_tx_hex,
        bad_program_mismatch_tx_hex,
        good_core,
        bad_witness_shape_core,
        bad_program_mismatch_core,
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(out_path, serde_json::to_vec_pretty(&fixture)?)
        .with_context(|| format!("writing {}", out_path.display()))?;
    let manifest_path = PathBuf::from("fixtures/manifests/p2wpkh_core_seam_poc.json");
    write_p2wpkh_seam_manifest(&manifest_path, &script_pubkey_hex)?;
    println!("minted p2wpkh seam fixture -> {}", out_path.display());
    println!("minted p2wpkh seam manifest -> {}", manifest_path.display());
    Ok(())
}

fn mint_findanddelete_seam(out_path: &Path) -> Result<()> {
    let report = doctor_report().map_err(|e| {
        anyhow!(
            "doctor failed: {e:#}\nSet BITCOIND_RPC_URL/USER/PASS and start regtest bitcoind first."
        )
    })?;
    if report.chain != "regtest" {
        return Err(anyhow!(
            "mint-findanddelete-seam requires regtest, got {}",
            report.chain
        ));
    }

    let rpc = SimpleRpc::from_env()?;
    let wallet_name = "jb_legacy_ms";
    ensure_wallet_loaded_simple_with_descriptors(&rpc, wallet_name, false)?;
    let wallet = rpc.for_wallet(wallet_name);

    let mine_addr = wallet.call("getnewaddress", json!(["jb_fd_mining", "bech32"]))?;
    let mine_addr = mine_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing mining addr"))?
        .to_string();
    let block_count = rpc.call("getblockcount", json!([]))?.as_u64().unwrap_or(0);
    if block_count < 101 {
        wallet.call("generatetoaddress", json!([101 - block_count, mine_addr]))?;
    }

    let redeem_script_hex = "01aa01aa01bb52ae".to_string();
    let decoded = rpc.call("decodescript", json!([redeem_script_hex.clone()]))?;
    let p2sh_addr = decoded["p2sh"]
        .as_str()
        .ok_or_else(|| anyhow!("decodescript missing p2sh address"))?
        .to_string();
    let p2sh_spk = format!(
        "a914{}87",
        hex::encode(hash160_cli(&hex::decode(&redeem_script_hex)?))
    );

    let funding_txid = wallet.call("sendtoaddress", json!([p2sh_addr, 1.0]))?;
    let funding_txid = funding_txid
        .as_str()
        .ok_or_else(|| anyhow!("sendtoaddress missing txid"))?
        .to_string();

    let mining_addr = wallet.call("getnewaddress", json!(["jb_fd_confirm", "bech32"]))?;
    let mining_addr = mining_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing confirm addr"))?
        .to_string();
    wallet.call("generatetoaddress", json!([1, mining_addr]))?;

    let tx = wallet.call("gettransaction", json!([funding_txid, true, true]))?;
    let funding_hex = tx["hex"]
        .as_str()
        .ok_or_else(|| anyhow!("gettransaction missing hex"))?
        .to_string();
    let decoded_funding = rpc.call("decoderawtransaction", json!([funding_hex]))?;
    let vouts = decoded_funding["vout"]
        .as_array()
        .ok_or_else(|| anyhow!("decoderawtransaction missing vout"))?;
    let mut funding_vout = None::<u32>;
    let mut funding_sats = None::<u64>;
    for v in vouts {
        let spk_hex = v["scriptPubKey"]["hex"].as_str().unwrap_or_default();
        if spk_hex == p2sh_spk {
            funding_vout = v["n"].as_u64().map(|n| n as u32);
            funding_sats = v["value"]
                .as_f64()
                .map(|btc| (btc * 100_000_000.0).round() as u64);
            break;
        }
    }
    let funding_vout =
        funding_vout.ok_or_else(|| anyhow!("could not locate findanddelete funding output"))?;
    let funding_sats =
        funding_sats.ok_or_else(|| anyhow!("missing findanddelete funding output value"))?;
    if funding_sats <= 1_000 {
        return Err(anyhow!("funding output too small"));
    }

    let sink_addr = wallet.call("getnewaddress", json!(["jb_fd_sink", "bech32"]))?;
    let sink_addr = sink_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing sink addr"))?
        .to_string();
    let sink_info = wallet.call("getaddressinfo", json!([sink_addr]))?;
    let sink_spk = sink_info["scriptPubKey"]
        .as_str()
        .ok_or_else(|| anyhow!("getaddressinfo missing scriptPubKey"))?;
    let sink_spk = hex::decode(sink_spk).context("decode sink scriptPubKey hex")?;
    let spend_sats = funding_sats - 1_000;

    let redeem_script = hex::decode(&redeem_script_hex).context("decode redeem script")?;
    let subset_aabb_sig = build_push_only_scriptsig(&[&[0xaa], &[0xbb]], &redeem_script)?;
    let subset_aa_sig = build_push_only_scriptsig(&[&[0xaa]], &redeem_script)?;
    let subset_aaaa_sig = build_push_only_scriptsig(&[&[0xaa], &[0xaa]], &redeem_script)?;

    let subset_aabb_tx_hex = build_legacy_tx(
        &funding_txid,
        funding_vout,
        &subset_aabb_sig,
        spend_sats,
        &sink_spk,
    )?;
    let subset_aa_tx_hex = build_legacy_tx(
        &funding_txid,
        funding_vout,
        &subset_aa_sig,
        spend_sats,
        &sink_spk,
    )?;
    let subset_aaaa_tx_hex = build_legacy_tx(
        &funding_txid,
        funding_vout,
        &subset_aaaa_sig,
        spend_sats,
        &sink_spk,
    )?;

    let subset_aabb_core = testmempoolaccept_once(&rpc, &subset_aabb_tx_hex)?;
    let subset_aa_core = testmempoolaccept_once(&rpc, &subset_aa_tx_hex)?;
    let subset_aaaa_core = testmempoolaccept_once(&rpc, &subset_aaaa_tx_hex)?;

    let fixture = FindAndDeleteCoreSeamFixture {
        name: "p2sh_findanddelete_core_seam".to_string(),
        network: "regtest".to_string(),
        redeem_script_hex,
        funding_outpoint: format!("{}:{}", funding_txid, funding_vout),
        context_heights: vec![173_805],
        script_pubkey_hex: p2sh_spk.clone(),
        subset_aabb_tx_hex,
        subset_aa_tx_hex,
        subset_aaaa_tx_hex,
        subset_aabb_core,
        subset_aa_core,
        subset_aaaa_core,
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(out_path, serde_json::to_vec_pretty(&fixture)?)
        .with_context(|| format!("writing {}", out_path.display()))?;
    let manifest_path = PathBuf::from("fixtures/manifests/p2sh_findanddelete_core_seam_poc.json");
    write_findanddelete_core_manifest(&manifest_path, &p2sh_spk)?;
    let codeseparator_manifest_path =
        PathBuf::from("fixtures/manifests/p2sh_findanddelete_codeseparator_core_poc.json");
    write_findanddelete_codeseparator_manifest(&codeseparator_manifest_path, &p2sh_spk)?;
    let sighash_manifest_path =
        PathBuf::from("fixtures/manifests/p2sh_findanddelete_sighash_core_poc.json");
    write_findanddelete_sighash_manifest(&sighash_manifest_path, &p2sh_spk)?;
    println!(
        "minted findanddelete core seam fixture -> {}",
        out_path.display()
    );
    println!(
        "minted findanddelete core seam manifest -> {}",
        manifest_path.display()
    );
    println!(
        "minted findanddelete codeseparator manifest -> {}",
        codeseparator_manifest_path.display()
    );
    println!(
        "minted findanddelete sighash manifest -> {}",
        sighash_manifest_path.display()
    );
    Ok(())
}

fn mint_sighash_single_seam(out_path: &Path) -> Result<()> {
    let report = doctor_report().map_err(|e| {
        anyhow!(
            "doctor failed: {e:#}\nSet BITCOIND_RPC_URL/USER/PASS and start regtest bitcoind first."
        )
    })?;
    if report.chain != "regtest" {
        return Err(anyhow!(
            "mint-sighash-single-seam requires regtest, got {}",
            report.chain
        ));
    }

    let rpc = SimpleRpc::from_env()?;
    let wallet_name = "jb_legacy_ms";
    ensure_wallet_loaded_simple_with_descriptors(&rpc, wallet_name, false)?;
    let wallet = rpc.for_wallet(wallet_name);

    let mine_addr = wallet.call("getnewaddress", json!(["jb_sighash_mining", "bech32"]))?;
    let mine_addr = mine_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing mining addr"))?
        .to_string();
    let block_count = rpc.call("getblockcount", json!([]))?.as_u64().unwrap_or(0);
    if block_count < 101 {
        wallet.call("generatetoaddress", json!([101 - block_count, mine_addr]))?;
    }

    let legacy_addr = wallet.call("getnewaddress", json!(["jb_sighash_legacy", "legacy"]))?;
    let legacy_addr = legacy_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing legacy addr"))?
        .to_string();
    let legacy_info = wallet.call("getaddressinfo", json!([legacy_addr]))?;
    let script_code_hex = legacy_info["scriptPubKey"]
        .as_str()
        .ok_or_else(|| anyhow!("getaddressinfo missing scriptPubKey"))?
        .to_string();
    let script_code = hex::decode(&script_code_hex).context("decode script_code_hex")?;

    let funding_txid_a = wallet.call("sendtoaddress", json!([legacy_addr, 1.0]))?;
    let funding_txid_a = funding_txid_a
        .as_str()
        .ok_or_else(|| anyhow!("sendtoaddress A missing txid"))?
        .to_string();
    let funding_txid_b = wallet.call("sendtoaddress", json!([legacy_addr, 1.0]))?;
    let funding_txid_b = funding_txid_b
        .as_str()
        .ok_or_else(|| anyhow!("sendtoaddress B missing txid"))?
        .to_string();

    let confirm_addr = wallet.call("getnewaddress", json!(["jb_sighash_confirm", "bech32"]))?;
    let confirm_addr = confirm_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing confirm addr"))?
        .to_string();
    wallet.call("generatetoaddress", json!([1, confirm_addr]))?;

    let (vout_a, sats_a) =
        locate_output_by_script(&rpc, &wallet, &funding_txid_a, &script_code_hex)?;
    let (vout_b, sats_b) =
        locate_output_by_script(&rpc, &wallet, &funding_txid_b, &script_code_hex)?;
    let total_sats = sats_a + sats_b;
    if total_sats <= 2_000 {
        return Err(anyhow!("funding outputs too small"));
    }

    let sink_addr = wallet.call("getnewaddress", json!(["jb_sighash_sink", "bech32"]))?;
    let sink_addr = sink_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing sink addr"))?
        .to_string();
    let sink_info = wallet.call("getaddressinfo", json!([sink_addr]))?;
    let sink_spk = sink_info["scriptPubKey"]
        .as_str()
        .ok_or_else(|| anyhow!("getaddressinfo missing sink scriptPubKey"))?;
    let sink_spk = hex::decode(sink_spk).context("decode sink scriptPubKey")?;

    let spend_total = total_sats - 1_500;
    let single_bug_tx_hex = build_legacy_tx_multi(
        &[
            LegacyTxInputRef::empty(&funding_txid_a, vout_a),
            LegacyTxInputRef::empty(&funding_txid_b, vout_b),
        ],
        &[LegacyTxOutputRef::new(spend_total, &sink_spk)],
    )?;
    let single_bug_anyonecanpay_tx_hex = build_legacy_tx_multi(
        &[
            LegacyTxInputRef::empty(&funding_txid_a, vout_a),
            LegacyTxInputRef::empty(&funding_txid_b, vout_b),
        ],
        &[LegacyTxOutputRef::new(spend_total, &sink_spk)],
    )?;
    let single_control_tx_hex = build_legacy_tx_multi(
        &[
            LegacyTxInputRef::empty(&funding_txid_a, vout_a),
            LegacyTxInputRef::empty(&funding_txid_b, vout_b),
        ],
        &[
            LegacyTxOutputRef::new(spend_total - 1_000, &sink_spk),
            LegacyTxOutputRef::new(1_000, &script_code),
        ],
    )?;
    let single_control_anyonecanpay_tx_hex = single_control_tx_hex.clone();

    let single_bug_core = testmempoolaccept_once(&rpc, &single_bug_tx_hex)?;
    let single_bug_anyonecanpay_core =
        testmempoolaccept_once(&rpc, &single_bug_anyonecanpay_tx_hex)?;
    let single_control_core = testmempoolaccept_once(&rpc, &single_control_tx_hex)?;
    let single_control_anyonecanpay_core =
        testmempoolaccept_once(&rpc, &single_control_anyonecanpay_tx_hex)?;

    let fixture = SighashSingleSeamFixture {
        name: "sighash_single_core_seam".to_string(),
        network: "regtest".to_string(),
        funding_outpoints: vec![
            format!("{}:{}", funding_txid_a, vout_a),
            format!("{}:{}", funding_txid_b, vout_b),
        ],
        script_code_hex: script_code_hex.clone(),
        context_heights: vec![133_000, 300_000],
        single_bug_tx_hex,
        single_bug_anyonecanpay_tx_hex,
        single_control_tx_hex,
        single_control_anyonecanpay_tx_hex,
        single_bug_core,
        single_bug_anyonecanpay_core,
        single_control_core,
        single_control_anyonecanpay_core,
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(out_path, serde_json::to_vec_pretty(&fixture)?)
        .with_context(|| format!("writing {}", out_path.display()))?;
    let manifest_path = PathBuf::from("fixtures/manifests/sighash_single_core_seam_poc.json");
    write_sighash_single_manifest(&manifest_path, &script_code_hex)?;
    println!(
        "minted sighash single seam fixture -> {}",
        out_path.display()
    );
    println!(
        "minted sighash single seam manifest -> {}",
        manifest_path.display()
    );
    Ok(())
}

fn mint_dummygrind_seam(out_path: &Path) -> Result<()> {
    let report = doctor_report().map_err(|e| {
        anyhow!(
            "doctor failed: {e:#}\nSet BITCOIND_RPC_URL/USER/PASS and start regtest bitcoind first."
        )
    })?;
    if report.chain != "regtest" {
        return Err(anyhow!(
            "mint-dummygrind-seam requires regtest, got {}",
            report.chain
        ));
    }

    let rpc = SimpleRpc::from_env()?;
    let wallet_name = "jb_harness";
    ensure_wallet_loaded_simple_with_descriptors(&rpc, wallet_name, true)?;
    let wallet = rpc.for_wallet(wallet_name);

    let mine_addr = wallet.call("getnewaddress", json!(["jb_dummygrind_mining", "bech32"]))?;
    let mine_addr = mine_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing mining addr"))?
        .to_string();
    let block_count = rpc.call("getblockcount", json!([]))?.as_u64().unwrap_or(0);
    if block_count < 101 {
        wallet.call("generatetoaddress", json!([101 - block_count, mine_addr]))?;
    }

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0x11u8; 32]).context("dummygrind secret key")?;
    let pubkey = PublicKey::from_secret_key(&secp, &secret_key).serialize();
    let pubkey_hex = hex::encode(pubkey);
    let redeem_script_hex = format!("5121{}51ae", pubkey_hex);
    let decoded = rpc.call("decodescript", json!([redeem_script_hex.clone()]))?;
    let p2sh_addr = decoded["p2sh"]
        .as_str()
        .ok_or_else(|| anyhow!("decodescript missing p2sh address"))?
        .to_string();
    let p2sh_spk = format!(
        "a914{}87",
        hex::encode(hash160_cli(&hex::decode(&redeem_script_hex)?))
    );

    let funding_txid = wallet.call("sendtoaddress", json!([p2sh_addr, 1.0]))?;
    let funding_txid = funding_txid
        .as_str()
        .ok_or_else(|| anyhow!("sendtoaddress missing txid"))?
        .to_string();
    let confirm_addr = wallet.call("getnewaddress", json!(["jb_dummygrind_confirm", "bech32"]))?;
    let confirm_addr = confirm_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing confirm addr"))?
        .to_string();
    wallet.call("generatetoaddress", json!([1, confirm_addr]))?;
    let (funding_vout, funding_sats) =
        locate_output_by_script(&rpc, &wallet, &funding_txid, &p2sh_spk)?;
    if funding_sats <= 1_000 {
        return Err(anyhow!("funding output too small"));
    }

    let sink_addr = wallet.call("getnewaddress", json!(["jb_dummygrind_sink", "bech32"]))?;
    let sink_addr = sink_addr
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress missing sink addr"))?
        .to_string();
    let sink_info = wallet.call("getaddressinfo", json!([sink_addr]))?;
    let sink_spk = sink_info["scriptPubKey"]
        .as_str()
        .ok_or_else(|| anyhow!("getaddressinfo missing sink scriptPubKey"))?;
    let sink_spk = hex::decode(sink_spk).context("decode sink scriptPubKey")?;
    let spend_sats = funding_sats - 1_000;
    let sighash_type = 0x01u32;
    let digest = legacy_sighash_one_input_one_output(
        &funding_txid,
        funding_vout,
        &hex::decode(&redeem_script_hex).context("decode redeem script")?,
        spend_sats,
        &sink_spk,
        sighash_type,
    );
    let msg = Message::from_digest_slice(&digest).context("dummygrind message")?;
    let sig = secp.sign_ecdsa(&msg, &secret_key);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(sighash_type as u8);
    let redeem_script = hex::decode(&redeem_script_hex).context("decode redeem script")?;

    let dummy_empty_sig = build_push_only_scriptsig(&[&[], &sig_bytes], &redeem_script)?;
    let dummy_zero_sig = build_push_only_scriptsig(&[&[0x00], &sig_bytes], &redeem_script)?;
    let dummy_32 = vec![0x42; 32];
    let dummy_32_sig = build_push_only_scriptsig(&[&dummy_32, &sig_bytes], &redeem_script)?;

    let dummy_empty_tx_hex = build_legacy_tx(
        &funding_txid,
        funding_vout,
        &dummy_empty_sig,
        spend_sats,
        &sink_spk,
    )?;
    let dummy_zero_tx_hex = build_legacy_tx(
        &funding_txid,
        funding_vout,
        &dummy_zero_sig,
        spend_sats,
        &sink_spk,
    )?;
    let dummy_32_tx_hex = build_legacy_tx(
        &funding_txid,
        funding_vout,
        &dummy_32_sig,
        spend_sats,
        &sink_spk,
    )?;

    let dummy_empty_core = testmempoolaccept_once(&rpc, &dummy_empty_tx_hex)?;
    let dummy_zero_core = testmempoolaccept_once(&rpc, &dummy_zero_tx_hex)?;
    let dummy_32_core = testmempoolaccept_once(&rpc, &dummy_32_tx_hex)?;

    let fixture = DummygrindSeamFixture {
        name: "p2sh_dummygrind_core_seam".to_string(),
        network: "regtest".to_string(),
        redeem_script_hex,
        funding_outpoint: format!("{}:{}", funding_txid, funding_vout),
        script_pubkey_hex: p2sh_spk.clone(),
        context_heights: vec![170_000, 300_000],
        dummy_empty_tx_hex,
        dummy_zero_tx_hex,
        dummy_32_tx_hex,
        dummy_empty_core,
        dummy_zero_core,
        dummy_32_core,
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(out_path, serde_json::to_vec_pretty(&fixture)?)
        .with_context(|| format!("writing {}", out_path.display()))?;
    let manifest_path = PathBuf::from("fixtures/manifests/p2sh_dummygrind_core_seam_poc.json");
    write_dummygrind_manifest(&manifest_path, &p2sh_spk)?;
    println!("minted dummygrind seam fixture -> {}", out_path.display());
    println!(
        "minted dummygrind seam manifest -> {}",
        manifest_path.display()
    );
    Ok(())
}

fn write_p2wpkh_seam_manifest(path: &Path, script_pubkey_hex: &str) -> Result<()> {
    let manifest = json!({
      "name": "p2wpkh_core_seam_poc",
      "windows": [
        {
          "name": "p2wpkh-shape-h481823",
          "start_height": 481823,
          "end_height": 481823,
          "representative_heights": [481823],
          "epoch": "segwit-active"
        },
        {
          "name": "p2wpkh-shape-h700000",
          "start_height": 700000,
          "end_height": 700000,
          "representative_heights": [700000],
          "epoch": "segwit-active"
        }
      ],
      "fixtures": [
        {
          "id": "p2wpkh_good",
          "description": "Wallet-signed P2WPKH spend (control)",
          "window": "p2wpkh-shape-h700000",
          "tx_hex_blob": "../blobs/p2wpkh-core-seam.json",
          "tx_hex_field": "good_tx_hex",
          "spend_type": "p2wpkh",
          "metadata": {
            "quirk_target": "segwit-shape-seam",
            "checksighook": "true",
            "script_pubkey_hex": script_pubkey_hex
          }
        },
        {
          "id": "p2wpkh_bad_witness_shape",
          "description": "Witness stack shape mutation",
          "window": "p2wpkh-shape-h481823",
          "tx_hex_blob": "../blobs/p2wpkh-core-seam.json",
          "tx_hex_field": "bad_witness_shape_tx_hex",
          "spend_type": "p2wpkh",
          "metadata": {
            "quirk_target": "segwit-shape-seam",
            "checksighook": "true",
            "script_pubkey_hex": script_pubkey_hex
          }
        },
        {
          "id": "p2wpkh_bad_program_mismatch",
          "description": "Witness pubkey/program mismatch mutation",
          "window": "p2wpkh-shape-h700000",
          "tx_hex_blob": "../blobs/p2wpkh-core-seam.json",
          "tx_hex_field": "bad_program_mismatch_tx_hex",
          "spend_type": "p2wpkh",
          "metadata": {
            "quirk_target": "segwit-shape-seam",
            "checksighook": "true",
            "script_pubkey_hex": script_pubkey_hex
          }
        }
      ]
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_findanddelete_core_manifest(path: &Path, script_pubkey_hex: &str) -> Result<()> {
    let manifest = json!({
      "name": "p2sh_findanddelete_core_seam_poc",
      "windows": [
        {
          "name": "findanddelete-core-aabb-h173805",
          "start_height": 173805,
          "end_height": 173805,
          "representative_heights": [173805],
          "epoch": "post-bip16-pre-bip34"
        },
        {
          "name": "findanddelete-core-aa-h173805",
          "start_height": 173805,
          "end_height": 173805,
          "representative_heights": [173805],
          "epoch": "post-bip16-pre-bip34"
        },
        {
          "name": "findanddelete-core-aaaa-h173805",
          "start_height": 173805,
          "end_height": 173805,
          "representative_heights": [173805],
          "epoch": "post-bip16-pre-bip34"
        }
      ],
      "fixtures": [
        {
          "id": "findanddelete_core_aabb",
          "description": "Regtest-funded subset [aa,bb] specimen",
          "window": "findanddelete-core-aabb-h173805",
          "tx_hex_blob": "../blobs/p2sh-findanddelete-core-seam.json",
          "tx_hex_field": "subset_aabb_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "checkmultisig-findanddelete-core",
            "findanddelete_hook": "true",
            "checksighook": "false",
            "codeseparator_pos": "-1",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        },
        {
          "id": "findanddelete_core_aa",
          "description": "Regtest-funded subset [aa] specimen",
          "window": "findanddelete-core-aa-h173805",
          "tx_hex_blob": "../blobs/p2sh-findanddelete-core-seam.json",
          "tx_hex_field": "subset_aa_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "checkmultisig-findanddelete-core",
            "findanddelete_hook": "true",
            "checksighook": "false",
            "codeseparator_pos": "-1",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        },
        {
          "id": "findanddelete_core_aaaa",
          "description": "Regtest-funded subset [aa,aa] specimen",
          "window": "findanddelete-core-aaaa-h173805",
          "tx_hex_blob": "../blobs/p2sh-findanddelete-core-seam.json",
          "tx_hex_field": "subset_aaaa_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "checkmultisig-findanddelete-core",
            "findanddelete_hook": "true",
            "checksighook": "false",
            "codeseparator_pos": "-1",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        }
      ]
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_findanddelete_codeseparator_manifest(path: &Path, script_pubkey_hex: &str) -> Result<()> {
    let manifest = json!({
      "name": "p2sh_findanddelete_codeseparator_core_poc",
      "windows": [
        {
          "name": "findanddelete-codeseparator-neg1-h173805",
          "start_height": 173805,
          "end_height": 173805,
          "representative_heights": [173805],
          "epoch": "post-bip16-pre-bip34"
        },
        {
          "name": "findanddelete-codeseparator-3-h173805",
          "start_height": 173805,
          "end_height": 173805,
          "representative_heights": [173805],
          "epoch": "post-bip16-pre-bip34"
        }
      ],
      "fixtures": [
        {
          "id": "findanddelete_codeseparator_neg1",
          "description": "Regtest-funded subset [aa,bb], CODESEPARATOR position -1",
          "window": "findanddelete-codeseparator-neg1-h173805",
          "tx_hex_blob": "../blobs/p2sh-findanddelete-core-seam.json",
          "tx_hex_field": "subset_aabb_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "checkmultisig-findanddelete-codeseparator",
            "findanddelete_hook": "true",
            "checksighook": "false",
            "codeseparator_pos": "-1",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        },
        {
          "id": "findanddelete_codeseparator_3",
          "description": "Regtest-funded subset [aa,bb], CODESEPARATOR position 3",
          "window": "findanddelete-codeseparator-3-h173805",
          "tx_hex_blob": "../blobs/p2sh-findanddelete-core-seam.json",
          "tx_hex_field": "subset_aabb_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "checkmultisig-findanddelete-codeseparator",
            "findanddelete_hook": "true",
            "checksighook": "false",
            "codeseparator_pos": "3",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        }
      ]
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_findanddelete_sighash_manifest(path: &Path, script_pubkey_hex: &str) -> Result<()> {
    let manifest = json!({
      "name": "p2sh_findanddelete_sighash_core_poc",
      "windows": [
        {
          "name": "findanddelete-sighash-all-h173805",
          "start_height": 173805,
          "end_height": 173805,
          "representative_heights": [173805],
          "epoch": "post-bip16-pre-bip34"
        },
        {
          "name": "findanddelete-sighash-none-h173805",
          "start_height": 173805,
          "end_height": 173805,
          "representative_heights": [173805],
          "epoch": "post-bip16-pre-bip34"
        }
      ],
      "fixtures": [
        {
          "id": "findanddelete_sighash_all",
          "description": "Regtest-funded subset [aa,bb], sighash ALL",
          "window": "findanddelete-sighash-all-h173805",
          "tx_hex_blob": "../blobs/p2sh-findanddelete-core-seam.json",
          "tx_hex_field": "subset_aabb_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "checkmultisig-findanddelete-sighash",
            "findanddelete_hook": "true",
            "checksighook": "false",
            "codeseparator_pos": "-1",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        },
        {
          "id": "findanddelete_sighash_none",
          "description": "Regtest-funded subset [aa,bb], sighash NONE",
          "window": "findanddelete-sighash-none-h173805",
          "tx_hex_blob": "../blobs/p2sh-findanddelete-core-seam.json",
          "tx_hex_field": "subset_aabb_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "checkmultisig-findanddelete-sighash",
            "findanddelete_hook": "true",
            "checksighook": "false",
            "codeseparator_pos": "-1",
            "sighash_type": "0x02",
            "script_pubkey_hex": script_pubkey_hex
          }
        }
      ]
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_sighash_single_manifest(path: &Path, script_code_hex: &str) -> Result<()> {
    let manifest = json!({
      "name": "sighash_single_core_seam_poc",
      "windows": [
        {
          "name": "sighash-single-bug-h133000",
          "start_height": 133000,
          "end_height": 133000,
          "representative_heights": [133000],
          "epoch": "pre-bip16"
        },
        {
          "name": "sighash-single-bug-acp-h133000",
          "start_height": 133000,
          "end_height": 133000,
          "representative_heights": [133000],
          "epoch": "pre-bip16"
        },
        {
          "name": "sighash-single-control-h300000",
          "start_height": 300000,
          "end_height": 300000,
          "representative_heights": [300000],
          "epoch": "post-bip34"
        },
        {
          "name": "sighash-single-control-acp-h300000",
          "start_height": 300000,
          "end_height": 300000,
          "representative_heights": [300000],
          "epoch": "post-bip34"
        }
      ],
      "fixtures": [
        {
          "id": "sighash_single_bug",
          "description": "Two-input one-output SINGLE bug specimen",
          "window": "sighash-single-bug-h133000",
          "tx_hex_blob": "../blobs/sighash-single-core-seam.json",
          "tx_hex_field": "single_bug_tx_hex",
          "spend_type": "legacy_sighash",
          "metadata": {
            "quirk_target": "sighash-single-degeneracy",
            "input_index": "1",
            "sighash_type": "0x03",
            "script_code_hex": script_code_hex
          }
        },
        {
          "id": "sighash_single_bug_anyonecanpay",
          "description": "Two-input one-output SINGLE|ANYONECANPAY bug specimen",
          "window": "sighash-single-bug-acp-h133000",
          "tx_hex_blob": "../blobs/sighash-single-core-seam.json",
          "tx_hex_field": "single_bug_anyonecanpay_tx_hex",
          "spend_type": "legacy_sighash",
          "metadata": {
            "quirk_target": "sighash-single-degeneracy",
            "input_index": "1",
            "sighash_type": "0x83",
            "script_code_hex": script_code_hex
          }
        },
        {
          "id": "sighash_single_control",
          "description": "Two-input two-output SINGLE control specimen",
          "window": "sighash-single-control-h300000",
          "tx_hex_blob": "../blobs/sighash-single-core-seam.json",
          "tx_hex_field": "single_control_tx_hex",
          "spend_type": "legacy_sighash",
          "metadata": {
            "quirk_target": "sighash-single-degeneracy",
            "input_index": "1",
            "sighash_type": "0x03",
            "script_code_hex": script_code_hex
          }
        },
        {
          "id": "sighash_single_control_anyonecanpay",
          "description": "Two-input two-output SINGLE|ANYONECANPAY control specimen",
          "window": "sighash-single-control-acp-h300000",
          "tx_hex_blob": "../blobs/sighash-single-core-seam.json",
          "tx_hex_field": "single_control_anyonecanpay_tx_hex",
          "spend_type": "legacy_sighash",
          "metadata": {
            "quirk_target": "sighash-single-degeneracy",
            "input_index": "1",
            "sighash_type": "0x83",
            "script_code_hex": script_code_hex
          }
        }
      ]
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_dummygrind_manifest(path: &Path, script_pubkey_hex: &str) -> Result<()> {
    let manifest = json!({
      "name": "p2sh_dummygrind_core_seam_poc",
      "windows": [
        {
          "name": "dummygrind-empty-h170000",
          "start_height": 170000,
          "end_height": 170000,
          "representative_heights": [170000],
          "epoch": "pre-bip16"
        },
        {
          "name": "dummygrind-zero-h300000",
          "start_height": 300000,
          "end_height": 300000,
          "representative_heights": [300000],
          "epoch": "post-bip34"
        },
        {
          "name": "dummygrind-32-h300000",
          "start_height": 300000,
          "end_height": 300000,
          "representative_heights": [300000],
          "epoch": "post-bip34"
        }
      ],
      "fixtures": [
        {
          "id": "dummygrind_empty",
          "description": "Funded multisig control with empty dummy",
          "window": "dummygrind-empty-h170000",
          "tx_hex_blob": "../blobs/p2sh-dummygrind-core-seam.json",
          "tx_hex_field": "dummy_empty_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "dummygrind-txid-axis",
            "dummygrind_hook": "true",
            "checksighook": "true",
            "input_index": "0",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        },
        {
          "id": "dummygrind_zero",
          "description": "Funded multisig variant with one-byte zero dummy",
          "window": "dummygrind-zero-h300000",
          "tx_hex_blob": "../blobs/p2sh-dummygrind-core-seam.json",
          "tx_hex_field": "dummy_zero_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "dummygrind-txid-axis",
            "dummygrind_hook": "true",
            "checksighook": "true",
            "input_index": "0",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        },
        {
          "id": "dummygrind_32",
          "description": "Funded multisig variant with 32-byte dummy",
          "window": "dummygrind-32-h300000",
          "tx_hex_blob": "../blobs/p2sh-dummygrind-core-seam.json",
          "tx_hex_field": "dummy_32_tx_hex",
          "spend_type": "p2sh",
          "metadata": {
            "quirk_target": "dummygrind-txid-axis",
            "dummygrind_hook": "true",
            "checksighook": "true",
            "input_index": "0",
            "sighash_type": "0x01",
            "script_pubkey_hex": script_pubkey_hex
          }
        }
      ]
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn doctor() -> Result<()> {
    let report = doctor_report()?;
    println!("doctor: ok");
    println!("rpc_url={}", report.rpc_url);
    println!("chain={}", report.chain);
    println!(
        "wallet={} ready={}",
        report.wallet_name, report.wallet_ready
    );
    println!("state_path={}", report.state_path.display());
    println!(
        "funding_outpoint={}",
        report
            .funding_outpoint
            .as_deref()
            .unwrap_or("<missing in state file>")
    );
    println!("funding_outpoint_exists={}", report.funding_outpoint_exists);
    println!("suggested_start_command={}", report.suggested_start_command);
    Ok(())
}

#[derive(serde::Serialize)]
struct ReplaySummary {
    checked: usize,
    divergences: usize,
}

#[derive(serde::Serialize)]
struct DemoSummary {
    total_iterations: usize,
    divergences_found: usize,
    counts_by_normalized_class: BTreeMap<String, usize>,
    seed_path: String,
    best_event_path: Option<String>,
    reduced_testcase_path: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ReasonCount {
    reason: String,
    count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SummaryOutput {
    total_events: usize,
    scanned_files: usize,
    parsed_events: usize,
    malformed_files: usize,
    counts_by_normalized_class: BTreeMap<String, usize>,
    counts_by_core_reason: BTreeMap<String, usize>,
    top_core_reasons: Vec<ReasonCount>,
    policy_allowed_count: usize,
    policy_rejected_count: usize,
    counts_by_policy_reason: BTreeMap<String, usize>,
    top_policy_reasons: Vec<ReasonCount>,
    counts_by_rust_reason: BTreeMap<String, usize>,
    mutation_histogram: BTreeMap<String, usize>,
    unique_core_reason_count: usize,
    unique_mutation_count: usize,
    interestingness_score: usize,
}

fn demo_run(
    out_dir: &Path,
    iterations: usize,
    seed: u64,
    force: bool,
    _corpus: &Path,
) -> Result<()> {
    let report = doctor_report().map_err(|e| {
        anyhow!(
            "doctor failed: {e:#}\nRun this first:\n  cargo run -p jurassic-bitcoin-cli -- doctor"
        )
    })?;
    println!(
        "doctor: ok chain={} rpc_url={}",
        report.chain, report.rpc_url
    );

    prepare_out_dir(out_dir, force)?;
    let events_dir = out_dir.join("events");
    let reduced_dir = out_dir.join("reduced");
    fs::create_dir_all(&events_dir)
        .with_context(|| format!("creating {}", events_dir.display()))?;
    fs::create_dir_all(&reduced_dir)
        .with_context(|| format!("creating {}", reduced_dir.display()))?;

    let seed_path = out_dir.join("seed-p2wpkh.json");
    let seed_case = mint_seed_testcase("seed-p2wpkh".to_string())?;
    fs::write(&seed_path, serde_json::to_vec_pretty(&seed_case)?)
        .with_context(|| format!("writing {}", seed_path.display()))?;

    let mut checked = 0usize;
    let mut replay_divergences = 0usize;
    let mut all_events: Vec<(DivergenceEvent, TestCase, PathBuf)> = Vec::new();

    checked += 1;
    let core = run_testcase_core(&seed_case);
    let rust = run_testcase_rust(&seed_case);
    if let Some(event) = diff_results(&seed_case, &core, &rust) {
        replay_divergences += 1;
        let path = write_divergence_event(&events_dir, &event, &seed_case)?;
        all_events.push((event, seed_case.clone(), path));
    }

    let replay_summary = ReplaySummary {
        checked,
        divergences: replay_divergences,
    };
    let replay_summary_path = out_dir.join("replay-summary.json");
    fs::write(
        &replay_summary_path,
        serde_json::to_vec_pretty(&replay_summary)?,
    )
    .with_context(|| format!("writing {}", replay_summary_path.display()))?;

    let mut rng = StdRng::seed_from_u64(seed);
    let mut class_counts: BTreeMap<String, usize> = BTreeMap::new();
    for _ in 0..iterations {
        let mut_result = mutate_testcase_with_trace(&seed_case, &mut rng);
        let mutated = mut_result.testcase;
        let core = run_testcase_core(&mutated);
        let rust = run_testcase_rust(&mutated);
        if let Some(mut event) = diff_results(&mutated, &core, &rust) {
            event.mutations_applied = mut_result.mutations_applied;
            *class_counts
                .entry(event.normalized_class.clone())
                .or_insert(0) += 1;
            let path = write_divergence_event(&events_dir, &event, &mutated)?;
            all_events.push((event, mutated, path));
        }
    }

    let best_idx = all_events
        .iter()
        .position(|(e, _, _)| e.normalized_class != "UNCLASSIFIED")
        .or_else(|| all_events.first().map(|_| 0usize));

    let mut reduced_path: Option<PathBuf> = None;
    let mut best_event_path: Option<PathBuf> = None;
    if let Some(idx) = best_idx {
        let (event, case, event_path) = &all_events[idx];
        best_event_path = Some(event_path.clone());
        let reduced = reduce_divergence(case);
        let out = reduced_dir.join(format!("{}.json", reduced.id));
        fs::write(&out, serde_json::to_vec_pretty(&reduced)?)
            .with_context(|| format!("writing {}", out.display()))?;
        reduced_path = Some(out);
        println!(
            "best divergence: {} class={}",
            event.testcase_id, event.normalized_class
        );
    }

    let summary = DemoSummary {
        total_iterations: iterations,
        divergences_found: all_events.len(),
        counts_by_normalized_class: class_counts.clone(),
        seed_path: seed_path.display().to_string(),
        best_event_path: best_event_path.as_ref().map(|p| p.display().to_string()),
        reduced_testcase_path: reduced_path.as_ref().map(|p| p.display().to_string()),
    };
    let summary_path = out_dir.join("demo-summary.json");
    fs::write(&summary_path, serde_json::to_vec_pretty(&summary)?)
        .with_context(|| format!("writing {}", summary_path.display()))?;

    println!("demo summary:");
    println!("iterations={}", iterations);
    println!("divergences_found={}", all_events.len());
    println!("counts_by_normalized_class={:?}", class_counts);
    println!("seed={}", seed_path.display());
    println!(
        "best_event={}",
        best_event_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".to_string())
    );
    println!(
        "reduced={}",
        reduced_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".to_string())
    );
    println!("bundle={}", out_dir.display());
    Ok(())
}

fn prepare_out_dir(out_dir: &Path, force: bool) -> Result<()> {
    if out_dir.exists() {
        let has_entries = fs::read_dir(out_dir)
            .with_context(|| format!("reading {}", out_dir.display()))?
            .next()
            .is_some();
        if has_entries && !force {
            return Err(anyhow!(
                "out-dir {} is not empty; use --force to overwrite",
                out_dir.display()
            ));
        }
        if force {
            fs::remove_dir_all(out_dir)
                .with_context(|| format!("removing {}", out_dir.display()))?;
        }
    }
    fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    Ok(())
}

fn replay_era(
    manifest_path: &Path,
    out_dir: &Path,
    limit_per_epoch: usize,
    rpc_fetch: bool,
    force: bool,
) -> Result<()> {
    prepare_out_dir(out_dir, force)?;
    let manifest = load_manifest(manifest_path)?;
    let fixtures = materialize_fixtures(
        manifest_path,
        &manifest,
        &FixtureOptions {
            rpc_fetch,
            cache_dir: default_cache_dir(),
            limit_per_epoch,
        },
    )?;

    let mut fixtures_by_window: BTreeMap<String, Vec<jb_fixtures::MaterializedFixture>> =
        BTreeMap::new();
    for fixture in fixtures {
        fixtures_by_window
            .entry(fixture.window.clone())
            .or_default()
            .push(fixture);
    }

    for (window, cases) in fixtures_by_window {
        let epoch_dir = out_dir.join(&window);
        fs::create_dir_all(&epoch_dir)
            .with_context(|| format!("creating {}", epoch_dir.display()))?;
        let events_dir = epoch_dir.join("events");
        fs::create_dir_all(&events_dir)
            .with_context(|| format!("creating {}", events_dir.display()))?;

        let mut checked = 0usize;
        let mut divergences = 0usize;
        for case in cases {
            checked += 1;
            let inferred_epoch = epoch_for_height(case.height).label().to_string();
            let epoch_label = case.epoch.clone().unwrap_or(inferred_epoch);
            let context = ValidationContext {
                height: case.height,
                median_time_past: None,
                block_time: None,
                epoch: Some(epoch_label.clone()),
            };
            let profile_flags = flags_for_context(&ProfileContextView {
                height: case.height,
                median_time_past: context.median_time_past,
                block_time: context.block_time,
                epoch: context.epoch.clone(),
            });

            let mut metadata = case.metadata.clone();
            metadata.insert("fixture_window".to_string(), case.window.clone());
            metadata.insert("manifest_name".to_string(), manifest.name.clone());
            metadata.insert("consensus_epoch".to_string(), epoch_label);
            metadata.insert("consensus_flags".to_string(), profile_flags.join(","));

            let testcase = TestCase {
                id: format!("{}-h{}", case.id, case.height),
                description: case.description,
                network: "mainnet".to_string(),
                utxo_set: Vec::new(),
                tx_hex: case.tx_hex,
                flags: profile_flags,
                context: Some(context),
                core_template: Some(CoreTemplate {
                    kind: "testmempoolaccept_tx_hex".to_string(),
                    spend_type: case.spend_type,
                    feerate_sats_vb: None,
                }),
                metadata,
            };

            let core = run_testcase_core(&testcase);
            let rust = run_testcase_rust(&testcase);
            if let Some(event) = diff_results(&testcase, &core, &rust) {
                divergences += 1;
                let _ = write_divergence_event(&events_dir, &event, &testcase)?;
            }
        }

        let replay_summary = ReplaySummary {
            checked,
            divergences,
        };
        let replay_summary_path = epoch_dir.join("replay-summary.json");
        fs::write(
            &replay_summary_path,
            serde_json::to_vec_pretty(&replay_summary)?,
        )
        .with_context(|| format!("writing {}", replay_summary_path.display()))?;

        let summary = summarize_dir_offline(&epoch_dir)?;
        let summary_path = epoch_dir.join("summary.json");
        fs::write(&summary_path, serde_json::to_vec_pretty(&summary)?)
            .with_context(|| format!("writing {}", summary_path.display()))?;

        println!(
            "epoch={} checked={} divergences={} summary={}",
            window,
            checked,
            divergences,
            summary_path.display()
        );
    }
    Ok(())
}

fn fetch_fixtures(manifest_path: &Path, out_index: &Path, strict: bool) -> Result<()> {
    let manifest = load_manifest(manifest_path)?;
    let cache_dir = default_cache_dir();
    let report = fetch_txid_fixtures(&manifest, &cache_dir)?;

    if let Some(parent) = out_index.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(out_index, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("writing {}", out_index.display()))?;

    print_fetch_report(&report, out_index);
    if strict && report.failed > 0 {
        return Err(anyhow!(
            "strict mode: {} txid fetches failed (see {})",
            report.failed,
            out_index.display()
        ));
    }
    Ok(())
}

fn print_fetch_report(report: &FetchReport, out_index: &Path) {
    println!("fetch_manifest={}", report.manifest_name);
    println!("cache_dir={}", report.cache_dir);
    println!(
        "txids_total={} fetched={} cached={} failed={}",
        report.total_txids, report.fetched, report.cached, report.failed
    );
    println!("fetch_index={}", out_index.display());
}

fn extract_era(
    start_height: u32,
    end_height: u32,
    limit_per_height: usize,
    out_corpus: &Path,
    force: bool,
) -> Result<()> {
    if start_height > end_height {
        return Err(anyhow!("start-height must be <= end-height"));
    }
    prepare_out_dir(out_corpus, force)?;
    let rpc = SimpleRpc::from_env()?;

    let mut written = 0usize;
    for height in start_height..=end_height {
        let block_hash = match rpc.call("getblockhash", json!([height])) {
            Ok(v) => match v.as_str() {
                Some(s) => s.to_string(),
                None => continue,
            },
            Err(_) => continue,
        };
        let block = match rpc.call("getblock", json!([block_hash, 2])) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let txs = block["tx"].as_array().cloned().unwrap_or_default();
        for (idx, tx) in txs.into_iter().take(limit_per_height).enumerate() {
            let tx_hex = match tx["hex"].as_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let txid = tx["txid"].as_str().unwrap_or("unknown").to_string();
            let id = format!("mainnet-h{}-tx{:04}", height, idx);
            let mut metadata = BTreeMap::new();
            metadata.insert("source".to_string(), "mainnet-block".to_string());
            metadata.insert("block_hash".to_string(), block_hash.clone());
            metadata.insert("txid".to_string(), txid);
            let tc = TestCase {
                id: id.clone(),
                description: format!("Extracted mainnet tx at height {}", height),
                network: "mainnet".to_string(),
                utxo_set: Vec::new(),
                tx_hex,
                flags: Vec::new(),
                context: Some(ValidationContext {
                    height,
                    median_time_past: None,
                    block_time: None,
                    epoch: None,
                }),
                core_template: Some(jb_model::CoreTemplate {
                    kind: "decode_tx_hex".to_string(),
                    spend_type: "rawtx".to_string(),
                    feerate_sats_vb: None,
                }),
                metadata,
            };
            let path = out_corpus.join(format!("{id}.json"));
            fs::write(&path, serde_json::to_vec_pretty(&tc)?)
                .with_context(|| format!("writing {}", path.display()))?;
            written += 1;
        }
    }
    println!(
        "extracted_testcases={} out={}",
        written,
        out_corpus.display()
    );
    Ok(())
}

#[derive(Clone)]
struct SimpleRpc {
    url: String,
    user: String,
    pass: String,
}

#[derive(Debug, Deserialize)]
struct SimpleRpcResponse {
    result: Option<Value>,
    error: Option<SimpleRpcErr>,
}

#[derive(Debug, Deserialize)]
struct SimpleRpcErr {
    code: i64,
    message: String,
}

impl SimpleRpc {
    fn from_env() -> Result<Self> {
        Ok(Self {
            url: std::env::var("BITCOIND_RPC_URL")
                .context("missing BITCOIND_RPC_URL (example: http://127.0.0.1:8332)")?,
            user: std::env::var("BITCOIND_RPC_USER").context("missing BITCOIND_RPC_USER")?,
            pass: std::env::var("BITCOIND_RPC_PASS").context("missing BITCOIND_RPC_PASS")?,
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let req = json!({
            "jsonrpc":"1.0",
            "id":"jb",
            "method": method,
            "params": params
        });
        let auth = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.user, self.pass))
        );
        let resp: SimpleRpcResponse = ureq::post(&self.url)
            .set("content-type", "text/plain")
            .set("authorization", &auth)
            .send_json(req)
            .with_context(|| format!("rpc call failed: {method}"))?
            .into_json()
            .with_context(|| format!("rpc decode failed: {method}"))?;
        if let Some(err) = resp.error {
            return Err(anyhow!("rpc {method} error {}: {}", err.code, err.message));
        }
        resp.result
            .ok_or_else(|| anyhow!("rpc {method} returned null result"))
    }

    fn for_wallet(&self, wallet: &str) -> Self {
        Self {
            url: format!("{}/wallet/{}", self.url.trim_end_matches('/'), wallet),
            user: self.user.clone(),
            pass: self.pass.clone(),
        }
    }
}

fn ensure_wallet_loaded_simple_with_descriptors(
    rpc: &SimpleRpc,
    wallet: &str,
    descriptors: bool,
) -> Result<()> {
    let wallets = rpc.call("listwallets", json!([]))?;
    let loaded = wallets
        .as_array()
        .map(|arr| arr.iter().any(|w| w.as_str() == Some(wallet)))
        .unwrap_or(false);
    if loaded {
        return Ok(());
    }
    match rpc.call("loadwallet", json!([wallet])) {
        Ok(_) => Ok(()),
        Err(load_err) => {
            match rpc.call(
                "createwallet",
                json!([wallet, false, false, "", false, false, descriptors]),
            ) {
                Ok(_) => Ok(()),
                Err(create_err) => rpc.call("loadwallet", json!([wallet])).map(|_| ()).map_err(
                    |_| {
                        anyhow!(
                            "loadwallet failed: {load_err:#}; createwallet failed: {create_err:#}"
                        )
                    },
                ),
            }
        }
    }
}

fn build_legacy_tx(
    prev_txid_hex: &str,
    prev_vout: u32,
    script_sig: &[u8],
    output_sats: u64,
    output_spk: &[u8],
) -> Result<String> {
    let input = LegacyTxInputRef {
        prev_txid_hex: prev_txid_hex.to_string(),
        prev_vout,
        script_sig: script_sig.to_vec(),
        sequence: 0xffff_ffff,
    };
    let output = LegacyTxOutputRef::new(output_sats, output_spk);
    build_legacy_tx_multi(&[input], &[output])
}

#[derive(Debug, Clone)]
struct LegacyTxInputRef {
    prev_txid_hex: String,
    prev_vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

impl LegacyTxInputRef {
    fn empty(prev_txid_hex: &str, prev_vout: u32) -> Self {
        Self {
            prev_txid_hex: prev_txid_hex.to_string(),
            prev_vout,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        }
    }
}

#[derive(Debug, Clone)]
struct LegacyTxOutputRef {
    value_sats: u64,
    script_pubkey: Vec<u8>,
}

impl LegacyTxOutputRef {
    fn new(value_sats: u64, script_pubkey: &[u8]) -> Self {
        Self {
            value_sats,
            script_pubkey: script_pubkey.to_vec(),
        }
    }
}

fn build_legacy_tx_multi(
    inputs: &[LegacyTxInputRef],
    outputs: &[LegacyTxOutputRef],
) -> Result<String> {
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_le_bytes()); // version
    out.extend_from_slice(&encode_varint(inputs.len() as u64));
    for input in inputs {
        let mut txid = hex::decode(&input.prev_txid_hex).context("decode prev txid")?;
        if txid.len() != 32 {
            return Err(anyhow!("prev txid must be 32 bytes"));
        }
        txid.reverse();
        out.extend_from_slice(&txid);
        out.extend_from_slice(&input.prev_vout.to_le_bytes());
        out.extend_from_slice(&encode_varint(input.script_sig.len() as u64));
        out.extend_from_slice(&input.script_sig);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }

    out.extend_from_slice(&encode_varint(outputs.len() as u64));
    for output in outputs {
        out.extend_from_slice(&output.value_sats.to_le_bytes());
        out.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
        out.extend_from_slice(&output.script_pubkey);
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // locktime
    Ok(hex::encode(out))
}

fn locate_output_by_script(
    rpc: &SimpleRpc,
    wallet: &SimpleRpc,
    txid: &str,
    script_pubkey_hex: &str,
) -> Result<(u32, u64)> {
    let tx = wallet.call("gettransaction", json!([txid, true, true]))?;
    let funding_hex = tx["hex"]
        .as_str()
        .ok_or_else(|| anyhow!("gettransaction missing hex"))?
        .to_string();
    let decoded_funding = rpc.call("decoderawtransaction", json!([funding_hex]))?;
    let vouts = decoded_funding["vout"]
        .as_array()
        .ok_or_else(|| anyhow!("decoderawtransaction missing vout"))?;
    for v in vouts {
        let spk_hex = v["scriptPubKey"]["hex"].as_str().unwrap_or_default();
        if spk_hex == script_pubkey_hex {
            let vout = v["n"]
                .as_u64()
                .ok_or_else(|| anyhow!("funding output missing n"))? as u32;
            let sats = v["value"]
                .as_f64()
                .map(|btc| (btc * 100_000_000.0).round() as u64)
                .ok_or_else(|| anyhow!("funding output missing value"))?;
            return Ok((vout, sats));
        }
    }
    Err(anyhow!("could not locate funding output for script"))
}

fn legacy_sighash_one_input_one_output(
    prev_txid_hex: &str,
    prev_vout: u32,
    script_code: &[u8],
    output_sats: u64,
    output_spk: &[u8],
    sighash_type: u32,
) -> [u8; 32] {
    let mut ser = Vec::new();
    ser.extend_from_slice(&1u32.to_le_bytes());
    ser.extend_from_slice(&encode_varint(1));
    let mut txid = hex::decode(prev_txid_hex).unwrap_or_default();
    txid.reverse();
    ser.extend_from_slice(&txid);
    ser.extend_from_slice(&prev_vout.to_le_bytes());
    ser.extend_from_slice(&encode_varint(script_code.len() as u64));
    ser.extend_from_slice(script_code);
    ser.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    ser.extend_from_slice(&encode_varint(1));
    ser.extend_from_slice(&output_sats.to_le_bytes());
    ser.extend_from_slice(&encode_varint(output_spk.len() as u64));
    ser.extend_from_slice(output_spk);
    ser.extend_from_slice(&0u32.to_le_bytes());
    ser.extend_from_slice(&sighash_type.to_le_bytes());
    let first = Sha256::digest(&ser);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn build_push_only_scriptsig(pushes: &[&[u8]], redeem_script: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for push in pushes {
        append_pushdata(&mut out, push)?;
    }
    append_pushdata(&mut out, redeem_script)?;
    Ok(out)
}

fn append_pushdata(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    match data.len() {
        0 => out.push(0x00),
        1..=75 => {
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        76..=0xff => {
            out.push(0x4c);
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        0x100..=0xffff => {
            out.push(0x4d);
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(data);
        }
        _ => return Err(anyhow!("pushdata too large")),
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct SegwitOneInputTx {
    version: [u8; 4],
    prev_txid_le: [u8; 32],
    prev_vout: [u8; 4],
    script_sig: Vec<u8>,
    sequence: [u8; 4],
    outputs_raw: Vec<u8>,
    witness_items: Vec<Vec<u8>>,
    locktime: [u8; 4],
}

fn parse_segwit_tx_one_input(tx_hex: &str) -> Result<SegwitOneInputTx> {
    let bytes = hex::decode(tx_hex).context("decode tx hex")?;
    let mut i = 0usize;
    if bytes.len() < 10 {
        return Err(anyhow!("tx too short"));
    }
    let version = bytes[i..i + 4]
        .try_into()
        .map_err(|_| anyhow!("version parse"))?;
    i += 4;
    if bytes.get(i) != Some(&0x00) || bytes.get(i + 1) != Some(&0x01) {
        return Err(anyhow!("not segwit marker/flag tx"));
    }
    i += 2;
    let vin = read_varint_bytes(&bytes, &mut i).ok_or_else(|| anyhow!("read vin"))?;
    if vin != 1 {
        return Err(anyhow!("expected one input, got {}", vin));
    }
    let prev_txid_le = bytes[i..i + 32]
        .try_into()
        .map_err(|_| anyhow!("prev txid parse"))?;
    i += 32;
    let prev_vout = bytes[i..i + 4]
        .try_into()
        .map_err(|_| anyhow!("prev vout parse"))?;
    i += 4;
    let script_len = read_varint_bytes(&bytes, &mut i).ok_or_else(|| anyhow!("script len"))?;
    let script_sig = bytes[i..i + script_len as usize].to_vec();
    i += script_len as usize;
    let sequence = bytes[i..i + 4]
        .try_into()
        .map_err(|_| anyhow!("sequence parse"))?;
    i += 4;

    let out_count_pos = i;
    let vout_count = read_varint_bytes(&bytes, &mut i).ok_or_else(|| anyhow!("vout count"))?;
    for _ in 0..vout_count {
        i += 8;
        let spk_len = read_varint_bytes(&bytes, &mut i).ok_or_else(|| anyhow!("spk len"))?;
        i += spk_len as usize;
        if i > bytes.len() {
            return Err(anyhow!("malformed vout"));
        }
    }
    let outputs_raw = bytes[out_count_pos..i].to_vec();

    let witness_count = read_varint_bytes(&bytes, &mut i).ok_or_else(|| anyhow!("wit count"))?;
    let mut witness_items = Vec::new();
    for _ in 0..witness_count {
        let n = read_varint_bytes(&bytes, &mut i).ok_or_else(|| anyhow!("wit item len"))?;
        let item = bytes
            .get(i..i + n as usize)
            .ok_or_else(|| anyhow!("wit item bytes"))?
            .to_vec();
        i += n as usize;
        witness_items.push(item);
    }
    let locktime = bytes
        .get(i..i + 4)
        .ok_or_else(|| anyhow!("locktime"))?
        .try_into()
        .map_err(|_| anyhow!("locktime parse"))?;
    i += 4;
    if i != bytes.len() {
        return Err(anyhow!("unexpected trailing bytes"));
    }

    Ok(SegwitOneInputTx {
        version,
        prev_txid_le,
        prev_vout,
        script_sig,
        sequence,
        outputs_raw,
        witness_items,
        locktime,
    })
}

fn serialize_segwit_tx_one_input(tx: &SegwitOneInputTx) -> String {
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version);
    out.push(0x00);
    out.push(0x01);
    out.extend_from_slice(&encode_varint(1));
    out.extend_from_slice(&tx.prev_txid_le);
    out.extend_from_slice(&tx.prev_vout);
    out.extend_from_slice(&encode_varint(tx.script_sig.len() as u64));
    out.extend_from_slice(&tx.script_sig);
    out.extend_from_slice(&tx.sequence);
    out.extend_from_slice(&tx.outputs_raw);
    out.extend_from_slice(&encode_varint(tx.witness_items.len() as u64));
    for item in &tx.witness_items {
        out.extend_from_slice(&encode_varint(item.len() as u64));
        out.extend_from_slice(item);
    }
    out.extend_from_slice(&tx.locktime);
    hex::encode(out)
}

fn read_varint_bytes(bytes: &[u8], idx: &mut usize) -> Option<u64> {
    let first = *bytes.get(*idx)?;
    *idx += 1;
    match first {
        0x00..=0xfc => Some(first as u64),
        0xfd => {
            let raw = bytes.get(*idx..*idx + 2)?;
            *idx += 2;
            Some(u16::from_le_bytes([raw[0], raw[1]]) as u64)
        }
        0xfe => {
            let raw = bytes.get(*idx..*idx + 4)?;
            *idx += 4;
            Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as u64)
        }
        _ => {
            let raw = bytes.get(*idx..*idx + 8)?;
            *idx += 8;
            Some(u64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]))
        }
    }
}

fn hash160_cli(data: &[u8]) -> [u8; 20] {
    let sha = sha2::Sha256::digest(data);
    let ripe = ripemd::Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

fn encode_varint(n: u64) -> Vec<u8> {
    if n <= 0xfc {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut out = vec![0xfd];
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out
    } else if n <= 0xffff_ffff {
        let mut out = vec![0xfe];
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out
    } else {
        let mut out = vec![0xff];
        out.extend_from_slice(&n.to_le_bytes());
        out
    }
}

fn testmempoolaccept_once(rpc: &SimpleRpc, tx_hex: &str) -> Result<SeamAccept> {
    let accept = rpc.call("testmempoolaccept", json!([[tx_hex]]))?;
    let first = accept
        .as_array()
        .and_then(|arr| arr.first())
        .ok_or_else(|| anyhow!("testmempoolaccept missing result"))?;
    Ok(SeamAccept {
        allowed: first["allowed"].as_bool().unwrap_or(false),
        reject_reason: first["reject-reason"].as_str().map(ToOwned::to_owned),
    })
}

fn summarize(dir: &Path, write_json: bool, compare: bool) -> Result<()> {
    if compare {
        let out = summarize_compare_offline(dir)?;
        print_compare_table(dir, &out);
        if write_json {
            let path = dir.join("compare.json");
            fs::write(&path, serde_json::to_vec_pretty(&out)?)
                .with_context(|| format!("writing {}", path.display()))?;
            println!("compare_json={}", path.display());
        }
        return Ok(());
    }

    let summary = summarize_dir_offline(dir)?;
    print_summary_table(dir, &summary);
    if write_json {
        let out = dir.join("summary.json");
        fs::write(&out, serde_json::to_vec_pretty(&summary)?)
            .with_context(|| format!("writing {}", out.display()))?;
        println!("summary_json={}", out.display());
    }
    Ok(())
}

fn summarize_dir_offline(dir: &Path) -> Result<SummaryOutput> {
    let events_root = dir.join("events");
    let mut counts_by_normalized_class: BTreeMap<String, usize> = BTreeMap::new();
    let mut counts_by_core_reason: BTreeMap<String, usize> = BTreeMap::new();
    let mut counts_by_policy_reason: BTreeMap<String, usize> = BTreeMap::new();
    let mut counts_by_rust_reason: BTreeMap<String, usize> = BTreeMap::new();
    let mut mutation_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut unique_core_reasons: BTreeSet<String> = BTreeSet::new();
    let mut unique_mutations: BTreeSet<String> = BTreeSet::new();

    let mut parsed_events = 0usize;
    let mut malformed_files = 0usize;
    let mut policy_allowed_count = 0usize;
    let mut policy_rejected_count = 0usize;

    let mut files = Vec::new();
    collect_json_files(&events_root, &mut files)?;
    files.sort();
    let scanned_files = files.len();

    for path in files {
        let bytes = match fs::read(&path) {
            Ok(v) => v,
            Err(_) => {
                malformed_files += 1;
                continue;
            }
        };
        let event: DivergenceEvent = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                malformed_files += 1;
                continue;
            }
        };
        parsed_events += 1;
        *counts_by_normalized_class
            .entry(event.normalized_class.clone())
            .or_insert(0) += 1;

        if event.core_allowed {
            policy_allowed_count += 1;
        } else {
            policy_rejected_count += 1;
        }

        let core_reason = event.core_reason.unwrap_or_else(|| "<none>".to_string());
        *counts_by_core_reason
            .entry(core_reason.clone())
            .or_insert(0) += 1;
        let policy_reason = if event.core_allowed {
            "<allowed>".to_string()
        } else {
            core_reason.clone()
        };
        *counts_by_policy_reason.entry(policy_reason).or_insert(0) += 1;
        if core_reason != "<none>" {
            unique_core_reasons.insert(core_reason);
        }

        let rust_reason = event.rust_reason.unwrap_or_else(|| "<none>".to_string());
        *counts_by_rust_reason.entry(rust_reason).or_insert(0) += 1;

        for m in event.mutations_applied {
            *mutation_histogram.entry(m.clone()).or_insert(0) += 1;
            unique_mutations.insert(m);
        }
    }

    let non_unclassified = counts_by_normalized_class
        .iter()
        .filter(|(k, _)| k.as_str() != "UNCLASSIFIED")
        .map(|(_, v)| *v)
        .sum::<usize>();
    let interestingness_score =
        non_unclassified + unique_core_reasons.len() + unique_mutations.len();

    let mut top_core_reasons: Vec<ReasonCount> = counts_by_core_reason
        .iter()
        .map(|(reason, count)| ReasonCount {
            reason: reason.clone(),
            count: *count,
        })
        .collect();
    top_core_reasons.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    top_core_reasons.truncate(10);
    let mut top_policy_reasons: Vec<ReasonCount> = counts_by_policy_reason
        .iter()
        .map(|(reason, count)| ReasonCount {
            reason: reason.clone(),
            count: *count,
        })
        .collect();
    top_policy_reasons.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    top_policy_reasons.truncate(10);

    Ok(SummaryOutput {
        total_events: parsed_events,
        scanned_files,
        parsed_events,
        malformed_files,
        counts_by_normalized_class,
        counts_by_core_reason,
        top_core_reasons,
        policy_allowed_count,
        policy_rejected_count,
        counts_by_policy_reason,
        top_policy_reasons,
        counts_by_rust_reason,
        mutation_histogram,
        unique_core_reason_count: unique_core_reasons.len(),
        unique_mutation_count: unique_mutations.len(),
        interestingness_score,
    })
}

fn collect_json_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_json_files(&path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("json")
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.ends_with("-event.json"))
                .unwrap_or(false)
        {
            out.push(path);
        }
    }
    Ok(())
}

fn print_summary_table(dir: &Path, s: &SummaryOutput) {
    println!("Summary: {}", dir.display());
    println!("total_events={}", s.total_events);
    println!(
        "files_scanned={} parsed={} malformed={}",
        s.scanned_files, s.parsed_events, s.malformed_files
    );
    println!("interestingness_score={}", s.interestingness_score);

    println!("\nBy Class");
    for (k, v) in &s.counts_by_normalized_class {
        println!("{:20} {}", k, v);
    }

    println!("\nTop Core Reasons");
    for rc in &s.top_core_reasons {
        println!("{:5} {}", rc.count, rc.reason);
    }

    println!(
        "\nPolicy Surface\nallowed={} rejected={}",
        s.policy_allowed_count, s.policy_rejected_count
    );
    for rc in &s.top_policy_reasons {
        println!("{:5} {}", rc.count, rc.reason);
    }

    println!("\nRust Reasons");
    for (k, v) in &s.counts_by_rust_reason {
        println!("{:5} {}", v, k);
    }

    println!("\nMutations");
    for (k, v) in &s.mutation_histogram {
        println!("{:5} {}", v, k);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EpochCompareRow {
    epoch: String,
    counts_by_normalized_class: BTreeMap<String, usize>,
    top_core_reasons: Vec<ReasonCount>,
    policy_allowed_count: usize,
    policy_rejected_count: usize,
    top_policy_reasons: Vec<ReasonCount>,
    top_mutations: Vec<ReasonCount>,
    reasons_only_in_epoch: Vec<String>,
    mutations_only_in_epoch: Vec<String>,
    unique_specimen_count: usize,
    sighash_context_tag_count: usize,
    sighash_context_tags_only_in_epoch: Vec<String>,
    sighash_digest_count: usize,
    sighash_digests_only_in_epoch: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompareOutput {
    epochs: Vec<EpochCompareRow>,
    class_table: BTreeMap<String, BTreeMap<String, usize>>,
}

fn summarize_compare_offline(root: &Path) -> Result<CompareOutput> {
    let epoch_dirs = collect_epoch_dirs(root)?;
    if epoch_dirs.is_empty() {
        return Err(anyhow!(
            "no epoch dirs with summary.json found under {}",
            root.display()
        ));
    }

    let mut class_table: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut reason_sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut mutation_sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut specimen_sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut sighash_tag_sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut sighash_digest_sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rows = Vec::new();

    for (epoch, epoch_dir) in &epoch_dirs {
        let summary_path = epoch_dir.join("summary.json");
        let summary_bytes = fs::read(&summary_path)
            .with_context(|| format!("reading {}", summary_path.display()))?;
        let summary: SummaryOutput = serde_json::from_slice(&summary_bytes)
            .with_context(|| format!("parsing {}", summary_path.display()))?;

        for (class, count) in &summary.counts_by_normalized_class {
            class_table
                .entry(class.clone())
                .or_default()
                .insert(epoch.clone(), *count);
        }

        let events_dir = epoch_dir.join("events");
        let mut files = Vec::new();
        collect_json_files(&events_dir, &mut files)?;
        files.sort();

        let mut reasons = BTreeSet::new();
        let mut mutations = BTreeSet::new();
        let mut specimen_ids = BTreeSet::new();
        let mut sighash_tags = BTreeSet::new();
        let mut sighash_digests = BTreeSet::new();
        for event_path in files {
            let bytes = match fs::read(&event_path) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let event: DivergenceEvent = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(reason) = event.core_reason.clone().filter(|r| r != "<none>") {
                reasons.insert(reason);
            }
            for m in &event.mutations_applied {
                mutations.insert(m.clone());
            }
            if let Some(tag) = event.rust.details.get("sighash_context_tag") {
                if !tag.is_empty() {
                    sighash_tags.insert(tag.clone());
                }
            }
            if let Some(digest) = event.rust.details.get("sighash_digest_hex") {
                if !digest.is_empty() {
                    sighash_digests.insert(digest.clone());
                }
            }
            let testcase_path = event_path
                .parent()
                .map(|p| p.join(format!("{}-testcase.json", event.testcase_id)));
            let specimen_source = testcase_path
                .as_ref()
                .and_then(|p| fs::read(p).ok())
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .unwrap_or_else(|| serde_json::to_value(&event).unwrap_or(Value::Null));
            if let Ok(id) = specimen_id_for_value(&specimen_source) {
                specimen_ids.insert(id);
            }
        }
        reason_sets.insert(epoch.clone(), reasons);
        mutation_sets.insert(epoch.clone(), mutations);
        specimen_sets.insert(epoch.clone(), specimen_ids);
        sighash_tag_sets.insert(epoch.clone(), sighash_tags);
        sighash_digest_sets.insert(epoch.clone(), sighash_digests);

        let top_mutations = top_reasons(summary.mutation_histogram, 5);
        rows.push(EpochCompareRow {
            epoch: epoch.clone(),
            counts_by_normalized_class: summary.counts_by_normalized_class,
            top_core_reasons: top_reasons(summary.counts_by_core_reason, 5),
            policy_allowed_count: summary.policy_allowed_count,
            policy_rejected_count: summary.policy_rejected_count,
            top_policy_reasons: top_reasons(summary.counts_by_policy_reason, 5),
            top_mutations,
            reasons_only_in_epoch: Vec::new(),
            mutations_only_in_epoch: Vec::new(),
            unique_specimen_count: 0,
            sighash_context_tag_count: 0,
            sighash_context_tags_only_in_epoch: Vec::new(),
            sighash_digest_count: 0,
            sighash_digests_only_in_epoch: Vec::new(),
        });
    }

    for row in &mut rows {
        let own_reasons = reason_sets.get(&row.epoch).cloned().unwrap_or_default();
        let mut other_reasons = BTreeSet::new();
        for (epoch, set) in &reason_sets {
            if *epoch != row.epoch {
                other_reasons.extend(set.iter().cloned());
            }
        }
        let own_mutations = mutation_sets.get(&row.epoch).cloned().unwrap_or_default();
        let mut other_mutations = BTreeSet::new();
        for (epoch, set) in &mutation_sets {
            if *epoch != row.epoch {
                other_mutations.extend(set.iter().cloned());
            }
        }
        let unique_specimens = specimen_sets
            .get(&row.epoch)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|id| {
                !specimen_sets
                    .iter()
                    .filter(|(epoch, _)| **epoch != row.epoch)
                    .any(|(_, set)| set.contains(id))
            })
            .collect::<Vec<_>>();
        let own_tags = sighash_tag_sets
            .get(&row.epoch)
            .cloned()
            .unwrap_or_default();
        let mut other_tags = BTreeSet::new();
        for (epoch, set) in &sighash_tag_sets {
            if *epoch != row.epoch {
                other_tags.extend(set.iter().cloned());
            }
        }
        let own_digests = sighash_digest_sets
            .get(&row.epoch)
            .cloned()
            .unwrap_or_default();
        let mut other_digests = BTreeSet::new();
        for (epoch, set) in &sighash_digest_sets {
            if *epoch != row.epoch {
                other_digests.extend(set.iter().cloned());
            }
        }

        row.reasons_only_in_epoch = own_reasons
            .difference(&other_reasons)
            .cloned()
            .collect::<Vec<_>>();
        row.reasons_only_in_epoch.sort();
        row.mutations_only_in_epoch = own_mutations
            .difference(&other_mutations)
            .cloned()
            .collect::<Vec<_>>();
        row.mutations_only_in_epoch.sort();
        row.unique_specimen_count = unique_specimens.len();
        row.sighash_context_tag_count = own_tags.len();
        row.sighash_context_tags_only_in_epoch = own_tags
            .difference(&other_tags)
            .cloned()
            .collect::<Vec<_>>();
        row.sighash_context_tags_only_in_epoch.sort();
        row.sighash_digest_count = own_digests.len();
        row.sighash_digests_only_in_epoch = own_digests
            .difference(&other_digests)
            .cloned()
            .collect::<Vec<_>>();
        row.sighash_digests_only_in_epoch.sort();
    }

    rows.sort_by(|a, b| a.epoch.cmp(&b.epoch));

    Ok(CompareOutput {
        epochs: rows,
        class_table,
    })
}

fn collect_epoch_dirs(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let summary_path = path.join("summary.json");
        if summary_path.exists() {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            out.push((name, path));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn print_compare_table(root: &Path, c: &CompareOutput) {
    println!("Compare Summary: {}", root.display());
    let epochs = c.epochs.iter().map(|e| e.epoch.clone()).collect::<Vec<_>>();
    println!("epochs={}", epochs.join(", "));

    println!("\nClass Counts");
    print!("{:24}", "normalized_class");
    for e in &epochs {
        print!(" {:>12}", e);
    }
    println!();
    for (class, by_epoch) in &c.class_table {
        print!("{:24}", class);
        for e in &epochs {
            let n = by_epoch.get(e).copied().unwrap_or(0);
            print!(" {:>12}", n);
        }
        println!();
    }

    println!("\nTop Core Reasons Per Epoch");
    for row in &c.epochs {
        println!("[{}]", row.epoch);
        for r in &row.top_core_reasons {
            println!("  {:5} {}", r.count, r.reason);
        }
    }

    println!("\nPolicy Surface Per Epoch");
    for row in &c.epochs {
        println!("[{}]", row.epoch);
        println!(
            "  allowed={} rejected={}",
            row.policy_allowed_count, row.policy_rejected_count
        );
        for r in &row.top_policy_reasons {
            println!("  {:5} {}", r.count, r.reason);
        }
    }

    println!("\nTop Mutations Per Epoch");
    for row in &c.epochs {
        println!("[{}]", row.epoch);
        for r in &row.top_mutations {
            println!("  {:5} {}", r.count, r.reason);
        }
    }

    println!("\nSet Differences");
    for row in &c.epochs {
        println!("[{}]", row.epoch);
        println!(
            "  reasons_only_in_epoch={}",
            if row.reasons_only_in_epoch.is_empty() {
                "<none>".to_string()
            } else {
                row.reasons_only_in_epoch.join(", ")
            }
        );
        println!(
            "  mutations_only_in_epoch={}",
            if row.mutations_only_in_epoch.is_empty() {
                "<none>".to_string()
            } else {
                row.mutations_only_in_epoch.join(", ")
            }
        );
        println!("  unique_specimen_count={}", row.unique_specimen_count);
        println!(
            "  sighash_context_tag_count={}",
            row.sighash_context_tag_count
        );
        println!(
            "  sighash_context_tags_only_in_epoch={}",
            if row.sighash_context_tags_only_in_epoch.is_empty() {
                "<none>".to_string()
            } else {
                row.sighash_context_tags_only_in_epoch.join(", ")
            }
        );
        println!("  sighash_digest_count={}", row.sighash_digest_count);
        println!(
            "  sighash_digests_only_in_epoch={}",
            if row.sighash_digests_only_in_epoch.is_empty() {
                "<none>".to_string()
            } else {
                row.sighash_digests_only_in_epoch.join(", ")
            }
        );
    }
}

#[derive(Debug, Clone, Serialize)]
struct MuseumEpochSummary {
    epoch: String,
    total_events: usize,
    counts_by_normalized_class: BTreeMap<String, usize>,
    policy_allowed_count: usize,
    policy_rejected_count: usize,
    top_core_reasons: Vec<ReasonCount>,
    top_policy_reasons: Vec<ReasonCount>,
    top_rust_reasons: Vec<ReasonCount>,
}

#[derive(Debug, Clone, Serialize)]
struct MuseumSpecimen {
    specimen_id: String,
    testcase_id: String,
    epoch: String,
    normalized_class: String,
    core_reason: Option<String>,
    policy_allowed: bool,
    policy_reason: Option<String>,
    core_mode: Option<String>,
    rust_reason: Option<String>,
    script_trace: Option<String>,
    txid_hex: Option<String>,
    dummy_len: Option<String>,
    dummy_affects_sighash: Option<String>,
    sighash_context_tag: Option<String>,
    sighash_digest_hex: Option<String>,
    sighash_type: Option<String>,
    sighash_single_bug: Option<String>,
    mutations_applied: Vec<String>,
    label: Option<String>,
    event_path: String,
    reduced_testcase_path: Option<String>,
    testcase_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MuseumData {
    epochs: Vec<MuseumEpochSummary>,
    specimens: Vec<MuseumSpecimen>,
}

#[derive(Debug, Clone, Serialize)]
struct LabelSuggestion {
    specimen_id: String,
    suggested_label: String,
    confidence: String,
    rationale: String,
}

#[derive(Debug, Clone)]
struct ReportRow {
    fixture_id: String,
    epoch: String,
    shadow_ok: bool,
    shadow_reason: String,
    core_allowed: bool,
    core_reject_reason: String,
    txid_hex: String,
    sighash_digest_hex: String,
    dummy_len: String,
    findanddelete_removed_total: String,
    findanddelete_codeseparator_pos: String,
    sighash_type: String,
    sighash_single_bug: String,
    family_label: String,
}

fn museum(in_dir: &Path, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let labels_path = out_dir.join("labels.json");
    let labels = load_labels_map(&labels_path)?;
    let dataset = build_museum_data(in_dir, &labels)?;

    let data_path = out_dir.join("data.json");
    fs::write(&data_path, serde_json::to_vec_pretty(&dataset)?)
        .with_context(|| format!("writing {}", data_path.display()))?;
    let html_path = out_dir.join("index.html");
    fs::write(&html_path, museum_html_template())
        .with_context(|| format!("writing {}", html_path.display()))?;
    println!("museum_data={}", data_path.display());
    println!("museum_index={}", html_path.display());
    Ok(())
}

fn suggest_labels(in_dir: &Path, out_path: &Path) -> Result<()> {
    let dataset = build_museum_data(in_dir, &BTreeMap::new())?;
    let mut suggestions = Vec::new();
    for specimen in dataset.specimens {
        if let Some(suggestion) = suggest_label_for_specimen(&specimen) {
            suggestions.push(suggestion);
        }
    }
    fs::write(out_path, serde_json::to_vec_pretty(&suggestions)?)
        .with_context(|| format!("writing {}", out_path.display()))?;
    println!("suggestions={}", out_path.display());
    println!("count={}", suggestions.len());
    Ok(())
}

fn apply_label(specimen: &str, label: &str, labels_path: &Path) -> Result<()> {
    let mut labels = load_labels_map(labels_path)?;
    labels.insert(specimen.to_string(), label.to_string());
    if let Some(parent) = labels_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(labels_path, serde_json::to_vec_pretty(&labels)?)
        .with_context(|| format!("writing {}", labels_path.display()))?;
    println!("label_applied specimen={} label={}", specimen, label);
    println!("labels_file={}", labels_path.display());
    Ok(())
}

fn report(dir: &Path, format: ReportFormat, out: Option<&Path>) -> Result<()> {
    let dataset = build_museum_data(dir, &BTreeMap::new())?;
    let mut rows = build_report_rows(dir, &dataset)?;
    rows.sort_by(|a, b| a.fixture_id.cmp(&b.fixture_id).then_with(|| a.epoch.cmp(&b.epoch)));

    let label_suggestions = rows
        .iter()
        .filter_map(|r| {
            let specimen = dataset
                .specimens
                .iter()
                .find(|s| strip_height_suffix(&s.testcase_id) == r.fixture_id && s.epoch == r.epoch)?;
            suggest_label_for_specimen(specimen).map(|s| s.suggested_label)
        })
        .collect::<Vec<_>>();
    let mut label_counts = BTreeMap::<String, usize>::new();
    for label in label_suggestions {
        *label_counts.entry(label).or_insert(0) += 1;
    }

    let rendered = match format {
        ReportFormat::Md => render_report_md(dir, &rows, &label_counts),
        ReportFormat::Latex => render_report_latex(dir, &rows, &label_counts),
    };
    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::write(path, rendered.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
        println!("report_out={}", path.display());
    } else {
        print!("{rendered}");
    }
    Ok(())
}

fn build_report_rows(dir: &Path, dataset: &MuseumData) -> Result<Vec<ReportRow>> {
    let mut event_files = Vec::new();
    collect_event_json_files_anywhere(dir, &mut event_files)?;
    event_files.sort();
    let mut rows = Vec::new();
    for event_path in event_files {
        let bytes = match fs::read(&event_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let event: DivergenceEvent = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let epoch = find_epoch_from_event_path(&event_path).unwrap_or_else(|| "unknown".to_string());
        let fixture_id = strip_height_suffix(&event.testcase_id);
        let family_label = dataset
            .specimens
            .iter()
            .find(|s| s.testcase_id == event.testcase_id)
            .and_then(suggest_label_for_specimen)
            .map(|s| s.suggested_label)
            .unwrap_or_default();
        rows.push(ReportRow {
            fixture_id,
            epoch,
            shadow_ok: event.rust_ok,
            shadow_reason: shorten_reason(event.rust_reason.as_deref().unwrap_or("<none>")),
            core_allowed: event.core_allowed,
            core_reject_reason: shorten_reason(event.core_reason.as_deref().unwrap_or("<none>")),
            txid_hex: shorten_hex(
                event
                    .rust
                    .details
                    .get("txid_hex")
                    .map(String::as_str)
                    .unwrap_or(""),
            ),
            sighash_digest_hex: shorten_hex(
                event
                    .rust
                    .details
                    .get("sighash_digest_hex")
                    .map(String::as_str)
                    .unwrap_or(""),
            ),
            dummy_len: event
                .rust
                .details
                .get("dummy_len")
                .cloned()
                .unwrap_or_default(),
            findanddelete_removed_total: event
                .rust
                .details
                .get("findanddelete_removed_total")
                .cloned()
                .unwrap_or_default(),
            findanddelete_codeseparator_pos: event
                .rust
                .details
                .get("findanddelete_codeseparator_pos")
                .cloned()
                .unwrap_or_default(),
            sighash_type: event
                .rust
                .details
                .get("sighash_type")
                .cloned()
                .or_else(|| event.rust.details.get("findanddelete_sighash_type").cloned())
                .unwrap_or_default(),
            sighash_single_bug: event
                .rust
                .details
                .get("sighash_single_bug")
                .cloned()
                .unwrap_or_default(),
            family_label,
        });
    }
    Ok(rows)
}

fn render_report_md(dir: &Path, rows: &[ReportRow], label_counts: &BTreeMap<String, usize>) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Report: {}\n\n", dir.display()));
    out.push_str("Labels:\n");
    if label_counts.is_empty() {
        out.push_str("- <none>\n\n");
    } else {
        for (label, count) in label_counts {
            out.push_str(&format!("- {} ({})\n", label, count));
        }
        out.push('\n');
    }
    out.push_str("| fixture_id | epoch | label | shadow_ok | shadow_reason | core_allowed | core_reject_reason | txid_hex | sighash_digest_hex | dummy_len | fd_removed | codeseparator_pos | sighash_type | sighash_single_bug |\n");
    out.push_str("|---|---|---|---:|---|---:|---|---|---|---:|---:|---:|---|---|\n");
    for row in rows {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | `{}` | `{}` | {} | {} | {} | {} | {} |\n",
            row.fixture_id,
            row.epoch,
            if row.family_label.is_empty() { "<none>" } else { &row.family_label },
            row.shadow_ok,
            row.shadow_reason,
            row.core_allowed,
            row.core_reject_reason,
            row.txid_hex,
            row.sighash_digest_hex,
            blank_dash(&row.dummy_len),
            blank_dash(&row.findanddelete_removed_total),
            blank_dash(&row.findanddelete_codeseparator_pos),
            blank_dash(&row.sighash_type),
            blank_dash(&row.sighash_single_bug),
        ));
    }
    out
}

fn render_report_latex(
    dir: &Path,
    rows: &[ReportRow],
    label_counts: &BTreeMap<String, usize>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("% Report: {}\n", latex_escape(&dir.display().to_string())));
    if label_counts.is_empty() {
        out.push_str("% Labels: <none>\n");
    } else {
        out.push_str("% Labels: ");
        let labels = label_counts
            .iter()
            .map(|(label, count)| format!("{} ({})", latex_escape(label), count))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&labels);
        out.push('\n');
    }
    out.push_str("\\begin{tabular}{lllllllrrrrll}\n\\toprule\n");
    out.push_str("fixture\\_id & epoch & label & shadow\\_ok & shadow\\_reason & core\\_allowed & core\\_reject\\_reason & txid & sighash & dummy & fd & csep & shtype & single\\\\\n\\midrule\n");
    for row in rows {
        out.push_str(&format!(
            "{} & {} & {} & {} & {} & {} & {} & \\texttt{{{}}} & \\texttt{{{}}} & {} & {} & {} & {} & {}\\\\\n",
            latex_escape(&row.fixture_id),
            latex_escape(&row.epoch),
            latex_escape(if row.family_label.is_empty() { "<none>" } else { &row.family_label }),
            row.shadow_ok,
            latex_escape(&row.shadow_reason),
            row.core_allowed,
            latex_escape(&row.core_reject_reason),
            latex_escape(&row.txid_hex),
            latex_escape(&row.sighash_digest_hex),
            latex_escape(blank_dash(&row.dummy_len)),
            latex_escape(blank_dash(&row.findanddelete_removed_total)),
            latex_escape(blank_dash(&row.findanddelete_codeseparator_pos)),
            latex_escape(blank_dash(&row.sighash_type)),
            latex_escape(blank_dash(&row.sighash_single_bug)),
        ));
    }
    out.push_str("\\bottomrule\n\\end{tabular}\n");
    out
}

fn strip_height_suffix(testcase_id: &str) -> String {
    if let Some((head, tail)) = testcase_id.rsplit_once("-h") {
        if !head.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
            return head.to_string();
        }
    }
    testcase_id.to_string()
}

fn shorten_hex(raw: &str) -> String {
    if raw.len() <= 16 {
        raw.to_string()
    } else {
        format!("{}...", &raw[..16])
    }
}

fn shorten_reason(raw: &str) -> String {
    const MAX: usize = 48;
    if raw.len() <= MAX {
        raw.to_string()
    } else {
        format!("{}...", &raw[..MAX])
    }
}

fn blank_dash(raw: &str) -> &str {
    if raw.is_empty() { "-" } else { raw }
}

fn latex_escape(raw: &str) -> String {
    raw.replace('\\', "\\textbackslash{}")
        .replace('_', "\\_")
        .replace('&', "\\&")
        .replace('%', "\\%")
        .replace('#', "\\#")
        .replace('{', "\\{")
        .replace('}', "\\}")
}

fn load_labels_map(path: &Path) -> Result<BTreeMap<String, String>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let parsed: Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    let mut out = BTreeMap::new();
    if let Some(obj) = parsed.as_object() {
        for (k, v) in obj {
            if let Some(label) = v.as_str() {
                out.insert(k.clone(), label.to_string());
            }
        }
    }
    Ok(out)
}

fn build_museum_data(in_dir: &Path, labels: &BTreeMap<String, String>) -> Result<MuseumData> {
    let mut event_files = Vec::new();
    collect_event_json_files_anywhere(in_dir, &mut event_files)?;
    event_files.sort();

    let reduced_map = index_reduced_testcases(in_dir)?;
    let mut epoch_class_counts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut epoch_core_reason_counts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut epoch_policy_reason_counts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut epoch_rust_reason_counts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut epoch_policy_allowed_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut epoch_policy_rejected_counts: BTreeMap<String, usize> = BTreeMap::new();

    let mut specimens = Vec::new();
    for event_path in &event_files {
        let bytes = match fs::read(event_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let event: DivergenceEvent = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let testcase_path = event_path
            .parent()
            .map(|p| p.join(format!("{}-testcase.json", event.testcase_id)));
        let testcase_value = testcase_path
            .as_ref()
            .and_then(|p| fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());

        let reduced_path = reduced_map.get(&event.testcase_id).cloned();
        let canonical_source = if let Some(path) = &reduced_path {
            fs::read(path)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .or_else(|| testcase_value.clone())
                .unwrap_or_else(|| serde_json::to_value(&event).unwrap_or(Value::Null))
        } else if let Some(v) = testcase_value.clone() {
            v
        } else {
            serde_json::to_value(&event).unwrap_or(Value::Null)
        };
        let specimen_id = specimen_id_for_value(&canonical_source)?;

        let epoch = find_epoch_from_event_path(event_path).unwrap_or_else(|| "unknown".to_string());
        *epoch_class_counts
            .entry(epoch.clone())
            .or_default()
            .entry(event.normalized_class.clone())
            .or_insert(0) += 1;
        *epoch_core_reason_counts
            .entry(epoch.clone())
            .or_default()
            .entry(
                event
                    .core_reason
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string()),
            )
            .or_insert(0) += 1;
        if event.core_allowed {
            *epoch_policy_allowed_counts
                .entry(epoch.clone())
                .or_insert(0) += 1;
        } else {
            *epoch_policy_rejected_counts
                .entry(epoch.clone())
                .or_insert(0) += 1;
        }
        let policy_reason = if event.core_allowed {
            "<allowed>".to_string()
        } else {
            event
                .core_reason
                .clone()
                .unwrap_or_else(|| "<none>".to_string())
        };
        *epoch_policy_reason_counts
            .entry(epoch.clone())
            .or_default()
            .entry(policy_reason)
            .or_insert(0) += 1;
        *epoch_rust_reason_counts
            .entry(epoch.clone())
            .or_default()
            .entry(
                event
                    .rust_reason
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string()),
            )
            .or_insert(0) += 1;

        let script_trace = event.rust.details.get("script_trace").cloned();
        let txid_hex = event.rust.details.get("txid_hex").cloned();
        let dummy_len = event.rust.details.get("dummy_len").cloned();
        let dummy_affects_sighash = event.rust.details.get("dummy_affects_sighash").cloned();
        let sighash_context_tag = event.rust.details.get("sighash_context_tag").cloned();
        let sighash_digest_hex = event.rust.details.get("sighash_digest_hex").cloned();
        let sighash_type = event.rust.details.get("sighash_type").cloned().or_else(|| {
            event
                .rust
                .details
                .get("findanddelete_sighash_type")
                .cloned()
        });
        let sighash_single_bug = event.rust.details.get("sighash_single_bug").cloned();
        specimens.push(MuseumSpecimen {
            specimen_id: specimen_id.clone(),
            testcase_id: event.testcase_id.clone(),
            epoch,
            normalized_class: event.normalized_class.clone(),
            core_reason: event.core_reason.clone(),
            policy_allowed: event.core_allowed,
            policy_reason: if event.core_allowed {
                Some("<allowed>".to_string())
            } else {
                event.core_reason.clone()
            },
            core_mode: event.core.details.get("mode").cloned(),
            rust_reason: event.rust_reason.clone(),
            script_trace,
            txid_hex,
            dummy_len,
            dummy_affects_sighash,
            sighash_context_tag,
            sighash_digest_hex,
            sighash_type,
            sighash_single_bug,
            mutations_applied: event.mutations_applied.clone(),
            label: labels.get(&specimen_id).cloned(),
            event_path: event_path.display().to_string(),
            reduced_testcase_path: reduced_path.map(|p| p.display().to_string()),
            testcase_path: testcase_path.map(|p| p.display().to_string()),
        });
    }
    specimens.sort_by(|a, b| a.specimen_id.cmp(&b.specimen_id));

    let mut epochs = Vec::new();
    for (epoch, counts_by_normalized_class) in epoch_class_counts {
        let total_events = counts_by_normalized_class.values().sum::<usize>();
        let top_core_reasons = top_reasons(
            epoch_core_reason_counts
                .get(&epoch)
                .cloned()
                .unwrap_or_default(),
            5,
        );
        let top_rust_reasons = top_reasons(
            epoch_rust_reason_counts
                .get(&epoch)
                .cloned()
                .unwrap_or_default(),
            5,
        );
        epochs.push(MuseumEpochSummary {
            epoch: epoch.clone(),
            total_events,
            counts_by_normalized_class,
            policy_allowed_count: epoch_policy_allowed_counts
                .get(&epoch)
                .copied()
                .unwrap_or(0),
            policy_rejected_count: epoch_policy_rejected_counts
                .get(&epoch)
                .copied()
                .unwrap_or(0),
            top_core_reasons,
            top_policy_reasons: top_reasons(
                epoch_policy_reason_counts
                    .get(&epoch)
                    .cloned()
                    .unwrap_or_default(),
                5,
            ),
            top_rust_reasons,
        });
    }
    epochs.sort_by(|a, b| a.epoch.cmp(&b.epoch));

    Ok(MuseumData { epochs, specimens })
}

fn top_reasons(counts: BTreeMap<String, usize>, max: usize) -> Vec<ReasonCount> {
    let mut out: Vec<ReasonCount> = counts
        .into_iter()
        .map(|(reason, count)| ReasonCount { reason, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    out.truncate(max);
    out
}

fn collect_event_json_files_anywhere(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_event_json_files_anywhere(&path, out)?;
            continue;
        }
        let is_event_json = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|name| name.ends_with("-event.json"))
            .unwrap_or(false);
        if is_event_json {
            out.push(path);
        }
    }
    Ok(())
}

fn index_reduced_testcases(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut files = Vec::new();
    collect_json_files_loose(root, &mut files)?;
    let mut out = BTreeMap::new();
    for path in files {
        let maybe_name = path.file_name().and_then(|s| s.to_str());
        if let Some(name) = maybe_name {
            if let Some(id) = name.strip_suffix("-reduced.json") {
                out.insert(id.to_string(), path);
            }
        }
    }
    Ok(out)
}

fn collect_json_files_loose(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_json_files_loose(&path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

fn find_epoch_from_event_path(path: &Path) -> Option<String> {
    let mut cur = path.parent();
    while let Some(p) = cur {
        if p.file_name().and_then(|s| s.to_str()) == Some("events") {
            return p
                .parent()
                .and_then(|x| x.file_name())
                .and_then(|s| s.to_str())
                .map(ToOwned::to_owned);
        }
        cur = p.parent();
    }
    None
}

fn specimen_id_for_value(value: &Value) -> Result<String> {
    let canonical = canonical_json_string(value)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

fn canonical_json_string(value: &Value) -> Result<String> {
    fn canonicalize(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut ordered = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    if let Some(child) = map.get(k) {
                        ordered.insert(k.clone(), canonicalize(child));
                    }
                }
                Value::Object(ordered)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
            _ => v.clone(),
        }
    }
    let canonical = canonicalize(value);
    serde_json::to_string(&canonical).context("serialize canonical json")
}

fn suggest_label_for_specimen(specimen: &MuseumSpecimen) -> Option<LabelSuggestion> {
    let reason_joined = format!(
        "{} {} {}",
        specimen.core_reason.as_deref().unwrap_or(""),
        specimen.rust_reason.as_deref().unwrap_or(""),
        specimen.script_trace.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    let muts = specimen
        .mutations_applied
        .iter()
        .map(|m| m.to_ascii_lowercase())
        .collect::<Vec<_>>();

    let choose = |label: &str, confidence: &str, rationale: &str| LabelSuggestion {
        specimen_id: specimen.specimen_id.clone(),
        suggested_label: label.to_string(),
        confidence: confidence.to_string(),
        rationale: rationale.to_string(),
    };

    if specimen.sighash_single_bug.as_deref() == Some("true") {
        return Some(choose(
            "SIGHASH_SINGLE_DEGENERACY",
            "high",
            "specimen records the legacy SIGHASH_SINGLE bug path",
        ));
    }
    if specimen.dummy_len.is_some() {
        return Some(choose(
            "DUMMYGRIND_TXID_AXIS",
            "high",
            "dummy element changes txid while the recorded sighash digest remains stable",
        ));
    }
    if specimen
        .sighash_type
        .as_deref()
        .and_then(parse_sighash_type_label)
        .map(|v| (v & 0x80) != 0)
        .unwrap_or(false)
    {
        return Some(choose(
            "ANYONECANPAY_AXIS",
            "medium",
            "sighash type includes the ANYONECANPAY bit",
        ));
    }
    if specimen.sighash_digest_hex.is_some() {
        return None;
    }
    if reason_joined.contains("findanddelete") {
        return Some(choose(
            "CHECKMULTISIG_FINDANDDELETE",
            "high",
            "reason/trace contains findanddelete hook marker",
        ));
    }
    if reason_joined.contains("dummy checkmultisig argument must be zero") {
        return Some(choose(
            "NULLDUMMY_POLICY_ONLY",
            "high",
            "core reject reason shows NULLDUMMY-style policy enforcement",
        ));
    }
    if specimen.sighash_context_tag.is_some() {
        return Some(choose(
            "SCRIPT_CODE_MUTATION",
            "medium",
            "specimen includes derived sighash context tag from mutated scriptCode",
        ));
    }
    if reason_joined.contains("checksighook") {
        return Some(choose(
            "CHECKSIGHOOK_FORCED_FAIL",
            "high",
            "reason/trace contains checksighook marker",
        ));
    }
    if reason_joined.contains("pushdata")
        && (reason_joined.contains("length") || reason_joined.contains("overrun"))
    {
        return Some(choose(
            "PUSHDATA_LEN_OVERRUN",
            "high",
            "pushdata plus length/overrun signal in reason/trace",
        ));
    }
    if specimen.normalized_class == "SCRIPT_FAIL" && reason_joined.contains("stack") {
        return Some(choose(
            "STACK_UNDERFLOW_STRUCTURAL",
            "high",
            "script fail with stack-related reason",
        ));
    }
    if muts
        .iter()
        .any(|m| m.contains("sequence") || m.contains("locktime"))
    {
        return Some(choose(
            "FUZZ_SEQUENCE_MUTATION",
            "medium",
            "mutation trace contains sequence/locktime mutation",
        ));
    }
    if reason_joined.contains("standard")
        || reason_joined.contains("minimal")
        || reason_joined.contains("cleanstack")
        || reason_joined.contains("policy")
    {
        return Some(choose(
            "POLICY_MINIMALDATA_ONLY",
            "low",
            "reason appears policy/standardness-oriented",
        ));
    }
    None
}

fn parse_sighash_type_label(raw: &str) -> Option<u32> {
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    raw.parse::<u32>().ok()
}

fn museum_html_template() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Quirk Museum</title>
  <style>
    :root { --bg:#f5f1e8; --ink:#1c1a17; --accent:#aa3d2f; --muted:#6b6257; --card:#fffaf2; }
    body { margin:0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif; background:var(--bg); color:var(--ink); }
    .wrap { display:grid; grid-template-columns: 280px 1fr; min-height:100vh; }
    .sidebar { padding:20px; border-right:1px solid #d8cfbf; background:linear-gradient(180deg,#f9f5ed,#efe8da); }
    .main { padding:20px; }
    h1 { margin:0 0 12px 0; font-size:24px; }
    .muted { color:var(--muted); }
    .card { background:var(--card); border:1px solid #dfd4c2; border-radius:10px; padding:12px; margin:12px 0; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { border-bottom:1px solid #e3d7c6; text-align:left; padding:8px 6px; vertical-align:top; }
    th { background:#f2e9db; position:sticky; top:0; }
    input, select { width:100%; padding:8px; margin:6px 0; border:1px solid #cdbfa9; border-radius:6px; background:white; }
    a { color:var(--accent); text-decoration:none; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid #d8c9b3; background:#fff; font-size:12px; }
  </style>
</head>
<body>
<div class="wrap">
  <aside class="sidebar">
    <h1>Quirk Museum</h1>
    <div class="muted">Specimen browser</div>
    <div class="card">
      <label>Epoch</label><select id="fEpoch"><option value="">All</option></select>
      <label>Class</label><select id="fClass"><option value="">All</option></select>
      <label>Reason contains</label><input id="fReason" />
      <label>Mutation contains</label><input id="fMutation" />
    </div>
    <div id="epochSummary"></div>
  </aside>
  <main class="main">
    <div class="card"><span id="counts" class="pill"></span></div>
    <table>
      <thead><tr><th>Specimen</th><th>Epoch</th><th>Class</th><th>Label</th><th>Policy</th><th>Core</th><th>Rust</th><th>Trace</th><th>Mutations</th><th>Links</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </main>
</div>
<script>
const state = { data:null, filtered:[] };
const el = (id) => document.getElementById(id);
fetch('data.json').then(r => r.json()).then(data => { state.data = data; init(); apply(); });
function init(){
  const epochs = [...new Set(state.data.specimens.map(s => s.epoch))].sort();
  const classes = [...new Set(state.data.specimens.map(s => s.normalized_class))].sort();
  for (const e of epochs){ const o=document.createElement('option'); o.value=e; o.textContent=e; el('fEpoch').appendChild(o); }
  for (const c of classes){ const o=document.createElement('option'); o.value=c; o.textContent=c; el('fClass').appendChild(o); }
  ['fEpoch','fClass','fReason','fMutation'].forEach(id => el(id).addEventListener('input', apply));
  renderEpochSummary();
}
function apply(){
  const fEpoch = el('fEpoch').value;
  const fClass = el('fClass').value;
  const fReason = el('fReason').value.toLowerCase();
  const fMutation = el('fMutation').value.toLowerCase();
  state.filtered = state.data.specimens.filter(s => {
    if (fEpoch && s.epoch !== fEpoch) return false;
    if (fClass && s.normalized_class !== fClass) return false;
    const reasonBlob = `${s.core_reason||''} ${s.rust_reason||''}`.toLowerCase();
    if (fReason && !reasonBlob.includes(fReason)) return false;
    const muts = (s.mutations_applied||[]).join(' ').toLowerCase();
    if (fMutation && !muts.includes(fMutation)) return false;
    return true;
  });
  renderRows();
  el('counts').textContent = `${state.filtered.length} specimens`;
}
function renderRows(){
  const tbody = el('rows');
  tbody.innerHTML = '';
  for (const s of state.filtered){
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${s.specimen_id.slice(0,16)}</code><br/><span class="muted">${s.testcase_id}</span></td>
      <td>${s.epoch}</td>
      <td>${s.normalized_class}</td>
      <td>${s.label||''}</td>
      <td>${s.policy_allowed ? 'allowed' : 'rejected'}<br/><span class="muted">${s.policy_reason||''}${s.core_mode ? ` [${s.core_mode}]` : ''}</span></td>
      <td>${s.core_reason||''}</td>
      <td>${s.rust_reason||''}</td>
      <td>${s.script_trace||''}</td>
      <td>${(s.mutations_applied||[]).join(', ')}</td>
      <td>
        <a href="${s.event_path}" target="_blank">event</a>
        ${s.reduced_testcase_path ? ` | <a href="${s.reduced_testcase_path}" target="_blank">reduced</a>` : ''}
        ${s.testcase_path ? ` | <a href="${s.testcase_path}" target="_blank">testcase</a>` : ''}
      </td>`;
    tbody.appendChild(tr);
  }
}
function renderEpochSummary(){
  const host = el('epochSummary');
  host.innerHTML = '';
  for (const e of state.data.epochs){
    const div = document.createElement('div');
    div.className = 'card';
    div.innerHTML = `<strong>${e.epoch}</strong><div class="muted">${e.total_events} events</div><div class="muted">policy allowed=${e.policy_allowed_count} rejected=${e.policy_rejected_count}</div>`;
    host.appendChild(div);
  }
}
</script>
</body>
</html>"#
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Command, ReportRow, latex_escape, prepare_out_dir, render_report_latex,
        shorten_hex, specimen_id_for_value, summarize_compare_offline, summarize_dir_offline,
    };
    use clap::Parser;
    use jb_model::{DivergenceEvent, ExecResult};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn parses_demo_run_flags() {
        let cli = Cli::try_parse_from([
            "jurassic-bitcoin",
            "demo-run",
            "--out-dir",
            "artifacts/demo-x",
            "--iterations",
            "42",
            "--seed",
            "9",
            "--force",
            "--corpus",
            "corpus",
        ])
        .expect("parse");
        match cli.cmd {
            Command::DemoRun {
                iterations,
                seed,
                force,
                ..
            } => {
                assert_eq!(iterations, 42);
                assert_eq!(seed, 9);
                assert!(force);
            }
            _ => panic!("expected demo-run"),
        }
    }

    #[test]
    fn parses_replay_era_manifest_flags() {
        let cli = Cli::try_parse_from([
            "jurassic-bitcoin",
            "replay-era",
            "--manifest",
            "fixtures/manifests/era_2009_2013_poc.json",
            "--out-dir",
            "artifacts/era-2009-2013",
            "--limit-per-epoch",
            "123",
            "--rpc-fetch",
            "--force",
        ])
        .expect("parse");

        match cli.cmd {
            Command::ReplayEra {
                manifest,
                out_dir,
                limit_per_epoch,
                rpc_fetch,
                force,
            } => {
                assert!(manifest.ends_with("era_2009_2013_poc.json"));
                assert!(out_dir.ends_with("era-2009-2013"));
                assert_eq!(limit_per_epoch, 123);
                assert!(rpc_fetch);
                assert!(force);
            }
            _ => panic!("expected replay-era"),
        }
    }

    #[test]
    fn parses_fetch_and_summarize_compare_flags() {
        let fetch = Cli::try_parse_from([
            "jurassic-bitcoin",
            "fetch-fixtures",
            "--manifest",
            "fixtures/manifests/era_2009_2013_poc.json",
            "--out-index",
            "fixtures/cache/index.json",
            "--strict",
        ])
        .expect("parse fetch-fixtures");
        match fetch.cmd {
            Command::FetchFixtures {
                manifest,
                out_index,
                strict,
            } => {
                assert!(manifest.ends_with("era_2009_2013_poc.json"));
                assert!(out_index.ends_with("index.json"));
                assert!(strict);
            }
            _ => panic!("expected fetch-fixtures"),
        }

        let summarize = Cli::try_parse_from([
            "jurassic-bitcoin",
            "summarize",
            "--dir",
            "artifacts/era-2009-2013",
            "--compare",
            "--json",
        ])
        .expect("parse summarize compare");
        match summarize.cmd {
            Command::Summarize { compare, json, .. } => {
                assert!(compare);
                assert!(json);
            }
            _ => panic!("expected summarize"),
        }

        let report = Cli::try_parse_from([
            "jurassic-bitcoin",
            "report",
            "--dir",
            "artifacts/p2sh-dummygrind-core-seam",
            "--format",
            "latex",
            "--out",
            "artifacts/p2sh-dummygrind-core-seam/report.tex",
        ])
        .expect("parse report");
        match report.cmd {
            Command::Report {
                dir,
                format,
                out,
            } => {
                assert!(dir.ends_with("p2sh-dummygrind-core-seam"));
                assert!(matches!(format, super::ReportFormat::Latex));
                assert!(out.expect("out").ends_with("report.tex"));
            }
            _ => panic!("expected report"),
        }
    }

    #[test]
    fn parses_museum_and_label_commands() {
        let museum = Cli::try_parse_from([
            "jurassic-bitcoin",
            "museum",
            "--in",
            "artifacts/era-2009-2013",
            "--out",
            "artifacts/museum",
        ])
        .expect("parse museum");
        match museum.cmd {
            Command::Museum { r#in, out } => {
                assert!(r#in.ends_with("era-2009-2013"));
                assert!(out.ends_with("museum"));
            }
            _ => panic!("expected museum"),
        }

        let apply = Cli::try_parse_from([
            "jurassic-bitcoin",
            "apply-label",
            "--specimen",
            "abc",
            "--label",
            "STACK_UNDERFLOW_STRUCTURAL",
            "--labels",
            "museum/labels.json",
        ])
        .expect("parse apply-label");
        match apply.cmd {
            Command::ApplyLabel {
                specimen,
                label,
                labels,
            } => {
                assert_eq!(specimen, "abc");
                assert_eq!(label, "STACK_UNDERFLOW_STRUCTURAL");
                assert!(labels.ends_with("labels.json"));
            }
            _ => panic!("expected apply-label"),
        }

        let mint = Cli::try_parse_from([
            "jurassic-bitcoin",
            "mint-p2sh-seam",
            "--out",
            "fixtures/blobs/p2sh-core-seam.json",
        ])
        .expect("parse mint-p2sh-seam");
        match mint.cmd {
            Command::MintP2shSeam { out } => {
                assert!(out.ends_with("p2sh-core-seam.json"));
            }
            _ => panic!("expected mint-p2sh-seam"),
        }

        let mint_w = Cli::try_parse_from([
            "jurassic-bitcoin",
            "mint-p2wpkh-seam",
            "--out",
            "fixtures/blobs/p2wpkh-core-seam.json",
        ])
        .expect("parse mint-p2wpkh-seam");
        match mint_w.cmd {
            Command::MintP2wpkhSeam { out } => {
                assert!(out.ends_with("p2wpkh-core-seam.json"));
            }
            _ => panic!("expected mint-p2wpkh-seam"),
        }

        let mint_fd = Cli::try_parse_from([
            "jurassic-bitcoin",
            "mint-findanddelete-seam",
            "--out",
            "fixtures/blobs/p2sh-findanddelete-core-seam.json",
        ])
        .expect("parse mint-findanddelete-seam");
        match mint_fd.cmd {
            Command::MintFindanddeleteSeam { out } => {
                assert!(out.ends_with("p2sh-findanddelete-core-seam.json"));
            }
            _ => panic!("expected mint-findanddelete-seam"),
        }

        let mint_ss = Cli::try_parse_from([
            "jurassic-bitcoin",
            "mint-sighash-single-seam",
            "--out",
            "fixtures/blobs/sighash-single-core-seam.json",
        ])
        .expect("parse mint-sighash-single-seam");
        match mint_ss.cmd {
            Command::MintSighashSingleSeam { out } => {
                assert!(out.ends_with("sighash-single-core-seam.json"));
            }
            _ => panic!("expected mint-sighash-single-seam"),
        }
    }

    #[test]
    fn specimen_id_is_stable_for_key_order() {
        let a = json!({"b":2,"a":1});
        let b = json!({"a":1,"b":2});
        let ida = specimen_id_for_value(&a).expect("id a");
        let idb = specimen_id_for_value(&b).expect("id b");
        assert_eq!(ida, idb);
    }

    #[test]
    fn out_dir_overwrite_behavior() {
        let temp = std::env::temp_dir().join(format!("jb-demo-outdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("create");
        std::fs::write(temp.join("marker.txt"), b"x").expect("write marker");

        let err = prepare_out_dir(&temp, false).expect_err("should fail without force");
        let msg = format!("{err:#}");
        assert!(msg.contains("not empty"));

        prepare_out_dir(&temp, true).expect("force cleanup");
        let count = std::fs::read_dir(&temp).expect("read").count();
        assert_eq!(count, 0);
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn summarize_aggregates_fixture() {
        let root = std::env::temp_dir().join(format!("jb-summarize-{}", std::process::id()));
        let events_dir = root.join("events").join("2026-02-25");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&events_dir).expect("create events");

        let base_event = |id: &str,
                          class: &str,
                          core_reason: Option<&str>,
                          rust_reason: Option<&str>,
                          muts: Vec<&str>| {
            DivergenceEvent {
                testcase_id: id.to_string(),
                core: ExecResult::err(core_reason.unwrap_or("")),
                rust: ExecResult::err(rust_reason.unwrap_or("")),
                core_allowed: false,
                rust_ok: false,
                core_reason: core_reason.map(|s| s.to_string()),
                rust_reason: rust_reason.map(|s| s.to_string()),
                normalized_class: class.to_string(),
                mutations_applied: muts.into_iter().map(|s| s.to_string()).collect(),
                diff_summary: "d".to_string(),
                timestamp: chrono::Utc::now(),
                artifacts: vec![PathBuf::from("x")],
            }
        };

        let e1 = base_event(
            "a",
            "PREVOUT_MISSING",
            Some("wrong prevout (not harness funding outpoint)"),
            Some("wrong prevout (not harness funding outpoint)"),
            vec!["mutate_sequence", "mutate_locktime"],
        );
        let e2 = base_event(
            "b",
            "UNCLASSIFIED",
            Some("txn-mempool-conflict"),
            Some("unsupported: script not implemented"),
            vec!["mutate_sequence"],
        );
        std::fs::write(
            events_dir.join("a-event.json"),
            serde_json::to_vec_pretty(&e1).expect("serialize e1"),
        )
        .expect("write e1");
        std::fs::write(
            events_dir.join("b-event.json"),
            serde_json::to_vec_pretty(&e2).expect("serialize e2"),
        )
        .expect("write e2");
        std::fs::write(events_dir.join("bad-event.json"), b"{not-json").expect("write bad");

        let s = summarize_dir_offline(&root).expect("summarize");
        assert_eq!(s.total_events, 2);
        assert_eq!(s.malformed_files, 1);
        assert_eq!(
            *s.counts_by_normalized_class
                .get("PREVOUT_MISSING")
                .unwrap_or(&0),
            1
        );
        assert_eq!(
            *s.mutation_histogram.get("mutate_sequence").unwrap_or(&0),
            2
        );
        assert!(s.interestingness_score >= 3);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn summarize_compare_with_epoch_dirs() {
        let root = std::env::temp_dir().join(format!("jb-compare-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let e1 = root.join("epoch-a");
        let e2 = root.join("epoch-b");
        std::fs::create_dir_all(e1.join("events")).expect("epoch a");
        std::fs::create_dir_all(e2.join("events")).expect("epoch b");

        let event = |id: &str, class: &str, reason: &str, muts: Vec<&str>| DivergenceEvent {
            testcase_id: id.to_string(),
            core: ExecResult::err(reason),
            rust: ExecResult::err("r"),
            core_allowed: false,
            rust_ok: false,
            core_reason: Some(reason.to_string()),
            rust_reason: Some("r".to_string()),
            normalized_class: class.to_string(),
            mutations_applied: muts.into_iter().map(|m| m.to_string()).collect(),
            diff_summary: "d".to_string(),
            timestamp: chrono::Utc::now(),
            artifacts: vec![],
        };

        let s1 = super::SummaryOutput {
            total_events: 1,
            scanned_files: 1,
            parsed_events: 1,
            malformed_files: 0,
            counts_by_normalized_class: BTreeMap::from([(String::from("SCRIPT_FAIL"), 1usize)]),
            counts_by_core_reason: BTreeMap::from([(String::from("reason-a"), 1usize)]),
            top_core_reasons: vec![super::ReasonCount {
                reason: "reason-a".to_string(),
                count: 1,
            }],
            policy_allowed_count: 0,
            policy_rejected_count: 1,
            counts_by_policy_reason: BTreeMap::from([(String::from("reason-a"), 1usize)]),
            top_policy_reasons: vec![super::ReasonCount {
                reason: "reason-a".to_string(),
                count: 1,
            }],
            counts_by_rust_reason: BTreeMap::new(),
            mutation_histogram: BTreeMap::from([(String::from("mut-a"), 1usize)]),
            unique_core_reason_count: 1,
            unique_mutation_count: 1,
            interestingness_score: 1,
        };
        let s2 = super::SummaryOutput {
            total_events: 1,
            scanned_files: 1,
            parsed_events: 1,
            malformed_files: 0,
            counts_by_normalized_class: BTreeMap::from([(String::from("PARSE_FAIL"), 1usize)]),
            counts_by_core_reason: BTreeMap::from([(String::from("reason-b"), 1usize)]),
            top_core_reasons: vec![super::ReasonCount {
                reason: "reason-b".to_string(),
                count: 1,
            }],
            policy_allowed_count: 0,
            policy_rejected_count: 1,
            counts_by_policy_reason: BTreeMap::from([(String::from("reason-b"), 1usize)]),
            top_policy_reasons: vec![super::ReasonCount {
                reason: "reason-b".to_string(),
                count: 1,
            }],
            counts_by_rust_reason: BTreeMap::new(),
            mutation_histogram: BTreeMap::from([(String::from("mut-b"), 1usize)]),
            unique_core_reason_count: 1,
            unique_mutation_count: 1,
            interestingness_score: 1,
        };

        std::fs::write(
            e1.join("summary.json"),
            serde_json::to_vec_pretty(&s1).expect("serialize s1"),
        )
        .expect("write s1");
        std::fs::write(
            e2.join("summary.json"),
            serde_json::to_vec_pretty(&s2).expect("serialize s2"),
        )
        .expect("write s2");

        let ev1 = event("a", "SCRIPT_FAIL", "reason-a", vec!["mut-a"]);
        let ev2 = event("b", "PARSE_FAIL", "reason-b", vec!["mut-b"]);
        std::fs::write(
            e1.join("events").join("a-event.json"),
            serde_json::to_vec_pretty(&ev1).expect("serialize e1"),
        )
        .expect("write e1");
        std::fs::write(
            e1.join("events").join("a-testcase.json"),
            serde_json::to_vec_pretty(&json!({"id":"a"})).expect("serialize tc1"),
        )
        .expect("write tc1");
        std::fs::write(
            e2.join("events").join("b-event.json"),
            serde_json::to_vec_pretty(&ev2).expect("serialize e2"),
        )
        .expect("write e2");
        std::fs::write(
            e2.join("events").join("b-testcase.json"),
            serde_json::to_vec_pretty(&json!({"id":"b"})).expect("serialize tc2"),
        )
        .expect("write tc2");

        let cmp = summarize_compare_offline(&root).expect("compare");
        assert_eq!(cmp.epochs.len(), 2);
        assert!(
            cmp.epochs.iter().any(|e| e.epoch == "epoch-a"
                && e.reasons_only_in_epoch.contains(&"reason-a".to_string()))
        );
        assert!(cmp.class_table.contains_key("SCRIPT_FAIL"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn report_latex_escapes_and_shortens_hex() {
        assert_eq!(shorten_hex("1234567890abcdef1234567890abcdef"), "1234567890abcdef...");
        assert_eq!(latex_escape("a_b%c&d"), "a\\_b\\%c\\&d");

        let rows = vec![ReportRow {
            fixture_id: "dummy_zero".to_string(),
            epoch: "post_bip16_h173805".to_string(),
            family_label: "DUMMYGRIND_TXID_AXIS".to_string(),
            shadow_ok: true,
            shadow_reason: "ok_under_shadow".to_string(),
            core_allowed: false,
            core_reject_reason:
                "mempool-script-verify-flag-failed (Dummy CHECKMULTISIG argument must be zero)"
                    .to_string(),
            txid_hex: shorten_hex(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            sighash_digest_hex: shorten_hex(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            ),
            dummy_len: "32".to_string(),
            findanddelete_removed_total: String::new(),
            findanddelete_codeseparator_pos: "-1".to_string(),
            sighash_type: "0x01".to_string(),
            sighash_single_bug: "false".to_string(),
        }];
        let mut labels = BTreeMap::new();
        labels.insert("DUMMYGRIND_TXID_AXIS".to_string(), 1usize);

        let latex = render_report_latex(PathBuf::from("artifacts/p2sh_dummygrind_core_seam").as_path(), &rows, &labels);
        assert!(latex.contains("\\texttt{0123456789abcdef...}"));
        assert!(latex.contains("DUMMYGRIND\\_TXID\\_AXIS"));
        assert!(latex.contains("post\\_bip16\\_h173805"));
        assert!(latex.contains("Dummy CHECKMULTISIG argument must be zero"));
    }
}
