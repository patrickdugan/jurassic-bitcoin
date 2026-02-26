use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
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
    let mut counts_by_rust_reason: BTreeMap<String, usize> = BTreeMap::new();
    let mut mutation_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut unique_core_reasons: BTreeSet<String> = BTreeSet::new();
    let mut unique_mutations: BTreeSet<String> = BTreeSet::new();

    let mut parsed_events = 0usize;
    let mut malformed_files = 0usize;

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

        let core_reason = event.core_reason.unwrap_or_else(|| "<none>".to_string());
        *counts_by_core_reason
            .entry(core_reason.clone())
            .or_insert(0) += 1;
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

    Ok(SummaryOutput {
        total_events: parsed_events,
        scanned_files,
        parsed_events,
        malformed_files,
        counts_by_normalized_class,
        counts_by_core_reason,
        top_core_reasons,
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
    top_mutations: Vec<ReasonCount>,
    reasons_only_in_epoch: Vec<String>,
    mutations_only_in_epoch: Vec<String>,
    unique_specimen_count: usize,
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

        let top_mutations = top_reasons(summary.mutation_histogram, 5);
        rows.push(EpochCompareRow {
            epoch: epoch.clone(),
            counts_by_normalized_class: summary.counts_by_normalized_class,
            top_core_reasons: top_reasons(summary.counts_by_core_reason, 5),
            top_mutations,
            reasons_only_in_epoch: Vec::new(),
            mutations_only_in_epoch: Vec::new(),
            unique_specimen_count: 0,
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
    }
}

#[derive(Debug, Clone, Serialize)]
struct MuseumEpochSummary {
    epoch: String,
    total_events: usize,
    counts_by_normalized_class: BTreeMap<String, usize>,
    top_core_reasons: Vec<ReasonCount>,
    top_rust_reasons: Vec<ReasonCount>,
}

#[derive(Debug, Clone, Serialize)]
struct MuseumSpecimen {
    specimen_id: String,
    testcase_id: String,
    epoch: String,
    normalized_class: String,
    core_reason: Option<String>,
    rust_reason: Option<String>,
    script_trace: Option<String>,
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
    let mut epoch_rust_reason_counts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();

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
        specimens.push(MuseumSpecimen {
            specimen_id: specimen_id.clone(),
            testcase_id: event.testcase_id.clone(),
            epoch,
            normalized_class: event.normalized_class.clone(),
            core_reason: event.core_reason.clone(),
            rust_reason: event.rust_reason.clone(),
            script_trace,
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
            epoch,
            total_events,
            counts_by_normalized_class,
            top_core_reasons,
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
      <thead><tr><th>Specimen</th><th>Epoch</th><th>Class</th><th>Label</th><th>Core</th><th>Rust</th><th>Trace</th><th>Mutations</th><th>Links</th></tr></thead>
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
    div.innerHTML = `<strong>${e.epoch}</strong><div class="muted">${e.total_events} events</div>`;
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
        Cli, Command, prepare_out_dir, specimen_id_for_value, summarize_compare_offline,
        summarize_dir_offline,
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
}
