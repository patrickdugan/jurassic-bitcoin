use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use jb_consensus_profile::{epochs_for_range, flags_for_height};
use jb_core_exec::{doctor_report, mint_seed_testcase, run_testcase_core};
use jb_corpus::{load_corpus, write_divergence_event};
use jb_diff::diff_results;
use jb_model::{DivergenceEvent, TestCase, ValidationContext};
use jb_mutator::mutate_testcase_with_trace;
use jb_reducer::reduce_divergence;
use jb_rust_shadow::run_testcase_rust;
use rand::{rngs::StdRng, SeedableRng};
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
    },
    ReplayEra {
        #[arg(long)]
        start_height: u32,
        #[arg(long)]
        end_height: u32,
        #[arg(long, default_value_t = 150)]
        limit: usize,
        #[arg(long, default_value = "artifacts/era")]
        out_dir: PathBuf,
        #[arg(long, default_value = "corpus")]
        corpus: PathBuf,
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
        Command::Summarize { dir, json } => summarize(&dir, json),
        Command::ReplayEra {
            start_height,
            end_height,
            limit,
            out_dir,
            corpus,
            force,
        } => replay_era(start_height, end_height, limit, &out_dir, &corpus, force),
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
    let case_bytes =
        fs::read(&case_path).with_context(|| format!("reading testcase {}", case_path.display()))?;
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
    println!("wallet={} ready={}", report.wallet_name, report.wallet_ready);
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

fn demo_run(out_dir: &Path, iterations: usize, seed: u64, force: bool, _corpus: &Path) -> Result<()> {
    let report = doctor_report().map_err(|e| {
        anyhow!(
            "doctor failed: {e:#}\nRun this first:\n  cargo run -p jurassic-bitcoin-cli -- doctor"
        )
    })?;
    println!("doctor: ok chain={} rpc_url={}", report.chain, report.rpc_url);

    prepare_out_dir(out_dir, force)?;
    let events_dir = out_dir.join("events");
    let reduced_dir = out_dir.join("reduced");
    fs::create_dir_all(&events_dir).with_context(|| format!("creating {}", events_dir.display()))?;
    fs::create_dir_all(&reduced_dir).with_context(|| format!("creating {}", reduced_dir.display()))?;

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
            *class_counts.entry(event.normalized_class.clone()).or_insert(0) += 1;
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
    start_height: u32,
    end_height: u32,
    limit: usize,
    out_dir: &Path,
    corpus_dir: &Path,
    force: bool,
) -> Result<()> {
    if start_height > end_height {
        return Err(anyhow!("start-height must be <= end-height"));
    }
    prepare_out_dir(out_dir, force)?;
    let corpus = load_corpus(corpus_dir)?;
    if corpus.is_empty() {
        return Err(anyhow!("corpus is empty: {}", corpus_dir.display()));
    }

    let epochs = epochs_for_range(start_height, end_height);
    for epoch in epochs {
        let epoch_dir = out_dir.join(format!("{}-h{}", epoch.label, epoch.sample_height));
        fs::create_dir_all(&epoch_dir).with_context(|| format!("creating {}", epoch_dir.display()))?;
        let events_dir = epoch_dir.join("events");
        fs::create_dir_all(&events_dir).with_context(|| format!("creating {}", events_dir.display()))?;

        let mut checked = 0usize;
        let mut divergences = 0usize;
        let epoch_flags = flags_for_height(epoch.sample_height);

        for tc in corpus.iter().take(limit) {
            checked += 1;
            let mut adjusted = tc.clone();
            adjusted.context = Some(ValidationContext {
                height: epoch.sample_height,
                median_time_past: None,
            });
            adjusted.flags = epoch_flags.clone();
            adjusted.id = format!("{}-h{}", adjusted.id, epoch.sample_height);

            let core = run_testcase_core(&adjusted);
            let rust = run_testcase_rust(&adjusted);
            if let Some(event) = diff_results(&adjusted, &core, &rust) {
                divergences += 1;
                let _ = write_divergence_event(&events_dir, &event, &adjusted)?;
            }
        }

        let replay_summary = ReplaySummary { checked, divergences };
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
            "epoch={} height={} checked={} divergences={} summary={}",
            epoch.label,
            epoch.sample_height,
            checked,
            divergences,
            summary_path.display()
        );
    }
    Ok(())
}

fn summarize(dir: &Path, write_json: bool) -> Result<()> {
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

        let core_reason = event
            .core_reason
            .unwrap_or_else(|| "<none>".to_string());
        *counts_by_core_reason.entry(core_reason.clone()).or_insert(0) += 1;
        if core_reason != "<none>" {
            unique_core_reasons.insert(core_reason);
        }

        let rust_reason = event
            .rust_reason
            .unwrap_or_else(|| "<none>".to_string());
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
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
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

#[cfg(test)]
mod tests {
    use super::{prepare_out_dir, summarize_dir_offline, Cli, Command};
    use clap::Parser;
    use jb_model::{DivergenceEvent, ExecResult};
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

        let base_event = |id: &str, class: &str, core_reason: Option<&str>, rust_reason: Option<&str>, muts: Vec<&str>| {
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
}
