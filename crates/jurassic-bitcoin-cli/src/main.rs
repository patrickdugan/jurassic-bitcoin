use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use jb_core_exec::{doctor_report, mint_seed_testcase, run_testcase_core};
use jb_corpus::{load_corpus, write_divergence_event};
use jb_diff::diff_results;
use jb_model::{DivergenceEvent, TestCase};
use jb_mutator::mutate_testcase_with_trace;
use jb_reducer::reduce_divergence;
use jb_rust_shadow::run_testcase_rust;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;
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

#[cfg(test)]
mod tests {
    use super::{prepare_out_dir, Cli, Command};
    use clap::Parser;

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
}
