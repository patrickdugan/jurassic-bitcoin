use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use jb_core_exec::{mint_seed_testcase, run_testcase_core};
use jb_corpus::{load_corpus, write_divergence_event};
use jb_diff::diff_results;
use jb_model::TestCase;
use jb_mutator::mutate_testcase_with_trace;
use jb_reducer::reduce_divergence;
use jb_rust_shadow::run_testcase_rust;
use rand::{rngs::StdRng, SeedableRng};
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
