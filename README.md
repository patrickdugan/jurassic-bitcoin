# Jurassic Bitcoin

Jurassic Bitcoin is a consensus observability and differential testing harness for Bitcoin Core.
It compares Bitcoin Core behavior against a minimal Rust shadow executor on identical inputs and
stores reproducible divergence artifacts.

## Why

Bitcoin Core is canonical. This project does not attempt to replace or fork consensus. It exists to:

- make consensus behavior more observable
- expand adversarial testcase coverage
- produce minimized reproductions for review and QA workflows

## Scope

- testcase schema and corpus loader
- Core execution wrapper (real RPC template path + deterministic stub fallback)
- minimal Rust shadow execution path
- differential comparator and artifact writer
- corpus replay, fuzz loop, and simple reducer CLI commands

## Non-goals

- production node implementation
- networking, wallet, mempool, or mining features
- consensus rule changes

## Workspace Layout

- `crates/jb-model`: shared schemas (`TestCase`, `ExecResult`, `DivergenceEvent`)
- `crates/jb-ingest`: ingest helpers
- `crates/jb-core-exec`: Bitcoin Core execution wrapper
- `crates/jb-rust-shadow`: minimal Rust shadow executor
- `crates/jb-diff`: result comparator
- `crates/jb-corpus`: corpus/artifact IO
- `crates/jb-mutator`: testcase mutation
- `crates/jb-reducer`: divergence minimization
- `crates/jurassic-bitcoin-cli`: `replay`, `fuzz`, `reduce`, and `mint-seed` commands

## Run (MVP)

```bash
cargo run -p jurassic-bitcoin-cli -- replay --corpus corpus --max 100
```

This includes one intentional testcase mismatch (`hello-divergence`) so artifact writing can be
verified immediately.

Run fuzzing:

```bash
cargo run -p jurassic-bitcoin-cli -- fuzz --corpus corpus --iterations 1000 --seed 7
```

Mint a deterministic tx seed for tx-hex fuzzing:

```bash
cargo run -p jurassic-bitcoin-cli -- mint-seed --out corpus/seed-p2wpkh.json
```

Reduce a found divergence:

```bash
cargo run -p jurassic-bitcoin-cli -- reduce --event artifacts/YYYY-MM-DD/hello-divergence-event.json
```

## Core RPC Environment

- `BITCOIND_RPC_URL`
- `BITCOIND_RPC_USER`
- `BITCOIND_RPC_PASS`

When these are not set, `jb-core-exec` runs deterministic stub mode.

Run Core for template mode:

```bash
bitcoind -regtest -server -txindex=1 -fallbackfee=0.0002
```

Core template mode supports:

```json
{
  "core_template": {
    "kind": "spend_harness_utxo",
    "spend_type": "p2wpkh",
    "feerate_sats_vb": 2
  }
}
```

```json
{
  "core_template": {
    "kind": "testmempoolaccept_tx_hex",
    "spend_type": "p2wpkh"
  }
}
```

`testmempoolaccept_tx_hex` rules:

- `tc.tx_hex` is consumed directly
- tx must parse as a valid Bitcoin transaction encoding
- tx inputs must include the harness funding outpoint
- otherwise result is deterministic error (`invalid tx encoding` or `wrong prevout (not harness funding outpoint)`)

Determinism hardening in `jb-core-exec`:

- fixed wallet: `jb_harness`
- persistent state file for `mining_addr`, `sink_addr`, and funding outpoint
- explicit spending of recorded funding outpoint (no steady-state `getnewaddress`)
- `lockunspent` applied to non-funding UTXOs

State path resolution:

- `JB_STATE_PATH` (if set)
- `D:\jurassic-data\jb-state.json` (if `D:\jurassic-data` exists)
- otherwise `artifacts/state.json`

## Regtest Seed Workflow

1. Run `bitcoind -regtest -server -txindex=1 -fallbackfee=0.0002`.
2. Set `BITCOIND_RPC_URL`, `BITCOIND_RPC_USER`, `BITCOIND_RPC_PASS`.
3. Mint a seed:
   `cargo run -p jurassic-bitcoin-cli -- mint-seed --out corpus/seed-p2wpkh.json`
4. Fuzz that corpus:
   `cargo run -p jurassic-bitcoin-cli -- fuzz --corpus corpus --iterations 1000 --seed 7`

## Windows Disk Hygiene

Rust build outputs and crate caches can grow quickly. To keep heavy data off `C:`, set:

```powershell
setx CARGO_HOME "D:\\cargo-home"
setx RUSTUP_HOME "D:\\rustup-home"
setx CARGO_TARGET_DIR "D:\\cargo-target"
```

Open a new terminal after setting these.
