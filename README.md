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

Bundled local binary (downloaded): `tools/bitcoin-core-30.2/bitcoin-30.2/bin/bitcoind.exe`

Pruned runner (datadir on `D:`):

```powershell
.\scripts\run-bitcoind-pruned.ps1 -DataDir "D:\bitcoin-regtest" -PruneMiB 550
```

Config template:

- `configs/bitcoin.regtest.pruned.conf`
- copy to `D:\bitcoin-regtest\bitcoin.conf`
- detailed guide: `docs/bitcoind-windows-regtest.md`

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

Rust shadow status for `testmempoolaccept_tx_hex`:

- parses tx encoding and input outpoints
- enforces harness funding outpoint context
- executes a basic script opcode slice for P2WPKH-style scriptCode:
  - pushes (`0x01..0x4b`, `PUSHDATA1/2/4`, `OP_0`, `OP_1..OP_16`)
  - `OP_DUP`, `OP_HASH160`, `OP_EQUALVERIFY`
  - `OP_CHECKSIG` via deterministic hook (`metadata.checksighook=true|false`)
- returns matching gate errors:
  - `invalid tx encoding`
  - `wrong prevout (not harness funding outpoint)`
- narrow scope limits:
  - one input only
  - witness form ending with `[sig, pubkey]` only
  - no signature hashing/crypto verification yet

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

1. Prepare `D:\bitcoin-regtest\bitcoin.conf` from `configs/bitcoin.regtest.pruned.conf`.
2. Start bitcoind in pruned regtest mode:
   `.\scripts\run-bitcoind-pruned.ps1 -DataDir "D:\bitcoin-regtest" -PruneMiB 550`
3. Set `BITCOIND_RPC_URL`, `BITCOIND_RPC_USER`, `BITCOIND_RPC_PASS`.
4. Run doctor:
   `cargo run -p jurassic-bitcoin-cli -- doctor`
5. Mint a seed:
   `cargo run -p jurassic-bitcoin-cli -- mint-seed --out corpus/seed-p2wpkh.json`
6. Fuzz that corpus:
   `cargo run -p jurassic-bitcoin-cli -- fuzz --corpus corpus --iterations 1000 --seed 7`

## Demo Run

One-command orchestrator for demos and grant walkthroughs:

```powershell
cargo run -p jurassic-bitcoin-cli -- demo-run --out-dir artifacts/demo --iterations 200 --seed 7
```

`demo-run` performs:

1. `doctor` preflight (RPC env, chain, wallet, state/funding visibility)
2. seed minting to `artifacts/demo/seed-p2wpkh.json`
3. replay on that seed with `replay-summary.json`
4. fuzz loop with divergence events under `artifacts/demo/events/YYYY-MM-DD/`
5. reducer on the best divergence candidate
6. final summary in `artifacts/demo/demo-summary.json`

Use `--force` to overwrite a non-empty output directory.

## Analyze Results

Summarize an existing demo bundle without re-running fuzzing:

```powershell
cargo run -p jurassic-bitcoin-cli -- summarize --dir artifacts/demo --json
```

This prints class/reason/mutation aggregates and writes `artifacts/demo/summary.json`.

## Grant Package

Grant-ready materials are in `docs/grants/`:

- `docs/grants/one_pager.md`
- `docs/grants/email_pitch.md`
- `docs/grants/demo_script.md`

Divergence artifacts include:

- normalized class labels (`PARSE_FAIL`, `PREVOUT_MISSING`, `SCRIPT_FAIL`, `POLICY_FAIL`, `SIG_FAIL`, `UNCLASSIFIED`)
- mutation trace list (`mutations_applied`) for fuzzed cases

## Windows Disk Hygiene

Rust build outputs and crate caches can grow quickly. To keep heavy data off `C:`, set:

```powershell
setx CARGO_HOME "D:\\cargo-home"
setx RUSTUP_HOME "D:\\rustup-home"
setx CARGO_TARGET_DIR "D:\\cargo-target"
```

Open a new terminal after setting these.
