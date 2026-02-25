# Demo Script (Grant Review)

This script demonstrates a complete deterministic run using local regtest in pruned mode on `D:\`.

## 1) Start bitcoind (pruned regtest on D:\)

```powershell
.\scripts\run-bitcoind-pruned.ps1 -DataDir "D:\bitcoin-regtest" -PruneMiB 550
```

Expected: `bitcoind` starts with regtest/server enabled and RPC bound to localhost.

## 2) Set RPC environment variables

```powershell
$env:BITCOIND_RPC_URL="http://127.0.0.1:18443"
$env:BITCOIND_RPC_USER="<rpcuser>"
$env:BITCOIND_RPC_PASS="<rpcpassword>"
```

Optional:

```powershell
$env:JB_BITCOIND_DATADIR="D:\bitcoin-regtest"
```

## 3) Run doctor (preflight)

```powershell
cargo run -p jurassic-bitcoin-cli -- doctor
```

Expected high-level output:

- `doctor: ok`
- `chain=regtest`
- `wallet=jb_harness ready=true`
- resolved `state_path`
- funding outpoint status
- suggested exact bitcoind start command

## 4) Run one-command demo bundle

```powershell
cargo run -p jurassic-bitcoin-cli -- demo-run --out-dir artifacts/demo --iterations 200 --seed 7 --force
```

Expected high-level output:

- seed file path
- divergence count/class summary
- best event path
- reduced testcase path
- `demo-summary.json` path

## 5) Summarize results offline

```powershell
cargo run -p jurassic-bitcoin-cli -- summarize --dir artifacts/demo --json
```

Expected high-level output:

- total events
- class histogram
- top core reject reasons
- mutation histogram
- `artifacts/demo/summary.json` written
