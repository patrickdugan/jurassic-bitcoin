# Litecoin BitVM Live Suite

This repo now owns the LTC/BitVM live-test control surface, even though the
protocol execution still runs in `C:\projects\tradelayer.js`.

## Local Layout

- Repo-local test entrypoints: `tests/litecoin-bitvm/`
- Node start helper: `scripts/litecoin-bitvm/start_testnet_node.ps1`
- Runner: `scripts/litecoin-bitvm/run_live_suite.ps1`
- Procedural-token runner: `scripts/litecoin-bitvm/run_procedural_suite.ps1`
- Pending-cache seed helper: `scripts/litecoin-bitvm/seed_watchtower_cache.js`
- Artifacts: `artifacts/litecoin-bitvm/<yyyy-MM-dd>/`

## What The Suite Covers

1. `tx30` Plan A `uphold`
2. `tx30` Plan A `reject`
3. Seed a pending BitVM cache in protocol state
4. Run one-shot watchtower in `challenge` mode

All stdout/stderr is written under the dated artifact folder, along with:

- `run-summary.json`
- `run-summary.md`

## Default Runtime Assumptions

- Litecoin Core testnet RPC on `127.0.0.1:19332`
- RPC auth: `user` / `pass`
- Wallet scope: `wallet.dat`
- Protocol repo: `C:\projects\tradelayer.js`
- Admin address: `tltc1qa0kd2d39nmeph3hvcx8ytv65ztcywg5sazhtw8`
- Challenger/winner address: `tltc1qwtgx0c9f92ww8gtat82zpsgu4gttwx37xzsf2v`

The suite performs a small preflight:

- verifies LTCTEST RPC
- loads `wallet.dat` if needed
- keeps the requested oracle admin address
- uses confirmed admin UTXOs when available
- falls back to wallet-visible zero-conf UTXOs when LTCTEST funds are pending
- funds the admin address if it has no wallet-visible UTXO, but does not mine LTCTEST blocks
- probes whether `tx30` is already active in protocol state
- skips repeated activation once `tx30` is already active
- records the selected admin address and UTXO in the artifact folder

## Run

If LTCTEST RPC is down, start the node first:

```powershell
powershell -File .\scripts\litecoin-bitvm\start_testnet_node.ps1
```

Then run the suite:

```powershell
pwsh -File .\scripts\litecoin-bitvm\run_live_suite.ps1
```

Or on Windows PowerShell:

```powershell
powershell -File .\scripts\litecoin-bitvm\run_live_suite.ps1
```

## Notes

- The external `tradelayer.js` harnesses needed `TIMEOUT_MS=180000` in this environment.
- The repo-local test entrypoints are thin wrappers around the external `tradelayer.js` live harnesses.
- Watchtower runs may detect older pending caches that already exist in protocol state, so
  the summary should be read together with the raw log.
- Procedural-token flow coverage lives in `docs/litecoin-bitvm/procedural_tokens.md`.
