# Quirk Museum Vite Dashboard

This app visualizes `artifacts/museum/data.json` as an interactive timeline and
quirk bubble field. It also has a Bitcoin DeFi Grafts tab backed by
`artifacts/grants/bitcoin_defi_graft_map.json`, including per-demo flow
diagrams, motif mechanics, and Bitcoin Core source anchors.

## Status

- Optional local UI for richer exploration.
- Canonical museum output remains the CLI-generated static bundle:
  - `cargo run -p jurassic-bitcoin-cli -- museum --in <artifacts> --out <museum-dir>`
  - outputs `<museum-dir>/data.json` and `<museum-dir>/index.html`

## Setup

```powershell
cd tools/quirk-museum-vite
npm install
npm run sync:data
npm run dev
```

Then open `http://localhost:5174`.

## Data refresh

After generating new museum data:

```powershell
cargo run -p jurassic-bitcoin-cli -- museum --in artifacts/era-2009-2013 --out artifacts/museum
python .\scripts\build_bitcoin_defi_graft_map.py
cd tools/quirk-museum-vite
npm run sync:data
```

`sync:data` copies:

- `artifacts/museum/data.json` -> `public/data.json`
- `artifacts/grants/bitcoin_defi_graft_map.json` -> `public/bitcoin-defi-graft-map.json`

If the graft map is missing, the app still renders a compact built-in fallback
for the DeFi tab.

The longer Mermaid diagram write-up lives at
`docs/bitcoin_defi_graft_diagrams.md`.

## Color key

- `SCRIPT_FAIL` -> amber
- `PARSE_FAIL` -> burnt orange
- `POLICY_FAIL` -> honey
- `SIG_FAIL` -> rust orange
- `PREVOUT_MISSING` -> terracotta
- `UNCLASSIFIED` -> sandstone
