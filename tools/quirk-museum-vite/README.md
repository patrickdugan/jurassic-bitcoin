# Quirk Museum Vite Dashboard

This app visualizes `artifacts/museum/data.json` as an interactive timeline and quirk bubble field.

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
cd tools/quirk-museum-vite
npm run sync:data
```

## Color key

- `SCRIPT_FAIL` -> amber
- `PARSE_FAIL` -> burnt orange
- `POLICY_FAIL` -> honey
- `SIG_FAIL` -> rust orange
- `PREVOUT_MISSING` -> terracotta
- `UNCLASSIFIED` -> sandstone
