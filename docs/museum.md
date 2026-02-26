# Quirk Museum

The museum command builds a static dashboard over divergence artifacts.

## Generate museum bundle

```powershell
cargo run -p jurassic-bitcoin-cli -- museum --in artifacts/era-2009-2013 --out artifacts/museum
```

Outputs:

- `artifacts/museum/data.json`
- `artifacts/museum/index.html`

Open `index.html` in a browser. The page supports filtering by epoch, class, reason, and mutation text.

## Vite dashboard (timeline + quirk bubbles)

```powershell
cd tools/quirk-museum-vite
npm install
npm run sync:data
npm run dev
```

Then open `http://localhost:5174`.

Design notes:

- top timeline layer with clickable glass scroller
- lower bubble field (soft orange-yellow palette)
- bubble colors mapped to quirk type (`normalized_class`)

## Suggest labels (rule-based)

```powershell
cargo run -p jurassic-bitcoin-cli -- suggest-labels --in artifacts/era-2009-2013 --out artifacts/museum/suggestions.json
```

This produces deterministic suggestions only. It does not modify labels.

## Apply a curated label

```powershell
cargo run -p jurassic-bitcoin-cli -- apply-label --specimen <specimen_id> --label PUSHDATA_LEN_OVERRUN --labels artifacts/museum/labels.json
```

Re-run `museum` after editing labels to refresh displayed labels.

## Specimen ID definition

`specimen_id` is `sha256(canonical_json)` where canonical JSON uses lexicographically sorted object keys.

Source preference:

1. reduced testcase JSON (`*-reduced.json`) if present
2. testcase JSON paired with event (`*-testcase.json`)
3. event JSON as fallback

## Screenshot capture

On Windows, open `artifacts/museum/index.html` and capture with Snipping Tool or browser screenshot.
