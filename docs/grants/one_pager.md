# Bitcoin Consensus Observatory (Jurassic Bitcoin)

## Problem Statement

Bitcoin consensus behavior is effectively defined by one canonical implementation, and many edge-case rules are only discoverable through behavior under adversarial inputs. This creates review pressure: contributors must reason about implicit historical "fossils" in consensus without a compact differential observability layer. Bitcoin Consensus Observatory addresses that gap by making Core behavior replayable, fuzzable, and reducible into reproducible divergence artifacts.

## What Exists Now

- Core oracle path with deterministic regtest templates, including direct `tx_hex` evaluation via `testmempoolaccept`
- Deterministic harness state management (stable wallet, funding outpoint, persisted state path)
- One-command demo orchestration: `demo-run` (doctor, seed mint, replay, fuzz, reduce, summary bundle)
- Divergence reducer for smaller repro cases
- Offline summarizer for artifact analysis (`summarize`) with class/reason/mutation aggregation
- Scientific artifact fields (`normalized_class`, reasons, mutation traces) for clustering and auditability
- Static museum/dashboard output plus curation loop (`museum`, `suggest-labels`, `apply-label`)
- Paper-ready seam table generation (`report --format md|latex`)
- Regtest-funded legacy seam families for:
  - FindAndDelete / `OP_CHECKMULTISIG` scriptCode mutation
  - `SIGHASH_SINGLE` degeneracy
  - `DUMMYGRIND` txid-axis malleability via the multisig dummy element
- Policy-vs-consensus-style stratification on the same specimen set (`policy_allowed`, `policy_reason`, shadow reason/digest fields)
- Windows-focused pruned regtest setup docs/config for quick reproducible execution

## Proposed 6-8 Week Micro-Grant Scope

### M1: Seed and Mutator Robustness

- Harden deterministic seed generation workflows for repeatable tx-hex corpora
- Expand structure-aware mutators around sequence/locktime/witness-length domains
- Improve mutation trace metadata for better post-run analysis

### M2: Legacy Quirk Surface Expansion

- Generalize the current legacy seam work into a reusable search bench for additional pre-2018 quirk families
- Add more historical axes where the harness can compute real digest surfaces rather than proxy tags
- Expand curated fixture families and labels so new constructions are measurable, replayable, and reviewable

### M3: CI-Friendly and Publishable Outputs

- Add deterministic CI mode for replay/fuzz/seam smoke checks
- Publish a curated corpus of labeled specimens and seam manifests
- Improve report-generation and operator docs for Core contributors and reviewers

## Risks and Mitigations

- Policy vs consensus noise:
  - Mitigation: explicit classification labels and scoped templates to separate policy rejects from semantic diffs.
- Nondeterminism in harness state:
  - Mitigation: persisted addresses/funding outpoint, stable state file, seeded fuzzing, fixed output layout.
- Misinterpretation as alternative node effort:
  - Mitigation: explicit non-goal language; Core remains canonical; project is observability/test infrastructure only.
- Scope creep:
  - Mitigation: narrow semantic milestones, template-first execution model, strict no-P2P/no-wallet expansion.

## Budget ($4,000)

- Engineering implementation (core harness + mutator + shadow semantics): $2,800
- Reproducibility/CI/docs hardening and artifact publishing: $700
- Review, issue triage, packaging, and maintainer communication: $500

Total: $4,000

## Current Wedge

In under a week, the project has already converted historically ossified Bitcoin behaviors into reproducible experimental surfaces with:

- deterministic cryptographic measurements (`txid_hex`, `sighash_digest_hex`, context tags)
- explicit policy-vs-consensus-style stratification on identical specimens
- stable specimen IDs, labels, museum views, and auto-generated LaTeX tables

That is the core value proposition: not another fuzzer, but a compact observability bench for testing ideas against Bitcoin's inherited consensus envelope.
