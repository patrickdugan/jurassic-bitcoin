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
- Windows-focused pruned regtest setup docs/config for quick reproducible execution

## Proposed 6-8 Week Micro-Grant Scope

### M1: Seed and Mutator Robustness

- Harden deterministic seed generation workflows for repeatable tx-hex corpora
- Expand structure-aware mutators around sequence/locktime/witness-length domains
- Improve mutation trace metadata for better post-run analysis

### M2: Behavior-Driven Rust Shadow Semantics

- Implement a narrow P2WPKH path in `rust_shadow` with BIP143 sighash and CHECKSIG verification
- Keep scope strict (no P2P, no wallet, no node behavior) to ensure reviewability
- Align error surfaces with Core where feasible for high-signal differential output

### M3: CI-Friendly and Publishable Outputs

- Add deterministic CI mode for replay/fuzz smoke checks
- Publish seed corpus + reduced divergences in a reviewable format
- Improve operator docs for Core contributors and reviewers

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
