Subject: Micro-grant proposal: reproducible consensus quirk observability bench for Bitcoin Core

Hello,

I am seeking a small micro-grant ($4k) to extend an existing prototype called Bitcoin Consensus Observatory (tagline: Jurassic Bitcoin), a deterministic observability and differential-testing harness for Bitcoin Core.

Current status:

- deterministic Core oracle integration on regtest (including direct `tx_hex` evaluation)
- one-command demo workflow (`doctor` -> `demo-run` -> `summarize`)
- divergence artifact generation with reduction and classification
- static museum/dashboard output plus label curation
- paper-ready figure table generation from artifact directories
- funded legacy seam families already demonstrating:
  - FindAndDelete / `OP_CHECKMULTISIG` scriptCode mutation
  - `SIGHASH_SINGLE` degeneracy
  - txid grinding via the multisig dummy element (`DUMMYGRIND`)
- reproducible Windows/local setup with pruned regtest support

The project is explicitly testing and observability infrastructure. It is not a node replacement effort and treats Bitcoin Core as canonical.

With 6-8 weeks of focused work, I plan to deliver:

1. stronger deterministic seed generation and structure-aware mutators
2. additional historically meaningful quirk families with real digest measurement
3. CI-friendly replay/seam smoke mode and publishable corpus/artifact documentation

I can provide a live, reproducible demo, a short technical brief, and paper-ready artifacts generated directly from the current repo.

If this is in scope for your current grant cycle, I would appreciate the chance to submit the full one-pager and demo materials.

Best,
[Your Name]
