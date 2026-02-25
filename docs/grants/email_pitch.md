Subject: Micro-grant proposal: deterministic differential testing harness for Bitcoin Core

Hello,

I am seeking a small micro-grant ($4k) to extend an existing prototype called Bitcoin Consensus Observatory (tagline: Jurassic Bitcoin), a deterministic differential testing harness for Bitcoin Core.

Current status:

- deterministic Core oracle integration on regtest (including direct `tx_hex` evaluation)
- one-command demo workflow (`doctor` -> `demo-run` -> `summarize`)
- divergence artifact generation with reduction and classification
- reproducible Windows/local setup with pruned regtest support

The project is explicitly testing and observability infrastructure. It is not a node replacement effort and treats Bitcoin Core as canonical.

With 6-8 weeks of focused work, I plan to deliver:

1. stronger deterministic seed generation and structure-aware mutators
2. a narrow behavior-driven `rust_shadow` semantic path (P2WPKH sighash + CHECKSIG)
3. CI-friendly replay/fuzz mode and publishable corpus/artifact documentation

I can provide a live, reproducible demo and a short technical brief showing current outputs and planned milestones.

If this is in scope for your current grant cycle, I would appreciate the chance to submit the full one-pager and demo materials.

Best,
[Your Name]
