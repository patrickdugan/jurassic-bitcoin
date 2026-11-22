#!/usr/bin/env python3
"""Write the CI research-fixture policy for the JB-FAD05 referee.

The policy is derived from the deterministic fixture constants and the
funding outpoint the CI harness chose. It is NOT an independently
authenticated registration; its `provenance` field says so. It exists so CI
can exercise the referee's policy interface end to end.
"""

import argparse
import json
from pathlib import Path

from jb_fad05 import (
    PAYOUT_SATS, PREVIOUS_STATE_ROOT, PROGRAM_ID, RECIPIENT_SECRET,
    SETTLEMENT_FEE_SATS, key_body, make_setup,
)
from seam_digests_standalone import sha256


def fixture_policy(receipt: dict) -> dict:
    setup = make_setup()
    script = bytes.fromhex(receipt["locking_script_hex"])
    if script != setup.script:
        raise SystemExit("receipt locking script differs from the fixture setup")
    return {
        "schema": "jb-fad05-policy-v1",
        "vault_txid": receipt["funding"]["txid"],
        "vault_vout": receipt["funding"]["vault_vout"],
        "funding_script_sha256": sha256(script).hex(),
        "hors_root": setup.hors.root.hex(),
        "recipient_body_hex": key_body(RECIPIENT_SECRET).hex(),
        "payout_sats": PAYOUT_SATS,
        "fee_sats": SETTLEMENT_FEE_SATS,
        "verified_program_id": PROGRAM_ID.hex(),
        "previous_state_root": PREVIOUS_STATE_ROOT.hex(),
        "provenance": "CI-generated research fixture from public deterministic constants; "
                      "not an independently authenticated registration",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--native-receipt", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    receipt = json.loads(Path(args.native_receipt).read_text(encoding="utf-8"))
    Path(args.output).write_text(json.dumps(fixture_policy(receipt), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
