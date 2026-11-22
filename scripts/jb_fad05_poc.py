#!/usr/bin/env python3
"""JB-FAD05 regtest proof of concept: the testnet4 staging, carried to confirmation.

Runs the same builder as jb_fad05_testnet4.py (4 x 546-sat aux coins,
1,000-sat bare FAD05 vault, 1 sat/vB) on an isolated regtest Core node started
with -acceptnonstdtxn=1, i.e. with the testnet4 node's policy. Where testnet4
stopped, the harness plays the miner:

  1  fund the wallet (450 blocks; above bitcoin-rs's regtest CSV height 432)
  2  build + sign the funding tx and grind the HORS-attested settlement
  3  sendrawtransaction(funding)     -> accepted into the mempool
  4  sendrawtransaction(settlement)  -> refused (CONST_SCRIPTCODE mempool policy)
  5  mine one block from the mempool  -> funding confirmed
  6  include the settlement miner-direct (generateblock) -> vault spent
  7  referee: settlement statement against the registered policy
  8  bury under 6 blocks

With --bitcoin-rs, every block is also submitted to an isolated bitcoin-rs
node (native validation engine) and the tips must match after each step.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from jb_fad01 import RPCFailure, wallet_rpc
from jb_fad04_verify import build_merkle_branch
from jb_fad05_bitcoin_rs import TimedRPC, free_ports, sha256_file, stop, wait_ready
from jb_fad05_testnet4 import stage
from jb_fad05_verify import verify_settlement

START_HEIGHT = 450
BURY = 6


class PoC:
    def __init__(self, core: TimedRPC, rs: TimedRPC | None):
        self.core, self.rs = core, rs
        self.steps: list[dict] = []

    def say(self, n: int, text: str, **data) -> None:
        row = {"step": n, "text": text} | data
        if self.rs is not None:
            row["tips_match"] = self.rs("getbestblockhash") == self.core("getbestblockhash")
            if not row["tips_match"]:
                raise SystemExit(f"step {n}: bitcoin-rs tip differs from Core")
        self.steps.append(row)
        print(f"[{n}] {text}", flush=True)

    def relay(self, block: str) -> None:
        if self.rs is None:
            return
        result = self.rs("submitblock", self.core("getblock", block, 0))
        if result is not None:
            raise SystemExit(f"bitcoin-rs refused Core block {block}: {result}")

    def generate(self, n: int, address: str) -> list[str]:
        blocks = []
        while len(blocks) < n:
            blocks += self.core("generatetoaddress", min(50, n - len(blocks)), address)
        for b in blocks:
            self.relay(b)
        return blocks


def run(core: TimedRPC, rs: TimedRPC | None) -> dict:
    if core("getblockchaininfo")["chain"] != "regtest":
        raise SystemExit("the proof of concept runs on regtest only")
    poc = PoC(core, rs)
    wallet = wallet_rpc(core, "jb_fad05_poc")
    miner = wallet("getnewaddress", "jb-fad05-poc-miner", "bech32")
    poc.generate(START_HEIGHT - core("getblockcount"), miner)
    poc.say(1, f"wallet funded; height {core('getblockcount')}",
            height=core("getblockcount"))

    receipt, funding_hex, settlement_hex, s = stage(core, wallet)
    ftxid, vault_vout = receipt["funding"]["txid"], receipt["funding"]["vault_vout"]
    poc.say(2, f"funding {ftxid[:16]}.. ({receipt['funding']['vsize']} vB) and settlement "
               f"{s.txid[:16]}.. built; indices {list(s.subsets[0])} / {list(s.subsets[1])}; "
               f"grind {receipt['settlement']['grind_seconds']} s",
            funding_txid=ftxid, settlement_txid=s.txid)

    core("sendrawtransaction", funding_hex)
    in_pool = ftxid in core("getrawmempool")
    if not in_pool:
        raise SystemExit("funding not in the mempool")
    poc.say(3, "funding accepted into the mempool (acceptnonstdtxn=1)", mempool=True)

    try:
        core("sendrawtransaction", settlement_hex)
        raise SystemExit("settlement unexpectedly entered the mempool")
    except RPCFailure as exc:
        refusal = str(exc)
    if "Signature is found in scriptCode" not in refusal:
        raise SystemExit("settlement refused for an unexpected reason: " + refusal)
    poc.say(4, "settlement refused by the mempool: CONST_SCRIPTCODE policy", refusal=refusal)

    funding_block = poc.generate(1, miner)[0]
    if ftxid not in core("getblock", funding_block, 1)["tx"]:
        raise SystemExit("mined block did not include the funding transaction")
    vault = core("gettxout", ftxid, vault_vout, False)
    if vault is None:
        raise SystemExit("vault output missing after funding confirmed")
    poc.say(5, f"funding mined from the mempool in {funding_block[:16]}..; vault "
               f"{ftxid[:16]}..:{vault_vout} holds {round(vault['value'] * 1e8)} sats",
            funding_block=funding_block)

    settle_block = core("generateblock", miner, [settlement_hex])["hash"]
    poc.relay(settle_block)
    txids = core("getblock", settle_block, 1)["tx"]
    if s.txid not in txids or core("gettxout", ftxid, vault_vout, False) is not None:
        raise SystemExit("settlement not confirmed")
    payout = core("gettxout", s.txid, 0, False)
    poc.say(6, f"settlement included miner-direct in {settle_block[:16]}..; vault spent; "
               f"payout {round(payout['value'] * 1e8)} sats to P2WSH(successor || salt || wallet key)",
            settlement_block=settle_block)

    witness = {
        "raw_funding_hex": funding_hex,
        "raw_spend_hex": settlement_hex,
        "payout_witness_script_hex": receipt["settlement"]["payout_witness_script"],
        "block_header_hex": core("getblockheader", settle_block, False),
        "claimed_block_hash": settle_block,
        "merkle": build_merkle_branch(txids, txids.index(s.txid)),
    }
    verdict = verify_settlement(receipt["policy_registration"], witness, settle_block)
    poc.say(7, f"referee accepts against the registered policy; statement "
               f"{verdict['statement_hash'][:16]}..",
            statement_hash=verdict["statement_hash"])

    poc.generate(BURY, miner)
    confirmations = core("getblock", settle_block, 1)["confirmations"]
    poc.say(8, f"settlement buried at {confirmations} confirmations",
            confirmations=confirmations)

    return {"experiment": "JB-FAD05 regtest proof of concept"} | receipt | {
        "steps": poc.steps,
        "referee": {k: verdict[k] for k in ("statement_hash", "statement", "checks", "indices")},
        "blocks": {"funding": funding_block, "settlement": settle_block},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bitcoind", type=Path, required=True)
    ap.add_argument("--bitcoin-rs", type=Path)
    ap.add_argument("--bitcoin-rs-commit", default="unknown")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    logs = args.output.parent
    with tempfile.TemporaryDirectory(prefix="jb-fad05-poc-") as tmp, ExitStack() as stack:
        tmp = Path(tmp)
        core_rpc, core_p2p, rs_rpc, rs_p2p = free_ports(4)
        secret = secrets.token_hex(24)
        (tmp / "core").mkdir()
        core_log = stack.enter_context((logs / "poc-bitcoind.log").open("w"))
        core_proc = subprocess.Popen(
            [str(args.bitcoind), "-regtest", f"-datadir={tmp / 'core'}", f"-rpcport={core_rpc}",
             f"-port={core_p2p}", "-listen=0", "-connect=0", "-dnsseed=0", "-server=1",
             "-acceptnonstdtxn=1", "-rpcuser=jbfad05", f"-rpcpassword={secret}",
             "-fallbackfee=0.0001", "-printtoconsole=1"],
            stdout=core_log, stderr=subprocess.STDOUT)
        stack.callback(stop, core_proc)
        core = TimedRPC(f"http://127.0.0.1:{core_rpc}", "jbfad05", secret)
        wait_ready(core, core_proc, "bitcoind")
        rs = None
        if args.bitcoin_rs:
            import os
            (tmp / "rs").mkdir()
            env = {k: v for k, v in os.environ.items() if not k.startswith("BITCOIN_RS_")}
            env |= {"BITCOIN_RS_RPC_USER": "jbfad05", "BITCOIN_RS_RPC_PASSWORD": secret}
            rs_log = stack.enter_context((logs / "poc-bitcoin-rs.log").open("w"))
            rs_proc = subprocess.Popen(
                [str(args.bitcoin_rs), "--network", "regtest", "--data-dir", str(tmp / "rs"),
                 "--rpc-bind", f"127.0.0.1:{rs_rpc}", "--p2p-listen", f"127.0.0.1:{rs_p2p}",
                 "--dns-seeds-enabled=false", "--validation-engine", "native",
                 "--log-level", "info"], env=env, stdout=rs_log, stderr=subprocess.STDOUT)
            stack.callback(stop, rs_proc)
            rs = TimedRPC(f"http://127.0.0.1:{rs_rpc}", "jbfad05", secret)
            wait_ready(rs, rs_proc, "bitcoin-rs")
        started = time.monotonic()
        result = run(core, rs)
        result["engines"] = {
            "bitcoind": core("getnetworkinfo")["subversion"],
            "bitcoind_sha256": sha256_file(args.bitcoind),
            "bitcoin_rs_commit": args.bitcoin_rs_commit if rs else None,
            "bitcoin_rs_sha256": sha256_file(args.bitcoin_rs) if rs else None,
            "bitcoin_rs_final_tip_matches": (rs("getbestblockhash") == core("getbestblockhash")) if rs else None,
        }
        result["seconds"] = round(time.monotonic() - started, 1)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"funding": result["funding"]["txid"], "settlement": result["settlement"]["txid"],
                      "blocks": result["blocks"], "engines": result["engines"],
                      "seconds": result["seconds"], "receipt": str(args.output)}, indent=2))
    if rs is not None and not result["engines"]["bitcoin_rs_final_tip_matches"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
