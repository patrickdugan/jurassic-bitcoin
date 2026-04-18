#!/usr/bin/env python3
"""Extract Litecoin RPC block windows into the repo testcase corpus format."""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import time
import urllib.request
from pathlib import Path


class RpcClient:
    def __init__(self, url: str, user: str, password: str, timeout_sec: int, retries: int) -> None:
        token = base64.b64encode(f"{user}:{password}".encode("ascii")).decode("ascii")
        self.url = url
        self.headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "text/plain",
        }
        self.timeout_sec = timeout_sec
        self.retries = retries

    def call(self, method: str, params: list[object]) -> object:
        body = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": "litecoin-history",
                "method": method,
                "params": params,
            }
        ).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                if payload.get("error") is not None:
                    raise RuntimeError(f"rpc {method} error: {payload['error']}")
                return payload["result"]
            except Exception as err:
                last_error = err
                if attempt >= self.retries:
                    break
                time.sleep(1 + attempt)
        raise RuntimeError(f"rpc {method} failed after retries: {last_error}")


def prepare_out_dir(path: Path, force: bool) -> None:
    if path.exists() and any(path.iterdir()):
        if not force:
            raise SystemExit(f"output dir is not empty: {path} (use --force)")
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def testcase_for_tx(
    *,
    tx: dict,
    block: dict,
    height: int,
    tx_index: int,
    prefix: str,
    network: str,
) -> dict:
    txid = str(tx.get("txid") or "unknown")
    case_id = f"{prefix}-h{height}-tx{tx_index:04d}"
    return {
        "id": case_id,
        "description": f"Extracted Litecoin tx at height {height}",
        "network": network,
        "utxo_set": [],
        "tx_hex": str(tx.get("hex") or ""),
        "flags": [],
        "context": {
            "height": height,
            "median_time_past": block.get("mediantime"),
            "block_time": block.get("time"),
            "epoch": None,
        },
        "core_template": {
            "kind": "decode_tx_hex",
            "spend_type": "rawtx",
            "feerate_sats_vb": None,
        },
        "metadata": {
            "source": "litecoin-rpc-block",
            "chain": network,
            "block_hash": block.get("hash"),
            "txid": txid,
            "tx_index": tx_index,
            "block_version": block.get("version"),
            "block_version_hex": block.get("versionHex"),
        },
    }


def extract_window(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_corpus).resolve()
    prepare_out_dir(out_dir, args.force)
    rpc = RpcClient(args.rpc_url, args.rpc_user, args.rpc_pass, args.timeout_secs, args.retries)

    chain = rpc.call("getblockchaininfo", [])
    chain_name = str(chain.get("chain") or args.network)
    if args.expected_chain and chain_name != args.expected_chain:
        raise SystemExit(f"expected chain {args.expected_chain}, got {chain_name}")

    written = 0
    for height in range(args.start_height, args.end_height + 1):
        block_hash = rpc.call("getblockhash", [height])
        block = rpc.call("getblock", [block_hash, 2])
        txs = list(block.get("tx") or [])
        for tx_index, tx in enumerate(txs[: args.limit_per_height]):
            tx_hex = tx.get("hex")
            if not isinstance(tx_hex, str) or not tx_hex:
                continue
            testcase = testcase_for_tx(
                tx=tx,
                block=block,
                height=height,
                tx_index=tx_index,
                prefix=args.prefix,
                network=args.network,
            )
            path = out_dir / f"{testcase['id']}.json"
            path.write_text(json.dumps(testcase, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
            written += 1

    meta = {
        "extractor": "scripts/extract_litecoin_history.py",
        "rpc_chain": chain_name,
        "network": args.network,
        "start_height": args.start_height,
        "end_height": args.end_height,
        "limit_per_height": args.limit_per_height,
        "written": written,
    }
    (out_dir / "_extract.json").write_text(json.dumps(meta, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"extracted_testcases={written} out={out_dir}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract Litecoin RPC block windows")
    parser.add_argument("--start-height", type=int, required=True)
    parser.add_argument("--end-height", type=int, required=True)
    parser.add_argument("--limit-per-height", type=int, default=25)
    parser.add_argument("--out-corpus", required=True)
    parser.add_argument("--prefix", default="ltctest")
    parser.add_argument("--network", default="litecoin-testnet")
    parser.add_argument("--expected-chain", default="test")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:19332/")
    parser.add_argument("--rpc-user", default="user")
    parser.add_argument("--rpc-pass", default="pass")
    parser.add_argument("--timeout-secs", type=int, default=60)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.start_height > args.end_height:
        raise SystemExit("--start-height must be <= --end-height")
    if args.limit_per_height < 1:
        raise SystemExit("--limit-per-height must be >= 1")
    return extract_window(args)


if __name__ == "__main__":
    raise SystemExit(main())
