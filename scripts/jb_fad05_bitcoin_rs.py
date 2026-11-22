#!/usr/bin/env python3
"""JB-FAD05 regtest demonstration on two consensus engines.

Starts an isolated Bitcoin Core regtest node (wallet, miner, reference) and
an isolated bitcoin-rs regtest node (native validation engine), with no P2P
link between them. jb_fad05_native.run_native drives Core; every block Core
accepts or invalidates is replayed into bitcoin-rs, and every transaction
Core refuses is wrapped in one hand-built block submitted to both engines.

The receipt is the native receipt plus `bitcoin_rs_differential` and the
binary hashes of both nodes. The run fails when any comparison disagrees.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from jb_fad01 import CoreRPC, RPCFailure
from jb_fad05_native import run_native


class TimedRPC(CoreRPC):
    """JSON-RPC client with a long timeout that records the slowest call.

    bitcoin-rs occasionally holds one submitblock past two minutes while its
    sync frontier settles (seen locally once in four runs); a fixed 120 s
    client timeout turned that into a false failure.
    """

    def __init__(self, url: str, user: str, password: str, timeout: float = 900):
        super().__init__(url, user, password)
        self.timeout = timeout
        self.slowest = (0.0, "")

    def __call__(self, method: str, *params):
        import json as _json
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen
        payload = _json.dumps({"jsonrpc": "1.0", "id": "jb-fad05", "method": method,
                               "params": params}).encode()
        req = Request(self.url, payload, {"Content-Type": "application/json",
                                          "Authorization": self.auth})
        t0 = time.monotonic()
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
        except HTTPError as e:
            body = e.read()
        took = time.monotonic() - t0
        if took > self.slowest[0]:
            self.slowest = (round(took, 2), method)
        try:
            data = _json.loads(body)
        except ValueError:
            raise RPCFailure(method + ": invalid RPC response") from None
        if data.get("error"):
            raise RPCFailure(method + ": " + str(data["error"]))
        return data["result"]


def free_ports(n: int) -> list[int]:
    ports = set()
    while len(ports) < n:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            ports.add(s.getsockname()[1])
    return sorted(ports)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_ready(rpc: CoreRPC, proc: subprocess.Popen, name: str, timeout: float = 120) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited with {proc.returncode}")
        try:
            rpc("getblockcount")
            return
        except (RPCFailure, OSError):
            time.sleep(0.5)
    raise RuntimeError(f"{name} RPC never became ready")


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bitcoind", type=Path, required=True)
    ap.add_argument("--bitcoin-rs", type=Path, required=True)
    ap.add_argument("--bitcoin-rs-commit", default="unknown")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    logs = args.output.parent
    with tempfile.TemporaryDirectory(prefix="jb-fad05-two-engine-") as tmp, ExitStack() as stack:
        tmp = Path(tmp)
        core_dir, rs_dir = tmp / "core", tmp / "rs"
        core_dir.mkdir()
        rs_dir.mkdir()
        core_rpc, core_p2p, rs_rpc, rs_p2p = free_ports(4)
        secret = secrets.token_hex(24)
        core_log = stack.enter_context((logs / "bitcoind.log").open("w"))
        core = subprocess.Popen(
            [str(args.bitcoind), "-regtest", f"-datadir={core_dir}", f"-rpcport={core_rpc}",
             f"-port={core_p2p}", "-listen=0", "-connect=0", "-dnsseed=0", "-server=1",
             "-rpcuser=jbfad05", f"-rpcpassword={secret}", "-fallbackfee=0.0001",
             "-printtoconsole=1"],
            stdout=core_log, stderr=subprocess.STDOUT)
        stack.callback(stop, core)
        env = {k: v for k, v in os.environ.items() if not k.startswith("BITCOIN_RS_")}
        env["BITCOIN_RS_RPC_USER"] = "jbfad05"
        env["BITCOIN_RS_RPC_PASSWORD"] = secret
        rs_log = stack.enter_context((logs / "bitcoin-rs.log").open("w"))
        rs = subprocess.Popen(
            [str(args.bitcoin_rs), "--network", "regtest", "--data-dir", str(rs_dir),
             "--rpc-bind", f"127.0.0.1:{rs_rpc}", "--p2p-listen", f"127.0.0.1:{rs_p2p}",
             "--dns-seeds-enabled=false", "--validation-engine", "native", "--log-level", "info"],
            env=env, stdout=rs_log, stderr=subprocess.STDOUT)
        stack.callback(stop, rs)
        core_rpc_client = TimedRPC(f"http://127.0.0.1:{core_rpc}", "jbfad05", secret)
        rs_rpc_client = TimedRPC(f"http://127.0.0.1:{rs_rpc}", "jbfad05", secret)
        wait_ready(core_rpc_client, core, "bitcoind")
        wait_ready(rs_rpc_client, rs, "bitcoin-rs")
        if core_rpc_client("getpeerinfo") or rs_rpc_client("getpeerinfo"):
            raise RuntimeError("isolated nodes unexpectedly have peers")
        started = time.monotonic()
        receipt = run_native(core_rpc_client, mirror=rs_rpc_client)
        receipt["two_engine"] = {
            "bitcoind_sha256": sha256_file(args.bitcoind),
            "bitcoind_version": core_rpc_client("getnetworkinfo")["subversion"],
            "bitcoin_rs_sha256": sha256_file(args.bitcoin_rs),
            "bitcoin_rs_commit": args.bitcoin_rs_commit,
            "bitcoin_rs_validation_engine": "native",
            "p2p_link": "none; blocks replayed via submitblock",
            "seconds": round(time.monotonic() - started, 1),
            "bitcoin_rs_slowest_rpc": {"seconds": rs_rpc_client.slowest[0],
                                       "method": rs_rpc_client.slowest[1]},
        }
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    diff = receipt["bitcoin_rs_differential"]
    summary = {
        "comparisons": diff["comparisons"],
        "by_kind": diff["by_kind"],
        "disagreements": len(diff["disagreements"]),
        "reason_class_mismatches": len(diff["reason_class_mismatches"]),
        "positive_control": receipt["positive_control"]["agree"],
        "final_tips_match": diff["final_tips_match"],
        "mirrored_prefix_blocks": diff["mirrored_prefix_blocks"],
        "core": receipt["two_engine"]["bitcoind_version"],
        "bitcoin_rs": receipt["two_engine"]["bitcoin_rs_commit"],
        "bitcoin_rs_slowest_rpc": receipt["two_engine"]["bitcoin_rs_slowest_rpc"],
        "receipt": str(args.output),
    }
    print(json.dumps(summary, indent=2))
    for row in diff["disagreements"]:
        print("DISAGREE", json.dumps(row)[:600], file=sys.stderr)
    if diff["disagreements"] or not diff["final_tips_match"] or not receipt["positive_control"]["agree"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
