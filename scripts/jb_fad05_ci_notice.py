#!/usr/bin/env python3
"""Publish the JB-FAD05 native verdicts as GitHub notice annotations.

Job logs and artifacts of a public repository need authentication to read;
check-run annotations do not. GitHub keeps 10 notices per step, so the
evidence is packed into at most 10 lines.
"""

import json
import sys
from pathlib import Path


def lines(d: Path) -> list[str]:
    r = json.loads((d / "native.json").read_text(encoding="utf-8"))
    ref = {w: json.loads((d / f"referee-{w}.json").read_text(encoding="utf-8"))
           for w in ("honest", "front_run", "unauthorized")}
    res = r["resources"]
    a = r["A_attestation_mutations"]
    b = r["B_sighash_flag_matrix"]
    dd, e, f, g = r["D_reorg_front_run"], r["E_retained_key"], r["F_bond_timeout"], r["G_split_utxo"]
    rejected = sorted(k for k, v in a.items() if isinstance(v, dict) and v["consensus"] == "rejected")
    out = [
        f"core={r['core_version']} script={res['script_bytes']}B ops={res['core_op_count']}/201 "
        f"tx={res['tx_bytes']}B/{res['tx_weight']}WU scriptSig={res['script_sig_bytes']}B",
        f"honest txid={r['honest']['txid']} block={r['honest']['block_evidence']['block_hash']} "
        f"r1={r['honest']['round1_indices']} r2={r['honest']['round2_indices']} attempts={r['honest']['attempts']}",
        f"A rejected {len(rejected)}/14 with tip preserved: {','.join(rejected)}",
        f"B flags accepted={b['accepted_flags']} rejected={b['rejected_count']}/256",
        "C twins accepted: " + ",".join(f"{k}->{v['txid'][:16]}" for k, v in r["C_txid_malleation"].items()),
        f"D front-run {dd['consensus']} txid={dd['front_run']['txid']} block={dd['block_evidence']['block_hash']} "
        f"flags={dd['front_run']['nonce_flags']} candidates={dd['front_run']['attempts']['candidates']}",
        f"E unauthorized {e['consensus']} txid={e['unauthorized']['txid']} unions={e['union_sizes']} "
        f"slash={e['equivocation_slash']['consensus']} single-attestation-slash="
        f"{e['slash_with_single_attestation_plus_guess']['consensus']}",
        f"F early-release={f['early_release']['consensus']} release-block={f['release_block']} "
        f"late-slash={f['late_slash']['consensus']}; G split spend block={g['block']} "
        f"round2-unspent={g['round2_utxo_still_unspent']}",
        "referee: " + "; ".join(f"{w}={'valid' if v['valid'] else 'rejected: ' + v['rejection']}"
                                for w, v in ref.items())
        + f"; statement_hash={ref['honest'].get('statement_hash')}",
    ]
    sums = (d / "SHA256SUMS").read_text(encoding="utf-8").split()
    pairs = dict(zip(sums[1::2], sums[0::2]))
    out.append("sha256 " + " ".join(f"{k}={v[:16]}" for k, v in pairs.items()))
    return out


def main():
    for line in lines(Path(sys.argv[1])):
        print("::notice title=jb-fad05-native::" + line.replace("%", "%25"))


if __name__ == "__main__":
    main()
