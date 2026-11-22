#!/usr/bin/env python3
"""JB-FAD05: HORS subset attestation on the two-round Binohash vault.

Extends JB-FAD04 (four sighash-mode pinning puzzles + two 10-choose-5
FindAndDelete nonce rounds in one bare legacy script) with an on-chain
HORS-style preimage attestation of the selected nonce indices.

For each round the locking script carries a 10-entry table of HASH160
commitments, one per pool index, laid out directly below the 10 pool
signatures. Each selection step reads ONE selector number d from the
unlocking stack and uses it twice:

    d  -> OP_ROLL on the signature region   (FindAndDelete target)
    d  -> OP_ROLL on the commitment region  (HORS commitment)

Both regions shrink identically, so the commitment rolled at step i always
belongs to the same pool index as the signature rolled at step i. The
spender must reveal the HASH160 preimage of that commitment. OP_WITHIN
enforces d_{i-1} <= d_i < 10-i, i.e. the canonical descending-index
encoding; any permutation, duplicate, or out-of-range selector fails.

The HORS secret (20 preimages) is the vault's spend-authorization key. The
module also builds an operator bond whose keyless branch slashes on any
sixth revealed preimage of one round (one-time-key equivocation), plus a
CSV-delayed operator release branch.

The parameters are deliberately tiny research values; see
jb_fad05_params.py for the production-scale budget analysis.
"""

from __future__ import annotations

import itertools
import math
import struct
from dataclasses import dataclass, replace

from jb_fad01 import AUX_REDEEM, demo_scalar, demo_sign, pubkey_bytes, verifies
from jb_fad02 import POOL_N, POOL_T, TARGET_SIG_BYTES, push_num, selection_depths
from jb_fad03_pinning import (
    FLAGS, OUTPUT_VARIANTS, SEQ0_LIMIT, SEQ1_LIMIT, rmin_sign,
)
from jb_fad04 import make_dual_setup
from seam_digests_standalone import (
    OP_CODESEPARATOR, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_SINGLE,
    UINT256_ONE, Tx, TxIn, TxOut, dsha256, find_and_delete, get_op, hash160,
    op, push, ser_tx, sha256, signature_hash, txid_hex,
)

RESEARCH_ID = "JB-FAD05"
STATEMENT_DOMAIN = b"JB-FAD05/BITVM-SETTLEMENT"
HORS_DOMAIN = b"JB-FAD05/HORS-SUBSET-ATTESTATION/v1"
PREIMAGE_BYTES = 20
ROUNDS = 2
EQUIV_T = POOL_T + 1          # a sixth preimage proves a second attestation

OP_0 = 0x00
OP_1 = 0x51
OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_2DROP = 0x6D
OP_DROP = 0x75
OP_DUP = 0x76
OP_PICK = 0x79
OP_ROLL = 0x7A
OP_SIZE = 0x82
OP_EQUALVERIFY = 0x88
OP_ADD = 0x93
OP_LESSTHANOREQUAL = 0xA1
OP_WITHIN = 0xA5
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKSEQUENCEVERIFY = 0xB2

AUX_VALUE_SATS = 30_000
VAULT_SATS = 150_000
BOND_SATS = 200_000
PAYOUT_SATS = 170_000
SETTLEMENT_FEE_SATS = AUX_VALUE_SATS + VAULT_SATS - PAYOUT_SATS
BOND_CSV_BLOCKS = 12

PROGRAM_SPEC = (
    b"JB-FAD05/toy-settlement-transition/v1:"
    b" successor = TaggedHash('JB-FAD05/state', previous_root || vault_txid_le"
    b" || vault_vout_le32 || len(recipient_body) || recipient_body"
    b" || payout_le64 || fee_le64)"
)
PROGRAM_ID = sha256(PROGRAM_SPEC)


# ---------------------------------------------------------------------------
# hashing helpers
# ---------------------------------------------------------------------------

def tagged_hash(tag: bytes, data: bytes) -> bytes:
    t = sha256(tag)
    return sha256(t + t + data)


def p2wsh(witness_script: bytes) -> bytes:
    return op(OP_0) + push(sha256(witness_script))


def successor_root(previous_root: bytes, vault_txid: str, vault_vout: int,
                   recipient_body: bytes, payout_sats: int, fee_sats: int) -> bytes:
    if len(previous_root) != 32:
        raise ValueError("state roots are 32 bytes")
    data = (previous_root + bytes.fromhex(vault_txid)[::-1] +
            struct.pack("<I", vault_vout) + bytes([len(recipient_body)]) +
            recipient_body + struct.pack("<q", payout_sats) +
            struct.pack("<q", fee_sats))
    return tagged_hash(b"JB-FAD05/state", data)


def payout_witness_script(successor: bytes, salt: int, recipient_body: bytes) -> bytes:
    """<successor_root> <salt> 2DROP <recipient body>: binds the state root
    into the single payout output. Stage 3 grinds the 4-byte salt."""
    return push(successor) + push(struct.pack("<I", salt)) + op(OP_2DROP) + recipient_body


def key_body(secret: int) -> bytes:
    return push(pubkey_bytes(secret)) + op(OP_CHECKSIG)


# ---------------------------------------------------------------------------
# HORS key: one 20-byte preimage per (round, pool index)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HorsKey:
    seed: bytes
    preimages: tuple[tuple[bytes, ...], ...]

    @property
    def tables(self) -> tuple[tuple[bytes, ...], ...]:
        return tuple(tuple(hash160(p) for p in row) for row in self.preimages)

    @property
    def root(self) -> bytes:
        return tagged_hash(b"JB-FAD05/hors-root",
                           b"".join(h for row in self.tables for h in row))


def make_hors_key(seed: bytes) -> HorsKey:
    rows = tuple(
        tuple(sha256(HORS_DOMAIN + seed + bytes([r, k]))[:PREIMAGE_BYTES]
              for k in range(POOL_N))
        for r in range(ROUNDS)
    )
    flat = [p for row in rows for p in row]
    if len(set(flat)) != len(flat) or len({hash160(p) for p in flat}) != len(flat):
        raise AssertionError("HORS preimages and commitments must be distinct")
    return HorsKey(seed, rows)


FIXTURE_HORS_SEED = sha256(b"JB-FAD05/operator-hors-seed/public-research-fixture")


# ---------------------------------------------------------------------------
# locking scripts
# ---------------------------------------------------------------------------

def snum(n: int) -> bytes:
    """Minimal push of a non-negative script number (any size)."""
    if n == 0:
        return op(OP_0)
    if 1 <= n <= 16:
        return op(OP_1 + n - 1)
    from jb_fad05_interp import num_encode
    return push(num_encode(n))


def round_leftover(n: int = POOL_N, t: int = POOL_T) -> int:
    """Items a round leaves on the stack: unselected signatures and
    commitments plus its t selector numbers."""
    return 2 * (n - t) + t


def round_script(pool_sigs: tuple[bytes, ...], pool_pub: bytes,
                 puzzle_pub: bytes, table: tuple[bytes, ...], *,
                 t: int = POOL_T, above: int = 0) -> bytes:
    """One Binohash nonce round with HORS attestation.

    Unlocking group, bottom to top:  nonce_sig  pre_0 .. pre_{t-1}  d_0 .. d_{t-1}
    pre_i opens the commitment of the pool index selected at step i.
    `above` is the number of stack items a previous round left on top of
    this group. Nothing is dropped: legacy consensus only inspects the final
    top element (CLEANSTACK is relay policy), so leftovers cost no opcodes.
    """
    n = len(pool_sigs)
    if len(table) != n or not 0 < t < n or t + 1 > 20:
        raise ValueError("bad round shape")
    # Move the nonce signature to the altstack after its size gate.
    s = (snum(2 * t + above) + op(OP_ROLL) + op(OP_SIZE) +
         snum(TARGET_SIG_BYTES) + op(OP_LESSTHANOREQUAL) + op(OP_VERIFY) +
         op(OP_TOALTSTACK))
    s += b"".join(push(h) for h in table)          # commitment region
    s += b"".join(push(sig) for sig in pool_sigs)  # signature region (top)
    for i in range(t):
        rem = n - i
        sel = 2 * rem + above + (t - 1 - i)        # depth of d_i
        s += snum(sel) + op(OP_PICK) + op(OP_DUP)
        s += snum(0) if i == 0 else snum(sel + 3) + op(OP_PICK)   # d_{i-1}
        s += snum(rem) + op(OP_WITHIN) + op(OP_VERIFY)
        s += op(OP_ROLL) + op(OP_TOALTSTACK)       # signature for FindAndDelete
        s += snum(sel - 1) + op(OP_PICK)           # d_i again
        s += snum(rem - 1) + op(OP_ADD) + op(OP_ROLL)   # matching commitment
        # pre_i lies below the rolled commitment (1), both regions (rem-1
        # each), the `above` items, all t selectors and pre_{i+1..t-1}.
        s += snum(2 * rem + above + 2 * t - 2 - i) + op(OP_ROLL)
        s += op(OP_HASH160) + op(OP_EQUALVERIFY)
    # Dummy, then t pool signatures with the nonce signature last (on top),
    # matched against t pool keys followed by the puzzle key.
    s += op(OP_0) + op(OP_FROMALTSTACK) * (t + 1)
    s += (snum(t + 1) + push(pool_pub) * t + push(puzzle_pub) +
          snum(t + 1) + op(OP_CHECKMULTISIG))
    return s


def pin_prefix(pin_pubkeys: dict[str, bytes]) -> bytes:
    return b"".join(
        op(OP_SIZE) + push_num(TARGET_SIG_BYTES) + op(OP_LESSTHANOREQUAL) +
        op(OP_VERIFY) + push(pin_pubkeys[name]) + op(OP_CHECKSIGVERIFY)
        for name, _ in FLAGS
    )


@dataclass(frozen=True)
class Fad05Setup:
    script: bytes
    second_offset: int
    pools: tuple[tuple[bytes, ...], tuple[bytes, ...]]
    pool_pubs: tuple[bytes, bytes]
    puzzle_secrets: tuple[int, int]
    pin_secrets: dict[str, int]
    pin_pubkeys: dict[str, bytes]
    hors: HorsKey


def make_setup(hors_seed: bytes = FIXTURE_HORS_SEED) -> Fad05Setup:
    base = make_dual_setup()   # reuse FAD04's public deterministic pool/pin keys
    hors = make_hors_key(hors_seed)
    pools = (base.first.pool_sigs, base.second.pool_sigs)
    pool_pubs = (pubkey_bytes(base.first.pool_secret),
                 pubkey_bytes(base.second.pool_secret))
    puzzles = (base.first.puzzle_secret, base.second.puzzle_secret)
    r1 = round_script(pools[0], pool_pubs[0], pubkey_bytes(puzzles[0]), hors.tables[0])
    r2 = round_script(pools[1], pool_pubs[1], pubkey_bytes(puzzles[1]), hors.tables[1],
                      above=round_leftover())
    head = pin_prefix(base.pin_pubkeys) + r1 + op(OP_VERIFY) + op(OP_CODESEPARATOR)
    script = head + r2
    if len(script) > 10_000:
        raise AssertionError("bare script exceeds consensus 10,000-byte bound")
    return Fad05Setup(script, len(head), pools, pool_pubs, puzzles,
                      dict(base.pin_secrets), dict(base.pin_pubkeys), hors)


def bond_script(table: tuple[bytes, ...], operator_pub: bytes,
                csv_blocks: int = BOND_CSV_BLOCKS) -> bytes:
    """Operator bond for one round's HORS table.

    IF branch (keyless): six distinct preimages of this round's table, in
    canonical descending-index order. A one-time HORS key that attested one
    5-subset reveals exactly five; a sixth proves a second attestation.
    ELSE branch: operator signature after a CSV relative delay.
    """
    s = op(OP_IF) + b"".join(push(h) for h in table)
    for i in range(EQUIV_T):
        remaining = POOL_N - i
        sel = remaining + (EQUIV_T - 1 - i)
        s += push_num(sel) + op(OP_PICK) + op(OP_DUP)
        s += push_num(0) if i == 0 else push_num(sel + 3) + op(OP_PICK)
        s += push_num(remaining) + op(OP_WITHIN) + op(OP_VERIFY) + op(OP_ROLL)
        s += (push_num(remaining + 2 * EQUIV_T - 1 - i) + op(OP_ROLL) +
              op(OP_HASH160) + op(OP_EQUALVERIFY))
    s += op(OP_1)   # leftovers stay below; only the top element is checked
    s += (op(OP_ELSE) + push_num(csv_blocks) + op(OP_CHECKSEQUENCEVERIFY) +
          op(OP_DROP) + push(operator_pub) + op(OP_CHECKSIG) + op(OP_ENDIF))
    return s


OPERATOR_SECRET = demo_scalar("JB-FAD05/operator-bond-key")
RECIPIENT_SECRET = demo_scalar("JB-FAD05/policy-recipient")
ATTACKER_SECRET = demo_scalar("JB-FAD05/front-runner")
UNAUTHORIZED_SECRET = demo_scalar("JB-FAD05/operator-unauthorized-payee")
PREVIOUS_STATE_ROOT = tagged_hash(b"JB-FAD05/genesis-state", b"fixture-epoch-0")


# ---------------------------------------------------------------------------
# selectors and unlocking scripts
# ---------------------------------------------------------------------------

def canonical_depths(picks_desc: list[int], n: int = POOL_N) -> tuple[int, ...]:
    """OP_ROLL depths for strictly descending pool indices."""
    if any(picks_desc[i] <= picks_desc[i + 1] for i in range(len(picks_desc) - 1)):
        raise ValueError("picks must be strictly descending")
    return tuple(n - 1 - p - i for i, p in enumerate(picks_desc))


def round_unlock(nonce_sig: bytes, depths: tuple[int, ...],
                 preimages: tuple[bytes, ...]) -> bytes:
    return (push(nonce_sig) + b"".join(push(p) for p in preimages) +
            b"".join(snum(d) for d in depths))


def canonical_round_unlock(nonce_sig: bytes, subset: tuple[int, ...],
                           row: tuple[bytes, ...]) -> bytes:
    picks = sorted(subset, reverse=True)
    depths = selection_depths(tuple(subset))
    return round_unlock(nonce_sig, depths, tuple(row[p] for p in picks))


def build_script_sig(pins: dict[str, bytes], round1: bytes, round2: bytes) -> bytes:
    out = round2 + round1
    for name, _ in reversed(FLAGS):
        out += push(pins[name])
    return out


def equivocation_unlock(preimages_by_index: dict[int, bytes]) -> bytes:
    picks = sorted(preimages_by_index, reverse=True)[:EQUIV_T]
    if len(picks) < EQUIV_T:
        raise ValueError("equivocation needs six distinct preimages")
    depths = canonical_depths(picks)
    return (b"".join(push(preimages_by_index[p]) for p in picks) +
            b"".join(push_num(d) for d in depths) + op(OP_1))


def nonce_script_code(setup: Fad05Setup, which: int, subset: tuple[int, ...]) -> bytes:
    source = setup.script if which == 1 else setup.script[setup.second_offset:]
    removed = 0
    code = source
    for idx in subset:
        code, n = find_and_delete(code, push(setup.pools[which - 1][idx]))
        removed += n
    if removed != POOL_T:
        raise AssertionError("FindAndDelete removed an unexpected count")
    return code


def all_family_digests(script_code: bytes, tx: Tx, n_in: int,
                       flags: tuple[int, ...]) -> dict[int, bytes]:
    """Legacy sighash for ALL-like base types, sharing the serialization.

    Every flag whose low five bits are not NONE(2) or SINGLE(3) behaves like
    SIGHASH_ALL, but the full byte is appended to the preimage, so each such
    byte yields an independent digest for the same transaction.
    """
    code, _ = find_and_delete(script_code, op(OP_CODESEPARATOR))
    vin = tuple(replace(t, script_sig=(code if i == n_in else b""))
                for i, t in enumerate(tx.vin))
    full = ser_tx(Tx(tx.version, vin, tx.vout, tx.locktime))
    acp = ser_tx(Tx(tx.version, (vin[n_in],), tx.vout, tx.locktime))
    out = {}
    for f in flags:
        if (f & 0x1F) in (2, 3):
            raise ValueError("not an ALL-like flag")
        out[f] = dsha256((acp if f & SIGHASH_ANYONECANPAY else full) + struct.pack("<I", f))
    return out


ALL_LIKE_FLAGS = tuple([SIGHASH_ALL] + [f for f in range(256)
                                        if (f & 0x1F) not in (2, 3) and f != SIGHASH_ALL])


# ---------------------------------------------------------------------------
# settlement grinding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Settlement:
    tx: Tx
    subsets: tuple[tuple[int, ...], tuple[int, ...]]
    nonce_sigs: tuple[bytes, bytes]
    nonce_flags: tuple[int, int]
    pins: dict[str, bytes]
    pin_digests: dict[str, bytes]
    salt: int
    witness_script: bytes
    successor: bytes
    attempts: dict

    @property
    def txid(self) -> str:
        return txid_hex(self.tx)

    @property
    def indices(self) -> tuple[int, ...]:
        return self.subsets[0] + self.subsets[1]


def settlement_template(funding_txid: str, vault_vout: int, aux_vout: int,
                        payout_script: bytes, payout_sats: int = PAYOUT_SATS) -> Tx:
    prev = bytes.fromhex(funding_txid)[::-1]
    return Tx(2, (TxIn(prev, aux_vout, push(AUX_REDEEM), 0xF0000000),
                  TxIn(prev, vault_vout, b"", 0xF0000000)),
              (TxOut(payout_sats, payout_script),), 0)


@dataclass(frozen=True)
class RoundSpec:
    number: int                      # 1 or 2 (selects the HORS row)
    pool_sigs: tuple[bytes, ...]
    puzzle_secret: int
    source: bytes                    # scriptCode before FindAndDelete


def round_specs(setup: Fad05Setup) -> tuple[RoundSpec, RoundSpec]:
    return (RoundSpec(1, setup.pools[0], setup.puzzle_secrets[0], setup.script),
            RoundSpec(2, setup.pools[1], setup.puzzle_secrets[1],
                      setup.script[setup.second_offset:]))


def spec_code(spec: RoundSpec, subset: tuple[int, ...]) -> bytes:
    code = spec.source
    removed = 0
    for idx in subset:
        code, n = find_and_delete(code, push(spec.pool_sigs[idx]))
        removed += n
    if removed != POOL_T:
        raise AssertionError("FindAndDelete removed an unexpected count")
    return code


def grind_settlement(setup: Fad05Setup, funding_txid: str, vault_vout: int,
                     aux_vouts: list[int], recipient_body: bytes,
                     successor: bytes, *, payout_sats: int = PAYOUT_SATS,
                     required: tuple[tuple[int, ...], ...] | None = None,
                     nonce_flags: tuple[int, ...] = (SIGHASH_ALL,),
                     lock_script: bytes | None = None,
                     specs: tuple[RoundSpec, ...] | None = None,
                     max_candidates: int = 1 << 20,
                     seq1_limit: int = SEQ1_LIMIT) -> Settlement:
    """Four staged pins, then every nonce round in `specs`.

    Honest mode (required=None): search all 252 subsets per round with the
    canonical SIGHASH_ALL flag. Attack mode: the subsets are FIXED (they are
    the ones whose HORS preimages are public) and the attacker instead varies
    the transaction and the sighash flag byte among `nonce_flags`.
    """
    lock = lock_script if lock_script is not None else setup.script
    specs = specs if specs is not None else round_specs(setup)
    salt_ws = lambda salt: payout_witness_script(successor, salt, recipient_body)
    base = settlement_template(funding_txid, vault_vout, aux_vouts[0],
                               p2wsh(salt_ws(0)), payout_sats)
    attempts = {name: 0 for name, _ in FLAGS}
    attempts.update({f"round_{sp.number}": 0 for sp in specs}, candidates=0)

    def pin(tx, name, flag):
        digest = signature_hash(lock, tx, 1, flag)
        attempts[name] += 1
        return rmin_sign(digest, setup.pin_secrets[name], flag), digest

    if not 0 < seq1_limit <= 0x0FFFFFFF:
        raise ValueError("stage-1 sequence range must keep bit 31 set")
    for s1 in range(seq1_limit):
        t1 = replace(base, vin=(base.vin[0], replace(base.vin[1], sequence=0xF0000000 + s1)))
        sig1, d1 = pin(t1, *FLAGS[0])
        if len(sig1) > TARGET_SIG_BYTES:
            continue
        for aux in aux_vouts:
            t2 = replace(t1, vin=(replace(t1.vin[0], prevout_n=aux), t1.vin[1]))
            sig2, d2 = pin(t2, *FLAGS[1])
            if len(sig2) > TARGET_SIG_BYTES:
                continue
            for salt in range(OUTPUT_VARIANTS):
                ws = salt_ws(salt)
                t3 = replace(t2, vout=(TxOut(payout_sats, p2wsh(ws)),))
                sig3, d3 = pin(t3, *FLAGS[2])
                if len(sig3) > TARGET_SIG_BYTES:
                    continue
                for s0 in range(SEQ0_LIMIT):
                    t4 = replace(t3, vin=(replace(t3.vin[0], sequence=0xF0000000 + s0), t3.vin[1]))
                    sig4, d4 = pin(t4, *FLAGS[3])
                    if len(sig4) > TARGET_SIG_BYTES:
                        continue
                    attempts["candidates"] += 1
                    if attempts["candidates"] > max_candidates:
                        raise RuntimeError("candidate budget exhausted")
                    winners = []
                    for k, sp in enumerate(specs):
                        found = None
                        subsets = ([required[k]] if required else
                                   itertools.combinations(range(POOL_N), POOL_T))
                        for subset in subsets:
                            digests = all_family_digests(spec_code(sp, subset), t4, 1, nonce_flags)
                            for flag in nonce_flags:
                                attempts[f"round_{sp.number}"] += 1
                                sig = rmin_sign(digests[flag], sp.puzzle_secret, flag)
                                if len(sig) <= TARGET_SIG_BYTES:
                                    found = (tuple(subset), sig, flag)
                                    break
                            if found:
                                break
                        if not found:
                            break
                        winners.append(found)
                    if len(winners) != len(specs):
                        continue
                    pins = {FLAGS[0][0]: sig1, FLAGS[1][0]: sig2,
                            FLAGS[2][0]: sig3, FLAGS[3][0]: sig4}
                    digests = {FLAGS[0][0]: d1, FLAGS[1][0]: d2,
                               FLAGS[2][0]: d3, FLAGS[3][0]: d4}
                    rows = setup.hors.preimages
                    groups = [canonical_round_unlock(sig, sub, rows[sp.number - 1])
                              for sp, (sub, sig, _) in zip(specs, winners)]
                    script_sig = b"".join(reversed(groups))
                    for name, _ in reversed(FLAGS):
                        script_sig += push(pins[name])
                    tx = replace(t4, vin=(t4.vin[0], replace(t4.vin[1], script_sig=script_sig)))
                    return Settlement(
                        tx, tuple(w[0] for w in winners), tuple(w[1] for w in winners),
                        tuple(w[2] for w in winners), pins, digests, salt, ws,
                        successor, dict(attempts))
    raise RuntimeError("no settlement candidate within the registered work budget")


def split_scripts(setup: Fad05Setup) -> tuple[bytes, bytes]:
    """Production-shaped split: each round (with its own pins) in its own UTXO."""
    base = make_dual_setup()
    prefix = pin_prefix(base.pin_pubkeys)
    r1 = round_script(setup.pools[0], setup.pool_pubs[0],
                      pubkey_bytes(setup.puzzle_secrets[0]), setup.hors.tables[0])
    r2 = round_script(setup.pools[1], setup.pool_pubs[1],
                      pubkey_bytes(setup.puzzle_secrets[1]), setup.hors.tables[1])
    return prefix + r1, prefix + r2


def front_run(setup: Fad05Setup, observed: Settlement, funding_txid: str,
              vault_vout: int, aux_vouts: list[int], attacker_body: bytes,
              *, flags: tuple[int, ...] = ALL_LIKE_FLAGS) -> Settlement:
    """Re-use the HORS preimages revealed in `observed` for a new payee.

    The attacker knows only the ten revealed preimages, so it must land on
    exactly the same two subsets. Legacy Script cannot inspect a signature's
    final sighash byte, so the attacker grinds the flag byte as well.
    """
    leaked = {(r, idx): setup.hors.preimages[r][idx]
              for r in range(ROUNDS) for idx in observed.subsets[r]}
    s = grind_settlement(setup, funding_txid, vault_vout, aux_vouts, attacker_body,
                         tagged_hash(b"JB-FAD05/attacker-state", b"anything"),
                         required=observed.subsets, nonce_flags=flags)
    # Rebuild the scriptSig from leaked material only.
    rows = tuple(tuple(leaked.get((r, k), b"") for k in range(POOL_N)) for r in range(ROUNDS))
    script_sig = build_script_sig(
        s.pins, canonical_round_unlock(s.nonce_sigs[0], s.subsets[0], rows[0]),
        canonical_round_unlock(s.nonce_sigs[1], s.subsets[1], rows[1]))
    if script_sig != s.tx.vin[1].script_sig:
        raise AssertionError("front-run needed a preimage that was never revealed")
    return s


def release_unlock(bond: bytes, tx: Tx, n_in: int, label: str) -> bytes:
    digest = signature_hash(bond, tx, n_in, SIGHASH_ALL)
    sig = demo_sign(OPERATOR_SECRET, digest, label, SIGHASH_ALL)
    if not verifies(OPERATOR_SECRET, digest, sig):
        raise AssertionError("operator release signature")
    return push(sig) + op(OP_0)


# ---------------------------------------------------------------------------
# resources
# ---------------------------------------------------------------------------

def static_counts(script: bytes) -> dict:
    nonpush = 0
    pc = 0
    multisig_keys = 0
    prev = None
    while pc < len(script):
        pc, opcode, data = get_op(script, pc)
        if opcode > 0x60:
            nonpush += 1
        if opcode in (OP_CHECKMULTISIG, 0xAF) and prev is not None and 0x51 <= prev <= 0x60:
            multisig_keys += prev - 0x50
        prev = opcode
    return {
        "script_bytes": len(script),
        "nonpush_opcodes": nonpush,
        "checkmultisig_key_charge": multisig_keys,
        "core_op_count": nonpush + multisig_keys,
        "within_201": nonpush + multisig_keys <= 201,
        "within_10000_bytes": len(script) <= 10_000,
    }


def resources(setup: Fad05Setup, s: Settlement) -> dict:
    rows = static_counts(setup.script)
    rows.update(
        accurate_sigops=len(FLAGS) + (POOL_T + 1) * ROUNDS,
        legacy_block_sigops=len(FLAGS) + 20 * ROUNDS,
        script_sig_bytes=len(s.tx.vin[1].script_sig),
        tx_bytes=len(ser_tx(s.tx)),
        tx_weight=4 * len(ser_tx(s.tx)),
        hors_commitments=ROUNDS * POOL_N,
        revealed_preimages=ROUNDS * POOL_T,
        subsets_per_round=math.comb(POOL_N, POOL_T),
        raw_subset_bits=round(ROUNDS * math.log2(math.comb(POOL_N, POOL_T)), 3),
    )
    return rows


def settlement_record(s: Settlement) -> dict:
    rec = {
        "txid": s.txid,
        "raw_tx": ser_tx(s.tx).hex(),
    }
    for k, subset in enumerate(s.subsets):
        rec[f"round{k + 1}_indices"] = list(subset)
    return rec | {
        "nonce_flags": [f"0x{f:02x}" for f in s.nonce_flags],
        "pin_flags": {name: f"0x{s.pins[name][-1]:02x}" for name, _ in FLAGS},
        "payout_witness_script": s.witness_script.hex(),
        "successor_root": s.successor.hex(),
        "salt": s.salt,
        "attempts": s.attempts,
    }


def synthetic_funding(setup: Fad05Setup, aux_count: int = 64) -> tuple[Tx, int]:
    """Offline funding specimen with a fake prevout; vault at index aux_count."""
    from seam_digests_standalone import p2sh
    outs = ([TxOut(AUX_VALUE_SATS, p2sh(AUX_REDEEM)) for _ in range(aux_count)] +
            [TxOut(VAULT_SATS, setup.script), TxOut(VAULT_SATS, setup.script),
             TxOut(BOND_SATS, bond_script(setup.hors.tables[0], pubkey_bytes(OPERATOR_SECRET))),
             TxOut(BOND_SATS, bond_script(setup.hors.tables[1], pubkey_bytes(OPERATOR_SECRET)))])
    return Tx(2, (TxIn(bytes.fromhex("56" * 32), 0, b"", 0xFFFFFFFD),), tuple(outs), 0), aux_count
