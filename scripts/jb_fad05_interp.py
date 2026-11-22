#!/usr/bin/env python3
"""Minimal pre-SegWit Script interpreter used as an offline model for JB-FAD05.

Scope: bare legacy scriptPubKey evaluation with the consensus flags active on
Bitcoin mainnet for non-witness spends (BIP66 strict DER, BIP65 CLTV, BIP112
CSV, BIP147 NULLDUMMY, which segwit deployment made a block rule). Policy-only
rules (LOW_S, MINIMALDATA, SIGPUSHONLY, STRICTENC flag bytes, CLEANSTACK) are
deliberately NOT applied, because they are not consensus.

This model exists so offline tests can exercise every unlocking variant
before the native Bitcoin Core regtest lane runs. Native Core is the oracle;
any disagreement is a bug here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from seam_digests_standalone import (
    Tx, find_and_delete, get_op, hash160, push, sha256, signature_hash,
)

MAX_OPS = 201
MAX_STACK = 1000
MAX_ELEMENT = 520
MAX_SCRIPT = 10_000
LOCKTIME_THRESHOLD = 500_000_000
SEQUENCE_DISABLE = 1 << 31
SEQUENCE_TYPE = 1 << 22
SEQUENCE_MASK = 0x0000FFFF

DISABLED = {0x7E, 0x7F, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86,
            0x8D, 0x8E, 0x95, 0x96, 0x97, 0x98, 0x99}


class ScriptFailure(Exception):
    pass


def fail(msg: str):
    raise ScriptFailure(msg)


def num_decode(b: bytes, max_len: int = 4) -> int:
    if len(b) > max_len:
        fail("script number overflow")
    if not b:
        return 0
    v = int.from_bytes(b, "little")
    if b[-1] & 0x80:
        return -(v & ~(0x80 << (8 * (len(b) - 1))))
    return v


def num_encode(n: int) -> bytes:
    if n == 0:
        return b""
    neg = n < 0
    a = -n if neg else n
    out = bytearray()
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def cast_bool(b: bytes) -> bool:
    for i, x in enumerate(b):
        if x:
            return not (i == len(b) - 1 and x == 0x80)
    return False


def valid_der_encoding(sig: bytes) -> bool:
    """Port of Core's IsValidSignatureEncoding (BIP66), sig includes hashtype."""
    if len(sig) < 9 or len(sig) > 73:
        return False
    if sig[0] != 0x30 or sig[1] != len(sig) - 3:
        return False
    len_r = sig[3]
    if 5 + len_r >= len(sig):
        return False
    len_s = sig[5 + len_r]
    if len_r + len_s + 7 != len(sig):
        return False
    if sig[2] != 0x02 or len_r == 0 or sig[4] & 0x80:
        return False
    if len_r > 1 and sig[4] == 0 and not sig[5] & 0x80:
        return False
    if sig[len_r + 4] != 0x02 or len_s == 0 or sig[len_r + 6] & 0x80:
        return False
    if len_s > 1 and sig[len_r + 6] == 0 and not sig[len_r + 7] & 0x80:
        return False
    return True


def ecdsa_ok(pubkey: bytes, digest: bytes, sig_der: bytes) -> bool:
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey)
        key.verify(sig_der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass
class Trace:
    nonpush_static: int = 0
    op_count: int = 0          # Core's nOpCount, including CHECKMULTISIG keys
    sig_checks: list = field(default_factory=list)


def eval_script(script: bytes, stack: list[bytes], tx: Tx, n_in: int,
                trace: Trace | None = None) -> list[bytes]:
    if len(script) > MAX_SCRIPT:
        fail("script too large")
    trace = trace if trace is not None else Trace()
    alt: list[bytes] = []
    exec_stack: list[bool] = []
    codesep = [0]
    pc = 0
    while pc < len(script):
        pc, opcode, data = get_op(script, pc)
        fexec = all(exec_stack)
        if len(data) > MAX_ELEMENT:
            fail("push exceeds 520 bytes")
        if opcode > 0x60:
            trace.op_count += 1
            if trace.op_count > MAX_OPS:
                fail("op count exceeds 201")
        if opcode in DISABLED:
            fail("disabled opcode")
        if fexec and opcode <= 0x4E:
            stack.append(data)
        elif fexec or 0x63 <= opcode <= 0x68:
            _step(opcode, script, stack, alt, exec_stack, fexec, tx, n_in,
                  trace, codesep, pc)
        if len(stack) + len(alt) > MAX_STACK:
            fail("stack size exceeds 1000")
    if exec_stack:
        fail("unbalanced conditional")
    return stack


def _pop(stack: list[bytes]) -> bytes:
    if not stack:
        fail("invalid stack operation")
    return stack.pop()


def _check_sig(sig: bytes, pubkey: bytes, script_code: bytes, tx: Tx,
               n_in: int, trace: Trace) -> bool:
    if not sig:
        return False
    if not valid_der_encoding(sig):
        fail("non-DER signature (BIP66)")
    digest = signature_hash(script_code, tx, n_in, sig[-1])
    ok = ecdsa_ok(pubkey, digest, sig[:-1])
    trace.sig_checks.append({"flag": sig[-1], "len": len(sig), "ok": ok})
    return ok


def _step(opcode, script, stack, alt, exec_stack, fexec, tx, n_in, trace,
          codesep_ref, pc):
    if opcode == 0x4F:
        stack.append(num_encode(-1))
    elif 0x51 <= opcode <= 0x60:
        stack.append(num_encode(opcode - 0x50))
    elif opcode == 0x50:
        fail("OP_RESERVED")
    elif opcode in (0x61, 0xB0, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9):
        pass
    elif opcode in (0x63, 0x64):
        value = False
        if fexec:
            v = cast_bool(_pop(stack))
            value = v if opcode == 0x63 else not v
        exec_stack.append(value)
    elif opcode == 0x67:
        if not exec_stack:
            fail("ELSE without IF")
        exec_stack[-1] = not exec_stack[-1]
    elif opcode == 0x68:
        if not exec_stack:
            fail("ENDIF without IF")
        exec_stack.pop()
    elif opcode == 0x69:
        if not cast_bool(_pop(stack)):
            fail("OP_VERIFY failed")
    elif opcode == 0x6A:
        fail("OP_RETURN")
    elif opcode == 0x6B:
        alt.append(_pop(stack))
    elif opcode == 0x6C:
        if not alt:
            fail("empty altstack")
        stack.append(alt.pop())
    elif opcode == 0x6D:
        _pop(stack); _pop(stack)
    elif opcode == 0x75:
        _pop(stack)
    elif opcode == 0x76:
        x = _pop(stack); stack += [x, x]
    elif opcode == 0x77:
        x = _pop(stack); _pop(stack); stack.append(x)
    elif opcode == 0x78:
        if len(stack) < 2:
            fail("invalid stack operation")
        stack.append(stack[-2])
    elif opcode in (0x79, 0x7A):
        n = num_decode(_pop(stack))
        if n < 0 or n >= len(stack):
            fail("PICK/ROLL out of range")
        x = stack[-n - 1]
        if opcode == 0x7A:
            del stack[-n - 1]
        stack.append(x)
    elif opcode == 0x7C:
        if len(stack) < 2:
            fail("invalid stack operation")
        stack[-1], stack[-2] = stack[-2], stack[-1]
    elif opcode == 0x82:
        if not stack:
            fail("invalid stack operation")
        stack.append(num_encode(len(stack[-1])))
    elif opcode in (0x87, 0x88):
        b = _pop(stack); a = _pop(stack)
        eq = a == b
        if opcode == 0x88:
            if not eq:
                fail("OP_EQUALVERIFY failed")
        else:
            stack.append(b"\x01" if eq else b"")
    elif opcode in (0x8B, 0x8C, 0x8F, 0x90, 0x91, 0x92):
        a = num_decode(_pop(stack))
        r = {0x8B: a + 1, 0x8C: a - 1, 0x8F: -a, 0x90: abs(a),
             0x91: int(a == 0), 0x92: int(a != 0)}[opcode]
        stack.append(num_encode(r))
    elif opcode in (0x93, 0x94, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
                    0xA1, 0xA2, 0xA3, 0xA4):
        b = num_decode(_pop(stack)); a = num_decode(_pop(stack))
        r = {0x93: a + b, 0x94: a - b, 0x9A: int(a != 0 and b != 0),
             0x9B: int(a != 0 or b != 0), 0x9C: int(a == b), 0x9D: int(a == b),
             0x9E: int(a != b), 0x9F: int(a < b), 0xA0: int(a > b),
             0xA1: int(a <= b), 0xA2: int(a >= b), 0xA3: min(a, b),
             0xA4: max(a, b)}[opcode]
        if opcode == 0x9D:
            if not r:
                fail("OP_NUMEQUALVERIFY failed")
        else:
            stack.append(num_encode(r))
    elif opcode == 0xA5:
        hi = num_decode(_pop(stack)); lo = num_decode(_pop(stack))
        x = num_decode(_pop(stack))
        stack.append(num_encode(int(lo <= x < hi)))
    elif opcode == 0xA8:
        stack.append(sha256(_pop(stack)))
    elif opcode == 0xA9:
        stack.append(hash160(_pop(stack)))
    elif opcode == 0xAB:
        codesep_ref[0] = pc
    elif opcode in (0xAC, 0xAD):
        pubkey = _pop(stack); sig = _pop(stack)
        code, _ = find_and_delete(script[codesep_ref[0]:], push(sig))
        ok = _check_sig(sig, pubkey, code, tx, n_in, trace)
        if opcode == 0xAD:
            if not ok:
                fail("OP_CHECKSIGVERIFY failed")
        else:
            stack.append(b"\x01" if ok else b"")
    elif opcode in (0xAE, 0xAF):
        i = 1
        if len(stack) < i:
            fail("invalid stack operation")
        n_keys = num_decode(stack[-i])
        if n_keys < 0 or n_keys > 20:
            fail("pubkey count")
        trace.op_count += n_keys
        if trace.op_count > MAX_OPS:
            fail("op count exceeds 201")
        i += 1
        ikey = i
        i += n_keys
        if len(stack) < i:
            fail("invalid stack operation")
        n_sigs = num_decode(stack[-i])
        if n_sigs < 0 or n_sigs > n_keys:
            fail("sig count")
        i += 1
        isig = i
        i += n_sigs
        if len(stack) < i:
            fail("invalid stack operation")
        code = script[codesep_ref[0]:]
        for k in range(n_sigs):
            code, _ = find_and_delete(code, push(stack[-isig - k]))
        success = True
        while success and n_sigs > 0:
            sig = stack[-isig]
            key = stack[-ikey]
            if _check_sig(sig, key, code, tx, n_in, trace):
                isig += 1
                n_sigs -= 1
            ikey += 1
            n_keys -= 1
            if n_sigs > n_keys:
                success = False
        for _ in range(i - 1):
            stack.pop()
        if not stack:
            fail("missing CHECKMULTISIG dummy")
        if stack[-1]:
            fail("Dummy CHECKMULTISIG argument must be zero (BIP147)")
        stack.pop()
        if opcode == 0xAF:
            if not success:
                fail("OP_CHECKMULTISIGVERIFY failed")
        else:
            stack.append(b"\x01" if success else b"")
    elif opcode == 0xB1:
        if not stack:
            fail("invalid stack operation")
        lock = num_decode(stack[-1], 5)
        if lock < 0:
            fail("negative locktime")
        same_type = (tx.locktime < LOCKTIME_THRESHOLD) == (lock < LOCKTIME_THRESHOLD)
        if not same_type or lock > tx.locktime or tx.vin[n_in].sequence == 0xFFFFFFFF:
            fail("CHECKLOCKTIMEVERIFY unsatisfied")
    elif opcode == 0xB2:
        if not stack:
            fail("invalid stack operation")
        seq = num_decode(stack[-1], 5)
        if seq < 0:
            fail("negative sequence")
        if not seq & SEQUENCE_DISABLE:
            txseq = tx.vin[n_in].sequence
            if tx.version < 2 or txseq & SEQUENCE_DISABLE:
                fail("CHECKSEQUENCEVERIFY unsatisfied")
            mask = SEQUENCE_TYPE | SEQUENCE_MASK
            a, b = txseq & mask, seq & mask
            if (a < SEQUENCE_TYPE) != (b < SEQUENCE_TYPE) or b > a:
                fail("CHECKSEQUENCEVERIFY unsatisfied")
    else:
        fail(f"opcode {opcode:#04x} not modelled")


def verify_input(script_sig: bytes, script_pubkey: bytes, tx: Tx, n_in: int
                 ) -> tuple[bool, str, Trace]:
    """Legacy VerifyScript for a bare scriptPubKey; returns (ok, reason, trace)."""
    trace = Trace()
    try:
        # Push-only scriptSig is policy (SIGPUSHONLY) for bare scripts, not
        # consensus, so non-push scriptSig opcodes are evaluated here.
        stack = eval_script(script_sig, [], tx, n_in, Trace())
        stack = eval_script(script_pubkey, stack, tx, n_in, trace)
        if not stack or not cast_bool(stack[-1]):
            fail("script evaluated to false")
    except ScriptFailure as exc:
        return False, str(exc), trace
    return True, "ok", trace
