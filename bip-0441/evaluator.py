#!/usr/bin/env python3
"""Independent evaluator for the Tapleaf 0xC2 test vectors.

Every rule is implemented from the BIP texts alone: BIP 440 (varops budget),
BIP 441 (Tapleaf 0xC2), OP_TX, Extended Primitives, Reusable Macros, and the
BIPs they build on (340, 341, 342, 348, 449).  It checks every group of the
six vector files in this directory and exits nonzero on any mismatch, or
on any unsupported vector unless --allow-unsupported is given.

    python3 evaluator.py [--allow-unsupported] [file.json ...]
"""

import hashlib
import json
import re
import struct
import sys
from pathlib import Path

VECTOR_FILES = ['varops.json', 'tapleaf_0xc2.json', 'op_tx.json',
                'extended_primitives.json', 'reusable_macros.json',
                'extended_primitives_examples.json']


class Fail(Exception):
    """Script failure; the argument is the README's error name."""

    def __init__(self, name):
        super().__init__(name)
        self.name = name


class Unsupported(Exception):
    """A rule outside the five BIPs that this evaluator does not implement."""


# ---------------------------------------------------------------------------
# BIP 440: Cost Primitives
# ---------------------------------------------------------------------------

def wordspan(n):
    """Bytes in the 64-bit words that hold n bytes."""
    return (n + 7) // 8 * 8


def H(n):
    """Bytes a 64-byte-block hash processes for an n-byte message."""
    return (n + 9 + 63) // 64 * 64


BASE = 300
SIGCHECK = 500000


def READ(n):
    return 350 + 2 * wordspan(n)


def WRITE(n):
    return 800 + 7 * wordspan(n)


def ARITH(n):
    return 200 + 3 * wordspan(n)


def MOVE(k):
    return 200 + 23 * k


def MUL(n, m):
    return 700 + wordspan(n) + 18 * wordspan(m) + wordspan(n) * wordspan(m)


def Q(n, m):
    """Bytes by which the word span of an n-byte dividend exceeds an m-byte divisor's."""
    return max(0, wordspan(n) - wordspan(m))


def DIV(n, m):
    return 1150 + 60 * Q(n, m) + 11 * wordspan(m) + Q(n, m) * wordspan(m)


def HASH(n):
    return 50 + 40 * H(n)


def OP_TX_SELECT(k):
    """OP_TX, Varops Accounting."""
    return 1550 + 620 * k


PRIMITIVES = {
    'BASE': lambda v: BASE, 'SIGCHECK': lambda v: SIGCHECK,
    'READ': lambda v: READ(v['n']), 'WRITE': lambda v: WRITE(v['n']),
    'ARITH': lambda v: ARITH(v['n']), 'MOVE': lambda v: MOVE(v['k']),
    'MUL': lambda v: MUL(v['n'], v['m']), 'DIV': lambda v: DIV(v['n'], v['m']),
    'HASH': lambda v: HASH(v['n']),
}

# BIP 441, Execution of Tapscript 0xC2; Reusable Macros, Size limit.
MAX_ELEMENT = 4_000_000
MAX_STACK_BYTES = 8_000_000
MAX_STACK_ITEMS = 32768
MAX_SCRIPT = 4_000_000
# Reusable Macros, Unrolling: references visited may saturate here; a capped
# total already exceeds any budget. The scan's size limit bounds the others.
MAX_TOTAL = 2**64 - 1
# BIP 440, Derivation of Costs: the varops budget of a whole block.
MAX_BLOCK_BUDGET = 10_000 * 4_000_000
NO_CODESEP = 0xffffffff

# ---------------------------------------------------------------------------
# Opcodes: the Bitcoin script numbering used by BIPs 341/342, BIP 441's
# renamed shifts, and the opcodes assigned by the three drafts.
# ---------------------------------------------------------------------------

OPCODES = {'OP_0': 0x00, 'OP_FALSE': 0x00, 'OP_PUSHDATA1': 0x4c,
           'OP_PUSHDATA2': 0x4d, 'OP_PUSHDATA4': 0x4e, 'OP_1NEGATE': 0x4f,
           'OP_RESERVED': 0x50, 'OP_1': 0x51, 'OP_TRUE': 0x51}
for _i in range(2, 17):
    OPCODES['OP_%d' % _i] = 0x50 + _i
for _i, _name in enumerate(
        'NOP VER IF NOTIF VERIF VERNOTIF ELSE ENDIF VERIFY RETURN '
        'TOALTSTACK FROMALTSTACK 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP IFDUP DEPTH '
        'DROP DUP NIP OVER PICK ROLL ROT SWAP TUCK '
        'CAT SUBSTR LEFT RIGHT SIZE INVERT AND OR XOR EQUAL EQUALVERIFY '
        'RESERVED1 RESERVED2 1ADD 1SUB 2MUL 2DIV NEGATE ABS NOT 0NOTEQUAL '
        'ADD SUB MUL DIV MOD LSHIFT RSHIFT BOOLAND BOOLOR NUMEQUAL '
        'NUMEQUALVERIFY NUMNOTEQUAL LESSTHAN GREATERTHAN LESSTHANOREQUAL '
        'GREATERTHANOREQUAL MIN MAX WITHIN RIPEMD160 SHA1 SHA256 HASH160 '
        'HASH256 CODESEPARATOR CHECKSIG CHECKSIGVERIFY CHECKMULTISIG '
        'CHECKMULTISIGVERIFY NOP1 CHECKLOCKTIMEVERIFY CHECKSEQUENCEVERIFY '
        'NOP4 NOP5 NOP6 NOP7 NOP8 NOP9 NOP10 CHECKSIGADD'.split()):
    OPCODES['OP_' + _name] = 0x61 + _i
OPCODES.update({
    'OP_UPSHIFT': OPCODES['OP_LSHIFT'],      # BIP 441, Bitshift Opcodes
    'OP_DOWNSHIFT': OPCODES['OP_RSHIFT'],
    'OP_TWEAKADD': 0xbe,                     # Extended Primitives
    'OP_TX': 0xbf,                           # OP_TX
    'OP_CHECKSIGFROMSTACK': 0xcc,            # Extended Primitives
    'OP_BYTEREV': 0xcf,                      # Extended Primitives
    'OP_MACRO': 0xd0,                        # Reusable Macros
    'OP_CALLMACRO': 0xd1,                    # Reusable Macros
})


globals().update(OPCODES)              # OP_DUP, OP_CAT, ... as constants

# BIP 342's OP_SUCCESSx, less the fifteen opcodes BIP 441 re-enables and the
# opcodes the drafts assign, plus the three BIP 441 renames to OP_SUCCESSx.
SUCCESS_C0 = ({80, 98, 137, 138} | set(range(126, 130)) | set(range(131, 135))
              | {141, 142} | set(range(149, 154)) | set(range(187, 255)))
SUCCESS_C2 = ({79, 80, 98, 137, 138, 143, 144} | set(range(187, 255))) - {
    OP_TWEAKADD, OP_TX, OP_CHECKSIGFROMSTACK, OP_BYTEREV, OP_MACRO, OP_CALLMACRO}

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------

def parse_hex(text):
    """Hex with the README's XX{n} runs."""
    out = bytearray()
    for lit, count in re.findall(r'([0-9a-fA-F]*)(?:\{(\d+)\})?', text):
        out += bytes.fromhex(lit)
        if count:
            out += out[-1:] * (int(count) - 1)
    return bytes(out)


def parse_stack(items):
    """Stack list, bottom to top, with {"element", "count"} repeats."""
    stack = []
    for item in items:
        if isinstance(item, dict):
            stack += [parse_hex(item['element'])] * item['count']
        else:
            stack.append(parse_hex(item))
    return stack


def parse_script(tokens):
    """Script tokens: opcode names and raw 0x bytes."""
    out = bytearray()
    for token in tokens:
        if token.startswith('0x'):
            out += parse_hex(token[2:])
        elif token in OPCODES:
            out.append(OPCODES[token])
        else:
            raise Unsupported('unknown token ' + token)
    return bytes(out)


def num(b):
    """BIP 441: a stack value as an arbitrary-length little-endian number."""
    return int.from_bytes(b, 'little')


def enc(v):
    """BIP 441: minimal little-endian encoding; zero is empty."""
    return v.to_bytes((v.bit_length() + 7) // 8, 'little')


def trim(b):
    """Strip trailing zero bytes."""
    return b[:len(b.rstrip(b'\x00'))]


def compact_size(v):
    if v < 253:
        return bytes([v])
    if v <= 0xffff:
        return b'\xfd' + struct.pack('<H', v)
    if v <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', v)
    return b'\xff' + struct.pack('<Q', v)


def read_compact_size(b, pos, end):
    """Canonical CompactSize at pos; None if truncated or noncanonical."""
    if pos >= end:
        return None
    first = b[pos]
    pos += 1
    if first < 253:
        return first, pos
    width, minimum = {253: (2, 253), 254: (4, 0x10000), 255: (8, 0x100000000)}[first]
    if end - pos < width:
        return None
    value = int.from_bytes(b[pos:pos + width], 'little')
    if value < minimum:
        return None
    return value, pos + width


def ser_string(b):
    return compact_size(len(b)) + b


def le32(v):
    return struct.pack('<I', v)


def le64(v):
    return struct.pack('<Q', v)


def sha256(b):
    return hashlib.sha256(b).digest()


def sha1(b):
    return hashlib.sha1(b).digest()


def tagged_hash(tag, msg):
    """BIP 340: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def ripemd160(b):
    try:
        return hashlib.new('ripemd160', b).digest()
    except ValueError:
        return _ripemd160(b)


def _ripemd160(msg):
    """RIPEMD-160 for a hashlib without it."""
    r = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
         3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
         1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
         4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    s = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
         7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
         11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
         11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
         9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    ss = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    K = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]
    KK = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0]
    F = [lambda x, y, z: x ^ y ^ z,
         lambda x, y, z: (x & y) | (~x & z),
         lambda x, y, z: (x | ~y) ^ z,
         lambda x, y, z: (x & z) | (y & ~z),
         lambda x, y, z: x ^ (y | ~z)]
    M = 0xffffffff

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & M

    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    padded = msg + b'\x80' + b'\x00' * ((55 - len(msg)) % 64) + le64(8 * len(msg))
    for off in range(0, len(padded), 64):
        x = struct.unpack('<16I', padded[off:off + 64])
        a, b, c, d, e = h
        aa, bb, cc, dd, ee = h
        for j in range(80):
            t = rol((a + F[j // 16](b, c, d) + x[r[j]] + K[j // 16]) & M, s[j]) + e
            a, e, d, c, b = e, d, rol(c, 10), b, t & M
            t = rol((aa + F[4 - j // 16](bb, cc, dd) + x[rr[j]] + KK[j // 16]) & M, ss[j]) + ee
            aa, ee, dd, cc, bb = ee, dd, rol(cc, 10), bb, t & M
        h = [(h[1] + c + dd) & M, (h[2] + d + ee) & M, (h[3] + e + aa) & M,
             (h[4] + a + bb) & M, (h[0] + b + cc) & M]
    return struct.pack('<5I', *h)


# ---------------------------------------------------------------------------
# secp256k1 and BIP 340
# ---------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, 1)


def point_add(a, b):
    """Jacobian point addition; None is the point at infinity."""
    if a is None:
        return b
    if b is None:
        return a
    x1, y1, z1 = a
    x2, y2, z2 = b
    z1z1, z2z2 = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2z2 % P, x2 * z1z1 % P
    s1, s2 = y1 * z2 * z2z2 % P, y2 * z1 * z1z1 % P
    if u1 == u2:
        return point_double(a) if s1 == s2 else None
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2 = h * h % P
    h3 = h2 * h % P
    x3 = (r * r - h3 - 2 * u1 * h2) % P
    y3 = (r * (u1 * h2 - x3) - s1 * h3) % P
    return (x3, y3, h * z1 * z2 % P)


def point_double(a):
    if a is None or a[1] == 0:
        return None
    x, y, z = a
    s = 4 * x * y * y % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * pow(y, 4, P)) % P
    return (x3, y3, 2 * y * z % P)


def point_mul(a, k):
    result = None
    while k:
        if k & 1:
            result = point_add(result, a)
        a = point_double(a)
        k >>= 1
    return result


def affine(a):
    x, y, z = a
    zi = pow(z, P - 2, P)
    return (x * zi * zi % P, y * zi * zi * zi % P)


def lift_x(x):
    """BIP 340 lift_x: the point with x-coordinate x and even Y, or None."""
    if x >= P:
        return None
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if y * y % P != c:
        return None
    if y & 1:
        y = P - y
    return (x, y, 1)


def schnorr_verify(pk, msg, sig):
    """BIP 340 Verify(pk, m, sig)."""
    if len(pk) != 32 or len(sig) != 64:
        return False
    point = lift_x(int.from_bytes(pk, 'big'))
    if point is None:
        return False
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash('BIP0340/challenge', sig[:32] + pk + msg), 'big') % N
    R = point_add(point_mul(G, s), point_mul(point, N - e))
    if R is None:
        return False
    x, y = affine(R)
    return y % 2 == 0 and x == r


def tweak_add(pk, t):
    """BIP 341 taproot_tweak_pubkey for tweak t: (parity, x-only key)."""
    point = lift_x(int.from_bytes(pk, 'big'))
    if point is None or t >= N:
        return None
    Q = point_add(point, point_mul(G, t))
    if Q is None:
        return None
    x, y = affine(Q)
    return y & 1, x.to_bytes(32, 'big')


# ---------------------------------------------------------------------------
# Transactions and the BIP 341 signature message
# ---------------------------------------------------------------------------

class TxIn:
    def __init__(self, prevout_hash, prevout_n, script_sig, sequence):
        self.prevout_hash = prevout_hash
        self.prevout_n = prevout_n
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = []

    def serialize(self):
        return (self.prevout_hash + le32(self.prevout_n)
                + ser_string(self.script_sig) + le32(self.sequence))

    def serialize_witness(self):
        return compact_size(len(self.witness)) + b''.join(ser_string(w) for w in self.witness)


class TxOut:
    def __init__(self, value, script_pubkey):
        self.value = value
        self.script_pubkey = script_pubkey

    def serialize(self):
        return le64(self.value) + ser_string(self.script_pubkey)


class Tx:
    def __init__(self, version, vin, vout, locktime):
        self.version = version
        self.vin = vin
        self.vout = vout
        self.locktime = locktime

    def serialize(self, with_witness):
        """BIP 141 serialization; the witness marker only with witness data."""
        out = le32(self.version)
        if with_witness and any(i.witness for i in self.vin):
            out += b'\x00\x01'
        out += compact_size(len(self.vin)) + b''.join(i.serialize() for i in self.vin)
        out += compact_size(len(self.vout)) + b''.join(o.serialize() for o in self.vout)
        if with_witness and any(i.witness for i in self.vin):
            out += b''.join(i.serialize_witness() for i in self.vin)
        return out + le32(self.locktime)

    def weight(self):
        """BIP 141: 3 * base size + total size."""
        return 3 * len(self.serialize(False)) + len(self.serialize(True))


def _read_cs(raw, pos):
    r = read_compact_size(raw, pos, len(raw))
    if r is None:
        raise Unsupported('bad CompactSize in transaction')
    return r


def parse_tx(raw):
    version = struct.unpack('<I', raw[0:4])[0]
    pos = 4
    count, pos = _read_cs(raw, pos)
    witness = False
    if count == 0 and raw[pos] == 1:
        witness = True
        count, pos = _read_cs(raw, pos + 1)
    vin = []
    for _ in range(count):
        prevout_hash, prevout_n = raw[pos:pos + 32], struct.unpack('<I', raw[pos + 32:pos + 36])[0]
        length, pos = _read_cs(raw, pos + 36)
        script_sig = raw[pos:pos + length]
        pos += length
        sequence = struct.unpack('<I', raw[pos:pos + 4])[0]
        vin.append(TxIn(prevout_hash, prevout_n, script_sig, sequence))
        pos += 4
    count, pos = _read_cs(raw, pos)
    vout = []
    for _ in range(count):
        value = struct.unpack('<Q', raw[pos:pos + 8])[0]
        length, pos = _read_cs(raw, pos + 8)
        vout.append(TxOut(value, raw[pos:pos + length]))
        pos += length
    if witness:
        for txin in vin:
            count, pos = _read_cs(raw, pos)
            for _ in range(count):
                length, pos = _read_cs(raw, pos)
                txin.witness.append(raw[pos:pos + length])
                pos += length
    tx = Tx(version, vin, vout, struct.unpack('<I', raw[pos:pos + 4])[0])
    if pos + 4 != len(raw):
        raise Unsupported('trailing bytes in transaction')
    return tx


def parse_txout(raw):
    value = struct.unpack('<Q', raw[:8])[0]
    length, pos = _read_cs(raw, 8)
    if pos + length != len(raw):
        raise Unsupported('bad output serialization')
    return TxOut(value, raw[pos:pos + length])


class SpendContext:
    """The spend of one input: transaction, spent outputs, index and annex."""

    def __init__(self, tx, spent, index, annex):
        self.tx = tx
        self.spent = spent
        self.index = index
        self.annex = annex


def sig_msg(ctx, hash_type, ext_flag, leaf_hash=None, codesep_pos=None):
    """BIP 341 Common Signature Message with the BIP 342 extension (ext_flag 1).

    Returns the TapSighash of the message, or None for an invalid hash_type
    or SIGHASH_SINGLE without a corresponding output.
    """
    if hash_type not in (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
        return None
    tx, spent, index = ctx.tx, ctx.spent, ctx.index
    anyonecanpay = hash_type & 0x80
    output_type = 1 if hash_type == 0 else hash_type & 3
    msg = bytes([hash_type]) + le32(tx.version) + le32(tx.locktime)
    if not anyonecanpay:
        msg += sha256(b''.join(i.prevout_hash + le32(i.prevout_n) for i in tx.vin))
        msg += sha256(b''.join(le64(o.value) for o in spent))
        msg += sha256(b''.join(ser_string(o.script_pubkey) for o in spent))
        msg += sha256(b''.join(le32(i.sequence) for i in tx.vin))
    if output_type == 1:
        msg += sha256(b''.join(o.serialize() for o in tx.vout))
    msg += bytes([2 * ext_flag + (1 if ctx.annex is not None else 0)])
    if anyonecanpay:
        txin = tx.vin[index]
        msg += txin.prevout_hash + le32(txin.prevout_n)
        msg += spent[index].serialize() + le32(txin.sequence)
    else:
        msg += le32(index)
    if ctx.annex is not None:
        msg += sha256(ser_string(ctx.annex))
    if output_type == 3:
        if index >= len(tx.vout):
            return None
        msg += sha256(tx.vout[index].serialize())
    if ext_flag == 1:
        msg += leaf_hash + b'\x00' + le32(codesep_pos)
    return tagged_hash('TapSighash', b'\x00' + msg)


def leaf_hash(version, script):
    """BIP 341 tapleaf hash."""
    return tagged_hash('TapLeaf', bytes([version]) + ser_string(script))


def merkle_root(leaf, control):
    """BIP 341: fold the control block's path onto the tapleaf hash."""
    k = leaf
    for off in range(33, len(control), 32):
        node = control[off:off + 32]
        k = tagged_hash('TapBranch', k + node if k < node else node + k)
    return k


# ---------------------------------------------------------------------------
# Script decoding and Reusable Macros
# ---------------------------------------------------------------------------

def read_instruction(b, pos, end):
    """One instruction at pos: (opcode, payload, macro index, next position).

    Returns None if the instruction is cut off by end.  The payload is the
    push data of a push opcode; the index is OP_CALLMACRO's CompactSize.
    """
    op = b[pos]
    pos += 1
    if op <= OP_PUSHDATA4:
        if op < OP_PUSHDATA1:
            size = op
        else:
            width = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[op]
            if end - pos < width:
                return None
            size = int.from_bytes(b[pos:pos + width], 'little')
            pos += width
        if end - pos < size:
            return None
        return op, b[pos:pos + size], None, pos + size
    if op == OP_CALLMACRO:
        r = read_compact_size(b, pos, end)
        if r is None:
            return None
        return op, None, r[0], r[1]
    return op, None, None, pos


class Totals:
    """Reusable Macros, Unrolling: totals of a body or the main script."""

    def __init__(self):
        self.length = 0        # unrolled length
        self.instructions = 0  # instructions after unrolling
        self.references = 0    # references visited
        self.substituted = 0   # instructions that come from bodies


class Program:
    """A well-formed committed script: its bodies, totals and main script."""

    def __init__(self, script, bodies, totals, main, main_totals):
        self.script = script
        self.bodies = bodies            # (begin, end) of each body
        self.totals = totals            # Totals of each body
        self.main = main                # (begin, end) of the main script
        self.main_totals = main_totals


def _decode_sequence(b, begin, end, totals):
    """Decode a body or the main script; 'success', 'failure', 'oversized'
    or its Totals."""
    t = Totals()
    pos = begin
    while pos < end:
        r = read_instruction(b, pos, end)
        if r is None:
            return 'failure'
        op, _, index, pos_next = r
        if op in SUCCESS_C2:
            return 'success'
        if op == OP_MACRO:
            return 'failure'
        if op == OP_CALLMACRO:
            if index >= len(totals):
                return 'failure'
            body = totals[index]
            t.length += body.length
            t.instructions += body.instructions
            t.references = min(MAX_TOTAL, t.references + 1 + body.references)
            t.substituted += body.instructions
        else:
            t.length += pos_next - pos
            t.instructions += 1
        # Reusable Macros, Scan: the size limit fails at the crossing instruction.
        if t.length > MAX_SCRIPT:
            return 'oversized'
        pos = pos_next
    return t


def decode_script(script):
    """Reusable Macros, Scan; BIP 342's OP_SUCCESSx scan without
    declarations.  Returns ('well-formed', Program), ('success', None),
    ('failure', None) or ('oversized', None), a failure at the size limit."""
    bodies, totals = [], []
    pos, end = 0, len(script)
    while pos < end and script[pos] == OP_MACRO:
        r = read_compact_size(script, pos + 1, end)
        if r is None or r[0] > end - r[1]:
            return 'failure', None
        length, begin = r
        result = _decode_sequence(script, begin, begin + length, totals)
        if isinstance(result, str):
            return result, None
        bodies.append((begin, begin + length))
        totals.append(result)
        pos = begin + length
    result = _decode_sequence(script, pos, end, totals)
    if isinstance(result, str):
        return result, None
    return 'well-formed', Program(script, bodies, totals, (pos, end), result)


def unrolling_charge(program):
    """Reusable Macros, Unrolling step 3."""
    if not program.bodies:
        return 0
    t = program.main_totals
    return BASE * (t.substituted + t.references) + WRITE(t.length)


def unroll(program):
    """Reusable Macros, Unrolling step 4: the main script with every
    reference replaced, written in one pass that follows each reference
    into its body."""
    b = program.script
    if not program.bodies:
        return b[program.main[0]:program.main[1]]
    out, frames = bytearray(), [list(program.main)]
    while frames:
        frame = frames[-1]
        if frame[0] == frame[1]:
            frames.pop()
            continue
        pos = frame[0]
        op, _, index, frame[0] = read_instruction(b, pos, frame[1])
        if op == OP_CALLMACRO:
            frames.append(list(program.bodies[index]))
        else:
            out += b[pos:frame[0]]
    return bytes(out)


def check_sig(sig, pk, ctx, leaf, codesep_pos):
    """BIP 342, Rules for signature opcodes and Signature validation.
    True for a valid signature or an unknown key type, False for an empty
    signature; raises on an invalid one."""
    if not pk:
        raise Fail('TAPSCRIPT_EMPTY_PUBKEY')
    if not sig:
        return False
    if len(pk) != 32:
        return True
    if len(sig) not in (64, 65):
        raise Fail('SCHNORR_SIG_SIZE')
    hash_type = sig[64] if len(sig) == 65 else 0
    if len(sig) == 65 and hash_type == 0:
        raise Fail('SCHNORR_SIG_HASHTYPE')
    if ctx is None:
        raise Fail('SCHNORR_SIG')
    msg = sig_msg(ctx, hash_type, 1, leaf, codesep_pos)
    if msg is None:
        raise Fail('SCHNORR_SIG_HASHTYPE')
    if not schnorr_verify(pk, msg, sig[:64]):
        raise Fail('SCHNORR_SIG')
    return True


# ---------------------------------------------------------------------------
# Tapleaf 0xC2 execution
# ---------------------------------------------------------------------------

STACK_OPS = range(OP_TOALTSTACK, OP_TUCK + 1)
SPLICE_OPS = range(OP_CAT, OP_SIZE + 1)
BITWISE_OPS = (OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_LSHIFT, OP_RSHIFT)
ARITH_OPS = (OP_1ADD, OP_1SUB, OP_2MUL, OP_2DIV, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD)
COMPARE_OPS = ((OP_NOT, OP_0NOTEQUAL, OP_EQUAL, OP_EQUALVERIFY)
               + tuple(range(OP_BOOLAND, OP_WITHIN + 1)))
HASH_OPS = range(OP_RIPEMD160, OP_HASH256 + 1)
SIG_OPS = (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD)
EXTENDED_OPS = (OP_CHECKSIGFROMSTACK, OP_TWEAKADD, OP_BYTEREV)
NOPS = (OP_NOP, OP_NOP1, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10)
DEFAULT_CONTROL = b'\xc2' + bytes(32)

# BIP 441, Enabled Opcodes: "If there are fewer than the required number of
# stack elements, these opcodes fail validation"; likewise for every opcode.
ARITY = {}
for _n, _names in (
        (1, 'IF NOTIF VERIFY CHECKLOCKTIMEVERIFY CHECKSEQUENCEVERIFY TOALTSTACK IFDUP '
            'DROP DUP SIZE INVERT 1ADD 1SUB 2MUL 2DIV NOT 0NOTEQUAL RIPEMD160 SHA1 '
            'SHA256 HASH160 HASH256 BYTEREV TX'),
        (2, '2DROP 2DUP NIP OVER PICK ROLL SWAP TUCK CAT LEFT RIGHT AND OR XOR LSHIFT '
            'RSHIFT ADD SUB MUL DIV MOD EQUAL EQUALVERIFY BOOLAND BOOLOR NUMEQUAL '
            'NUMEQUALVERIFY NUMNOTEQUAL LESSTHAN GREATERTHAN LESSTHANOREQUAL '
            'GREATERTHANOREQUAL MIN MAX CHECKSIG CHECKSIGVERIFY TWEAKADD'),
        (3, '3DUP ROT SUBSTR WITHIN CHECKSIGADD CHECKSIGFROMSTACK'),
        (4, '2OVER 2SWAP'), (6, '2ROT')):
    for _name in _names.split():
        ARITY[OPCODES['OP_' + _name]] = _n


class Interpreter:
    """Executes a committed Tapleaf 0xC2 script and meters it (BIP 441 and
    BIP 440, as amended by OP_TX, Extended Primitives and Reusable Macros).

    After run(): `cost` is the varops charged, `stack` the final stack and
    `success` whether the script succeeded immediately.
    """

    def __init__(self, script, stack, budget, ctx=None, control=DEFAULT_CONTROL):
        self.committed = script
        self.leaf_hash = leaf_hash(0xc2, script)
        self.stack = list(stack)
        self.alt = []
        self.nbytes = sum(map(len, stack))      # bytes on both stacks
        self.budget = budget
        self.cost = 0
        self.ctx = ctx
        self.control = control
        self.codesep_pos = NO_CODESEP
        self.conditions = []
        self.false_count = 0                     # False entries of conditions
        self.success = False

    # -- metering and stack helpers --------------------------------------

    def charge(self, varops):
        self.cost += varops

    def check_budget(self):
        if self.cost > self.budget:
            raise Fail('VAROP_COUNT')

    def pop(self):
        v = self.stack.pop()
        self.nbytes -= len(v)
        return v

    def push(self, v):
        if len(v) > MAX_ELEMENT:
            raise Fail('STACK_ELEMENT_SIZE')
        self.stack.append(v)
        self.nbytes += len(v)

    def read(self):
        """Pop an operand that is read as a number or inspected: READ."""
        v = self.pop()
        self.charge(READ(len(v)))
        return v

    def write(self, v):
        """Produce a value: WRITE(length)."""
        self.charge(WRITE(len(v)))
        self.push(v)

    def write_num(self, value):
        """Produce a numeric result at its minimal length."""
        self.write(enc(value))

    def push_num(self, value):
        """Push a numeric result computed in place at its minimal length: no WRITE."""
        self.push(enc(value))

    def check_limits(self):
        """BIP 441 stack limits after an executed opcode."""
        if len(self.stack) + len(self.alt) > MAX_STACK_ITEMS:
            raise Fail('STACK_SIZE')
        if self.nbytes > MAX_STACK_BYTES:
            raise Fail('TOTAL_STACK_SIZE')

    # -- the main loop ----------------------------------------------------

    def run(self, final):
        """Validate the script; with `final`, apply BIP 441's final result rule."""
        result, program = decode_script(self.committed)
        if result == 'failure':
            raise Fail('BAD_OPCODE')
        if result == 'oversized':
            raise Fail('SCRIPT_SIZE')
        if result == 'success':
            self.success = True
            return
        if len(self.stack) > MAX_STACK_ITEMS:
            raise Fail('STACK_SIZE')
        if any(len(v) > MAX_ELEMENT for v in self.stack):
            raise Fail('STACK_ELEMENT_SIZE')
        if self.nbytes > MAX_STACK_BYTES:
            raise Fail('TOTAL_STACK_SIZE')
        self.charge(unrolling_charge(program))
        self.check_budget()
        script = unroll(program)
        pos, position = 0, 0
        while pos < len(script):
            op, data, _, pos_next = read_instruction(script, pos, len(script))
            executing = self.false_count == 0
            if executing or OP_IF <= op <= OP_ENDIF:
                if op != OP_TX:
                    self.charge(BASE)
                self.execute(op, data, position, executing)
                if self.success:                 # BIP 440: charges precede success
                    self.check_budget()
                    return
                self.check_limits()
                self.check_budget()
            pos, position = pos_next, position + 1
        if self.conditions:
            raise Fail('UNBALANCED_CONDITIONAL')
        if final:                                # BIP 441, final success check
            if len(self.stack) != 1:
                raise Fail('CLEANSTACK')
            self.charge(READ(len(self.stack[0])))
            self.check_budget()
            if num(self.stack[0]) == 0:
                raise Fail('EVAL_FALSE')
        self.check_budget()

    def execute(self, op, data, position, executing):
        if executing and len(self.stack) < ARITY.get(op, 0):
            raise Fail('INVALID_STACK_OPERATION')
        if op <= OP_PUSHDATA4:
            self.write(data)
        elif OP_1 <= op <= OP_16:
            self.write_num(op - OP_1 + 1)
        elif op in NOPS:
            pass
        elif op == OP_CODESEPARATOR:
            self.codesep_pos = position
        elif op in (OP_IF, OP_NOTIF):            # BIP 342, consensus MINIMALIF
            value = False
            if executing:
                top = self.pop()
                if top not in (b'', b'\x01'):
                    raise Fail('TAPSCRIPT_MINIMALIF')
                value = (top == b'\x01') != (op == OP_NOTIF)
            self.conditions.append(value)
            self.false_count += not value
        elif op in (OP_ELSE, OP_ENDIF):
            if not self.conditions:
                raise Fail('UNBALANCED_CONDITIONAL')
            if op == OP_ELSE:
                self.false_count += 1 if self.conditions[-1] else -1
                self.conditions[-1] = not self.conditions[-1]
            else:
                self.false_count -= not self.conditions.pop()
        elif op in (OP_VERIF, OP_VERNOTIF):
            raise Fail('BAD_OPCODE')
        elif op == OP_RETURN:
            raise Fail('OP_RETURN')
        elif op in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
            raise Fail('TAPSCRIPT_CHECKMULTISIG')
        elif op == OP_VERIFY:
            if num(self.read()) == 0:
                raise Fail('VERIFY')
        elif op in (OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY):
            self.exec_timelock(op)
        elif op in STACK_OPS:
            self.exec_stack(op)
        elif op in SPLICE_OPS:
            self.exec_splice(op)
        elif op in BITWISE_OPS:
            self.exec_bitwise(op)
        elif op in ARITH_OPS:
            self.exec_arith(op)
        elif op in COMPARE_OPS:
            self.exec_compare(op)
        elif op in HASH_OPS:
            self.exec_hash(op)
        elif op in SIG_OPS:
            self.exec_sig(op)
        elif op in EXTENDED_OPS:
            self.exec_extended(op)
        elif op == OP_TX:
            self.exec_tx()
        else:
            raise Fail('BAD_OPCODE')

    # -- BIP 440, Stack Manipulation ----------------------------------------

    def exec_stack(self, op):
        st = self.stack
        if op == OP_TOALTSTACK:
            self.charge(MOVE(1))
            self.alt.append(st.pop())
        elif op == OP_FROMALTSTACK:
            if not self.alt:
                raise Fail('INVALID_ALTSTACK_OPERATION')
            self.charge(MOVE(1))
            st.append(self.alt.pop())
        elif op == OP_2DROP:
            self.pop()
            self.pop()
        elif op in (OP_2DUP, OP_3DUP, OP_2OVER):
            n = ARITY[op]
            for v in st[-n:-n + 2] if op == OP_2OVER else st[-n:]:
                self.write(v)
        elif op == OP_2ROT:
            self.charge(MOVE(6))
            st[-6:] = st[-4:] + st[-6:-4]
        elif op == OP_2SWAP:
            self.charge(MOVE(4))
            st[-4:] = st[-2:] + st[-4:-2]
        elif op == OP_IFDUP:
            self.charge(READ(len(st[-1])))
            if num(st[-1]):
                self.write(st[-1])
        elif op == OP_DEPTH:
            self.write_num(len(st))
        elif op == OP_DROP:
            self.pop()
        elif op == OP_DUP:
            self.write(st[-1])
        elif op == OP_NIP:
            self.charge(MOVE(2))
            top = self.pop()
            self.pop()
            self.push(top)
        elif op == OP_OVER:
            self.write(st[-2])
        elif op in (OP_PICK, OP_ROLL):
            n = num(self.read())
            if n >= len(st):
                raise Fail('INVALID_STACK_OPERATION')
            if op == OP_PICK:
                self.write(st[-1 - n])
            else:
                self.charge(MOVE(n + 1))
                st.append(st.pop(-1 - n))
        elif op == OP_ROT:
            self.charge(MOVE(3))
            st.append(st.pop(-3))
        elif op == OP_SWAP:
            self.charge(MOVE(2))
            st[-1], st[-2] = st[-2], st[-1]
        elif op == OP_TUCK:
            self.write(st[-1])
            self.charge(MOVE(2))
            st[-3], st[-2] = st[-2], st[-3]

    # -- BIP 441, Splice Opcodes --------------------------------------------

    def exec_splice(self, op):
        if op == OP_CAT:
            b = self.pop()
            a = self.pop()
            self.write(a + b)
        elif op == OP_SUBSTR:
            length = num(self.read())
            begin = num(self.read())
            a = self.pop()
            start = min(begin, len(a))
            out = min(length, len(a) - start)
            self.charge(ARITH(out))
            self.push(a[start:start + out])
        elif op == OP_LEFT:
            n = num(self.read())
            a = self.pop()
            self.push(a[:min(n, len(a))])
        elif op == OP_RIGHT:
            n = num(self.read())
            a = self.pop()
            out = min(n, len(a))
            self.charge(ARITH(out))
            self.push(a[len(a) - out:])
        elif op == OP_SIZE:
            self.write_num(len(self.stack[-1]))

    # -- BIP 441, Bit Operation and Bitshift Opcodes ------------------------

    def exec_bitwise(self, op):
        if op == OP_INVERT:
            a = self.read()
            self.charge(ARITH(len(a)))
            self.push((num(a) ^ ((1 << 8 * len(a)) - 1)).to_bytes(len(a), 'little'))
        elif op in (OP_AND, OP_OR, OP_XOR):
            b = self.read()
            a = self.read()
            self.charge(ARITH(max(len(a), len(b))))
            x, y = num(a), num(b)
            r = x & y if op == OP_AND else x | y if op == OP_OR else x ^ y
            self.push(r.to_bytes(max(len(a), len(b)), 'little'))
        elif op == OP_LSHIFT:                    # OP_UPSHIFT
            bits = num(self.read())
            a = self.read()
            self.charge(ARITH(len(a)))
            n = len(a) + (bits + 7) // 8
            if n > MAX_ELEMENT:
                raise Fail('STACK_ELEMENT_SIZE')
            self.charge(WRITE(n))                # BIP 441: charged before the result is built
            self.check_budget()
            self.push((num(a) << bits).to_bytes(n, 'little'))
        elif op == OP_RSHIFT:                    # OP_DOWNSHIFT
            bits = num(self.read())
            a = self.read()
            self.charge(ARITH(len(a)))
            keep = len(a) - bits // 8
            if keep <= 0:
                self.push(b'')
            else:
                self.push(((num(a) >> bits) & ((1 << 8 * keep) - 1)).to_bytes(keep, 'little'))

    # -- BIP 441, Extended Opcodes and Multiply and Divide Opcodes ----------

    def exec_arith(self, op):
        if op in (OP_1ADD, OP_1SUB, OP_2MUL, OP_2DIV):
            a = self.read()
            self.charge(ARITH(len(a)))
            v = num(a)
            if op == OP_1SUB and v == 0:
                raise Fail('SUB_UNDERFLOW')
            if op in (OP_1ADD, OP_2MUL):
                self.write_num(v + 1 if op == OP_1ADD else 2 * v)
            else:
                self.push_num(v - 1 if op == OP_1SUB else v // 2)
        elif op in (OP_ADD, OP_SUB):
            b = self.read()
            a = self.read()
            self.charge(ARITH(max(len(a), len(b))))
            if op == OP_SUB and num(b) > num(a):
                raise Fail('SUB_UNDERFLOW')
            if op == OP_ADD:
                self.write_num(num(a) + num(b))
            else:
                self.push_num(num(a) - num(b))
        elif op == OP_MUL:
            b = self.read()
            a = self.read()
            self.charge(MUL(max(len(a), len(b)), min(len(a), len(b))) + WRITE(wordspan(len(a)) + wordspan(len(b))))
            self.check_budget()
            self.push(enc(num(a) * num(b)))
        else:                                    # OP_DIV, OP_MOD
            b = self.read()
            a = self.read()
            self.charge(DIV(len(trim(a)), len(trim(b))))
            self.check_budget()
            if num(b) == 0:
                raise Fail('DIVIDE_BY_ZERO')
            self.push_num(num(a) // num(b) if op == OP_DIV else num(a) % num(b))

    # -- BIP 440, Control and Comparison Operators ---------------------------

    def exec_compare(self, op):
        if op in (OP_NOT, OP_0NOTEQUAL):
            zero = num(self.read()) == 0
            self.write_num(int(zero if op == OP_NOT else not zero))
        elif op in (OP_EQUAL, OP_EQUALVERIFY):
            b = self.pop()
            a = self.pop()
            if len(a) == len(b):
                self.charge(READ(len(a)))
            if op == OP_EQUAL:
                self.write_num(int(a == b))
            elif a != b:
                raise Fail('EQUALVERIFY')
        elif op == OP_WITHIN:
            hi = num(self.read())
            lo = num(self.read())
            x = self.read()
            self.charge(READ(len(x)))
            self.write_num(int(lo <= num(x) < hi))
        else:
            b = num(self.read())
            a = num(self.read())
            if op in (OP_MIN, OP_MAX):
                self.push_num(min(a, b) if op == OP_MIN else max(a, b))
                return
            r = {OP_BOOLAND: a != 0 and b != 0, OP_BOOLOR: a != 0 or b != 0,
                 OP_NUMEQUAL: a == b, OP_NUMEQUALVERIFY: a == b, OP_NUMNOTEQUAL: a != b,
                 OP_LESSTHAN: a < b, OP_GREATERTHAN: a > b,
                 OP_LESSTHANOREQUAL: a <= b, OP_GREATERTHANOREQUAL: a >= b}[op]
            if op == OP_NUMEQUALVERIFY:
                if not r:
                    raise Fail('NUMEQUALVERIFY')
            else:
                self.write_num(int(r))

    # -- BIP 440, Hash Operators; BIP 441, Limited Hashing Opcodes ----------

    def exec_hash(self, op):
        if op in (OP_RIPEMD160, OP_SHA1) and len(self.stack[-1]) > 520:
            raise Fail('HASH_OPERAND_SIZE')
        a = self.pop()
        self.charge(HASH(len(a)))
        if op in (OP_HASH160, OP_HASH256):
            self.charge(HASH(32))
        self.write({OP_RIPEMD160: ripemd160, OP_SHA1: sha1, OP_SHA256: sha256,
                    OP_HASH160: lambda x: ripemd160(sha256(x)),
                    OP_HASH256: lambda x: sha256(sha256(x))}[op](a))

    # -- BIP 65 and BIP 112 with BIP 441's numeric operand ------------------

    def exec_timelock(self, op):
        operand = self.stack[-1]                 # stays on the stack
        self.charge(READ(len(operand)))
        value = num(operand)
        if value >= 1 << 32:
            raise Fail('UNSATISFIED_LOCKTIME')
        if op == OP_CHECKSEQUENCEVERIFY and value & (1 << 31):
            return                               # disable flag: no-op
        if self.ctx is None:
            raise Fail('UNSATISFIED_LOCKTIME')
        tx = self.ctx.tx
        txin = tx.vin[self.ctx.index]
        if op == OP_CHECKLOCKTIMEVERIFY:
            if ((value < 500000000) != (tx.locktime < 500000000) or value > tx.locktime
                    or txin.sequence == 0xffffffff):
                raise Fail('UNSATISFIED_LOCKTIME')
        else:
            mask = (1 << 22) | 0xffff
            have, want = txin.sequence & mask, value & mask
            if (tx.version < 2 or txin.sequence & (1 << 31)
                    or (have < 1 << 22) != (want < 1 << 22) or want > have):
                raise Fail('UNSATISFIED_LOCKTIME')

    # -- BIP 342 signature opcodes with BIP 441's charges --------------------

    def exec_sig(self, op):
        st = self.stack
        if op in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            pk, sig = st[-1], st[-2]
            if sig:
                self.charge(HASH(96) + SIGCHECK)
            self.check_budget()
            ok = check_sig(sig, pk, self.ctx, self.leaf_hash, self.codesep_pos)
            self.pop()
            self.pop()
            if op == OP_CHECKSIG:
                self.write_num(int(ok))
            elif not ok:
                raise Fail('CHECKSIGVERIFY')
        else:                                    # OP_CHECKSIGADD
            pk, n, sig = st[-1], st[-2], st[-3]
            self.charge(READ(len(n)))
            if sig:
                self.charge(HASH(96) + SIGCHECK + ARITH(len(n)))
            self.check_budget()
            ok = check_sig(sig, pk, self.ctx, self.leaf_hash, self.codesep_pos)
            for _ in range(3):
                self.pop()
            self.write_num(num(n) + int(ok))

    # -- Extended Primitives ------------------------------------------------

    def exec_extended(self, op):
        st = self.stack
        if op == OP_CHECKSIGFROMSTACK:
            pk, msg, sig = st[-1], st[-2], st[-3]
            if sig:
                self.charge(SIGCHECK + HASH(64 + len(msg)))
            self.check_budget()
            if not pk:
                raise Fail('PUBKEYTYPE')
            if len(pk) == 32 and sig:
                if len(sig) != 64:
                    raise Fail('SCHNORR_SIG_SIZE')
                if not schnorr_verify(pk, msg, sig):
                    raise Fail('SCHNORR_SIG')
            for _ in range(3):
                self.pop()
            self.write_num(int(bool(sig)))
        elif op == OP_TWEAKADD:
            pk, t = st[-1], st[-2]
            if len(pk) != 32 or len(t) != 32:
                raise Fail('TWEAKADD')
            self.charge(SIGCHECK + WRITE(32))
            self.check_budget()
            result = tweak_add(pk, int.from_bytes(t, 'big'))
            if result is None:
                raise Fail('TWEAKADD')
            self.pop()
            self.pop()
            self.push(result[1])
        else:                                    # OP_BYTEREV
            a = self.pop()
            self.charge(ARITH(len(a)))
            self.check_budget()
            self.push(a[::-1])

    # -- OP_TX ----------------------------------------------------------------

    def exec_tx(self):
        """OP_TX Execution, steps 1 to 9."""
        st = self.stack
        selector = self.pop()
        if not selector:
            raise Fail('TX_SELECTOR')
        self.charge(BASE)
        if selector[0] != 0:                     # Future Selector Versions
            self.success = True
            return
        if len(selector) != 6:
            raise Fail('TX_SELECTOR')
        fmt, current, scopes, in_fields, out_fields = selector[1:]
        in_scope, out_scope = scopes >> 4, scopes & 0x0f
        if (in_scope > 4 or out_scope > 4 or out_fields & 0xfc
                or (in_scope == 0) != (in_fields == 0)
                or (out_scope == 0) != (out_fields == 0)
                or not (fmt & 0xfe or current or in_fields or out_fields)):
            raise Fail('TX_SELECTOR')
        operand_count = {0: 0, 1: 0, 2: 0, 3: 1, 4: 2}
        n_in, n_out = operand_count[in_scope], operand_count[out_scope]
        if len(st) < n_in + n_out:
            raise Fail('INVALID_STACK_OPERATION')
        operands = [num(self.read()) for _ in range(n_in + n_out)][::-1]
        if any(v >= 1 << 32 for v in operands):
            raise Fail('TX_SELECTOR')
        if self.ctx is None:
            raise Fail('TX_CONTEXT')
        tx, spent, index = self.ctx.tx, self.ctx.spent, self.ctx.index

        def select(scope, total, ops):
            """Input and Output Scopes: the selected indices."""
            if scope == 0:
                return []
            if scope == 1:
                chosen = [index]
            elif scope == 2:
                return list(range(total))
            elif scope == 3:
                chosen = [ops[0]]
            else:
                if ops[1] < 1:
                    raise Fail('TX_SELECTOR')
                if ops[0] + ops[1] > total:
                    raise Fail('TX_CONTEXT')
                chosen = list(range(ops[0], ops[0] + ops[1]))
            if chosen[-1] >= total:
                raise Fail('TX_CONTEXT')
            return chosen

        inputs = select(in_scope, len(tx.vin), operands[:n_in])
        outputs = select(out_scope, len(tx.vout), operands[n_in:])

        def visit(add):
            """Pass each selected value to add(kind, value, width) in output
            order; returns the records scanned for aggregate fields."""
            k_extra = 0

            def number(value, width):
                add('number', value, width)

            def fixed(b):
                add('fixed', b, None)

            def string(b):
                add('string', b, None)

            if fmt & 0x02:
                number(tx.version, 4)
            if fmt & 0x04:
                number(tx.locktime, 4)
            if fmt & 0x08:
                number(tx.weight(), 4)
                k_extra += len(tx.vin) + len(tx.vout) + sum(len(i.witness) for i in tx.vin)
            if fmt & 0x10:
                number(len(tx.vin), 4)
            if fmt & 0x20:
                number(sum(o.value for o in spent), 8)
                k_extra += len(tx.vin)
            for i in inputs:
                txin, prev = tx.vin[i], spent[i]
                if in_fields & 0x01:
                    fixed(txin.prevout_hash)
                if in_fields & 0x02:
                    number(txin.prevout_n, 4)
                if in_fields & 0x04:
                    number(prev.value, 8)
                if in_fields & 0x08:
                    string(prev.script_pubkey)
                if in_fields & 0x10:
                    string(txin.script_sig)
                if in_fields & 0x20:
                    number(txin.sequence, 4)
                if in_fields & 0x40:
                    number(len(txin.witness), 4)
                if in_fields & 0x80:
                    add('count', len(txin.witness), None)
                    for item in txin.witness:
                        string(item)
            if fmt & 0x40:
                number(len(tx.vout), 4)
            if fmt & 0x80:
                number(sum(o.value for o in tx.vout), 8)
                k_extra += len(tx.vout)
            for o in outputs:
                if out_fields & 0x01:
                    number(tx.vout[o].value, 8)
                if out_fields & 0x02:
                    string(tx.vout[o].script_pubkey)
            if current & 0x01:
                number(index, 4)
            if current & 0x02:
                string(self.ctx.annex if self.ctx.annex is not None else b'')
            if current & 0x04:
                string(self.committed)
            if current & 0x08:
                fixed(self.leaf_hash)
            if current & 0x10:
                string(self.control)
            if current & 0x20:
                fixed(self.control[1:33])
            if current & 0x40:
                fixed(merkle_root(self.leaf_hash, self.control))
            if current & 0x80:
                number(self.codesep_pos, 4)
            return k_extra

        def encode(kind, value, width):
            """A value's collated encoding, and its result unless collated."""
            if kind == 'number':
                if value >> (8 * width):
                    raise Fail('TX_CONTEXT')
                return value.to_bytes(width, 'little'), enc(value)
            if kind == 'count':
                return compact_size(value), None
            if kind == 'string':
                return ser_string(value), value
            return value, value

        # Size the results in a first pass, and produce them in a second once
        # they are paid for, so that nothing is held per selected value.
        collate = fmt & 0x01
        sizes = {'values': 0, 'results': 0, 'bytes': 0, 'largest': 0, 'write': 0}

        def measure(kind, value, width):
            collated, result = encode(kind, value, width)
            sizes['values'] += 1
            if collate:
                sizes['bytes'] += len(collated)
            elif result is not None:
                sizes['results'] += 1
                sizes['bytes'] += len(result)
                sizes['largest'] = max(sizes['largest'], len(result))
                sizes['write'] += WRITE(len(result))

        k_extra = visit(measure)
        if collate:
            sizes.update(results=1, largest=sizes['bytes'], write=WRITE(sizes['bytes']))
        if sizes['largest'] > MAX_ELEMENT:
            raise Fail('STACK_ELEMENT_SIZE')
        if len(st) + len(self.alt) + sizes['results'] > MAX_STACK_ITEMS:
            raise Fail('STACK_SIZE')
        if self.nbytes + sizes['bytes'] > MAX_STACK_BYTES:
            raise Fail('TOTAL_STACK_SIZE')
        self.charge(OP_TX_SELECT(sizes['values'] + k_extra) + sizes['write'])
        self.check_budget()
        collated_result = bytearray()

        def produce(kind, value, width):
            collated, result = encode(kind, value, width)
            if collate:
                collated_result.extend(collated)
            elif result is not None:
                self.push(result)

        visit(produce)
        if collate:
            self.push(bytes(collated_result))


# ---------------------------------------------------------------------------
# BIP 440: the transaction-wide budget, and complete spends
# ---------------------------------------------------------------------------

def witness_program(spk):
    """BIP 141: (version, program) of a witness program scriptPubKey, else None."""
    if 4 <= len(spk) <= 42 and spk[1] == len(spk) - 2:
        if spk[0] == 0:
            return 0, spk[2:]
        if OP_1 <= spk[0] <= OP_16:
            return spk[0] - OP_1 + 1, spk[2:]
    return None


def pushes(script):
    """The pushed values of a push-only script, else None."""
    out, pos = [], 0
    while pos < len(script):
        r = read_instruction(script, pos, len(script))
        if r is None or r[0] > OP_16:
            return None
        out.append(r[1] if r[1] is not None else enc(max(0, r[0] - OP_1 + 1)))
        pos = r[3]
    return out


def strip_annex(witness):
    """BIP 341: (witness without the annex, annex or None)."""
    if len(witness) >= 2 and witness[-1][:1] == b'\x50':
        return witness[:-1], witness[-1]
    return witness, None


def input_kind(txin, spk):
    """BIP 440, Design: 'legacy', 'v0', 'keypath' and 'c0' inputs are
    excluded from the budget; 'c2' and 'other' inputs fund it."""
    program, wrapped = witness_program(spk), False
    if program is None:
        if not (len(spk) == 23 and spk[0] == OP_HASH160 and spk[1] == 20 and spk[22] == OP_EQUAL):
            return 'legacy'
        redeem = pushes(txin.script_sig)
        program = witness_program(redeem[-1]) if redeem else None
        if program is None:
            return 'legacy'
        wrapped = True
    version, data = program
    if version == 0:
        return 'v0'
    if version != 1 or len(data) != 32 or wrapped:
        return 'other'
    witness, _ = strip_annex(txin.witness)
    if len(witness) == 1:
        return 'keypath'
    if len(witness) >= 2 and witness[-1][:1] in (b'\xc0', b'\xc1'):
        return 'c0'
    if len(witness) >= 2 and witness[-1][:1] in (b'\xc2', b'\xc3'):
        return 'c2'
    return 'other'


def spends_script_path(txin, spk):
    """A Taproot script-path spend: an unwrapped 32-byte witness version 1
    program with at least two witness elements after the annex."""
    program = witness_program(spk)
    if program is None or program[0] != 1 or len(program[1]) != 32:
        return False
    witness, _ = strip_annex(txin.witness)
    return len(witness) >= 2


def tx_budget(tx, spent):
    """BIP 440, Design: 10,000 varops per weight unit of the funding inputs,
    less one SIGCHECK for the commitment check of each funding input that
    spends a Taproot script path."""
    kinds = [input_kind(txin, out.script_pubkey) for txin, out in zip(tx.vin, spent)]
    if 'c2' not in kinds:
        return 0, kinds
    weight, commitments = tx.weight(), 0
    for txin, out, kind in zip(tx.vin, spent, kinds):
        if kind in ('legacy', 'v0', 'keypath', 'c0'):
            weight -= 4 * len(txin.serialize()) + len(txin.serialize_witness())
        elif spends_script_path(txin, out.script_pubkey):
            commitments += 1
    return 10000 * weight - commitments * SIGCHECK, kinds


def cast_to_bool(v):
    """Legacy and BIP 342 CastToBool: nonzero, except negative zero."""
    return any(v[:-1]) or v[-1:] not in (b'', b'\x00', b'\x80')


def run_tapscript_c0(script, stack, ctx, txin):
    """BIP 342 validation of a Tapleaf 0xC0 script, for the opcodes the
    vectors use: pushes, constants, OP_DROP, OP_2DUP, OP_CHECKSIG and
    OP_CHECKSIGVERIFY.  Other opcodes are unsupported."""
    pos = 0
    while pos < len(script):
        if script[pos] in SUCCESS_C0:
            return
        r = read_instruction(script, pos, len(script))
        if r is None:
            raise Fail('BAD_OPCODE')
        pos = r[3]
    st = list(stack)
    leaf = leaf_hash(0xc0, script)
    budget = 50 + len(txin.serialize_witness())
    pos = 0
    while True:
        if len(st) > 1000 or any(len(v) > 520 for v in st):
            raise Fail('STACK_SIZE')
        if pos >= len(script):
            break
        op, data, _, pos = read_instruction(script, pos, len(script))
        if op <= OP_PUSHDATA4:
            st.append(data)
        elif OP_1 <= op <= OP_16:
            st.append(bytes([op - OP_1 + 1]))
        elif op == OP_DROP and st:
            st.pop()
        elif op == OP_2DUP and len(st) >= 2:
            st += st[-2:]
        elif op in (OP_CHECKSIG, OP_CHECKSIGVERIFY) and len(st) >= 2:
            pk, sig = st.pop(), st.pop()
            if sig:
                budget -= 50
                if budget < 0:
                    raise Fail('TAPSCRIPT_VALIDATION_WEIGHT')
            ok = check_sig(sig, pk, ctx, leaf, NO_CODESEP)
            if op == OP_CHECKSIG:
                st.append(b'\x01' if ok else b'')
            elif not ok:
                raise Fail('CHECKSIGVERIFY')
        elif op in (OP_DROP, OP_2DUP, OP_CHECKSIG, OP_CHECKSIGVERIFY):
            raise Fail('INVALID_STACK_OPERATION')
        else:
            raise Unsupported('0xC0 opcode 0x%02x' % op)
    if len(st) != 1 or not cast_to_bool(st[0]):
        raise Fail('EVAL_FALSE')


def run_legacy(script, stack):
    """Legacy and witness version 0 execution, for scripts of pushes and
    OP_1 to OP_16; other opcodes, such as ECDSA checks, are unsupported."""
    if len(script) > 10000:
        raise Fail('SCRIPT_SIZE')
    st, pos = list(stack), 0
    while pos < len(script):
        r = read_instruction(script, pos, len(script))
        if r is None:
            raise Fail('BAD_OPCODE')
        op, data, _, pos = r
        if op > OP_PUSHDATA4 and not OP_1 <= op <= OP_16:
            raise Unsupported('legacy opcode 0x%02x' % op)
        if data is not None and len(data) > 520:
            raise Fail('PUSH_SIZE')
        st.append(data if data is not None else bytes([op - OP_1 + 1]))
        if len(st) > 1000:
            raise Fail('STACK_SIZE')
    return st


def verify_input(tx, spent, index, kind, remaining):
    """Validate one input; returns the varops it charged."""
    txin, spk = tx.vin[index], spent[index].script_pubkey
    if kind == 'legacy':                         # P2SH runs into OP_HASH160
        if txin.witness:
            raise Fail('WITNESS_UNEXPECTED')
        st = run_legacy(spk, run_legacy(txin.script_sig, []))
        if not st or not cast_to_bool(st[-1]):
            raise Fail('EVAL_FALSE')
        return 0
    wrapped = kind in ('v0', 'other') and witness_program(spk) is None
    if wrapped:                                  # BIP 16 wrapper
        redeem = pushes(txin.script_sig)[-1]
        if ripemd160(sha256(redeem)) != spk[2:22]:
            raise Fail('EQUALVERIFY')
        if txin.script_sig != bytes([len(redeem)]) + redeem:
            raise Fail('WITNESS_MALLEATED_P2SH')   # BIP 141: exactly one push
        spk = redeem
    elif txin.script_sig:
        raise Fail('WITNESS_MALLEATED')            # BIP 141: must be empty
    if not cast_to_bool(witness_program(spk)[1]):  # the program is left on top and must be true
        raise Fail('EVAL_FALSE')
    if kind == 'v0':                             # BIP 141 witness version 0
        program, witness = witness_program(spk)[1], txin.witness
        if len(program) == 20:
            raise Unsupported('P2WPKH input %d not evaluated' % index)
        if len(program) != 32:
            raise Fail('WITNESS_PROGRAM_WRONG_LENGTH')
        if not witness:
            raise Fail('WITNESS_PROGRAM_WITNESS_EMPTY')
        if sha256(witness[-1]) != program:
            raise Fail('WITNESS_PROGRAM_MISMATCH')
        if any(len(w) > 520 for w in witness[:-1]):
            raise Fail('PUSH_SIZE')
        st = run_legacy(witness[-1], witness[:-1])
        if len(st) != 1 or not cast_to_bool(st[0]):
            raise Fail('CLEANSTACK' if len(st) != 1 else 'EVAL_FALSE')
        return 0
    version, program = witness_program(spk)
    if wrapped or version != 1 or len(program) != 32:
        return 0                                 # BIP 141: unencumbered
    witness, annex = strip_annex(txin.witness)   # BIP 341 script validation
    ctx = SpendContext(tx, spent, index, annex)
    q = spk[2:]
    if not witness:
        raise Fail('WITNESS_PROGRAM_WITNESS_EMPTY')
    if kind == 'keypath':
        sig = witness[0]
        if len(sig) not in (64, 65):
            raise Fail('SCHNORR_SIG_SIZE')
        hash_type = sig[64] if len(sig) == 65 else 0
        msg = sig_msg(ctx, hash_type, 0) if hash_type or len(sig) == 64 else None
        if msg is None or not schnorr_verify(q, msg, sig[:64]):
            raise Fail('SCHNORR_SIG')
        return 0
    script, control = witness[-2], witness[-1]
    if len(control) < 33 or (len(control) - 33) % 32 or len(control) > 33 + 32 * 128:
        raise Fail('TAPROOT_WRONG_CONTROL_SIZE')
    version = control[0] & 0xfe
    root = merkle_root(leaf_hash(version, script), control)
    tweak = int.from_bytes(tagged_hash('TapTweak', control[1:33] + root), 'big')
    if tweak_add(control[1:33], tweak) != (control[0] & 1, q):
        raise Fail('WITNESS_PROGRAM_MISMATCH')
    if kind == 'c2':
        interp = Interpreter(script, witness[:-2], remaining, ctx, control)
        interp.run(True)
        return interp.cost
    if kind == 'c0':
        run_tapscript_c0(script, witness[:-2], ctx, txin)
    return 0                                     # future leaf versions succeed


def verify_tx(tx, spent):
    """Every input against the one budget: (budget, varops, error, notes)."""
    budget, kinds = tx_budget(tx, spent)
    cost, notes = 0, []
    for index, kind in enumerate(kinds):
        try:
            cost += verify_input(tx, spent, index, kind, budget - cost)
        except Fail as f:
            return budget, None, f.name, notes
        except Unsupported as u:
            notes.append(str(u))
    return budget, cost, None, notes


# ---------------------------------------------------------------------------
# BIP 341: constructing outputs, for the signing vectors
# ---------------------------------------------------------------------------

def taproot_tree(leaves):
    """Merkle root and per-leaf paths of (depth, version, script) leaves
    listed in depth-first order."""
    stack = []                                   # (depth, hash, {leaf: path})
    for i, (depth, version, script) in enumerate(leaves):
        node = (depth, leaf_hash(version, script), {i: b''})
        while stack and stack[-1][0] == node[0]:
            _, left_hash, left = stack.pop()
            depth, right_hash, right = node
            paths = {k: p + right_hash for k, p in left.items()}
            paths.update({k: p + left_hash for k, p in right.items()})
            pair = min(left_hash, right_hash) + max(left_hash, right_hash)
            node = (depth - 1, tagged_hash('TapBranch', pair), paths)
        stack.append(node)
    if len(stack) != 1 or stack[0][0] != 0:
        raise Unsupported('leaves do not form a tree')
    return stack[0][1], stack[0][2]


# ---------------------------------------------------------------------------
# Vector groups
# ---------------------------------------------------------------------------

def parse_context(c):
    tx = parse_tx(parse_hex(c['tx']))
    spent = [parse_txout(parse_hex(o)) for o in c['spent_outputs']]
    annex = parse_hex(c['annex']) if 'annex' in c else None
    return SpendContext(tx, spent, c['input_index'], annex)


def run_script(v, budget):
    """A `scripts` vector: {'varops', 'final_stack'} or {'error'}."""
    script, stack = parse_script(v['script']), parse_stack(v.get('stack', []))
    ctx, control = None, DEFAULT_CONTROL
    if 'context' in v:
        ctx = parse_context(v['context'])
        control = parse_hex(v['context'].get('control_block', DEFAULT_CONTROL.hex()))
    interp = Interpreter(script, stack, budget, ctx, control)
    try:
        interp.run(bool(v.get('final')))
    except Fail as f:
        return {'error': f.name}
    got = {'varops': interp.cost}
    if not v.get('final'):
        got['final_stack'] = interp.stack
    return got


def check_primitive(v):
    return {'varops': PRIMITIVES[v['primitive']](v)}, {'varops': v['varops']}, []


def check_script(v):
    got = run_script(v, v.get('budget', 2 ** 64 - 1))
    exp = {'error': v['error']} if 'error' in v else {'varops': v['varops']}
    if 'final_stack' in v:
        exp['final_stack'] = parse_stack(v['final_stack'])
    if v.get('varops') and 'error' not in got:   # README: exactness rerun
        got['below budget'] = 'error' in run_script(v, v['varops'] - 1)
        exp['below budget'] = True
    return got, exp, []


def check_transaction(v):
    tx = parse_tx(parse_hex(v['tx']))
    spent = [parse_txout(parse_hex(o)) for o in v['spent_outputs']]
    budget, cost, error, notes = verify_tx(tx, spent)
    got = {'budget': budget, 'error': error} if error else {'budget': budget, 'varops': cost}
    return got, {k: v[k] for k in ('budget', 'varops', 'error') if k in v}, notes


def check_signing(v):
    leaves = [(l['depth'], parse_hex(l['version'])[0], parse_script(l['script']))
              for l in v['leaves']]
    root, paths = taproot_tree(leaves)
    internal = parse_hex(v['internal_key'])
    tweak = int.from_bytes(tagged_hash('TapTweak', internal + root), 'big')
    parity, output_key = tweak_add(internal, tweak)
    _, version, script = leaves[v['spend_leaf']]
    leaf = leaf_hash(version, script)
    sighash = sig_msg(parse_context(v['context']), v['hash_type'], 1, leaf,
                      v.get('codesep_pos', NO_CODESEP))
    got = {'script_pubkey': (b'\x51\x20' + output_key).hex(), 'leaf_hash': leaf.hex(),
           'control_block': (bytes([version | parity]) + internal + paths[v['spend_leaf']]).hex(),
           'sighash': sighash.hex() if sighash else None}
    return got, {k: v[k] for k in got}, []


def check_decoding(v):
    result, program = decode_script(parse_script(v['script']))
    got = {'result': 'failure' if result == 'oversized' else result}
    if program:
        got['declarations'] = len(program.bodies)
    return got, {k: v[k] for k in ('result', 'declarations') if k in v}, []


def check_unrolling(v):
    result, program = decode_script(parse_script(v['script']))
    if result != 'well-formed':
        return {'result': result}, {'result': 'well-formed'}, []
    t = program.main_totals
    got = {'declarations': len(program.bodies), 'unrolled_length': t.length,
           'substituted_instructions': t.substituted, 'references_visited': t.references,
           'unrolling_charge': unrolling_charge(program)}
    # Unrolling follows every reference, so only a charge that a block's
    # budget can pay is unrolled, as under consensus.
    if got['unrolling_charge'] <= MAX_BLOCK_BUDGET:
        unrolled = unroll(program)
        got['unrolled_sha256'] = sha256(unrolled).hex()
        if len(unrolled) <= 10000:
            got['unrolled'] = unrolled
    exp = {k: v.get(k) for k in got}
    if exp.get('unrolled') is not None:
        exp['unrolled'] = parse_script(exp['unrolled'])
    return got, exp, []


GROUPS = {'primitives': check_primitive, 'scripts': check_script,
          'transactions': check_transaction, 'signing': check_signing,
          'decoding': check_decoding, 'unrolling': check_unrolling}


def describe(d):
    """A short rendering of a result dict for mismatch reports."""
    def short(x):
        if isinstance(x, (bytes, bytearray)):
            return x.hex()[:24] + ('..' if len(x) > 12 else '')
        if isinstance(x, list):
            return '[' + ', '.join(short(i) for i in x[:4]) + (', ...' if len(x) > 4 else '') + ']'
        return str(x)
    return ', '.join('%s=%s' % (k, short(d[k])) for k in d)


def check_file(path):
    """Returns (checked, failed, unsupported) for one vector file."""
    data = json.loads(path.read_text())
    checked = failed = unsupported = 0
    for group, check in GROUPS.items():
        for category in data.get(group, []):
            for v in category['vectors']:
                label = '%s / %s / %s' % (path.name, category['category'], v['comment'])
                try:
                    got, exp, notes = check(v)
                except Unsupported as u:
                    unsupported += 1
                    print('  UNSUPPORTED %s: %s' % (label, u))
                    continue
                # Which failure a script reports is not consensus.
                same = (set(got) == set(exp) and all(
                    got[k] == exp[k] for k in exp if k != 'error'))
                if notes:
                    unsupported += 1
                    print('  UNSUPPORTED %s: %s; the rest %s' % (
                        label, '; '.join(notes), 'agrees' if same else 'DISAGREES'))
                else:
                    checked += 1
                if not same:
                    failed += 1
                    print('  MISMATCH %s:\n    expected %s\n    got      %s' % (
                        label, describe(exp), describe(got)))
    return checked, failed, unsupported


def main(argv):
    here = Path(__file__).resolve().parent
    allow_unsupported = '--allow-unsupported' in argv
    names = [a for a in argv if a != '--allow-unsupported'] or VECTOR_FILES
    totals = [0, 0, 0]
    for name in names:
        counts = check_file(here / name)
        print('%s: checked %d, failed %d, unsupported %d' % ((name,) + counts))
        totals = [a + b for a, b in zip(totals, counts)]
    print('checked %d vectors, %d failed; %d unsupported' % tuple(totals))
    return 1 if totals[1] or (totals[2] and not allow_unsupported) else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
