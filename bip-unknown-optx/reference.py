#!/usr/bin/env python3
"""Independent OP_TX selector and encoding reference, checked against bip-0441/op_tx.json."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


MAX_ELEMENT_SIZE = 4_000_000
MAX_STACK_BYTES = 8_000_000
MAX_STACK_ITEMS = 32_768
# BIP440 BASE, READ and WRITE, plus this BIP's OP_TX_SELECT.
BASE_COST = 300
SELECT_FIXED_COST = 1_550
SELECTED_ITEM_COST = 620
COLLATE = 0x01
TX_VERSION = 0x02
TX_LOCKTIME = 0x04
TX_WEIGHT = 0x08
INPUT_TOTAL_COUNT = 0x10
INPUT_TOTAL_AMOUNT = 0x20
OUTPUT_TOTAL_COUNT = 0x40
OUTPUT_TOTAL_AMOUNT = 0x80

CURRENT_INPUT_INDEX = 0x01
CURRENT_TAPROOT_ANNEX = 0x02
CURRENT_TAPSCRIPT = 0x04
CURRENT_TAPLEAF_HASH = 0x08
CURRENT_CONTROL_BLOCK = 0x10
CURRENT_INTERNAL_KEY = 0x20
CURRENT_TAPTREE_ROOT = 0x40
CURRENT_CODESEPARATOR_POSITION = 0x80

INPUT_PREVOUT_TXID = 0x01
INPUT_PREVOUT_INDEX = 0x02
INPUT_PREVOUT_AMOUNT = 0x04
INPUT_PREVOUT_SCRIPTPUBKEY = 0x08
INPUT_SCRIPTSIG = 0x10
INPUT_SEQUENCE = 0x20
INPUT_WITNESS_ITEM_COUNT = 0x40
INPUT_WITNESS_ITEMS = 0x80
OUTPUT_AMOUNT = 0x01
OUTPUT_SCRIPTPUBKEY = 0x02
OUTPUT_FIELDS = 0x03

SCOPE_NONE = 0x00
SCOPE_CURRENT = 0x01
SCOPE_ALL = 0x02
SCOPE_SINGLE = 0x03
SCOPE_RANGE = 0x04


class OPTXError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class VectorError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, size: int) -> bytes:
        if size < 0 or self.pos + size > len(self.data):
            raise OPTXError("truncated_data")
        result = self.data[self.pos : self.pos + size]
        self.pos += size
        return result

    def compact_size(self) -> int:
        prefix = self.read(1)[0]
        if prefix < 253:
            return prefix
        if prefix == 253:
            value = struct.unpack("<H", self.read(2))[0]
            if value < 253:
                raise OPTXError("noncanonical_compact_size")
            return value
        if prefix == 254:
            value = struct.unpack("<I", self.read(4))[0]
            if value <= 0xFFFF:
                raise OPTXError("noncanonical_compact_size")
            return value
        value = struct.unpack("<Q", self.read(8))[0]
        if value <= 0xFFFFFFFF:
            raise OPTXError("noncanonical_compact_size")
        return value

    def done(self) -> bool:
        return self.pos == len(self.data)


@dataclass
class TxIn:
    prev_hash: bytes
    prev_index: int
    script_sig: bytes
    sequence: int
    witness: list[bytes]


@dataclass
class TxOut:
    amount: int
    script_pubkey: bytes


@dataclass
class Transaction:
    version_raw: bytes
    inputs: list[TxIn]
    outputs: list[TxOut]
    locktime_raw: bytes
    stripped_size: int
    total_size: int


@dataclass
class Context:
    annex: bytes | None
    tapscript: bytes | None
    control_block: bytes | None
    codesep_pos: int | None


@dataclass
class ExecutionResult:
    outputs: list[bytes]
    varops: int
    immediate_success: bool = False


def tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative CompactSize")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", value)
    raise ValueError("CompactSize overflow")


def ser_string(value: bytes) -> bytes:
    return compact_size(len(value)) + value


def minimal_uint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative unsigned integer")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "little")


def parse_txout(raw: bytes) -> TxOut:
    reader = Reader(raw)
    amount = struct.unpack("<Q", reader.read(8))[0]
    script = reader.read(reader.compact_size())
    if not reader.done():
        raise OPTXError("trailing_txout_data")
    return TxOut(amount, script)


def parse_transaction(raw: bytes) -> Transaction:
    reader = Reader(raw)
    version_raw = reader.read(4)
    input_count = reader.compact_size()
    flags = 0
    if input_count == 0:
        flags = reader.read(1)[0]
        if flags:
            input_count = reader.compact_size()

    inputs: list[TxIn] = []
    for _ in range(input_count):
        prev_hash = reader.read(32)
        prev_index = struct.unpack("<I", reader.read(4))[0]
        script_sig = reader.read(reader.compact_size())
        sequence = struct.unpack("<I", reader.read(4))[0]
        inputs.append(TxIn(prev_hash, prev_index, script_sig, sequence, []))

    output_count = reader.compact_size() if input_count or flags else 0
    outputs: list[TxOut] = []
    for _ in range(output_count):
        amount = struct.unpack("<Q", reader.read(8))[0]
        script = reader.read(reader.compact_size())
        outputs.append(TxOut(amount, script))

    if flags & 1:
        flags ^= 1
        has_witness = False
        for txin in inputs:
            item_count = reader.compact_size()
            has_witness |= item_count != 0
            for _ in range(item_count):
                txin.witness.append(reader.read(reader.compact_size()))
        if not has_witness:
            raise OPTXError("superfluous_witness")
    if flags:
        raise OPTXError("unknown_transaction_optional_data")

    locktime_raw = reader.read(4)
    if not reader.done():
        raise OPTXError("trailing_transaction_data")
    stripped_size = (
        4 + len(compact_size(len(inputs))) + len(compact_size(len(outputs))) + 4
    )
    stripped_size += sum(
        32 + 4 + len(ser_string(txin.script_sig)) + 4 for txin in inputs
    )
    stripped_size += sum(8 + len(ser_string(txout.script_pubkey)) for txout in outputs)
    return Transaction(version_raw, inputs, outputs, locktime_raw, stripped_size, len(raw))


def parse_scope_operand(raw: bytes) -> int:
    # BIP441 arbitrary-length unsigned integer; trailing zero bytes are allowed.
    value = int.from_bytes(raw, "little")
    if value >= 1 << 32:
        raise OPTXError("invalid_scope_operand")
    return value


def parse_scope(scope: int, operands: list[bytes]) -> tuple[int, int]:
    if scope in (SCOPE_NONE, SCOPE_CURRENT, SCOPE_ALL):
        return 0, 0
    if scope == SCOPE_SINGLE:
        if not operands:
            raise OPTXError("missing_scope_operand")
        return parse_scope_operand(operands.pop()), 1
    if scope == SCOPE_RANGE:
        if not operands:
            raise OPTXError("missing_scope_operand")
        count = parse_scope_operand(operands.pop())
        if not operands:
            raise OPTXError("missing_scope_operand")
        start = parse_scope_operand(operands.pop())
        if count == 0:
            raise OPTXError("invalid_range")
        return start, count
    raise OPTXError("invalid_scope")


def resolve_scope(
    scope: int,
    start: int,
    count: int,
    total: int,
    current_index: int,
) -> list[int]:
    if scope == SCOPE_NONE:
        return []
    if scope == SCOPE_CURRENT:
        if current_index >= total:
            raise OPTXError("unavailable_record")
        return [current_index]
    if scope == SCOPE_ALL:
        return list(range(total))
    if scope == SCOPE_SINGLE:
        if start >= total:
            raise OPTXError("unavailable_record")
        return [start]
    if scope == SCOPE_RANGE:
        if start >= total or count > total - start:
            raise OPTXError("unavailable_record")
        return list(range(start, start + count))
    raise OPTXError("invalid_scope")


Value = tuple[bytes | None, bytes, bool]


class Sizes:
    """First pass over the selected values: their count, and the results'
    count, sizes and write cost."""

    def __init__(self, collate: bool):
        self.collate = collate
        self.values = self.bytes = self.largest = 0
        self.results, self.write = (1, write_cost(0)) if collate else (0, 0)

    def append(self, value: Value) -> None:
        semantic, collated, _ = value
        self.values += 1
        if self.collate:
            self.bytes += len(collated)
            self.largest, self.write = self.bytes, write_cost(self.bytes)
        elif semantic is not None:
            self.results += 1
            self.bytes += len(semantic)
            self.largest = max(self.largest, len(semantic))
            self.write += write_cost(len(semantic))


class Results:
    """Second pass over the selected values: the results, or their collation."""

    def __init__(self, collate: bool):
        self.collate = collate
        self.collated = bytearray()
        self.items: list[bytes] = []

    def append(self, value: Value) -> None:
        semantic, collated, _ = value
        if self.collate:
            self.collated += collated
        elif semantic is not None:
            self.items.append(semantic)

    def outputs(self) -> list[bytes]:
        return [bytes(self.collated)] if self.collate else self.items


def add_value(values: Sizes | Results, semantic: bytes | None, collated: bytes) -> None:
    """Record one selected byte string; a None semantic value exists only in COLLATE."""
    values.append((semantic, collated, False))


def add_number(values: Sizes | Results, number: int, collated: bytes) -> None:
    values.append((minimal_uint(number), collated, True))


def read_cost(size: int) -> int:
    # BIP440 READ(n) = 350 + 2 wordspan(n), with wordspan(n) the 8-byte word span.
    return 350 + 2 * ((size + 7) // 8 * 8)


def write_cost(size: int) -> int:
    # BIP440 WRITE(n) = 800 + 7 wordspan(n), with wordspan(n) the 8-byte word span.
    return 800 + 7 * ((size + 7) // 8 * 8)


def total_amount(outputs: list[TxOut]) -> int:
    total = 0
    for output in outputs:
        total += output.amount
        if total > 0xFFFFFFFFFFFFFFFF:
            raise OPTXError("amount_overflow")
    return total


def current_tapleaf_hash(context: Context) -> bytes:
    if context.tapscript is None:
        raise OPTXError("unavailable_context")
    return tagged_hash("TapLeaf", b"\xc2" + ser_string(context.tapscript))


def current_taptree_root(context: Context, tapleaf_hash: bytes) -> bytes:
    control = context.control_block
    if control is None or len(control) < 33 or (len(control) - 33) % 32:
        raise OPTXError("unavailable_context")
    root = tapleaf_hash
    for offset in range(33, len(control), 32):
        node = control[offset : offset + 32]
        root = tagged_hash("TapBranch", min(root, node) + max(root, node))
    return root


def general_outputs(
    selector: bytes,
    scope_operands: list[bytes],
    tx: Transaction,
    spent_outputs: list[TxOut],
    input_index: int,
    context: Context,
) -> tuple[Sizes, int, Callable[[], list[bytes]]]:
    if len(selector) < 6 or selector[0] != 0:
        raise OPTXError("invalid_selector_length")
    if len(selector) > 6:
        raise OPTXError("trailing_selector_data")
    globals_mask = selector[1]
    context_mask = selector[2]
    input_scope = selector[3] >> 4
    output_scope = selector[3] & 0x0F
    if input_scope > SCOPE_RANGE or output_scope > SCOPE_RANGE:
        raise OPTXError("invalid_scope")

    input_fields = selector[4]
    output_fields = selector[5]
    if output_fields & ~OUTPUT_FIELDS:
        raise OPTXError("undefined_selector_bits")
    if (input_scope == SCOPE_NONE) != (input_fields == 0):
        raise OPTXError("field_scope_mismatch")
    if (output_scope == SCOPE_NONE) != (output_fields == 0):
        raise OPTXError("field_scope_mismatch")

    operands = list(scope_operands)
    output_start, output_count = parse_scope(output_scope, operands)
    input_start, input_count = parse_scope(input_scope, operands)
    if operands:
        raise VectorError("scope_operands contains unused values")

    input_total_count_selected = bool(globals_mask & INPUT_TOTAL_COUNT)
    input_total_amount_selected = bool(globals_mask & INPUT_TOTAL_AMOUNT)
    output_total_count_selected = bool(globals_mask & OUTPUT_TOTAL_COUNT)
    output_total_amount_selected = bool(globals_mask & OUTPUT_TOTAL_AMOUNT)
    tx_weight_selected = bool(globals_mask & TX_WEIGHT)

    field_requested = bool(globals_mask & 0xFE or context_mask or input_fields or output_fields)
    if not field_requested:
        raise OPTXError("empty_selection")
    if (
        len(spent_outputs) != len(tx.inputs)
        or context.tapscript is None
        or context.control_block is None
        or context.codesep_pos is None
    ):
        raise OPTXError("unavailable_context")

    input_indices = resolve_scope(
        input_scope, input_start, input_count, len(tx.inputs), input_index
    )
    output_indices = resolve_scope(
        output_scope, output_start, output_count, len(tx.outputs), input_index
    )

    def visit(values: Sizes | Results) -> int:
        """Pass each selected value to values.append in output order; returns
        the records scanned for aggregate fields."""
        scanned_items = 0
        if globals_mask & TX_VERSION:
            version_value = struct.unpack("<I", tx.version_raw)[0]
            add_number(values, version_value, tx.version_raw)
        if globals_mask & TX_LOCKTIME:
            locktime = struct.unpack("<I", tx.locktime_raw)[0]
            add_number(values, locktime, tx.locktime_raw)
        if tx_weight_selected:
            weight = tx.stripped_size * 3 + tx.total_size
            add_number(values, weight, struct.pack("<I", weight))
            scanned_items += len(tx.inputs) + len(tx.outputs)
            scanned_items += sum(len(txin.witness) for txin in tx.inputs)

        if input_total_count_selected:
            count = len(tx.inputs)
            add_number(values, count, struct.pack("<I", count))
        if input_total_amount_selected:
            if len(spent_outputs) < len(tx.inputs):
                raise OPTXError("unavailable_context")
            amount = total_amount(spent_outputs[: len(tx.inputs)])
            add_number(values, amount, struct.pack("<Q", amount))

        for index in input_indices:
            txin = tx.inputs[index]
            if input_fields & INPUT_PREVOUT_TXID:
                add_value(values, txin.prev_hash, txin.prev_hash)
            if input_fields & INPUT_PREVOUT_INDEX:
                add_number(
                    values,
                    txin.prev_index,
                    struct.pack("<I", txin.prev_index),
                )
            if input_fields & (INPUT_PREVOUT_AMOUNT | INPUT_PREVOUT_SCRIPTPUBKEY):
                if index >= len(spent_outputs):
                    raise OPTXError("unavailable_context")
                spent = spent_outputs[index]
                if input_fields & INPUT_PREVOUT_AMOUNT:
                    add_number(
                        values,
                        spent.amount,
                        struct.pack("<Q", spent.amount),
                    )
                if input_fields & INPUT_PREVOUT_SCRIPTPUBKEY:
                    add_value(
                        values,
                        spent.script_pubkey,
                        ser_string(spent.script_pubkey),
                    )
            if input_fields & INPUT_SCRIPTSIG:
                add_value(values, txin.script_sig, ser_string(txin.script_sig))
            if input_fields & INPUT_SEQUENCE:
                add_number(
                    values,
                    txin.sequence,
                    struct.pack("<I", txin.sequence),
                )
            if input_fields & INPUT_WITNESS_ITEM_COUNT:
                count = len(txin.witness)
                add_number(values, count, struct.pack("<I", count))
            if input_fields & INPUT_WITNESS_ITEMS:
                add_value(values, None, compact_size(len(txin.witness)))
                for item in txin.witness:
                    add_value(values, item, ser_string(item))

        if output_total_count_selected:
            count = len(tx.outputs)
            add_number(values, count, struct.pack("<I", count))
        if output_total_amount_selected:
            amount = total_amount(tx.outputs)
            add_number(values, amount, struct.pack("<Q", amount))

        for index in output_indices:
            txout = tx.outputs[index]
            if output_fields & OUTPUT_AMOUNT:
                add_number(
                    values,
                    txout.amount,
                    struct.pack("<Q", txout.amount),
                )
            if output_fields & OUTPUT_SCRIPTPUBKEY:
                add_value(
                    values,
                    txout.script_pubkey,
                    ser_string(txout.script_pubkey),
                )

        if context_mask & CURRENT_INPUT_INDEX:
            add_number(values, input_index, struct.pack("<I", input_index))
        if context_mask & CURRENT_TAPROOT_ANNEX:
            annex = context.annex if context.annex is not None else b""
            add_value(values, annex, ser_string(annex))
        if context_mask & CURRENT_TAPSCRIPT:
            if context.tapscript is None:
                raise OPTXError("unavailable_context")
            add_value(values, context.tapscript, ser_string(context.tapscript))
        tapleaf_hash = None
        if context_mask & (CURRENT_TAPLEAF_HASH | CURRENT_TAPTREE_ROOT):
            tapleaf_hash = current_tapleaf_hash(context)
        if context_mask & CURRENT_TAPLEAF_HASH:
            assert tapleaf_hash is not None
            add_value(values, tapleaf_hash, tapleaf_hash)
        if context_mask & CURRENT_CONTROL_BLOCK:
            if context.control_block is None:
                raise OPTXError("unavailable_context")
            add_value(
                values,
                context.control_block,
                ser_string(context.control_block),
            )
        if context_mask & CURRENT_INTERNAL_KEY:
            if context.control_block is None or len(context.control_block) < 33:
                raise OPTXError("unavailable_context")
            internal_key = context.control_block[1:33]
            add_value(values, internal_key, internal_key)
        if context_mask & CURRENT_TAPTREE_ROOT:
            assert tapleaf_hash is not None
            taptree_root = current_taptree_root(context, tapleaf_hash)
            add_value(values, taptree_root, taptree_root)
        if context_mask & CURRENT_CODESEPARATOR_POSITION:
            if context.codesep_pos is None:
                raise OPTXError("unavailable_context")
            add_number(
                values,
                context.codesep_pos,
                struct.pack("<I", context.codesep_pos),
            )

        scanned_items += (
            len(tx.inputs) * input_total_amount_selected
            + len(tx.outputs) * output_total_amount_selected
        )
        return scanned_items

    # Size the results in a first pass, and produce them in a second once they
    # are paid for, so that nothing is held per selected value.
    sizes = Sizes(bool(globals_mask & COLLATE))
    scanned_items = visit(sizes)
    # BASE + READ per scope operand + OP_TX_SELECT(k) + result production.
    cost = BASE_COST + sum(read_cost(len(operand)) for operand in scope_operands) + SELECT_FIXED_COST
    cost += SELECTED_ITEM_COST * (sizes.values + scanned_items) + sizes.write

    def produce() -> list[bytes]:
        results = Results(sizes.collate)
        visit(results)
        return results.outputs()

    return sizes, cost, produce


def op_tx(
    stack: list[bytes],
    altstack: list[bytes],
    tx: Transaction,
    spent_outputs: list[TxOut],
    input_index: int,
    context: Context,
    available_varops: int,
) -> ExecutionResult:
    """Run OP_TX on a stack: pop the selector and scope operands, then push the results."""
    if not stack:
        raise OPTXError("missing_selector")
    selector = stack.pop()
    if not selector:
        raise OPTXError("invalid_selector_length")
    if selector[0] != 0:
        if BASE_COST > available_varops:
            raise OPTXError("varops_exhausted")
        return ExecutionResult([], BASE_COST, immediate_success=True)
    # Scope operands: one for SINGLE and two for RANGE, output scope on top.
    needed = 0
    if len(selector) >= 4:
        for scope in (selector[3] >> 4, selector[3] & 0x0F):
            needed += {SCOPE_SINGLE: 1, SCOPE_RANGE: 2}.get(scope, 0)
    scope_operands = stack[len(stack) - min(needed, len(stack)):]
    del stack[len(stack) - len(scope_operands):]
    if not 0 <= input_index < len(tx.inputs):
        raise OPTXError("invalid_current_input")
    sizes, varops, produce = general_outputs(
        selector, scope_operands, tx, spent_outputs, input_index, context
    )
    if sizes.largest > MAX_ELEMENT_SIZE:
        raise OPTXError("element_size_limit")
    if len(stack) + len(altstack) + sizes.results > MAX_STACK_ITEMS:
        raise OPTXError("stack_item_limit")
    if sum(len(value) for value in stack + altstack) + sizes.bytes > MAX_STACK_BYTES:
        raise OPTXError("stack_byte_limit")
    if varops > available_varops:
        raise OPTXError("varops_exhausted")
    return ExecutionResult(produce(), varops)


# ---------------------------------------------------------------------------
# The OP_TX vectors of bip-0441/op_tx.json. Each gives a stack and a script
# (opcode names and raw bytes), run as a Tapleaf 0xC2 script in a transaction
# context; see bip-0441/README.md. This reference runs the scripts that use
# only pushes, OP_NOP, OP_DROP, OP_TOALTSTACK, OP_CODESEPARATOR and OP_TX,
# and reports the others as needing a complete evaluator.

# Error names of the vectors: the failure classes of this reference.
ERROR_NAMES = {
    "missing_selector": "INVALID_STACK_OPERATION",
    "missing_scope_operand": "INVALID_STACK_OPERATION",
    "invalid_selector_length": "TX_SELECTOR",
    "trailing_selector_data": "TX_SELECTOR",
    "invalid_scope": "TX_SELECTOR",
    "undefined_selector_bits": "TX_SELECTOR",
    "field_scope_mismatch": "TX_SELECTOR",
    "empty_selection": "TX_SELECTOR",
    "invalid_scope_operand": "TX_SELECTOR",
    "invalid_range": "TX_SELECTOR",
    "unavailable_record": "TX_CONTEXT",
    "amount_overflow": "TX_CONTEXT",
    "element_size_limit": "STACK_ELEMENT_SIZE",
    "stack_item_limit": "STACK_SIZE",
    "stack_byte_limit": "TOTAL_STACK_SIZE",
    "varops_exhausted": "VAROP_COUNT",
    "truncated_push": "BAD_OPCODE",
}

OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x4C, 0x4D, 0x4E
OP_1, OP_16 = 0x51, 0x60
OP_NOP, OP_TOALTSTACK, OP_DROP, OP_CODESEPARATOR, OP_TX = 0x61, 0x6B, 0x75, 0xAB, 0xBF
OPCODES = {
    "OP_0": 0x00, "OP_NOP": OP_NOP, "OP_TOALTSTACK": OP_TOALTSTACK, "OP_DROP": OP_DROP,
    "OP_CODESEPARATOR": OP_CODESEPARATOR, "OP_TX": OP_TX,
    **{f"OP_{n}": OP_1 + n - 1 for n in range(1, 17)},
}
# BIP440 MOVE(k) = 200 + 23 k.
TOALTSTACK_COST = BASE_COST + 200 + 23


class Unsupported(Exception):
    pass


def parse_hex_runs(text: str) -> bytes:
    """Hex in which "XX{n}" stands for n bytes XX."""
    if text.startswith("0x"):
        text = text[2:]
    result = bytearray()
    for literal, count in re.findall(r"([0-9a-fA-F]*)(?:\{(\d+)\})?", text):
        result += bytes.fromhex(literal)
        if count:
            result += result[-1:] * (int(count) - 1)
    return bytes(result)


def parse_vector_stack(values: list[Any]) -> list[bytes]:
    result: list[bytes] = []
    for value in values:
        if isinstance(value, dict):
            result += [parse_hex_runs(value["element"])] * value["count"]
        else:
            result.append(parse_hex_runs(value))
    return result


def parse_script(tokens: list[str]) -> bytes:
    script = bytearray()
    for token in tokens:
        if token.startswith("0x"):
            script += parse_hex_runs(token)
        elif token in OPCODES:
            script.append(OPCODES[token])
        else:
            raise Unsupported(token)
    return bytes(script)


def instructions(script: bytes):
    """(opcode, pushed data or None) for each instruction. Decoding stops at
    the first opcode this reference does not run: it may be an OP_SUCCESSx,
    which makes the script succeed, or change how later bytes decode."""
    pos = 0
    while pos < len(script):
        opcode = script[pos]
        pos += 1
        if opcode <= OP_PUSHDATA4:
            if opcode < OP_PUSHDATA1:
                size = opcode
            else:
                width = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[opcode]
                size = int.from_bytes(script[pos : pos + width], "little")
                pos += width
            if pos + size > len(script):
                raise OPTXError("truncated_push")
            yield opcode, script[pos : pos + size]
            pos += size
        elif OP_1 <= opcode <= OP_16:
            yield opcode, bytes([opcode - OP_1 + 1])
        elif opcode in (OP_NOP, OP_TOALTSTACK, OP_DROP, OP_CODESEPARATOR, OP_TX):
            yield opcode, None
        else:
            raise Unsupported(f"opcode {opcode:#04x}")


def run_vector(vector: dict[str, Any]) -> dict[str, Any]:
    """The result fields of a scripts vector: final_stack and varops, or error."""
    script = parse_script(vector["script"])
    if "context" not in vector or vector.get("final"):
        raise Unsupported("no transaction context")
    raw = vector["context"]
    tx = parse_transaction(parse_hex_runs(raw["tx"]))
    spent_outputs = [parse_txout(parse_hex_runs(value)) for value in raw["spent_outputs"]]
    annex = parse_hex_runs(raw["annex"]) if "annex" in raw else None
    control_block = parse_hex_runs(raw.get("control_block", "c2" + "00" * 32))
    budget = vector.get("budget", 2**64 - 1)

    stack = parse_vector_stack(vector.get("stack", []))
    altstack: list[bytes] = []
    try:
        # The whole script is decoded before it runs.
        program = list(instructions(script))
        if len(stack) > MAX_STACK_ITEMS:
            raise OPTXError("stack_item_limit")
        if any(len(value) > MAX_ELEMENT_SIZE for value in stack):
            raise OPTXError("element_size_limit")
        if sum(len(value) for value in stack) > MAX_STACK_BYTES:
            raise OPTXError("stack_byte_limit")
        cost = 0
        codesep_pos = 0xFFFFFFFF
        for position, (opcode, data) in enumerate(program):
            if cost > budget:
                raise OPTXError("varops_exhausted")
            if data is not None:
                if len(data) > MAX_ELEMENT_SIZE:
                    raise OPTXError("element_size_limit")
                stack.append(data)
                cost += BASE_COST + write_cost(len(data))
            elif opcode in (OP_NOP, OP_CODESEPARATOR):
                cost += BASE_COST
                if opcode == OP_CODESEPARATOR:
                    codesep_pos = position
            elif opcode == OP_DROP:
                if not stack:
                    raise Unsupported("OP_DROP on an empty stack")
                stack.pop()
                cost += BASE_COST
            elif opcode == OP_TOALTSTACK:
                if not stack:
                    raise Unsupported("OP_TOALTSTACK on an empty stack")
                altstack.append(stack.pop())
                cost += TOALTSTACK_COST
            elif opcode == OP_TX:
                if cost > budget:
                    raise OPTXError("varops_exhausted")
                context = Context(annex, script, control_block, codesep_pos)
                result = op_tx(stack, altstack, tx, spent_outputs, raw["input_index"], context, budget - cost)
                if result.immediate_success:
                    return {"final_stack": stack, "varops": cost + result.varops}
                stack += result.outputs
                cost += result.varops
            if len(stack) + len(altstack) > MAX_STACK_ITEMS:
                raise OPTXError("stack_item_limit")
            if sum(map(len, stack)) + sum(map(len, altstack)) > MAX_STACK_BYTES:
                raise OPTXError("stack_byte_limit")
        if cost > budget:
            raise OPTXError("varops_exhausted")
    except OPTXError as exc:
        if exc.code not in ERROR_NAMES:
            raise VectorError(f"no error name for {exc.code}") from exc
        return {"error": ERROR_NAMES[exc.code]}
    return {"final_stack": stack, "varops": cost}


def check_vectors(path: Path) -> int:
    document = json.loads(path.read_text())
    checked = unsupported = failures = 0
    for category in document.get("scripts", []):
        for vector in category["vectors"]:
            try:
                actual = run_vector(vector)
            except Unsupported:
                unsupported += 1
                continue
            expected = {key: vector[key] for key in ("final_stack", "varops", "error") if key in vector}
            if "final_stack" in expected:
                expected["final_stack"] = parse_vector_stack(expected["final_stack"])
            checked += 1
            if actual != expected:
                failures += 1
                shown = {key: (len(value) if key == "final_stack" else value) for key, value in actual.items()}
                print(f"{vector['comment']}: observed {shown}")
    print(f"checked {checked} vectors, {failures} failed; {unsupported} need a complete evaluator")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "vectors",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "bip-0441" / "op_tx.json",
    )
    args = parser.parse_args()
    try:
        return check_vectors(args.vectors)
    except VectorError as exc:
        print(f"invalid vector file: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
