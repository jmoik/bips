#!/usr/bin/env python3
"""Independent reference for the Tapleaf 0xc2 reusable macros draft.

Implements static decoding of a committed script, unrolling with its totals
and size limit, and a small evaluator for an opcode subset, and checks them
against bip-0441/reusable_macros.json. The unrolling charge of a script with declarations is

    BASE * (substituted instructions + references visited) + WRITE(unrolled length)

and zero for a script without declarations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1 = 0x51
OP_16 = 0x60
OP_NOP = 0x61
OP_IF = 0x63
OP_NOTIF = 0x64
OP_VERIF = 0x65
OP_VERNOTIF = 0x66
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_DUP = 0x76
OP_CODESEPARATOR = 0xAB
OP_MACRO = 0xD0
OP_CALLMACRO = 0xD1
OP_TX = 0xBF

MAX_UNROLLED_SIZE = 4_000_000

# BIP 441 stack limits, for the initial stack and after every opcode.
MAX_STACK_ITEMS = 32_768
MAX_TOTAL_STACK_SIZE = 8_000_000
MAX_ELEMENT_SIZE = 4_000_000

# Totals saturate here, as the draft allows: a capped total already exceeds
# the unrolled size limit or any budget.
MAX_TOTAL = 2**64 - 1

# BIP 440, Derivation of Costs: the varops budget of a whole block.
MAX_BLOCK_BUDGET = 10_000 * 4_000_000

# BIP 440 charges: BASE, and WRITE(n) = WRITE_FIXED + WRITE_PER_BYTE * wordspan(n),
# where wordspan(n) rounds n up to a multiple of 8 bytes.
BASE = 300
WRITE_FIXED = 800
WRITE_PER_BYTE = 7

# OP_SUCCESSx in Tapleaf 0xc2: BIP 441's set, minus opcodes assigned by this
# draft and its companion drafts (OP_TX, OP_TWEAKADD, OP_CHECKSIGFROMSTACK,
# OP_BYTEREV). The vectors only rely on 0x50 and 0xf0.
ASSIGNED = {OP_MACRO, OP_CALLMACRO, OP_TX, 0xBE, 0xCC, 0xCF}
OP_SUCCESS = (
    {0x4F, 0x50, 0x62, 0x89, 0x8A, 0x8F, 0x90}
    | {op for op in range(187, 255) if op not in ASSIGNED}
)

WELL_FORMED = "well-formed"
SUCCESS = "success"
FAILURE = "failure"

# Unrolled scripts longer than this are given by hash only in the vectors.
MAX_VECTOR_HEX_BYTES = 10_000


class Unsupported(Exception):
    """An executed opcode outside the evaluator's subset."""


class VectorError(ValueError):
    pass


def read_compact_size(script: bytes, pos: int, end: int) -> tuple[int, int] | None:
    """Read a canonical CompactSize wholly within [pos, end)."""
    if pos >= end:
        return None
    prefix = script[pos]
    pos += 1
    if prefix < 253:
        return prefix, pos
    width = {253: 2, 254: 4, 255: 8}[prefix]
    if end - pos < width:
        return None
    value = int.from_bytes(script[pos:pos + width], "little")
    minimum = {253: 253, 254: 0x10000, 255: 0x100000000}[prefix]
    if value < minimum:
        return None
    return value, pos + width


@dataclass
class Instruction:
    opcode: int
    begin: int
    end: int
    data: bytes = b""
    index: int | None = None  # OP_CALLMACRO target


def read_instruction(script: bytes, pos: int, end: int) -> Instruction | None:
    """Read one instruction wholly within [pos, end); None if it does not fit."""
    begin = pos
    opcode = script[pos]
    pos += 1
    if opcode <= OP_PUSHDATA4:
        if opcode < OP_PUSHDATA1:
            size = opcode
        else:
            width = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[opcode]
            if end - pos < width:
                return None
            size = int.from_bytes(script[pos:pos + width], "little")
            pos += width
        if end - pos < size:
            return None
        return Instruction(opcode, begin, pos + size, script[pos:pos + size])
    if opcode == OP_CALLMACRO:
        read = read_compact_size(script, pos, end)
        if read is None:
            return None
        index, pos = read
        return Instruction(opcode, begin, pos, index=index)
    return Instruction(opcode, begin, pos)


@dataclass
class Totals:
    length: int = 0
    instructions: int = 0
    references: int = 0
    substituted: int = 0  # instructions contributed by references


@dataclass
class Decoded:
    result: str
    bodies: list[tuple[int, int]] = field(default_factory=list)
    body_totals: list[Totals] = field(default_factory=list)
    main: tuple[int, int] = (0, 0)
    main_totals: Totals = field(default_factory=Totals)


def decode_sequence(script: bytes, begin: int, end: int, limit: int,
                    body_totals: list[Totals]) -> str | Totals:
    """Decode one body or the main script. Returns SUCCESS/FAILURE, or its totals if well-formed."""
    totals = Totals()
    pos = begin
    while pos < end:
        ins = read_instruction(script, pos, end)
        if ins is None:
            return FAILURE
        if ins.opcode in OP_SUCCESS:
            return SUCCESS
        if ins.opcode == OP_MACRO:
            return FAILURE
        if ins.opcode == OP_CALLMACRO:
            if ins.index >= limit:
                return FAILURE
            target = body_totals[ins.index]
            totals.length = min(MAX_TOTAL, totals.length + target.length)
            totals.instructions = min(MAX_TOTAL, totals.instructions + target.instructions)
            totals.references = min(MAX_TOTAL, totals.references + 1 + target.references)
            totals.substituted = min(MAX_TOTAL, totals.substituted + target.instructions)
        else:
            totals.length = min(MAX_TOTAL, totals.length + ins.end - ins.begin)
            totals.instructions = min(MAX_TOTAL, totals.instructions + 1)
        pos = ins.end
    return totals


def decode(script: bytes) -> Decoded:
    """Static decoding: one pass in serialized order, first result decides."""
    decoded = Decoded(WELL_FORMED)
    pos, end = 0, len(script)
    while pos < end and script[pos] == OP_MACRO:
        read = read_compact_size(script, pos + 1, end)
        if read is None or read[0] > end - read[1]:
            return Decoded(FAILURE)
        length, body_begin = read
        body_end = body_begin + length
        outcome = decode_sequence(script, body_begin, body_end, len(decoded.bodies), decoded.body_totals)
        if isinstance(outcome, str):
            return Decoded(outcome)
        decoded.bodies.append((body_begin, body_end))
        decoded.body_totals.append(outcome)
        pos = body_end
    outcome = decode_sequence(script, pos, end, len(decoded.bodies), decoded.body_totals)
    if isinstance(outcome, str):
        return Decoded(outcome)
    decoded.main = (pos, end)
    decoded.main_totals = outcome
    return decoded


def instructions(script: bytes, begin: int, end: int) -> list[Instruction]:
    out = []
    pos = begin
    while pos < end:
        ins = read_instruction(script, pos, end)
        assert ins is not None
        out.append(ins)
        pos = ins.end
    return out


def unroll(script: bytes, decoded: Decoded) -> bytes | None:
    """The unrolled script, or None if it exceeds the size limit."""
    assert decoded.result == WELL_FORMED
    if decoded.main_totals.length > MAX_UNROLLED_SIZE:
        return None
    # One pass that follows each reference into its body. References go only to
    # earlier declarations, so the frame stack is at most one deeper than their number.
    out, frames = bytearray(), [list(decoded.main)]
    while frames:
        frame = frames[-1]
        if frame[0] == frame[1]:
            frames.pop()
            continue
        ins = read_instruction(script, frame[0], frame[1])
        frame[0] = ins.end
        if ins.opcode == OP_CALLMACRO:
            frames.append(list(decoded.bodies[ins.index]))
        else:
            out += script[ins.begin:ins.end]
    unrolled = bytes(out)
    assert len(unrolled) == decoded.main_totals.length
    return unrolled


def small_int(opcode: int) -> bytes:
    return bytes([opcode - OP_1 + 1])


def evaluate(script: bytes, initial_stack: list[bytes]) -> dict[str, Any]:
    """Execute a plain script (no declarations or references) over the evaluator's subset."""
    stack = list(initial_stack)
    total_size = sum(len(item) for item in stack)
    conditions: list[bool] = []
    false_count = 0  # False entries of conditions
    codeseparator = None

    def fail(reason: str) -> dict[str, Any]:
        return {"ok": False, "error": reason}

    for position, ins in enumerate(instructions(script, 0, len(script))):
        op = ins.opcode
        assert op not in (OP_MACRO, OP_CALLMACRO)
        executing = false_count == 0
        if not executing and not OP_IF <= op <= OP_ENDIF:
            continue
        if op in (OP_VERIF, OP_VERNOTIF):
            return fail("bad-opcode")
        if op in (OP_IF, OP_NOTIF):
            value = False
            if executing:
                if not stack:
                    return fail("invalid-stack-operation")
                top = stack.pop()
                total_size -= len(top)
                if len(top) > 1 or (len(top) == 1 and top[0] != 1):
                    return fail("minimalif")
                value = bool(top) != (op == OP_NOTIF)
            conditions.append(value)
            false_count += not value
        elif op == OP_ELSE:
            if not conditions:
                return fail("unbalanced-conditional")
            false_count += 1 if conditions[-1] else -1
            conditions[-1] = not conditions[-1]
        elif op == OP_ENDIF:
            if not conditions:
                return fail("unbalanced-conditional")
            false_count -= not conditions.pop()
        elif op <= OP_PUSHDATA4:
            stack.append(ins.data)
            total_size += len(ins.data)
        elif OP_1 <= op <= OP_16:
            stack.append(small_int(op))
            total_size += 1
        elif op == OP_NOP:
            pass
        elif op == OP_DUP:
            if not stack:
                return fail("invalid-stack-operation")
            stack.append(stack[-1])
            total_size += len(stack[-1])
        elif op == OP_DROP:
            if not stack:
                return fail("invalid-stack-operation")
            total_size -= len(stack.pop())
        elif op == OP_CODESEPARATOR:
            codeseparator = position
        else:
            raise Unsupported(f"opcode 0x{op:02x}")
        # BIP 441 stack limits apply after every opcode. The subset has no
        # altstack, and no element can grow past the element size limit.
        if len(stack) > MAX_STACK_ITEMS:
            return fail("stack-size")
        if total_size > MAX_TOTAL_STACK_SIZE:
            return fail("total-stack-size")

    if conditions:
        return fail("unbalanced-conditional")
    return {
        "ok": True,
        "final_stack": [item.hex() for item in stack],
        "codeseparator_position": codeseparator,
    }


def unrolling_charge(declarations: int, totals: Totals) -> int:
    if declarations == 0:
        return 0
    return (BASE * (totals.substituted + totals.references) + WRITE_FIXED
            + WRITE_PER_BYTE * ((totals.length + 7) // 8 * 8))


# ---------------------------------------------------------------------------
# The vectors of bip-0441/reusable_macros.json; see bip-0441/README.md.
# Scripts are lists of opcode names and raw bytes. Execution is checked by
# final stack or error only, for scripts within the evaluator's subset; the
# complete charges are left to a complete evaluator.

NAMES = {
    "OP_0": OP_0, "OP_PUSHDATA1": OP_PUSHDATA1, "OP_PUSHDATA2": OP_PUSHDATA2, "OP_PUSHDATA4": OP_PUSHDATA4,
    "OP_RESERVED": 0x50, "OP_NOP": OP_NOP, "OP_IF": OP_IF, "OP_NOTIF": OP_NOTIF, "OP_VERIF": OP_VERIF,
    "OP_VERNOTIF": OP_VERNOTIF, "OP_ELSE": OP_ELSE, "OP_ENDIF": OP_ENDIF, "OP_DROP": OP_DROP, "OP_DUP": OP_DUP,
    "OP_EQUAL": 0x87, "OP_ADD": 0x93, "OP_CODESEPARATOR": OP_CODESEPARATOR, "OP_CHECKSIG": 0xAC, "OP_TX": OP_TX,
    "OP_MACRO": OP_MACRO, "OP_CALLMACRO": OP_CALLMACRO,
    **{f"OP_{n}": OP_1 + n - 1 for n in range(1, 17)},
}

ERROR_NAMES = {
    "bad-opcode": "BAD_OPCODE",
    "invalid-stack-operation": "INVALID_STACK_OPERATION",
    "minimalif": "TAPSCRIPT_MINIMALIF",
    "stack-size": "STACK_SIZE",
    "total-stack-size": "TOTAL_STACK_SIZE",
    "unbalanced-conditional": "UNBALANCED_CONDITIONAL",
}


def initial_stack_error(stack: list[bytes]) -> str | None:
    """BIP 441's initial stack checks, in its order."""
    if len(stack) > MAX_STACK_ITEMS:
        return "STACK_SIZE"
    if sum(len(item) for item in stack) > MAX_TOTAL_STACK_SIZE:
        return "TOTAL_STACK_SIZE"
    if any(len(item) > MAX_ELEMENT_SIZE for item in stack):
        return "STACK_ELEMENT_SIZE"
    return None


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


def parse_script(tokens: list[str]) -> bytes:
    script = bytearray()
    for token in tokens:
        if token.startswith("0x"):
            script += parse_hex_runs(token)
        elif token in NAMES:
            script.append(NAMES[token])
        else:
            raise Unsupported(token)
    return bytes(script)


def parse_stack(values: list[Any]) -> list[bytes]:
    stack: list[bytes] = []
    for value in values:
        if isinstance(value, dict):
            stack += [parse_hex_runs(value["element"])] * value["count"]
        else:
            stack.append(parse_hex_runs(value))
    return stack


def decoding_result(vector: dict[str, Any]) -> dict[str, Any]:
    decoded = decode(parse_script(vector["script"]))
    result: dict[str, Any] = {"result": decoded.result}
    if decoded.result == WELL_FORMED:
        result["declarations"] = len(decoded.bodies)
    return result


def unrolling_result(vector: dict[str, Any]) -> dict[str, Any]:
    script = parse_script(vector["script"])
    decoded = decode(script)
    if decoded.result != WELL_FORMED:
        raise VectorError("unrolling needs a well-formed script")
    totals = decoded.main_totals
    result: dict[str, Any] = {
        "declarations": len(decoded.bodies),
        "unrolled_length": totals.length,
        "substituted_instructions": totals.substituted,
        "references_visited": totals.references,
    }
    result["within_limit"] = totals.length <= MAX_UNROLLED_SIZE
    if result["within_limit"]:
        result["unrolling_charge"] = unrolling_charge(len(decoded.bodies), totals)
    # Unrolling follows every reference, so only a charge that a block's
    # budget can pay is unrolled, as under consensus.
    if result["within_limit"] and result["unrolling_charge"] <= MAX_BLOCK_BUDGET:
        unrolled = unroll(script, decoded)
        assert unrolled is not None
        result["unrolled_sha256"] = hashlib.sha256(unrolled).hexdigest()
        if len(unrolled) <= MAX_VECTOR_HEX_BYTES:
            result["unrolled"] = unrolled
    return result


def script_result(vector: dict[str, Any]) -> dict[str, Any]:
    if "context" in vector or vector.get("final"):
        raise Unsupported("needs a transaction or the final result rule")
    script = parse_script(vector["script"])
    stack = parse_stack(vector.get("stack", []))
    decoded = decode(script)
    if decoded.result == FAILURE:
        return {"error": "BAD_OPCODE"}
    if decoded.result == SUCCESS:
        return {"final_stack": stack}
    # The draft's order of checks: initial stack checks, size limit, unrolling
    # charge from the totals, and only then construction.
    if (error := initial_stack_error(stack)) is not None:
        return {"error": error}
    if decoded.main_totals.length > MAX_UNROLLED_SIZE:
        return {"error": "SCRIPT_SIZE"}
    charge = unrolling_charge(len(decoded.bodies), decoded.main_totals)
    if charge > vector.get("budget", 2**64 - 1):
        return {"error": "VAROP_COUNT"}
    if "budget" in vector:
        raise Unsupported("needs the complete charges")
    unrolled = unroll(script, decoded)
    assert unrolled is not None
    result = evaluate(unrolled, stack)
    if not result["ok"]:
        return {"error": ERROR_NAMES[result["error"]]}
    return {"final_stack": [bytes.fromhex(item) for item in result["final_stack"]]}


def check_vectors(path: Path) -> int:
    document = json.loads(path.read_text())
    checks = {"decoding": decoding_result, "unrolling": unrolling_result, "scripts": script_result}
    checked = unsupported = failures = 0
    for group, compute in checks.items():
        for category in document.get(group, []):
            for vector in category["vectors"]:
                try:
                    actual = compute(vector)
                except Unsupported:
                    unsupported += 1
                    continue
                expected = {key: vector[key] for key in actual if key in vector}
                if group == "scripts":
                    expected = {key: vector[key] for key in ("final_stack", "error") if key in vector}
                    if "final_stack" in expected:
                        expected["final_stack"] = parse_stack(expected["final_stack"])
                if "unrolled" in expected:
                    expected["unrolled"] = parse_script(expected["unrolled"])
                checked += 1
                if actual != expected or not all(key in actual for key in expected):
                    failures += 1
                    print(f"{group} / {vector['comment']}: observed {str(actual)[:200]}")
    print(f"checked {checked} vectors, {failures} failed; {unsupported} need a complete evaluator")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "vectors",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "bip-0441" / "reusable_macros.json",
    )
    args = parser.parse_args()
    return check_vectors(args.vectors)


if __name__ == "__main__":
    sys.exit(main())
