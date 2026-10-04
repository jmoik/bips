```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: Reusable Macros in Tapleaf 0xc2
  Authors: Julian Moik <julianmoik@gmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-3-Clause
  Version: 0.1.0
  Requires: 440, 441
```

## Introduction

### Abstract

This BIP defines OP_MACRO and OP_CALLMACRO for Tapleaf 0xc2.  A script declares instruction sequences once, at the start of the script, and references them wherever they are needed.  Before execution, every reference is replaced by the instructions it names.  The resulting unrolled script then executes under the ordinary Tapleaf 0xc2 rules, so a script that uses macros behaves like the same script written out inline.

### Copyright

This document is licensed under the 3-clause BSD license.

### Motivation

Repeated instructions occupy block space each time they appear in a script.  Macros let a script store a repeated instruction sequence once and reference it from many places.  This can reduce transaction weight and fees for scripts with substantial repeated logic, without adding protocol-specific consensus operations.

BIP 440 funds a transaction's varops budget from its weight, and that budget exists to limit validation time.  Many scripts are limited by their weight long before their budget: a verifier built from repeated field arithmetic, for example, written out inline, uses only a small fraction of the varops its weight funds.  Macros let such scripts spend that headroom on block space instead.  A script can be compressed until its execution, together with the unrolling charge this BIP adds, uses the whole budget its transaction's reduced weight still funds.  A script compressed further would exceed its budget and fail, so validation time stays limited as for any other script.

Macros are not runtime functions.  Functions defined and called during execution let the witness supply code, let the called function be computed, and allow recursion, so they need call frames and make a script's behavior depend on more than its committed bytes.  Macros only compress: every body and reference is fixed in the committed script, which is unrolled into an ordinary Tapscript before execution, so the interpreter itself stays unchanged.

## Specification

These opcodes apply only to Tapleaf 0xc2 as defined by [BIP 441](bip-0441.mediawiki).  The *committed script* is the Tapscript as serialized in the witness and committed to by the Tapleaf hash.

### Opcode Assignments

| Opcode | Value | Previous `0xc2` meaning | Role |
| --- | --- | --- | --- |
| OP_MACRO | `0xd0` | OP_SUCCESS208 | Starts a declaration; declarations precede the main script |
| OP_CALLMACRO | `0xd1` | OP_SUCCESS209 | References a declared body, replaced by that body during unrolling |

Neither opcode ever executes.  Both belong to the encoding of the committed script, and neither appears as an opcode in the unrolled script.

### Encoding

A committed script is laid out as follows:

```text
OP_MACRO <length> <body 0>     # declarations: zero or more
OP_MACRO <length> <body 1>
...
<main script>                  # the rest of the script
```

Each *declaration* is OP_MACRO, the length of its body as a CompactSize, and the body.  Bodies are numbered from 0 in the order they appear.  Everything after the last declaration is the *main script*; without declarations, the whole script is the main script.

A *reference*, `OP_CALLMACRO <index>` with the index as a CompactSize, names a body by its number.  References can appear in bodies and in the main script.

Lengths and indices are CompactSize integers, as in Bitcoin's transaction serialization, and must use the shortest encoding.  For example, 5 must be encoded as `05`; its longer encoding `fd 05 00` makes the scan fail.

An *instruction* is an opcode together with the bytes that belong to it: a push opcode's length bytes and payload, or OP_CALLMACRO's index, which is therefore never an opcode and never a stack value.  Every other opcode is a one-byte instruction.  Every instruction lies entirely within one body or entirely within the main script: a push payload or an OP_CALLMACRO index cannot continue past the end of a body into the bytes that follow it.

### Scan

The BIP 342 OP_SUCCESSx scan is extended to macro declarations and references: it reads the committed script once, from its first byte to its last, without following references.  The scan stops as soon as a rule below makes it succeed or fail; if it reaches the end without either, the script is *well-formed*.

1. **Declarations.**  While the next unread byte is OP_MACRO, consume it and read a CompactSize length `L`.  If the length is missing, truncated or not in its shortest encoding, or `L` exceeds the number of remaining bytes, the scan **fails**.  Otherwise, scan the next `L` bytes as the next body, then continue after it.
2. **Main script.**  Scan all remaining bytes as the main script.

A body or the main script is scanned by reading its instructions in order until it ends:

- An instruction that is cut off by the end of the body or main script being scanned causes the scan to **fail**: a push whose length bytes or payload, or an OP_CALLMACRO whose index, would need bytes beyond that end.
- An OP_SUCCESSx opcode causes the scan to **succeed**: the script is valid, as specified by [BIP 342](bip-0342.mediawiki) for OP_SUCCESSx.
- OP_MACRO causes the scan to **fail**.  Declarations exist only at the start of the script, so OP_MACRO cannot appear in a body or in the main script.
- OP_CALLMACRO reads its CompactSize index.  The index must use the shortest encoding and must name a body declared earlier in the committed script: in a body, a body declared before it; in the main script, any body.  Otherwise the scan **fails**.  In particular, a body cannot reference itself or a later body.
- Any other instruction is accepted, and the scan continues.  An opcode that fails only when executed, such as OP_RETURN, does not make the scan fail.  Nor does OP_VERIF, which fails whenever it is reached, even in an unexecuted branch.

Consequences:

- The first success or failure in serialized order decides.  An OP_SUCCESSx in any body, including a body that is never referenced, makes the script succeed if no failure precedes it.  A failure anywhere before it makes the script fail.
- The scan result depends only on the committed script; witness data cannot affect it.
- No execution-time outcome, including OP_TX's immediate success for a reserved selector version, can make a script valid if it fails the scan.

### Unrolling

The *unrolled script* is the main script with every reference replaced by the body it names, repeated until no references remain.  Because a body can reference only earlier declarations, unrolling is finite.  The unrolled script contains no declarations and no references; unreferenced bodies do not contribute to it.

Unrolling a well-formed committed script takes place after the initial stack checks, just before execution, and proceeds as follows:

1. **Totals.**  Three totals of the unrolled script are determined:
   - *unrolled length*: its size in bytes;
   - *substituted instructions*: the number of its instructions that come from bodies rather than directly from the main script;
   - *references visited*: the number of references replaced during unrolling, where a reference inside a body counts once each time that body is substituted.

   The totals are computed before the unrolled script is constructed.  For each body in declaration order, record its unrolled length, instruction count and references visited, using the recorded values of the bodies it references; then do the same for the main script, whose substituted instructions are the instruction counts of the bodies it references.  Implementations may cap each total at any value large enough that a script reaching the cap still fails the size limit or the budget.
2. **Size limit.**  If the unrolled length exceeds 4,000,000 bytes, the script **fails**.  The limit applies to every Tapleaf 0xc2 script, with or without declarations.  Every instruction is at least one byte, so the unrolled script also has at most 4,000,000 instructions.
3. **Unrolling charge.**  If the committed script has at least one declaration, it is charged `BASE * (substituted instructions + references visited) + WRITE(unrolled length)` varops, where `BASE` and `WRITE` are BIP 440's fixed per-opcode charge and write charge.  If the charge exceeds the remaining budget, the script **fails**.
4. **Construction.**  The unrolled script is constructed.

A script with declarations but no references still pays `WRITE(unrolled length)`, because its unrolled script is constructed as a copy of its main script.

### Execution

The unrolled script is executed as the Tapscript under every BIP 441 rule, as amended by other deployed Tapleaf 0xc2 proposals.  The only exception is data that identifies the script itself: the Tapleaf hash, and with it every signature message, and OP_TX's `CURRENT_TAPSCRIPT` use the committed script.  Opcode positions, used for OP_CODESEPARATOR in signature messages and by OP_TX, are positions in the unrolled script.  Conditionals may cross body boundaries, because only the unrolled script is executed.

**Equivalence.**  Executing a well-formed committed script and executing its unrolled script, written out as an inline Tapscript, give the same result, final stack and opcode positions for any initial stack and transaction context, except that:

1. anything that commits to the script bytes differs, as stated above;
2. the transaction weight differs and the committed script pays the unrolling charge, so one of the two may exhaust the varops budget where the other does not.

Benchmarks of unrolled scripts with inactive references confirm that the unrolling charge, together with the ordinary charges of executing the unrolled script, covers unrolling, per script and across the inputs of a block ([METHODOLOGY.md](https://github.com/jmoik/varopsData/blob/master/METHODOLOGY.md)).

## Rationale

**Unroll, then execute.**  Replacing references before execution keeps macros out of the interpreter entirely.  The interpreter executes one opcode at a time, as it always has, and never meets OP_MACRO or OP_CALLMACRO.  Equivalence with the inline script holds by construction rather than by careful specification of how references behave during execution.  Conditionals, OP_CODESEPARATOR positions and error behavior need no macro-specific rules.  The cost is that the unrolled script must be built in memory, which requires the size limit below.

**Static macros.**  Every executable body and every reference target is fixed by the committed script.  Witness data can supply values and influence ordinary conditional execution, but cannot supply executable code or choose a reference target.  This avoids the static-analysis problems of dynamic code evaluation, as in the OP_EVAL of [BIP 12](bip-0012.mediawiki), and of runtime-defined functions.  A reference index taken from the stack would not be known until execution, so the committed script could not be unrolled before execution.

**One scan.**  Scanning the whole committed script once, in serialized order, makes the scan result depend only on the committed script, keeps the BIP 342 OP_SUCCESSx rule in its simplest form, and takes linear time.  Counting OP_SUCCESSx in unreferenced bodies matches BIP 342, where an OP_SUCCESSx in a branch that never executes also makes the script succeed, and preserves the most room for future soft forks to redefine OP_SUCCESSx inside bodies.

**Size limit.**  Nested references can grow the unrolled script exponentially in the size of the committed script, and the unrolled script is held in memory.  The budget does not bound that memory, because it prices time: a standard-size transaction could pay to write hundreds of megabytes of unrolled script.  A separate limit is therefore needed, just as BIP 441 keeps explicit stack limits alongside the budget.  It equals the block weight limit, which also bounds every script written inline, so macros reduce a program's weight but do not let it grow past that bound.  It is also the bound on the largest stack element.

**Unrolling charge.**  Script bytes pay for work proportional to their serialized size through their weight.  An instruction substituted from a body is not paid for by weight where it runs, so the unrolling charge pays `BASE` for each substituted instruction, including instructions that execution later skips in an inactive branch.  Otherwise a single reference inside an inactive branch could make validators process up to 4,000,000 instructions per script without charge.  Instructions of the main script remain paid for by their weight.  References visited are charged separately because unrolling visits every reference, and nesting can make that number large without adding any bytes to the unrolled script: twenty levels of bodies that each reference the previous body twice, ending in an empty body, visit 2,097,151 references and unroll to zero bytes.  The charge is computed from the declarations before any memory is allocated.

**Charging the unrolled bytes.**  `BASE` per instruction does not bound the work of copying large pushes: a body holding one push of 3,997 bytes costs one instruction to substitute but copies 4,000 bytes.  Without a size term, a block full of such scripts would copy far more bytes than BIP 440 funds, even though each script stays within the size limit.  The unrolled script is a new buffer of `unrolled length` bytes, which is exactly what `WRITE` prices elsewhere in BIP 440, so the charge reuses it.  `WRITE` is charged once per script, not per reference, so its fixed part is paid once.  Scripts without declarations are not unrolled and pay nothing, so existing script shapes are unaffected.

**Lower-index references.**  Requiring every body reference to name an earlier declaration prevents direct and indirect recursion with a check during the scan.  Recursion could never be valid anyway: references are unrolled before execution, whether or not their branch would run, so a recursive body would unroll without end.  The rule also lets the scan validate each body in a single pass and lets the totals be computed in declaration order.

## Examples

### Reusing Field Arithmetic

A proof verifier repeatedly multiplies numbers modulo the same prime `p`.  Let `<multiply-mod-p body>` be the serialized instructions `OP_MUL <p> OP_MOD`, with the 32-byte modulus pushed as part of the body:

```text
OP_MACRO 23 <multiply-mod-p body>  # body 0
<a> <b> OP_CALLMACRO 00            # main script
<c> <d> OP_CALLMACRO 00
```

The 32-byte `p` makes the serialized body 35 bytes, so its CompactSize length is the single byte `23`.  The two references leave `a*b mod p` and `c*d mod p` on the stack, exactly like the inline script with the body written out twice.  Each reference takes 2 bytes instead of 35 and the declaration takes 37, so `n` references save `33n - 37` bytes: 29 here, and 3,263 for 100 references.  Unrolling substitutes 6 instructions and visits 2 references, so the unrolling charge is `(6 + 2) * BASE` plus `WRITE` of the unrolled length; the arithmetic and both pushes of `p` then pay their ordinary charges.

### Nested Bodies

Bodies can extend one another.  Writing `<ref n>` for `OP_CALLMACRO n`, a compiler might emit:

```text
body 230:  OP_PICK OP_MUL OP_ADD OP_ADD OP_ADD OP_ADD   # referenced from 10 places
body 509:  <ref 230> OP_ADD OP_10 OP_ROLL OP_10
body 510:  <ref 509> OP_ROLL
```

`<ref 510>`, OP_CALLMACRO and a 3-byte index, is 4 bytes and unrolls to:

```text
OP_PICK OP_MUL OP_ADD OP_ADD OP_ADD OP_ADD OP_ADD OP_10 OP_ROLL OP_10 OP_ROLL
```

An arity opcode such as OP_MULTI, letting OP_ADD take several operands, would shorten the run of five OP_ADDs; macros store such runs once without a new opcode.

### Scan

The scan checks every body, referenced or not, before anything runs.  This script fails, although body 0 is never referenced:

```text
OP_MACRO 01 OP_PUSHDATA1     # body 0: the push needs a length byte past the body's end
OP_1                         # main script
```

This one succeeds, because an OP_SUCCESSx counts in any body:

```text
OP_MACRO 01 OP_SUCCESS80     # body 0
OP_1                         # main script
```

The first success or failure in serialized order decides, so this one succeeds too:

```text
OP_MACRO 01 OP_SUCCESS80     # body 0: succeeds here
OP_MACRO 01 OP_PUSHDATA1     # body 1: would fail, but comes later
```

## Test Vectors and Reference Code

[`bip-0441/reusable_macros.json`](bip-0441/reusable_macros.json) contains scan vectors (the `decoding` group), unrolling vectors and execution vectors, in the format of the Tapleaf 0xC2 BIPs described in [`bip-0441/README.md`](bip-0441/README.md).  [`bip-unknown-reusable-macros/reference.py`](bip-unknown-reusable-macros/reference.py) implements the scan, unrolling with its totals, and a small evaluator for a subset of opcodes, and checks the vectors it can run.  Implementations should check that:

- scan results match;
- unrolled scripts, totals and size-limit results match;
- the committed script and its unrolled script give the same result and final stack, and their charges differ by exactly the unrolling charge.

## Security Considerations

Nested references let a small committed script describe a large unrolled script, so script weight alone no longer bounds the number of executed operations.  The size limit bounds the unrolled script's memory to 4,000,000 bytes per script.  This assumes the unrolled script is written in one pass that follows each reference into its body, in time linear in the unrolled length and references visited.  Unrolling each body separately first would hold every intermediate expansion, which neither the limit nor the charge bounds.  The unrolling charge is computed and paid before the unrolled script is constructed, so unrolling work is metered even when the unrolled script is tiny.  Execution of the unrolled script is metered by BIP 440 as for any script.

Only committed bodies can be executed, and literal references prevent witness-supplied code and computed references.  References go only to earlier declarations, so there is no recursion.  The scan is unmetered but linear in the committed script's length, which weight funds.

## Backwards Compatibility

Without this BIP, both assigned opcodes are OP_SUCCESS opcodes in Tapleaf 0xc2.  Replacing immediate success with the stricter rules above can only invalidate previously valid spends and is therefore a soft fork.  For committed scripts without OP_MACRO and OP_CALLMACRO, the scan is the BIP 342 OP_SUCCESSx scan, the unrolled script is the committed script, and the unrolling charge is zero.  The size limit also applies to such scripts, but a script longer than 4,000,000 bytes cannot fit in a block, so it restricts only scripts with references.  Other script and Tapleaf versions are unchanged.

## Reference Implementation

The Bitcoin Core Tapleaf 0xc2 prototype implements the scan, unrolling with the size limit and charge, and execution of the unrolled script: <https://github.com/jmoik/bitcoin/tree/gsr>.

## Changelog

- 0.1.0: Initial draft.

## Thanks

This BIP would not exist without the thoughtful contributions of the following (in alphabetical order):

- Robin Linus
