# Tapleaf 0xc2: An overview of the Great Script Restoration proposals

## Summary

This is a set of five proposals that together define Tapleaf 0xc2, the
second Taproot leaf version. It restores the script capabilities
disabled in Bitcoin 0.3.1, adds transaction introspection and signature
verification over script-built messages, and limits the validation cost of
each 0xc2 script with an explicit computational budget. Legacy, segwit v0 and Tapleaf 0xc0
scripts are unchanged.

Together they form the Great Script Restoration (GSR): we are safely
restoring Script to its original power and making it great to build on with
the addition of missing tooling and primitives. The name now covers all
five documents, not only the varops budget and the restored opcodes. The
2025 quartet already proposed OP_TX and a set of new opcodes; those
opcodes are now Extended Primitives, and Reusable Macros is new.

## The five documents

1. **BIP 440: Varops Budget For Script Runtime Constraint.**
   Generalizes BIP 342's sigops budget to every operation: a transaction-wide
   budget funded by weight, from which each executed opcode pays a cost
   composed from a fixed set of primitives. The calibration target is that no
   block validates slower than the slowest block possible today.

2. **BIP 441: Restoration of disabled script (Tapleaf 0xC2).**
   Defines the new leaf version and re-enables the fifteen opcodes disabled in
   0.3.1: CAT, SUBSTR, LEFT, RIGHT, INVERT, AND, OR, XOR, UPSHIFT, DOWNSHIFT
   (renamed from LSHIFT, RSHIFT), 2MUL, 2DIV, MUL, DIV and MOD. Numbers become arbitrary-length unsigned
   little-endian integers. The stack element limit is increased from 520 to
   4,000,000 bytes, with a total stack limit of 8,000,000 bytes, and the
   element count limit is also increased from 1,000 to 32,768. Every opcode is specified
   step by step, together with its varops cost.

3. **OP_TX (draft).**
   Transaction introspection: A six-byte selector chooses among 25 fields of
   the spending transaction, its spent outputs and the current Taproot
   execution context (input index, annex, tapscript, leaf hash, control
   block, internal key, tree root, code-separator position). Values are pushed
   individually so scripts can do arithmetic on them, or collated into one
   element for hashing. Collation reproduces the BIP 341 component hashes.

4. **Tapleaf 0xc2: Extended Primitives (draft).**
   With BIP 441 and OP_TX alone, script still cannot do two
   things Bitcoin's consensus rules already do: verify a signature over a
   message it builds, and construct a Taproot output. OP_CHECKSIGFROMSTACK,
   with BIP 348 semantics, verifies a signature over any message on the
   stack, enabling custom sighash modes, rebindable signatures and key
   delegation. OP_TWEAKADD, with BIP 449 semantics, applies BIP 341's key
   tweak, so a script can compute the key of the next output, as
   state-carrying covenants and leaf replacement need. OP_BYTEREV reverses
   the bytes of an element, which lets OP_LESSTHAN order hashes for Taproot
   trees and converts between the big-endian encodings of BIP 340 and
   BIP 341 and the little-endian numbers of BIP 441. No new cryptography is
   introduced.

5. **Reusable Macros in Tapleaf 0xc2 (draft).**
   To optimize block space usage, a script can declare a repeated
   instruction sequence once. Written out inline, a script that repeats the
   same arithmetic many times, a proof verifier for example, uses only a
   small fraction of the varops its weight funds; macros let it spend that
   headroom instead of wasting scarce block space. OP_MACRO declares a sequence
   and OP_CALLMACRO references it. Macros only compress scripts and do not
   change how the interpreter works: references are replaced before
   execution, so a script with macros behaves exactly like its inline
   expansion. The unrolled script is limited to 4,000,000 bytes. The unrolling
   cost is covered by the varops budget and pays for each substituted instruction
   and visited reference, and for writing the unrolled script.

## Changes since the last published versions

**BIP 440**

- **Inputs with their own signature limits no longer fund the budget.** The
  budget was the total transaction weight times 10,000. It is meant for 0xc2
  inputs and now excludes the weight of legacy, witness v0, Taproot key-path
  and Tapleaf 0xc0 inputs.
  Previously the witness of a 0xc0 input funded both its own BIP 342 sigops
  budget and the varops budget of every 0xc2 input in the same transaction.
  Inputs of versions not yet defined do fund it, so a later version can share
  the budget through a soft fork. Each funding Taproot script-path input pays
  one SIGCHECK from the budget for its BIP 341 commitment check.
- **Categories regrouped as primitives.** The six speed categories are
  regrouped as cost primitives, and prices (except the
  signature cost) are refitted from benchmarks on seven machines, x86-64 under
  Linux and Windows and Apple ARM64 under macOS. Results from more hardware
  are welcome and can potentially raise the final costs.
- **A fixed per-opcode cost.** Operations on small operands were
  undercosted, relying on the implicit assumption that the block weight limit
  caps the number of opcodes a script executes. Every executed opcode now
  pays a fixed charge in addition to its data-dependent cost, and literal
  pushes are charged. This limits the number of logical operations a budget
  can fund even when the encoded script is compressed, so Reusable Macros
  can be added safely.

## Design and scope

- **What it enables.** General covenants, including recursive ones that
  carry state from output to output, such as the State-Carrying Output
  example in Extended Primitives; custom sighash modes and rebindable
  signatures; Taproot outputs built from computed data; and verification of
  proofs and hash-based (Lamport or Winternitz) signatures in script. The
  last makes a post-quantum fallback expressible without a new opcode,
  though Taproot key-path spends would still need to be disabled.
- **Later opcodes become optimizations.** Once script can express a
  construction, a dedicated opcode for it is no longer a prerequisite, only
  an optimization, judged by the weight or budget it saves. CTV- and
  TemplateHash-style commitments, for example, can already be built with
  OP_TX.
- **Soft fork.** Leaf 0xc2 is anyone-can-spend today, so every rule here
  only restricts and the set is a soft fork.
- **Static analysis.** Control flow is limited to OP_IF, OP_NOTIF, OP_ELSE
  and OP_ENDIF, as today: there are no loops or jumps, and no stack data is
  executed as code. Macro references are fixed in the script, so the
  unrolled script, at most 4,000,000 bytes, contains every opcode that can
  run, each at most once. Repetition must be written out to a fixed count;
  a loop whose count depends on data cannot be expressed. Numbers never
  wrap: arithmetic is unsigned and fails on underflow.
- **Existing specifications.** OP_CHECKSIGFROMSTACK and OP_TWEAKADD keep the
  names, values and semantics of BIP 348 and BIP 449, so they mean the same
  in both leaf versions, and the set is compatible with CTV, CSFS or
  TEMPLATEHASH activating in Tapleaf 0xc0.
- **Scope.** These proposals enable general and useful primitives while
  preventing new worst-case validation times.

## Deployment

All five documents define the one new leaf version, and we propose
activating them together as a single soft fork, as the reference
implementation does under one deployment.

## Open questions

- **Direction and risks.** Whether this comprehensive consensus change is
  the right direction for Bitcoin, and whether the capabilities it adds
  outweigh its risks and negative consequences. MEV is often raised as
  one: if covenants enabled shared contracts whose outcome depends on
  transaction order, such as on-chain exchanges or auctions, miners might
  profit from ordering transactions, which would favor large and
  sophisticated miners.
- **Segmented evaluation.** Whether OP_SEGMENT, in which an OP_SUCCESS
  opcode affects only its own segment, is useful enough to add. It would let
  a covenant require a fixed prefix, such as a delay, ahead of script
  another party supplies in the same leaf.
- **Arity opcode.** Whether OP_MULTI, which lets the following opcode take
  a variable number of operands, is worth adding. Extended Primitives leaves
  it out because no construction needs it and Reusable Macros handle
  repeated code.
- **Amount accounting across inputs.** Whether an opcode such as
  OP_FORWARDAMOUNT should let the node check the amounts that several inputs
  claim, which script cannot express.

## Implementation and tests

A Bitcoin Core branch implements all five documents, with unit, functional
and fuzz tests. JSON test vectors in `bip-0441/` match it. An independent
evaluator, written from the BIP texts alone, reproduces every vector.

## Links

- BIP 440: https://github.com/jmoik/bips/blob/gsr-full/bip-0440.mediawiki
- BIP 441: https://github.com/jmoik/bips/blob/gsr-full/bip-0441.mediawiki
- OP_TX draft: https://github.com/jmoik/bips/blob/gsr-full/bip-unknown-optx.md
- Extended Primitives draft: https://github.com/jmoik/bips/blob/gsr-full/bip-unknown-extended-primitives.md
- Reusable Macros draft: https://github.com/jmoik/bips/blob/gsr-full/bip-unknown-reusable-macros.md
- Reference implementation: https://github.com/jmoik/bitcoin/tree/gsr
- Benchmark data and code: https://github.com/jmoik/varopsData
- Previous discussion:
  https://groups.google.com/g/bitcoindev/c/GisTcPb8Jco/m/8znWcWwKAQAJ
  https://delvingbitcoin.org/t/benchmarking-bitcoin-script-evaluation-for-the-varops-budget-great-script-restoration/2094

Rusty Russell and Julian Moik
