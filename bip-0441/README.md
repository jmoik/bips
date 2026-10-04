# Test vectors for the Tapleaf 0xC2 BIPs

One file per BIP, plus one with the Extended Primitives examples. Its
`active` list names the BIPs its results depend on: a vector whose result
depends on another BIP is in that BIP's file. Every file passes with all five
BIPs enabled.

| File | BIP | `active` | Groups |
|---|---|---|---|
| `varops.json` | 440 Varops Budget | 440, 441 | primitives, scripts, transactions |
| `tapleaf_0xc2.json` | 441 Script Restoration | 440, 441 | scripts, transactions, signing |
| `op_tx.json` | OP_TX | 440, 441, op_tx | scripts |
| `extended_primitives.json` | Extended Primitives | 440, 441, extended_primitives | scripts |
| `reusable_macros.json` | Reusable Macros | 440, 441, op_tx, reusable_macros | decoding, unrolling, scripts |
| `extended_primitives_examples.json` | Extended Primitives, Examples | 440, 441, op_tx, extended_primitives | scripts |

`varops.json` covers costs systematically: every cost primitive, and every
opcode of BIPs 440 and 441 across operand sizes. The other files still give
the cost of each successful script.

## Format

A file is a JSON object with `bip`, `active`, and one or more groups. A group
is a list of categories, each `{"category": name, "vectors": [...]}`. A vector
has a `comment`, its inputs and its results. A result field that does not
apply is absent.

| Value | Encoding |
|---|---|
| Byte string | Hex. `XX{n}` stands for n bytes XX: `00{520}` is 520 zero bytes. |
| Stack | List of byte strings, bottom to top. `{"element": hex, "count": n}` stands for n copies. |
| Script | List of tokens: opcode names (`OP_0`, `OP_16`, `OP_ADD`) and raw bytes (`"0x4c02abcd"`). Pushes are raw bytes, including their opcode and length. `OP_LSHIFT` and `OP_RSHIFT` are BIP 441's OP_UPSHIFT and OP_DOWNSHIFT. |
| Transaction, output | Hex of the serialization, with witnesses. |
| Error | Name of the failure, as Bitcoin Core's `ScriptError` without `SCRIPT_ERR_` (`VAROP_COUNT`, `TAPSCRIPT_MINIMALIF`). |

Which of two failures a script reports is not consensus, so an
implementation only has to agree that a failing vector fails. The error
names help find the cause.

## Groups

| Group | Inputs | Results |
|---|---|---|
| `primitives` | `primitive`; its arguments `n` and `m`, or `k` | `varops` |
| `scripts` | `stack`, `script`; optional `budget`, `context`, `final` | `final_stack` and `varops`, or `error` |
| `transactions` | `tx`, `spent_outputs` (one per input) | `budget`; `varops` or `error` |
| `signing` | `internal_key`, `leaves`, `spend_leaf`, `context`, `hash_type`; optional `codesep_pos` | `script_pubkey`, `leaf_hash`, `control_block`, `sighash` |
| `decoding` | `script` | `result`; `declarations` if well-formed |
| `unrolling` | `script` (well-formed) | `declarations`, `unrolled_length`, `substituted_instructions`, `references_visited`, `unrolling_charge`; if a block's budget (40,000,000,000) can pay it, `unrolled_sha256` and, up to 10,000 bytes, `unrolled` |

**scripts.** The script runs as the Tapleaf 0xC2 script of a script-path
spend, from the initial `stack`, under consensus rules only.

| Field | Meaning |
|---|---|
| `budget` | Varops available to the script. Without it, 2<sup>64</sup> − 1. |
| `context` | The spend: `tx`, `spent_outputs`, `input_index`, and optionally `annex` (with its 0x50 prefix) and `control_block` (default: 0xC2 and 32 zero bytes). The leaf hash is that of the script with leaf version 0xC2. Without `context` there is no transaction, and no signature can verify. |
| `final` | With `true`, the final result rule of BIP 441 applies after execution, as for a witness; no `final_stack` is given. |
| `final_stack` | The stack when the script ends, before the final result rule. |
| `varops` | Total varops charged. |

**transactions.** Every input is verified, all against the one
transaction-wide budget of BIP 440. `budget` is that budget less one
SIGCHECK per funding script-path input for its commitment check, and 0
without a Tapleaf 0xC2 input, since nothing then reads it. `varops` is the
total the scripts charged, and `error` the failure of the first failing input.

**signing.** `leaves` are `{"depth", "version", "script"}` of a Taproot
output with internal key `internal_key`. The spend uses leaf `spend_leaf` in
`context`; `codesep_pos` defaults to 0xFFFFFFFF. `sighash` is the signature
message hash for `hash_type`.

**decoding.** `result` is `well-formed`, `success` (an OP_SUCCESSx came
first), or `failure`, which includes exceeding the unrolled size limit.

## Using the vectors

Run every file with all five BIPs enabled. Rerun each `scripts` vector with
a nonzero `varops` at a `budget` of `varops` − 1: it must fail, so `varops`
is exact.

Bitcoin Core's `tapleaf_0xc2_vector_tests` runs the five BIP files, copied
unchanged into `src/test/data`.

The expected results were computed by the Bitcoin Core prototype implementing
all five BIPs. `evaluator.py`, written from the BIP texts alone, checks every
vector in all six files, including the reruns at `varops` − 1:

```sh
python3 -B bip-0441/evaluator.py
```

It runs legacy and witness version 0 scripts only if they consist of pushes,
as those in the vectors do, and reports other such scripts as unsupported.
An unsupported vector fails the run unless `--allow-unsupported` is given.

## License

The files in this directory are licensed under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
