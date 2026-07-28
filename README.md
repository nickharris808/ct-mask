# ct-mask

**Your masked gadget is first-order secure — or here is the exact probe wire that recombines the secret. Two independent certificates, both replayable, neither a t-test.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Model](https://img.shields.io/badge/model-d%3D1%20glitch--free-orange.svg)](#the-model-read-this-first)
[![CI](https://img.shields.io/badge/CI-test%20matrix-brightgreen.svg)](.github/workflows/ci.yml)

> **▶ [Try it in your browser](https://huggingface.co/spaces/nickh007/hw-verify)** — paste Verilog, get a formal constant-time verdict with the leaking signals named. No install, nothing uploaded.


## Why this exists

Most masking verification reasons about **dependence**: a probe is secure if it touches at
most one share of each secret. That rule is sound, and it is not enough. It rejects the
gadgets that actually matter.

Take a domain-oriented masked AND. Its output share `c0` touches **both** shares of one
operand. A dependence-only analysis flags it. It is perfectly secure, because a fresh mask
refreshes the cross term — and no amount of dependence reasoning will ever see that.

ct-mask adds the missing certificate. If a probe wire *flips whenever a fresh mask bit
flips*, it is uniform over that mask and therefore independent of every secret,
**regardless of how many shares it touches**. Both certificates reduce to plain
unsatisfiability, so both are machine-checked refutations rather than statistical tests.

> **We certify gadgets a dependence-only tool reports as leaky, and we prove why.**

## The model, read this first

**Glitch-free gate-value probing, first order (`d = 1`), 2-share.** A probe observes the
stable Boolean value of one internal wire. Glitches, transitions, coupling, and physical
measurement are all outside this model. If your threat model includes them, a `SECURE`
verdict here does not cover you. This is the standard model for this class of tool, stated
plainly rather than buried.

## Install

> **Not yet on PyPI.** Install from a checkout:

```bash
git clone https://github.com/nickharris808/ct-mask.git && cd ct-mask
pip install .
```

Once published, this becomes `pip install ct-mask`.
The distribution is `ct-mask`; the import name is `ctmask`.

## 30-second quickstart

```bash
ct-mask corpus              # every bundled gadget against its expected verdict
ct-mask list                # what is in the corpus
ct-mask check dom_and       # full probe-by-probe report
```

## Worked example

```console
$ ct-mask check dom_and
dom_and
==================================================================
  model             glitch-free gate-value probing, first order (d=1), 2-share
  verdict           SECURE

  probe            secure  certificate   refreshed by
  --------------------------------------------------------
  a0b0            yes     dependence    -
  a0b1            yes     dependence    -
  a1b0            yes     dependence    -
  a1b1            yes     dependence    -
  cross0          yes     dependence    -
  cross1          yes     dependence    -
  c0              yes     uniformity    z
  c1              yes     uniformity    z

  modelled leakage over 4 secret classes (Hamming weight, glitch-free, unit weight):
    mean invariant across classes           True
    whole distribution invariant            False
    -> first-order secure. An adversary observing more than a mean is
       NOT covered by this verdict; that is a limit, not a defect.
```

`c0` and `c1` are the two wires a dependence-only tool cannot certify. They are exactly
where the uniformity certificate earns its place.

### And when a gadget genuinely leaks

```console
$ ct-mask check naive_and
  verdict           LEAKY

  LEAKY PROBES (these recombine a secret):
    c0  touches  a: a0; b: b0, b1
    c1  touches  a: a1; b: b0, b1
```

`c0 = (a0 & b0) XOR (a0 & b1)` simplifies to `a0 & b` — a share of one secret ANDed with
the *whole* of another, with no mask to refresh it. Exit status is `1`.

## Saying what a verdict does not cover

A first-order certificate is a statement about the **first moment** of the modelled
leakage, and nothing beyond it. ct-mask does not leave that to a footnote — it enumerates
the full modelled-leakage distribution exactly over the fresh randomness, for every secret
class, and records **two separate determinations**:

| Determination | DOM-AND |
|---|---|
| mean invariant across secret classes | `True` |
| whole distribution invariant | `False` |

Both go in the report. A gadget whose *mean* is not invariant is refused outright; a
recorded distributional dependence is a **disclosed limit of a passing verdict**, not a
tolerated failure. If your adversary sees more than a mean, the certificate tells you so
itself.

## The bundled corpus

Every secure gadget ships beside a broken counterpart, for the same reason a benchmark
needs controls — a tool that reports `SECURE` for everything is worthless.

| Gadget | Expected | What it is |
|---|---|---|
| `dom_and` | SECURE | domain-oriented masked AND, 2-share, one fresh mask |
| `refreshed_share` | SECURE | a single share refreshed by a fresh mask |
| `naive_and` | LEAKY | same structure as `dom_and`, no refresh |
| `unmasked_and` | LEAKY | no masking at all |
| `recombining_xor` | LEAKY | `a0 XOR a1` reconstructs the secret in one gate |

`naive_and` is *functionally correct* — the test suite proves `c0 XOR c1 == a AND b`. It is
broken in security, not in function, which is the only interesting kind of broken.

## Building your own gadget

```python
from ctmask import Netlist, analyse

n = Netlist("my_gadget")
n.add_input("a0", "share", of_secret="a")
n.add_input("a1", "share", of_secret="a")
n.add_input("z", "mask")
n.add_gate("t", "xor", "a0", "z")

r = analyse(n)
print(r.to_dict()["verdict"], r.probes[0].certificate)   # SECURE dependence
```

Input kinds are `secret`, `share` (naming the secret it shares), `mask` (fresh
randomness), and `public`. Gates are `and`, `or`, `xor`, `xnor`, `not`, `buf`.

## Exactness

Dependence is decided **semantically, by refutation**, not by looking at which names appear
in an expression. `(a0 AND z) XOR (a0 AND NOT z)` mentions `z` twice and does not depend on
it at all; ct-mask gets that right, and there is a test for it. Uniformity likewise requires
the mask to flip the probe *always*, not merely sometimes — a mask that only sometimes
changes a wire certifies nothing.

The symbolic and concrete evaluators are cross-checked against each other over the entire
input space of every bundled gadget. A verifier whose evaluator disagrees with its solver
is proving something other than what it reports.

## Honest limits

- **`d = 1` only.** No higher-order or multivariate analysis. A second probe is not modelled.
- **Glitch-free.** Transition and glitch-extended probing are not covered.
- **Modelled leakage, not measured.** The Hamming-weight function is a model, not an
  oscilloscope. Nothing here replaces a lab evaluation.
- **Gadget scale.** Exact distribution enumeration runs over the whole input space, so it
  is for gadgets, not for a full cipher. Probe certification itself scales further.
- **Sufficient, not necessary.** Both certificates are sufficient conditions. A `LEAKY`
  verdict means "neither certificate applies", and names the wire so you can judge.

## Proving this without showing your netlist

ct-mask verifies masking on a netlist **you hand it**. Attesting first-order security to a
third party *without disclosing the gadget*, and carrying a hardware timing result into a
software analysis through a machine-checked leakage contract, are commercial capabilities
and are not in this package. Everything here runs on designs you already control.

<!-- portfolio:start -->
## Part of the hw-verify toolkit

Five open tools, a dataset, and a browser demo for proving security properties of hardware and bounds checks. They share one boundary: **everything open analyses a design you disclose in full.**

| Project | What it does |
|---|---|
| **▶ [Live demo](https://huggingface.co/spaces/nickh007/hw-verify)** | Try the constant-time checker in your browser — runs the real analyzer via Pyodide |
| [`ctbench`](https://github.com/nickharris808/ctbench) | Matched-pair constant-time RTL benchmark + leaderboard |
| [`patchproof`](https://github.com/nickharris808/patchproof) | Prove a bounds-check fix eliminates *every* violating input |
| **`ct-mask`** (you are here) | First-order masking verification by two certificates |
| [`hw-verify-mcp`](https://github.com/nickharris808/hw-verify-mcp) | MCP server — all three checkers, callable by AI agents |
| [`ct-audit-action`](https://github.com/nickharris808/ct-audit-action) | GitHub Action — fail a PR on a leaky completion signal |
| [`hw-verify` dataset](https://huggingface.co/datasets/nickh007/hw-verify) | 49 records, 3 splits, byte-reproducible from these tools |
| [`hw-verify-static`](https://github.com/nickharris808/hw-verify-static) · [`hw-verify-space`](https://github.com/nickharris808/hw-verify-space) | Source for the live demo (Pyodide) and a fuller Gradio build |

**The commercial boundary.** Proving a property to a third party who never receives the design — a verdict bound to a commitment of a design that stays hidden — is a different problem and a commercial one. It is not in any of these packages.
<!-- portfolio:end -->

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing

New gadgets — especially ones you believe we get wrong — are the most valuable
contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).
