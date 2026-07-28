# Honest scope — what a ct-mask verdict does and does not mean

---

## The model, first

**Glitch-free gate-value probing, first order (`d = 1`), 2-share.** A probe observes
the stable Boolean value of one internal wire. This is the standard model for this
class of tool. Glitches, transitions, coupling, and physical measurement are all
outside it. If your threat model includes them, a `SECURE` verdict here does not
cover you.

## The claim, stated precisely

A `SECURE` verdict says:

> Every probe wire in the netlist was certified independent of every declared secret,
> under the model above, by one of two *sufficient* conditions — dependence or
> uniformity — each discharged as a machine-checked refutation rather than a
> statistical test.

## What it proves

- **Each probe is independent of every secret**, by one of:
  - **dependence** — the probe touches at most one share of each secret, and no raw
    unshared secret. The unused share is uniform and masks the one it touches.
  - **uniformity** — a fresh mask flips the probe *whenever* the mask flips, so the
    probe is uniform over that mask and independent of every secret **regardless of
    how many shares it touches**.
- **Dependence is decided semantically, by refutation** — not by looking at which
  names appear in an expression. `(a0 AND z) XOR (a0 AND NOT z)` mentions `z` twice
  and does not depend on it at all; ct-mask gets that right, and there is a test.
- **Uniformity requires the mask to flip the probe *always***, not merely sometimes.
  A mask that only sometimes changes a wire certifies nothing.

The uniformity certificate is why this tool exists: in a domain-oriented masked AND,
the output shares touch **both** shares of an operand and are perfectly secure. A
dependence-only analysis reports them as leaky. On `dom_and`, six probes certify by
dependence and **two certify only by uniformity**.

## What it does **not** prove

- **Nothing above first order.** No higher-order or multivariate analysis; a second
  simultaneous probe is not modelled. A `d=1` SECURE verdict is not a `d=2` claim.
- **Nothing about glitches or transitions.** Glitch-extended and transition-extended
  probing are not covered.
- **Nothing measured.** The Hamming-weight leakage function is a *model*, not an
  oscilloscope. Nothing here replaces a lab evaluation.
- **Both certificates are sufficient, not necessary.** A `LEAKY` verdict means
  "neither certificate applies", and names the wire so you can judge for yourself.

---

## The first moment, and only the first moment

A first-order certificate is a statement about the **first moment** of the modelled
leakage. ct-mask does not leave that to a footnote — it enumerates the modelled
leakage distribution exactly over the fresh randomness, for every secret class, and
records **two separate determinations**:

| Determination | DOM-AND |
|---|---|
| mean invariant across secret classes | `True` |
| whole distribution invariant | `False` |

Both go in the report. A gadget whose *mean* is not invariant is refused outright. A
recorded distributional dependence is a **disclosed limit of a passing verdict**, not
a tolerated failure. If your adversary sees more than a mean, the certificate says so
itself.

---

## Vacuous input is refused

A netlist with no probes, or with no secret to protect, satisfies every first-order
condition trivially. `all()` over an empty list is `True`, so this used to report
SECURE — a statement that is true, useless, and reads downstream as "certified".
Both now raise `VacuousNetlist`. A verdict has to be earned by discharging a proof
obligation.

## The enumeration wall

Probe certification is cheap and roughly linear. The modelled-leakage enumeration
visits every input assignment, so it costs `2^inputs`. Measured on one laptop:

| inputs | enumeration | probe certification |
|---|---|---|
| 11 | 32 ms | 21 ms |
| 15 | 252 ms | 49 ms |
| 19 | 4.3 s | 93 ms |
| 21 | 18.8 s | 128 ms |

It doubles per input, so 24 inputs is minutes and 30 is hours. Above
`max_enumeration_inputs` (default 20) the enumeration is **skipped and reported as
skipped**; `mean_invariant` and `distribution_invariant` stay `None` rather than
being faked, and the probe certification — which is the security verdict — is
unaffected. Raise the cap explicitly with `analyse(n, max_enumeration_inputs=...)`
if you want to wait.

This is a bound, not a speedup: exact enumeration of a `2^n` space cannot be made
cheap, and claiming otherwise would be its own kind of dishonesty.

---

## Proving this without showing your netlist

ct-mask verifies masking on a netlist **you hand it**. Attesting first-order security
to a third party *without disclosing the gadget* is a commercial capability and is
not in this package.

---

## Sibling tools

- [`ctbench`](https://github.com/nickharris808/ctbench) — constant-time RTL.
- [`patchproof`](https://github.com/nickharris808/patchproof) — bounds-check fixes.
- [`hw-verify-mcp`](https://github.com/nickharris808/hw-verify-mcp) — all three for agents.
- [Live demo](https://huggingface.co/spaces/nickh007/hw-verify).
