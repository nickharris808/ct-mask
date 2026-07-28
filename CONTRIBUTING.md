# Contributing to ct-mask

## The most valuable contribution: a gadget we get wrong

If you have a gadget you believe is secure and ct-mask calls `LEAKY`, or — far more
importantly — one you believe leaks and ct-mask calls `SECURE`, open an issue with it.
The second kind is a soundness bug and we treat it as such.

## Adding a gadget

1. Write a builder in `ctmask/gadgets.py` returning a `Netlist`.
2. Add it to `GADGETS` with its expected verdict.
3. If it is a *secure* gadget, add a broken counterpart too. A corpus without controls
   cannot tell a working tool from one that always says yes.
4. Prove the gadget is **functionally correct** in the test suite. A "masked AND" that is
   not an AND proves nothing about masking. See `test_dom_and_is_functionally_correct`.
5. Run `python -m pytest tests -q`.

## Both certificates must stay sound

- **Dependence** requires *no* raw-secret dependence and at most one share per secret.
  Depending on an unshared secret is not "touching one share" — there is no second share
  to mask it. This was a real bug once; there is a regression test.
- **Uniformity** requires the mask to flip the probe *always*, never sometimes. `a0 AND z`
  is changed by `z` but is not uniform over it.

Both are decided by refutation over exact Boolean semantics. Do not replace either with a
syntactic check on which names appear in an expression — that is the failure mode this
tool exists to avoid.

## Do not weaken the scope statement

The report records mean-invariance and distribution-invariance **separately**, and the
model line (`d=1`, glitch-free, 2-share) appears in every verdict. Please do not
consolidate these into a single "secure" flag. Overclaiming to this audience costs exactly
the credibility the tool is trying to earn.

## Style

`ruff check .` clean, 100-column lines.
