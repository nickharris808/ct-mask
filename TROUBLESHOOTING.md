# Troubleshooting

---

## `VacuousNetlist: netlist 'x' has no probes (no gates to observe)`

There is nothing to certify. A netlist of inputs alone satisfies every first-order
condition trivially, and reporting SECURE for it would read downstream as a certified
gadget. Add gates with `n.add_gate(name, op, *inputs)`.

## `VacuousNetlist: netlist 'x' declares no secret`

Everything is independent of a secret that does not exist. Declare inputs with
`kind="share"` naming `of_secret=...`, or `kind="secret"`.

```python
n.add_input("a0", "share", of_secret="a")
n.add_input("a1", "share", of_secret="a")
```

## The verdict is `LEAKY` and I think the gadget is fine

Read the `touches` column for the named probe. `LEAKY` means *neither* certificate
applied — the probe touches more than one share of some secret (or a raw unshared
secret) **and** no fresh mask always flips it.

Both certificates are sufficient conditions, not necessary ones, so a gadget secure
for a reason neither captures will be reported leaky. If you have one, it is the most
valuable possible contribution to the corpus.

The most common real cause is a missing refresh: `naive_and` has the same structure
as `dom_and` with the fresh mask removed, and `c0 = (a0 & b0) XOR (a0 & b1)`
simplifies to `a0 & b` — a share of one secret ANDed with the *whole* of another.

## `modelled leakage enumeration skipped: N inputs would need 2^N evaluations`

Not an error. The probe certification above it is complete and is the security
verdict; only the mean/distribution moments were skipped, and they are reported as
`None` rather than guessed.

```python
analyse(n, max_enumeration_inputs=24)   # explicitly opt in to the wait
analyse(n, measure_leakage=False)       # or skip the moments entirely
```

Cost doubles per input: 19 inputs ≈ 4 s, 21 ≈ 19 s, 24 ≈ minutes.

## `mean_invariant` is `None`

Either the enumeration was skipped (see above) or you passed
`measure_leakage=False`. `None` means *not measured* — it never means "passed".

## `distribution_invariant` is `False` but the verdict is `SECURE`

That is the expected result for DOM-AND, and it is the honest one. A first-order
verdict is a statement about the first moment. The distribution *does* depend on the
secret class at higher moments, and the report says so rather than letting you assume
more. If your adversary sees more than a mean, you are outside what this verdict
covers.

## A gate refers to a wire that does not exist

Gate inputs must already be declared as inputs or defined as earlier gates. Build the
netlist in topological order.

---

See [SCOPE.md](SCOPE.md) for what a verdict means.
