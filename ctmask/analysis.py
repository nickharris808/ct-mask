"""First-order probing security by two independent certificates.

**The model, stated up front.** Glitch-free gate-value probing, first order
(``d = 1``), 2-share. A probe observes the stable Boolean value of one internal
wire. This is the standard model for this class of tool, and it excludes glitches,
transitions, and coupling.

A probe ``w`` is first-order secure if its value is independent of every secret.
Two *sufficient* conditions are certified here, and they are genuinely different:

**(A) Dependence.** ``w`` depends on at most one share of each secret. The unused
share is uniform, so it masks the one ``w`` touches. Certificate: UNSAT of a
dependency miter — two copies of the circuit with every input tied except one
share, asserting the two copies' ``w`` differ. UNSAT means flipping that share can
never flip ``w``, i.e. ``w`` does not depend on it.

**(B) Uniformity.** There is a fresh mask ``r`` such that ``w`` *flips whenever*
``r`` flips. Then ``w = (something) XOR r`` is uniform over ``r`` and therefore
independent of every secret **regardless of how many shares it touches**.
Certificate: UNSAT of a miter tying every input except ``r``, whose copy B takes
the complement of copy A's ``r``, asserting the two copies' ``w`` are *equal*.

Condition (B) is what tools reasoning only about dependence miss. In a
domain-oriented masked AND, the output shares touch **both** shares of one operand
and are still perfectly secure, because a fresh mask refreshes them. A
dependence-only analysis reports those wires as leaky. They are not.
"""

from __future__ import annotations

import itertools
from collections import Counter
from dataclasses import dataclass, field

import z3

from .netlist import Netlist


@dataclass
class ProbeVerdict:
    probe: str
    secure: bool
    certificate: str | None          # "dependence" | "uniformity" | None
    touches: dict[str, list[str]]    # secret -> shares of it that the probe depends on
    masking_wire: str | None = None  # for a uniformity certificate, the refreshing mask

    def to_dict(self) -> dict:
        return {
            "probe": self.probe,
            "secure": self.secure,
            "certificate": self.certificate,
            "touches_shares": self.touches,
            "refreshed_by": self.masking_wire,
        }


@dataclass
class Report:
    gadget: str
    order: int = 1
    shares: int = 2
    model: str = "glitch-free gate-value probing, first order (d=1), 2-share"
    probes: list[ProbeVerdict] = field(default_factory=list)
    mean_invariant: bool | None = None
    distribution_invariant: bool | None = None
    secret_classes: int = 0

    @property
    def secure(self) -> bool:
        return all(p.secure for p in self.probes)

    @property
    def leaky_probes(self) -> list[str]:
        return [p.probe for p in self.probes if not p.secure]

    def to_dict(self) -> dict:
        return {
            "gadget": self.gadget,
            "verdict": "SECURE" if self.secure else "LEAKY",
            "model": self.model,
            "order": self.order,
            "shares": self.shares,
            "probes": [p.to_dict() for p in self.probes],
            "leaky_probes": self.leaky_probes,
            "certificates_used": {
                "dependence": sum(1 for p in self.probes if p.certificate == "dependence"),
                "uniformity": sum(1 for p in self.probes if p.certificate == "uniformity"),
            },
            "modelled_leakage": {
                "function": "Hamming weight over gate outputs (unit weight, glitch-free)",
                "secret_classes": self.secret_classes,
                "mean_invariant_across_secret_classes": self.mean_invariant,
                "distribution_invariant_across_secret_classes": self.distribution_invariant,
                "note": (
                    "These are two DIFFERENT determinations and are recorded separately. "
                    "A first-order certificate is a statement about the first moment only. "
                    "An adversary who observes more than a mean is not covered by a "
                    "first-order SECURE verdict."
                ),
            },
        }


def _two_copies(n: Netlist, flip: str, complement: bool) -> tuple[dict, dict]:
    """Two symbolic copies of the netlist, tied on every input except `flip`.

    With `complement=False` the flipped input is free in each copy (used to ask
    "can this input change the probe?"). With `complement=True` copy B's value is
    forced to the negation of copy A's (used to ask "does this input always flip
    the probe?").
    """
    a_env, b_env = {}, {}
    for i in n.inputs:
        va = z3.Bool(f"A_{i.name}")
        a_env[i.name] = va
        b_env[i.name] = z3.Not(va) if (i.name == flip and complement) else (
            z3.Bool(f"B_{i.name}") if i.name == flip else va
        )
    return n.symbolic(a_env), n.symbolic(b_env)


def depends_on(n: Netlist, probe: str, inp: str) -> bool:
    """Does `probe` functionally depend on input `inp`? Exact, by refutation."""
    va, vb = _two_copies(n, inp, complement=False)
    s = z3.Solver()
    s.add(va[probe] != vb[probe])
    return s.check() == z3.sat


def refreshed_by(n: Netlist, probe: str, mask: str) -> bool:
    """Does `probe` flip whenever `mask` flips, all else equal?

    If so, the probe is `something XOR mask` and is uniform over the mask, hence
    independent of every secret. Certified by UNSAT of "the two copies agree".
    """
    va, vb = _two_copies(n, mask, complement=True)
    s = z3.Solver()
    s.add(va[probe] == vb[probe])
    return s.check() == z3.unsat


def analyse_probe(n: Netlist, probe: str) -> ProbeVerdict:
    """Certify one probe by dependence, else by uniformity, else report it leaky."""
    touches: dict[str, list[str]] = {}
    direct: list[str] = []
    for secret in n.secrets():
        touches[secret] = [sh for sh in n.shares_of(secret) if depends_on(n, probe, sh)]
        # Depending on the *raw, unshared* secret is not "touching one share": there
        # is no second share to mask it, so the dependence argument does not apply.
        # Only a fresh mask can rescue such a probe.
        if secret in n.input_names and depends_on(n, probe, secret):
            direct.append(secret)
            touches[secret] = touches[secret] + [secret]

    # (A) dependence: no raw-secret dependence, and at most one share of each secret
    if not direct and all(len(v) <= 1 for v in touches.values()):
        return ProbeVerdict(probe, True, "dependence", touches)

    # (B) uniformity: some fresh mask always flips it
    for m in n.masks():
        if refreshed_by(n, probe, m):
            return ProbeVerdict(probe, True, "uniformity", touches, masking_wire=m)

    return ProbeVerdict(probe, False, None, touches)


def _leakage_distributions(n: Netlist) -> tuple[int, dict[tuple, Counter]]:
    """Modelled Hamming-weight distribution of the gate outputs, per secret class.

    Enumerates every sharing and every mask value, so the distribution is exact
    rather than sampled. Only attempted for small gadgets.
    """
    secrets = n.secrets()
    masks = n.masks()
    publics = [i.name for i in n.by_kind("public")]
    dists: dict[tuple, Counter] = {}

    for secret_vals in itertools.product([False, True], repeat=len(secrets)):
        cls = tuple(secret_vals)
        c: Counter = Counter()
        share_lists = [n.shares_of(s) for s in secrets]
        # first share of each secret is free; the last is determined by the XOR
        free_counts = [max(len(sl) - 1, 0) for sl in share_lists]
        for frees in itertools.product([False, True], repeat=sum(free_counts)):
            assignment: dict[str, bool] = {}
            k = 0
            for s, sl, fc in zip(secrets, share_lists, free_counts, strict=True):
                if not sl:
                    assignment[s] = dict(zip(secrets, secret_vals, strict=True))[s]
                    continue
                chosen = list(frees[k:k + fc])
                k += fc
                acc = False
                for name, val in zip(sl[:-1], chosen, strict=True):
                    assignment[name] = val
                    acc ^= val
                assignment[sl[-1]] = acc ^ dict(zip(secrets, secret_vals, strict=True))[s]
                if s in n.input_names:
                    assignment[s] = dict(zip(secrets, secret_vals, strict=True))[s]
            for mvals in itertools.product([False, True], repeat=len(masks)):
                assignment.update(dict(zip(masks, mvals, strict=True)))
                for pvals in itertools.product([False, True], repeat=len(publics)):
                    assignment.update(dict(zip(publics, pvals, strict=True)))
                    vals = n.evaluate(assignment)
                    hw = sum(1 for g in n.probes() if vals[g])
                    c[hw] += 1
        dists[cls] = c
    return len(dists), dists


def _mean(c: Counter) -> float:
    total = sum(c.values())
    return sum(k * v for k, v in c.items()) / total if total else 0.0


def analyse(n: Netlist, measure_leakage: bool = True) -> Report:
    """Full first-order analysis of a gadget."""
    r = Report(gadget=n.name)
    r.probes = [analyse_probe(n, p) for p in n.probes()]

    if measure_leakage and len(n.probes()) <= 32:
        classes, dists = _leakage_distributions(n)
        r.secret_classes = classes
        means = [round(_mean(c), 9) for c in dists.values()]
        r.mean_invariant = len(set(means)) <= 1
        norm = [
            tuple(sorted((k, v / sum(c.values())) for k, v in c.items()))
            for c in dists.values()
        ]
        r.distribution_invariant = len(set(norm)) <= 1
    return r
