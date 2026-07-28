"""Regression tests for vacuous SECURE verdicts.

`Report.secure` was `all(p.secure for p in self.probes)`.  Over an empty probe list
`all()` is True, so a netlist containing nothing at all was reported first-order
SECURE.  So was a netlist with gates but no secret to protect.  Both verdicts are
true statements about a trivially satisfied condition, and both read downstream --
in a report, in the dataset, in a slide -- as "this gadget was certified".

Nothing was certified.  A verdict has to be earned by discharging a proof obligation,
and there is no obligation to discharge when there are no probes or no secrets, so
the analysis refuses instead of passing.
"""

from __future__ import annotations

import pytest

from ctmask.analysis import Report, VacuousNetlist, analyse
from ctmask.gadgets import GADGETS, build
from ctmask.netlist import Netlist


def test_empty_netlist_refuses_rather_than_reporting_secure():
    with pytest.raises(VacuousNetlist, match="no probes"):
        analyse(Netlist("empty"))


def test_netlist_with_inputs_but_no_gates_refuses():
    n = Netlist("no_gates")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    with pytest.raises(VacuousNetlist, match="no probes"):
        analyse(n)


def test_netlist_with_no_secret_refuses():
    """Everything is independent of a secret that does not exist."""
    n = Netlist("no_secret")
    n.add_input("a", "public")
    n.add_input("b", "public")
    n.add_gate("g", "and", "a", "b")
    with pytest.raises(VacuousNetlist, match="no secret"):
        analyse(n)


def test_refusals_say_how_to_fix_the_netlist():
    with pytest.raises(VacuousNetlist) as e:
        analyse(Netlist("empty"))
    assert "add_gate" in str(e.value)

    n = Netlist("no_secret")
    n.add_input("a", "public")
    n.add_gate("g", "buf", "a")
    with pytest.raises(VacuousNetlist) as e:
        analyse(n)
    assert "of_secret" in str(e.value)


def test_report_secure_is_false_for_an_empty_probe_list():
    """Belt and braces: even if a Report is built directly, empty is not secure."""
    assert Report(gadget="hand-built").secure is False


def test_a_single_certified_probe_is_still_a_real_verdict():
    """The refusal must not swallow legitimately small gadgets."""
    n = Netlist("one_gate")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    n.add_gate("t", "buf", "a0")
    r = analyse(n)
    assert r.secure is True
    assert len(r.probes) == 1
    assert r.probes[0].certificate == "dependence"


@pytest.mark.parametrize("name", sorted(GADGETS))
def test_every_bundled_gadget_still_analyses(name):
    """Positive control: the corpus must be unaffected by the refusal."""
    r = analyse(build(name))
    assert r.probes, name
    assert r.to_dict()["verdict"] in ("SECURE", "LEAKY")


def test_a_leaky_gadget_is_still_leaky_not_refused():
    r = analyse(build("naive_and"))
    assert r.secure is False
    assert r.leaky_probes


# ---------------------------------------------------------------------------
# Out-of-distribution structural input.
# ---------------------------------------------------------------------------

def test_gate_referring_to_an_undefined_wire_raises():
    n = Netlist("dangling")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    with pytest.raises((KeyError, ValueError)):
        n.add_gate("t", "xor", "a0", "nonexistent")
        analyse(n)


def test_self_referential_gate_does_not_hang():
    n = Netlist("selfref")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    with pytest.raises((KeyError, ValueError, RecursionError)):
        n.add_gate("t", "xor", "a0", "t")
        analyse(n)


def test_first_order_verdict_never_claims_higher_order_security():
    """A d=1 SECURE verdict must state its own scope in the report."""
    d = analyse(build("dom_and")).to_dict()
    assert d["order"] == 1
    note = d["modelled_leakage"]["note"]
    assert "first moment" in note
    assert "not covered" in note
    # and the two determinations stay separate rather than collapsing to one flag
    ml = d["modelled_leakage"]
    assert ml["mean_invariant_across_secret_classes"] is True
    assert ml["distribution_invariant_across_secret_classes"] is False


# ---------------------------------------------------------------------------
# The enumeration wall.
#
# Probe certification is cheap and roughly linear; the modelled-leakage
# enumeration visits every input assignment and so costs 2^inputs. Measured:
# 19 inputs 4.3 s, 21 inputs 18.8 s, doubling per input — 24 inputs is minutes.
# The old guard was `len(probes) <= 32`, which measures the wrong quantity
# entirely, so a wide gadget looked like a hang with no explanation.
# ---------------------------------------------------------------------------

def _wide(k: int) -> Netlist:
    """A gadget with 2k+1 inputs and k gates — wide but shallow."""
    n = Netlist(f"wide{k}")
    for i in range(k):
        n.add_input(f"a{i}0", "share", of_secret=f"a{i}")
        n.add_input(f"a{i}1", "share", of_secret=f"a{i}")
    n.add_input("z", "mask")
    prev = "z"
    for i in range(k):
        n.add_gate(f"t{i}", "xor", f"a{i}0", prev)
        prev = f"t{i}"
    return n


def test_a_wide_gadget_returns_promptly_instead_of_enumerating_forever():
    import time

    start = time.perf_counter()
    r = analyse(_wide(12))            # 25 inputs -> 2^25 evaluations if unguarded
    elapsed = time.perf_counter() - start
    assert elapsed < 5, f"took {elapsed:.1f}s; the enumeration guard did not fire"
    assert r.leakage_skipped, "the skip must be recorded, not silent"


def test_the_skip_is_reported_and_says_what_was_lost_and_how_to_override():
    r = analyse(_wide(12))
    msg = r.leakage_skipped
    assert "2^" in msg
    assert "Probe certification above is unaffected" in msg
    assert "max_enumeration_inputs" in msg
    assert r.to_dict()["modelled_leakage"]["skipped"] == msg


def test_skipping_the_enumeration_does_not_fake_the_moments():
    """A skipped measurement must read as absent, never as a passing result."""
    r = analyse(_wide(12))
    assert r.mean_invariant is None
    assert r.distribution_invariant is None
    d = r.to_dict()["modelled_leakage"]
    assert d["mean_invariant_across_secret_classes"] is None
    assert d["distribution_invariant_across_secret_classes"] is None


def test_the_probe_verdict_is_still_complete_when_enumeration_is_skipped():
    """The security verdict comes from probe certification, not the moments."""
    r = analyse(_wide(12))
    assert len(r.probes) == 12
    assert all(p.certificate for p in r.probes)
    assert r.to_dict()["verdict"] in ("SECURE", "LEAKY")


def test_a_narrow_gadget_still_enumerates():
    """The guard must not switch off the measurement for ordinary gadgets."""
    r = analyse(_wide(4))             # 9 inputs
    assert r.leakage_skipped is None
    assert r.mean_invariant is not None
    assert r.secret_classes > 0


def test_every_bundled_gadget_is_under_the_cap():
    """If the shipped corpus tripped the guard, the README examples would change."""
    for name in GADGETS:
        assert analyse(build(name)).leakage_skipped is None, name


def test_the_cap_can_be_raised_explicitly():
    r = analyse(_wide(6), max_enumeration_inputs=13)   # 13 inputs, allowed
    assert r.leakage_skipped is None
    assert r.mean_invariant is not None


# ---------------------------------------------------------------------------
# The fan-in pre-filter must be a pure optimisation.
#
# `depends_on` skips the solver when the input is not in the probe's fan-in cone.
# That is sound because a value can only reach a wire along a path of gates, and the
# fan-in is by construction every input with such a path — so absence from it implies
# no dependence. The converse is NOT assumed: presence in the fan-in still asks z3.
#
# The argument is easy to invalidate by changing how gates record their inputs, so
# these tests check the property directly against an unfiltered oracle.
# ---------------------------------------------------------------------------

def _depends_unfiltered(n, probe, inp):
    """`depends_on` with the pre-filter bypassed: always ask the solver."""
    import z3

    from ctmask.analysis import _two_copies
    va, vb = _two_copies(n, inp, complement=False)
    s = z3.Solver()
    s.add(va[probe] != vb[probe])
    return s.check() == z3.sat


@pytest.mark.parametrize("name", sorted(GADGETS))
def test_prefilter_agrees_with_the_solver_on_every_probe_and_input(name):
    from ctmask.analysis import depends_on

    n = build(name)
    for probe in n.probes():
        for inp in n.input_names:
            fast = depends_on(n, probe, inp)
            slow = _depends_unfiltered(n, probe, inp)
            assert fast == slow, (
                f"{name}: depends_on({probe}, {inp}) = {fast} with the fan-in "
                f"pre-filter but {slow} without it — the optimisation changed an answer"
            )


@pytest.mark.parametrize("name", sorted(GADGETS))
def test_verdicts_are_unchanged_by_the_prefilter(name):
    """End-to-end: the corpus verdicts must be identical."""
    _builder, expected = GADGETS[name]
    assert analyse(build(name)).to_dict()["verdict"] == expected


def test_fan_in_is_a_subset_of_the_declared_inputs():
    from ctmask.analysis import fan_in

    n = build("dom_and")
    for probe in n.probes():
        assert fan_in(n, probe) <= set(n.input_names)


def test_an_input_outside_the_fan_in_never_reaches_the_probe():
    """The theorem the optimisation rests on, stated as a test."""
    from ctmask.analysis import fan_in

    for name in GADGETS:
        n = build(name)
        for probe in n.probes():
            outside = set(n.input_names) - fan_in(n, probe)
            for inp in outside:
                assert not _depends_unfiltered(n, probe, inp), (
                    f"{name}: {inp} is outside {probe}'s fan-in yet the solver says "
                    f"it affects the probe — the fan-in walk is missing an edge"
                )
