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
