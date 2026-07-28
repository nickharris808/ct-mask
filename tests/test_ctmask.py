"""Tests for ct-mask.

The load-bearing tests are the ones that check the tool says LEAKY when it should,
and the one that checks the symbolic and concrete evaluators agree — a verifier
whose evaluator disagrees with its solver is proving something other than what it
reports.
"""

from __future__ import annotations

import itertools

import pytest
import z3

from ctmask import GADGETS, Netlist, analyse, analyse_probe, build, depends_on, refreshed_by
from ctmask.cli import main

# ---------------------------------------------------------------------------
# The corpus.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(GADGETS))
def test_corpus_verdicts_match_expectations(name):
    expected = GADGETS[name][1]
    r = analyse(build(name), measure_leakage=False)
    assert ("SECURE" if r.secure else "LEAKY") == expected


def test_leaky_verdicts_name_the_offending_probe():
    for name, (_, expected) in GADGETS.items():
        if expected != "LEAKY":
            continue
        r = analyse(build(name), measure_leakage=False)
        assert r.leaky_probes, f"{name}: LEAKY but named no probe"


# ---------------------------------------------------------------------------
# The two certificates are genuinely different.
# ---------------------------------------------------------------------------

def test_dom_and_output_shares_need_the_uniformity_certificate():
    """The whole point of the tool: dependence alone is not enough for DOM.

    c0 touches BOTH shares of b, so a dependence-only analysis flags it. It is
    secure because the fresh mask z refreshes it.
    """
    n = build("dom_and")
    v = analyse_probe(n, "c0")
    assert v.secure
    assert v.certificate == "uniformity"
    assert v.masking_wire == "z"
    assert len(v.touches["b"]) == 2, "c0 should touch both shares of b"


def test_dom_and_inner_products_use_dependence():
    n = build("dom_and")
    v = analyse_probe(n, "a0b1")
    assert v.secure and v.certificate == "dependence"


def test_uniformity_can_rescue_a_raw_secret():
    """`a XOR z` with a raw secret and a fresh mask is uniform, hence secure."""
    n = Netlist("masked_raw")
    n.add_input("a", "secret")
    n.add_input("z", "mask")
    n.add_gate("t", "xor", "a", "z")
    v = analyse_probe(n, "t")
    assert v.secure and v.certificate == "uniformity"


def test_raw_secret_without_a_mask_is_leaky():
    """Regression: depending on an unshared secret is not 'touching one share'."""
    n = build("unmasked_and")
    v = analyse_probe(n, "ab")
    assert not v.secure
    assert v.certificate is None


def test_dependence_is_exact_not_syntactic():
    """`(a0 AND z) XOR (a0 AND NOT z)` mentions a0 twice but reduces to a0."""
    n = Netlist("exactness")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    n.add_input("z", "mask")
    n.add_gate("nz", "not", "z")
    n.add_gate("g1", "and", "a0", "z")
    n.add_gate("g2", "and", "a0", "nz")
    n.add_gate("t", "xor", "g1", "g2")       # == a0
    assert depends_on(n, "t", "a0")
    assert not depends_on(n, "t", "a1")
    # z cancels out entirely, so it does not refresh t
    assert not refreshed_by(n, "t", "z")


def test_refreshed_by_requires_always_flips_not_sometimes():
    """A mask that only sometimes changes the wire does not certify uniformity."""
    n = Netlist("partial")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    n.add_input("z", "mask")
    n.add_gate("t", "and", "a0", "z")        # z changes t only when a0 is 1
    assert depends_on(n, "t", "z")
    assert not refreshed_by(n, "t", "z")


# ---------------------------------------------------------------------------
# Moment separation.
# ---------------------------------------------------------------------------

def test_dom_and_mean_invariant_but_distribution_is_not():
    """The honest scope of a first-order verdict, measured rather than asserted."""
    r = analyse(build("dom_and"))
    assert r.secret_classes == 4
    assert r.mean_invariant is True
    assert r.distribution_invariant is False


def test_report_records_both_determinations_separately():
    d = analyse(build("dom_and")).to_dict()["modelled_leakage"]
    assert d["mean_invariant_across_secret_classes"] is True
    assert d["distribution_invariant_across_secret_classes"] is False
    assert "first moment" in d["note"]


def test_leaky_gadget_fails_the_mean_test_too():
    """An unrefreshed gadget leaks in the first moment, cross-checking the prover."""
    r = analyse(build("naive_and"))
    assert r.mean_invariant is False
    assert not r.secure


# ---------------------------------------------------------------------------
# Semantics: the symbolic and concrete evaluators must agree.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(GADGETS))
def test_symbolic_and_concrete_evaluation_agree(name):
    n = build(name)
    sym = n.symbolic()
    for bits in itertools.product([False, True], repeat=len(n.inputs)):
        assignment = dict(zip(n.input_names, bits, strict=True))
        concrete = n.evaluate(assignment)
        subst = [(z3.Bool(k), z3.BoolVal(v)) for k, v in assignment.items()]
        for w in n.wires:
            got = z3.simplify(z3.substitute(sym[w], *subst))
            assert z3.is_true(got) == concrete[w], f"{name}: disagreement on {w}"


def test_dom_and_is_functionally_correct():
    """c0 XOR c1 must equal a AND b, or the gadget is not an AND at all."""
    n = build("dom_and")
    for a0, a1, b0, b1, z in itertools.product([False, True], repeat=5):
        v = n.evaluate({"a0": a0, "a1": a1, "b0": b0, "b1": b1, "z": z})
        a, b = a0 ^ a1, b0 ^ b1
        assert (v["c0"] ^ v["c1"]) == (a and b)


def test_naive_and_is_also_functionally_correct():
    """The broken gadget is broken in security, not in function — that is the point."""
    n = build("naive_and")
    for a0, a1, b0, b1 in itertools.product([False, True], repeat=4):
        v = n.evaluate({"a0": a0, "a1": a1, "b0": b0, "b1": b1})
        assert (v["c0"] ^ v["c1"]) == ((a0 ^ a1) and (b0 ^ b1))


# ---------------------------------------------------------------------------
# Netlist validation.
# ---------------------------------------------------------------------------

def test_share_must_name_its_secret():
    n = Netlist("x")
    with pytest.raises(ValueError, match="must name the secret"):
        n.add_input("a0", "share")


def test_bad_kind_rejected():
    n = Netlist("x")
    with pytest.raises(ValueError, match="not in"):
        n.add_input("a", "sekrit")


def test_bad_gate_kind_rejected():
    n = Netlist("x")
    n.add_input("a", "public")
    with pytest.raises(ValueError, match="not in"):
        n.add_gate("g", "nand", "a", "a")


def test_gate_arity_enforced():
    n = Netlist("x")
    n.add_input("a", "public")
    with pytest.raises(ValueError, match="takes 2"):
        n.add_gate("g", "and", "a")


def test_duplicate_wire_rejected():
    n = Netlist("x")
    n.add_input("a", "public")
    with pytest.raises(ValueError, match="duplicate"):
        n.add_input("a", "public")


def test_undefined_input_rejected():
    n = Netlist("x")
    with pytest.raises(ValueError, match="not defined"):
        n.add_gate("g", "buf", "nope")


def test_unknown_gadget_raises():
    with pytest.raises(KeyError):
        build("nope")


def test_evaluate_requires_every_input():
    n = build("dom_and")
    with pytest.raises(KeyError):
        n.evaluate({"a0": True})


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def test_cli_corpus_passes():
    assert main(["corpus"]) == 0


def test_cli_check_exit_codes():
    assert main(["check", "dom_and", "--json"]) == 0
    assert main(["check", "naive_and", "--json"]) == 1


def test_cli_list(capsys):
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    for name in GADGETS:
        assert name in out
