"""A small library of masked and deliberately broken gadgets.

Every secure gadget ships beside a broken counterpart, for the same reason ctbench
does it: a tool that reports SECURE for everything is worthless, and the only way
to see that is to run it on something that genuinely leaks.
"""

from __future__ import annotations

from .netlist import Netlist


def dom_and() -> Netlist:
    """Domain-oriented masked AND, 2-share, one fresh mask.

    ``c0 = (a0 & b0) XOR ((a0 & b1) XOR z)``
    ``c1 = (a1 & b1) XOR ((a1 & b0) XOR z)``

    with ``c0 XOR c1 = a AND b``.

    This is the gadget that separates the two certificates. The output shares
    ``c0`` and ``c1`` each touch **both** shares of one operand, so a
    dependence-only analysis calls them leaky. They are secure, because the fresh
    mask ``z`` refreshes the cross term — which the uniformity certificate proves
    and the dependence certificate cannot.
    """
    n = Netlist("dom_and")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    n.add_input("b0", "share", of_secret="b")
    n.add_input("b1", "share", of_secret="b")
    n.add_input("z", "mask")

    n.add_gate("a0b0", "and", "a0", "b0")
    n.add_gate("a0b1", "and", "a0", "b1")
    n.add_gate("a1b0", "and", "a1", "b0")
    n.add_gate("a1b1", "and", "a1", "b1")

    n.add_gate("cross0", "xor", "a0b1", "z")     # refreshed cross term
    n.add_gate("cross1", "xor", "a1b0", "z")     # same mask, other domain
    n.add_gate("c0", "xor", "a0b0", "cross0")
    n.add_gate("c1", "xor", "a1b1", "cross1")
    n.outputs = ["c0", "c1"]
    return n


def naive_and() -> Netlist:
    """Unrefreshed masked AND — the classic broken gadget.

    Identical share structure to ``dom_and`` but with **no fresh mask**, so the
    cross terms are combined directly:

    ``c0 = (a0 & b0) XOR (a0 & b1)``   which is ``a0 & (b0 XOR b1)`` = ``a0 & b``

    That wire recombines the secret ``b`` with a share of ``a``. It is a real
    first-order leak and every correct tool must flag it.
    """
    n = Netlist("naive_and")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    n.add_input("b0", "share", of_secret="b")
    n.add_input("b1", "share", of_secret="b")

    n.add_gate("a0b0", "and", "a0", "b0")
    n.add_gate("a0b1", "and", "a0", "b1")
    n.add_gate("a1b0", "and", "a1", "b0")
    n.add_gate("a1b1", "and", "a1", "b1")
    n.add_gate("c0", "xor", "a0b0", "a0b1")      # = a0 & b  -> leaks
    n.add_gate("c1", "xor", "a1b0", "a1b1")      # = a1 & b  -> leaks
    n.outputs = ["c0", "c1"]
    return n


def unmasked_and() -> Netlist:
    """No masking at all: the probe is the secret AND directly."""
    n = Netlist("unmasked_and")
    n.add_input("a", "secret")
    n.add_input("b", "secret")
    n.add_gate("ab", "and", "a", "b")
    n.outputs = ["ab"]
    return n


def refreshed_share() -> Netlist:
    """A single share refreshed by a fresh mask: secure by uniformity alone.

    ``t = a0 XOR z``. It touches one share, so dependence already suffices; the
    point of the fixture is that uniformity *also* certifies it, which the test
    suite checks so the two certificates are known not to be accidentally identical.
    """
    n = Netlist("refreshed_share")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    n.add_input("z", "mask")
    n.add_gate("t", "xor", "a0", "z")
    n.outputs = ["t"]
    return n


def recombining_xor() -> Netlist:
    """``a0 XOR a1`` — reconstructs the secret in one gate. Must be flagged."""
    n = Netlist("recombining_xor")
    n.add_input("a0", "share", of_secret="a")
    n.add_input("a1", "share", of_secret="a")
    n.add_gate("recombined", "xor", "a0", "a1")
    n.outputs = ["recombined"]
    return n


#: name -> (builder, expected verdict). The expectations are the corpus.
GADGETS = {
    "dom_and": (dom_and, "SECURE"),
    "refreshed_share": (refreshed_share, "SECURE"),
    "naive_and": (naive_and, "LEAKY"),
    "unmasked_and": (unmasked_and, "LEAKY"),
    "recombining_xor": (recombining_xor, "LEAKY"),
}


def build(name: str) -> Netlist:
    if name not in GADGETS:
        raise KeyError(f"unknown gadget {name!r}; have {sorted(GADGETS)}")
    return GADGETS[name][0]()
