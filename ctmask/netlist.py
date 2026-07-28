"""A tiny gate-level netlist with exact Boolean semantics.

Masking verification needs a representation with *exact* semantics, not an
approximation: the whole question is whether a wire's value is independent of a
secret, and a syntactic over-approximation would report every share-touching wire
as leaky, which is the failure mode of naive tools.

So a netlist here is a straight-line Boolean circuit over typed inputs:

  - ``secret``  the sensitive value, before sharing;
  - ``share``   one share of a secret (``x0``, ``x1`` for a 2-sharing);
  - ``mask``    fresh uniform randomness;
  - ``public``  everything else.

Gates are evaluated exactly under a Python truth assignment and symbolically under
z3, and the two must agree — a differential the test suite enforces, because a
verifier whose evaluator disagrees with its solver is proving something other than
what it reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

GATE_KINDS = ("and", "or", "xor", "xnor", "not", "buf")
INPUT_KINDS = ("secret", "share", "mask", "public")


@dataclass(frozen=True)
class Input:
    name: str
    kind: str
    #: for a ``share``, which secret it is a share of; otherwise None
    of_secret: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in INPUT_KINDS:
            raise ValueError(f"{self.name}: kind {self.kind!r} not in {INPUT_KINDS}")
        if self.kind == "share" and not self.of_secret:
            raise ValueError(f"{self.name}: a share must name the secret it shares")


@dataclass(frozen=True)
class Gate:
    name: str
    kind: str
    inputs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.kind not in GATE_KINDS:
            raise ValueError(f"{self.name}: gate kind {self.kind!r} not in {GATE_KINDS}")
        arity = 1 if self.kind in ("not", "buf") else 2
        if len(self.inputs) != arity:
            raise ValueError(f"{self.name}: {self.kind} takes {arity} input(s)")


@dataclass
class Netlist:
    name: str
    inputs: list[Input] = field(default_factory=list)
    gates: list[Gate] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)

    # -- construction -------------------------------------------------------
    def add_input(self, name: str, kind: str, of_secret: str | None = None) -> str:
        self._fresh(name)
        self.inputs.append(Input(name, kind, of_secret))
        return name

    def add_gate(self, name: str, kind: str, *inputs: str) -> str:
        self._fresh(name)
        for i in inputs:
            if i not in self.wires:
                raise ValueError(f"{name}: input {i!r} is not defined yet")
        self.gates.append(Gate(name, kind, tuple(inputs)))
        return name

    def _fresh(self, name: str) -> None:
        if name in self.wires:
            raise ValueError(f"duplicate wire {name!r}")

    # -- queries ------------------------------------------------------------
    @property
    def wires(self) -> list[str]:
        return [i.name for i in self.inputs] + [g.name for g in self.gates]

    @property
    def input_names(self) -> list[str]:
        return [i.name for i in self.inputs]

    def by_kind(self, kind: str) -> list[Input]:
        return [i for i in self.inputs if i.kind == kind]

    def secrets(self) -> list[str]:
        """Every secret named, whether present as an input or only via its shares."""
        named = {i.name for i in self.by_kind("secret")}
        named |= {i.of_secret for i in self.by_kind("share") if i.of_secret}
        return sorted(named)

    def shares_of(self, secret: str) -> list[str]:
        return [i.name for i in self.by_kind("share") if i.of_secret == secret]

    def masks(self) -> list[str]:
        return [i.name for i in self.by_kind("mask")]

    def probes(self) -> list[str]:
        """Every internal wire an adversary may probe: the gates."""
        return [g.name for g in self.gates]

    # -- semantics ----------------------------------------------------------
    def symbolic(self, env: dict[str, z3.BoolRef] | None = None) -> dict[str, z3.BoolRef]:
        """Evaluate every wire symbolically under z3."""
        v: dict[str, z3.BoolRef] = dict(env or {})
        for i in self.inputs:
            v.setdefault(i.name, z3.Bool(i.name))
        for g in self.gates:
            a = v[g.inputs[0]]
            if g.kind == "not":
                v[g.name] = z3.Not(a)
            elif g.kind == "buf":
                v[g.name] = a
            elif g.kind == "and":
                v[g.name] = z3.And(a, v[g.inputs[1]])
            elif g.kind == "or":
                v[g.name] = z3.Or(a, v[g.inputs[1]])
            elif g.kind == "xor":
                v[g.name] = z3.Xor(a, v[g.inputs[1]])
            else:  # xnor
                v[g.name] = z3.Not(z3.Xor(a, v[g.inputs[1]]))
        return v

    def evaluate(self, assignment: dict[str, bool]) -> dict[str, bool]:
        """Evaluate every wire concretely. Used to cross-check the symbolic path."""
        v: dict[str, bool] = {}
        for i in self.inputs:
            if i.name not in assignment:
                raise KeyError(f"no value for input {i.name!r}")
            v[i.name] = bool(assignment[i.name])
        for g in self.gates:
            a = v[g.inputs[0]]
            if g.kind == "not":
                v[g.name] = not a
            elif g.kind == "buf":
                v[g.name] = a
            else:
                b = v[g.inputs[1]]
                v[g.name] = {
                    "and": a and b,
                    "or": a or b,
                    "xor": a != b,
                    "xnor": a == b,
                }[g.kind]
        return v
