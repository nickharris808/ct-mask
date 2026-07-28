"""ct-mask command line."""

from __future__ import annotations

import argparse
import json
import sys

from .analysis import analyse
from .gadgets import GADGETS, build


def _fmt(r) -> str:
    d = r.to_dict()
    lines = [
        f"{r.gadget}",
        "=" * 66,
        f"  model             {r.model}",
        f"  verdict           {d['verdict']}",
        "",
        "  probe            secure  certificate   refreshed by",
        "  " + "-" * 56,
    ]
    lines.extend(
        f"  {p.probe:<15} {'yes' if p.secure else 'NO ':<7} "
        f"{(p.certificate or '-'):<13} {p.masking_wire or '-'}"
        for p in r.probes
    )
    if r.leaky_probes:
        lines += ["", "  LEAKY PROBES (these recombine a secret):"]
        for p in r.probes:
            if not p.secure:
                touched = "; ".join(f"{s}: {', '.join(v)}" for s, v in p.touches.items() if v)
                lines.append(f"    {p.probe}  touches  {touched}")
    lines += [
        "",
        (f"  modelled leakage over {r.secret_classes} secret classes"
         " (Hamming weight, glitch-free, unit weight):"),
        f"    mean invariant across classes           {r.mean_invariant}",
        f"    whole distribution invariant            {r.distribution_invariant}",
    ]
    if r.mean_invariant and r.distribution_invariant is False:
        lines.append(
            "    -> first-order secure. An adversary observing more than a mean is\n"
            "       NOT covered by this verdict; that is a limit, not a defect."
        )
    return "\n".join(lines)


def _cmd_check(args) -> int:
    names = args.gadgets or sorted(GADGETS)
    reports = [analyse(build(n)) for n in names]
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        for r in reports:
            print(_fmt(r))
            print()
    return 0 if all(r.secure for r in reports) else 1


def _cmd_corpus(args) -> int:
    """Run every gadget and check it against its expected verdict."""
    bad = 0
    for name, (_, expected) in sorted(GADGETS.items()):
        r = analyse(build(name), measure_leakage=False)
        got = "SECURE" if r.secure else "LEAKY"
        ok = got == expected
        bad += not ok
        print(f"  [{'ok ' if ok else 'BAD'}] {name:<18} {got:<7} expected {expected}")
    print(f"\n  {len(GADGETS) - bad}/{len(GADGETS)} gadgets classified correctly")
    return 0 if bad == 0 else 1


def _cmd_list(args) -> int:
    for name, (builder, expected) in sorted(GADGETS.items()):
        doc = (builder.__doc__ or "").strip().splitlines()[0]
        print(f"  {name:<18} {expected:<7} {doc}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ct-mask",
        description="First-order masking verification by two independent certificates.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="analyse gadgets (default: all)")
    c.add_argument("gadgets", nargs="*")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=_cmd_check)

    b = sub.add_parser("corpus", help="run the whole corpus against expected verdicts")
    b.set_defaults(func=_cmd_corpus)

    lst = sub.add_parser("list", help="list the bundled gadgets")
    lst.set_defaults(func=_cmd_list)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
