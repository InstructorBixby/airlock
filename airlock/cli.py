"""Command line.

`serve` is the one that matters. The rest exist because the questions I
actually ask of this thing -- would this be allowed out, why did that
call go where it went, what has this engagement cost, did anything
leave -- should not require reading a JSONL file by hand.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from airlock import (__version__, audit, classify, engagement, policy,
                     prove, route, scrubmap, server, spend)
from airlock.detect import roster as roster_mod
from airlock.detect import scope as scope_mod


def _engagement(args):
    if not args.engagement:
        return None
    return engagement.load(Path(args.engagements) / args.engagement)


def _assemble(args):
    """Policy, detectors and map for this invocation."""
    pol = policy.load(args.policy)
    extra = [("roster", roster_mod.detector(
        roster_mod.load(args.roster)))]
    eng = _engagement(args)
    smap = None
    if eng is not None:
        if eng.scope is not None:
            extra.append(("scope", scope_mod.from_file(eng.scope,
                                                       eng.id)))
        if eng.extra_terms:
            extra.append(("terms", roster_mod.terms_detector(
                eng.extra_terms, eng.id)))
        smap = scrubmap.load(
            eng.map_path, engagement=eng.id,
            key=scrubmap.engagement_key(eng.key_path))
    elif getattr(args, "map", None):
        smap = scrubmap.load(args.map)
    return pol, extra, smap, eng


def cmd_serve(args) -> int:
    pol, extra, smap, eng = _assemble(args)
    log = audit.Log(args.log)
    gw = server.Gateway(pol, log, detectors=extra, scrubmap=smap,
                        engagement=eng)
    httpd = server.serve(gw, args.host, args.port)
    label = f", engagement {eng.id}" if eng else ""
    print(f"airlock on http://{args.host}:{args.port}/v1 "
          f"(policy {pol.source}{label})", file=sys.stderr)
    print(f"  export OPENAI_BASE_URL=http://{args.host}:{args.port}/v1",
          file=sys.stderr)
    if eng is not None and eng.deny_hosted:
        print("  hosted is denied for this engagement", file=sys.stderr)
    if gw.ceiling is not None:
        print(f"  spend ${gw.spent():.2f} of ${gw.ceiling:.2f}",
              file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_check(args) -> int:
    pol, extra, _, _ = _assemble(args)
    text = (sys.stdin.read() if args.file == "-"
            else Path(args.file).read_text())
    assessment = classify.classify_text(text, extra=extra)
    decision = route.decide(pol, assessment, check_available=False)
    if args.json:
        print(json.dumps({"assessment": assessment.to_json(),
                          "allowed": decision.allowed,
                          "backend": decision.backend,
                          "refusal": decision.refusal}, indent=1))
    elif args.why:
        print(decision.explain())
    else:
        verb = "allow" if decision.allowed else "refuse"
        print(f"{assessment.tier}: {verb}"
              + (f" via {decision.backend}" if decision.allowed
                 else f" -- {decision.refusal}"))
    return 0 if decision.allowed else 1


def cmd_why(args) -> int:
    rec = audit.Log(args.log).find(args.call)
    if rec is None:
        print(f"airlock: no call matching {args.call!r} in {args.log}",
              file=sys.stderr)
        return 1
    print(rec.explain())
    return 0


def cmd_spend(args) -> int:
    eng = args.engagement
    totals = spend.totals(audit.Log(args.log).records(),
                          engagement=eng)
    print(spend.report(totals))
    return 0


def cmd_prove(args) -> int:
    pol = policy.load(args.policy)
    local = [name for name, be in pol.backends.items() if be.is_local]
    proof = prove.prove(audit.Log(args.log).records(),
                        args.engagement_id, local_backends=local)
    print(proof.text())
    return 0 if proof.verdict == prove.CLEAN else 1


def cmd_engagements(args) -> int:
    found = engagement.discover(args.engagements)
    if not found:
        print(f"no engagements under {args.engagements}")
        return 1
    for eng in found.values():
        bits = []
        if eng.scope is not None:
            bits.append("scope")
        if eng.extra_terms:
            bits.append(f"{len(eng.extra_terms)} term(s)")
        if eng.max_cost_usd is not None:
            bits.append(f"ceiling ${eng.max_cost_usd:.2f}")
        if eng.deny_hosted:
            bits.append("hosted denied")
        print(f"{eng.id:24} {', '.join(bits) or '-'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="airlock",
        description="policy gateway for model calls")
    p.add_argument("--version", action="version",
                   version=f"airlock {__version__}")
    p.add_argument("--policy", default=str(policy.default_path()))
    p.add_argument("--roster", default="roster.yaml")
    p.add_argument("--log", default=str(audit.default_path()))
    p.add_argument("--engagements", default="engagements")
    p.add_argument("-e", "--engagement",
                   help="load this engagement's profile, scope and map")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the endpoint")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8111)
    s.add_argument("--map", help="scrubkit mapping, when not using -e")
    s.set_defaults(fn=cmd_serve)

    c = sub.add_parser("check", help="classify a file and print the "
                                     "routing decision")
    c.add_argument("file", help="path, or - for stdin")
    c.add_argument("--json", action="store_true")
    c.add_argument("--why", action="store_true")
    c.add_argument("--map")
    c.set_defaults(fn=cmd_check)

    w = sub.add_parser("why", help="explain a call from the audit log")
    w.add_argument("call", help="call id, or a unique prefix of one")
    w.set_defaults(fn=cmd_why)

    sub.add_parser("spend", help="what has been spent, by engagement"
                   ).set_defaults(fn=cmd_spend)

    pr = sub.add_parser("prove", help="did anything for this "
                                      "engagement reach a third party")
    pr.add_argument("engagement_id")
    pr.set_defaults(fn=cmd_prove)

    sub.add_parser("engagements",
                   help="list the engagement profiles found"
                   ).set_defaults(fn=cmd_engagements)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (policy.PolicyError, roster_mod.RosterError,
            scope_mod.ScopeError, engagement.EngagementError,
            scrubmap.MapError) as exc:
        print(f"airlock: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
