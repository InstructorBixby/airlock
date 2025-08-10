"""Command line.

`serve` is the one that matters. The rest exist because the two
questions I actually ask of this thing -- "would this be allowed out"
and "why did that call go where it went" -- should not require reading
a JSONL file by hand.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from airlock import (__version__, audit, classify, policy, route,
                     scrubmap, server)
from airlock.detect import roster as roster_mod


def _load(args):
    pol = policy.load(args.policy)
    engagements = roster_mod.load(args.roster)
    return pol, roster_mod.detector(engagements), engagements


def cmd_serve(args) -> int:
    pol, detector, engagements = _load(args)
    log = audit.Log(args.log)
    smap = scrubmap.load(args.map) if args.map else None
    gw = server.Gateway(pol, log, roster_detector=detector,
                        scrubmap=smap)
    httpd = server.serve(gw, args.host, args.port)
    print(f"airlock on http://{args.host}:{args.port}/v1 "
          f"({len(engagements)} engagement(s), policy {pol.source})",
          file=sys.stderr)
    print(f"  export OPENAI_BASE_URL=http://{args.host}:{args.port}/v1",
          file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_check(args) -> int:
    pol, detector, _ = _load(args)
    text = (sys.stdin.read() if args.file == "-"
            else Path(args.file).read_text())
    assessment = classify.classify_text(text,
                                        extra=[("roster", detector)])
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
    log = audit.Log(args.log)
    rec = log.find(args.call)
    if rec is None:
        print(f"airlock: no call matching {args.call!r} in {args.log}",
              file=sys.stderr)
        return 1
    print(rec.explain())
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
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the endpoint")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8111)
    s.add_argument("--map", help="scrubkit mapping, for reversible "
                                 "redaction")
    s.set_defaults(fn=cmd_serve)

    c = sub.add_parser("check", help="classify a file and print the "
                                     "routing decision")
    c.add_argument("file", help="path, or - for stdin")
    c.add_argument("--json", action="store_true")
    c.add_argument("--why", action="store_true",
                   help="print every route considered")
    c.set_defaults(fn=cmd_check)

    w = sub.add_parser("why", help="explain a call from the audit log")
    w.add_argument("call", help="call id, or a unique prefix of one")
    w.set_defaults(fn=cmd_why)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (policy.PolicyError, roster_mod.RosterError,
            scrubmap.MapError) as exc:
        print(f"airlock: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
