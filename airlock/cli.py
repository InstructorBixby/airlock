"""Command line.

`serve` is the one that matters. The rest exist because the questions
asked of this thing -- would this be allowed out, why did that call go
where it went, what has this engagement cost, did anything leave, is
the record intact, does this policy fail closed -- should not require
reading a JSONL file by hand at the end of a long week.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from airlock import (audit, classify, conformance, deprecations,
                     engagement, policy, policylint, prove, route,
                     scrubmap, selftest, server, spend, version)
from airlock.detect import roster as roster_mod
from airlock.detect import scope as scope_mod


def _engagement(args):
    if not getattr(args, "engagement", None):
        return None
    return engagement.load(Path(args.engagements) / args.engagement)


def _detectors(args, eng):
    extra = []
    if Path(args.roster).exists():
        extra.append(("roster", roster_mod.detector(
            roster_mod.load(args.roster))))
    if eng is not None:
        if eng.scope is not None:
            extra.append(("scope", scope_mod.from_file(eng.scope,
                                                       eng.id)))
        if eng.extra_terms:
            extra.append(("terms", roster_mod.terms_detector(
                eng.extra_terms, eng.id)))
    return extra


def _assemble(args, *, require_roster=True):
    pol = policy.load(args.policy)
    if require_roster and not Path(args.roster).exists():
        raise roster_mod.RosterError(
            f"no roster at {args.roster}; refusing to start, because "
            f"an absent roster classifies client material as public")
    eng = _engagement(args)
    extra = _detectors(args, eng)
    smap = None
    if eng is not None:
        smap = scrubmap.load(
            eng.map_path, engagement=eng.id,
            key=scrubmap.engagement_key(eng.key_path))
    elif getattr(args, "scrubmap", None):
        smap = scrubmap.load(args.scrubmap)
    return pol, extra, smap, eng


def cmd_serve(args) -> int:
    pol, extra, smap, eng = _assemble(args)
    if args.selftest:
        try:
            report = selftest.run(pol, detectors=extra)
        except selftest.SelfTestFailed as exc:
            print(exc.report.text(), file=sys.stderr)
            print(f"airlock: {exc}; not serving", file=sys.stderr)
            return 3
        print(f"selftest: {len(report.outcomes)} fail-closed case(s) "
              f"hold for {pol.source}", file=sys.stderr)
    else:
        print("airlock: starting WITHOUT a selftest; nothing has been "
              "proved about this policy", file=sys.stderr)

    log = audit.Log(args.log)
    gw = server.Gateway(pol, log, detectors=extra, scrubmap=smap,
                        engagement=eng)
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
    httpd = server.serve(gw, args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        audit.head_path(args.log).write_text(log.head + "\n")
    return 0


def cmd_check(args) -> int:
    pol, extra, _, _ = _assemble(args, require_roster=False)
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
    print(spend.report(spend.totals(audit.Log(args.log).records(),
                                    engagement=args.engagement)))
    return 0


def cmd_prove(args) -> int:
    pol = policy.load(args.policy)
    local = [name for name, be in pol.backends.items() if be.is_local]
    proof = prove.prove(audit.Log(args.log).records(),
                        args.engagement_id, local_backends=local)
    print(proof.text())
    return 0 if proof.verdict == prove.CLEAN else 1


def cmd_verify(args) -> int:
    log = audit.Log(args.log)
    expect = args.head
    hp = audit.head_path(args.log)
    if expect is None and hp.exists():
        expect = hp.read_text().strip()
    breaks = log.verify(expect_head=expect)
    if not breaks:
        n = sum(1 for _ in log.records())
        print(f"{n} record(s), chain intact, head {log.head[:19]}")
        return 0
    for b in breaks:
        print(str(b), file=sys.stderr)
    return 1


def cmd_policy(args) -> int:
    errors, notes = policylint.lint(args.policy)
    for n in notes:
        print(n)
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"{args.policy}: ok")
    return 0


def cmd_conformance(args) -> int:
    pol = policy.load(args.policy)
    cases = conformance.load_cases(args.cases)
    eng = _engagement(args)
    report = conformance.run(pol, cases,
                             detectors=_detectors(args, eng))
    print(report.text())
    return 1 if report.failed else 0


def cmd_doctor(args) -> int:
    from airlock import doctor
    print(doctor.report(doctor.checks(args.host, args.port)))
    return 0


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
    # Names the build, not just the release: a stale install on this
    # machine is the realistic version of "a control that reports
    # clean while doing nothing".
    p.add_argument("--version", action="version",
                   version=f"airlock {version.describe()}")
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
    s.add_argument("--scrubmap",
                   help="scrubkit mapping, when not using -e")
    s.add_argument("--selftest", action=argparse.BooleanOptionalAction,
                   default=True,
                   help="prove the fail-closed cases hold before "
                        "serving (default: on)")
    s.set_defaults(fn=cmd_serve)

    c = sub.add_parser("check", help="classify a file and print the "
                                     "routing decision")
    c.add_argument("file", help="path, or - for stdin")
    c.add_argument("--json", action="store_true")
    c.add_argument("--why", action="store_true")
    c.add_argument("--scrubmap")
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

    v = sub.add_parser("verify", help="check the audit chain")
    v.add_argument("--head", help="expected head digest; defaults to "
                                  "the recorded one")
    v.set_defaults(fn=cmd_verify)

    pl = sub.add_parser("policy", help="validate a policy file")
    pl.add_argument("action", choices=["lint"])
    pl.set_defaults(fn=cmd_policy)

    cf = sub.add_parser("conformance",
                        help="prove this policy fails closed")
    cf.add_argument("--cases", help="a cases file of your own")
    cf.set_defaults(fn=cmd_conformance)

    dr = sub.add_parser("doctor", help="what would bypass the gateway")
    dr.add_argument("--host", default="127.0.0.1")
    dr.add_argument("--port", type=int, default=8111)
    dr.set_defaults(fn=cmd_doctor)

    sub.add_parser("engagements",
                   help="list the engagement profiles found"
                   ).set_defaults(fn=cmd_engagements)
    return p


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = build_parser().parse_args(deprecations.rewrite_argv(argv))
    try:
        return args.fn(args)
    except (policy.PolicyError, roster_mod.RosterError,
            scope_mod.ScopeError, engagement.EngagementError,
            scrubmap.MapError) as exc:
        print(f"airlock: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
