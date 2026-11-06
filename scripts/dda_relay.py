#!/usr/bin/env python
"""dda_relay.py — turn Brad's chat yes into a recorded CONFIRMED approval (SPEC §4.5).

Runs on the workdir host, in Brad's own terminal (or a poller acting for
him) — never from an agent tool call (`lockguard` blocks agent-run relay
the same as agent-run `dda approve`). Stdlib only.

Two steps, one per subcommand:

  fetch  find Brad's confirming message in the Telegram update stream and
         print its ids (read-only: getUpdates with NO offset, so nothing
         is consumed; note it polls the same endpoint as the gateway, so
         a 409 while the gateway polls is polling contention, not refusal —
         long term the relay reads from the gateway store).
  relay  record the confirmation: refuse unknown senders before writing
         anything, require the digest Brad confirmed (--digest, 16+ hex,
         compared against the canonical payload before writing), run
         `dda approve`, then walk it with `dda approved`.
         Exits 0 only if the walk comes back human (CONFIRMED/VERIFIED) —
         any failure closes the gate instead of passing it.

Identity rule: the sender id must EXACTLY equal the approver's configured
`telegram_user_id` / `chat_user_id` in the workdir's config.yaml. The ids
go into the record verbatim, so anyone can check the message in the chat.
"""
import argparse
import json
import os
import sys
import urllib.request

REPO_SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)))


def _ddalib():
    if REPO_SCRIPTS not in sys.path:
        sys.path.insert(0, REPO_SCRIPTS)
    from ddalib import approvals  # noqa: E402
    from ddalib.layout import Workdir  # noqa: E402
    return approvals, Workdir


def cmd_fetch(args) -> int:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        print("dda_relay fetch: TELEGRAM_BOT_TOKEN is not set in this environment; "
              "the relay never stores the token, it only borrows it for this read", file=sys.stderr)
        return 2
    body = json.dumps({"limit": args.limit}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/getUpdates",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception as exc:  # network failure closes the gate: no ids, no relay
        print(f"dda_relay fetch: could not reach Telegram ({exc}); relay nothing", file=sys.stderr)
        return 1
    if not data.get("ok"):
        print(f"dda_relay fetch: Telegram said no: {str(data)[:200]}", file=sys.stderr)
        return 1
    hits = 0
    for u in data.get("result", []) or []:
        m = u.get("message") or u.get("edited_message") or {}
        chat = str((m.get("chat") or {}).get("id", ""))
        frm = str((m.get("from") or {}).get("id", ""))
        text = str(m.get("text") or "")
        if chat != args.chat_id or frm != args.user_id:
            continue
        if args.text_contains and args.text_contains not in text:
            continue
        hits += 1
        print(json.dumps({"update_id": u.get("update_id"), "chat_id": chat,
                          "user_id": frm, "message_id": m.get("message_id"),
                          "date": m.get("date"), "text": text}))
    if not hits:
        print("dda_relay fetch: no matching updates pending (already consumed by the "
              "gateway? check the chat log for the message id and pass it by hand)",
              file=sys.stderr)
        return 1
    return 0


def cmd_relay(args) -> int:
    approvals, Workdir = _ddalib()
    wd = Workdir.at(args.workdir)
    try:
        cfg = approvals.load_config(wd)
    except Exception as exc:
        print(f"dda_relay: refusing — config.yaml does not parse ({exc})", file=sys.stderr)
        return 2
    approvers = cfg.get("approvers") or []
    if args.channel == "telegram":
        who = approvals.telegram_approver(approvers, args.user_id)
    elif args.channel == "chat":
        who = approvals.chat_approver(approvers, args.user_id)
    else:
        print(f"dda_relay: refusing — unknown channel {args.channel!r} (telegram, chat)", file=sys.stderr)
        return 2
    if not who:
        # Refusal happens BEFORE anything is written: unknown senders never
        # reach `dda approve`, so the gate cannot pass on a stranger's yes.
        print(f"dda_relay: refusing — {args.channel} user {args.user_id} is not a configured "
              f"approver in this workdir's config.yaml", file=sys.stderr)
        return 2
    kw = {"telegram": (args.user_id, args.message_id)} if args.channel == "telegram" \
        else {"chat": (args.user_id, args.message_id)}
    # Digest pin: Brad confirms a specific digest in the chat. The relay
    # carries it and refuses to write unless it still matches the
    # canonical payload — his yes binds this exact state, not a later one.
    if not args.digest or not approvals._DIGEST16_RE.match(args.digest):
        print("dda_relay: refusing — --digest (16+ hex) is required: pass the digest Brad confirmed",
              file=sys.stderr)
        return 2
    try:
        current = approvals.current_digest(wd, args.kind)
    except Exception as exc:
        print(f"dda_relay: refusing — cannot compute the current {args.kind} digest ({exc})",
              file=sys.stderr)
        return 1
    if current != args.digest and not current.startswith(args.digest):
        print(f"dda_relay: refusing — state moved since Brad's yes "
              f"(confirmed {args.digest[:16]}, current {current[:16]}); capture a fresh yes",
              file=sys.stderr)
        return 1
    try:
        res = approvals.do_approve(wd, args.kind, artifact=args.artifact,
                                   message=args.message, **kw)
    except Exception as exc:
        print(f"dda_relay: refusing — dda approve failed ({exc})", file=sys.stderr)
        return 1
    blk = res.get("telegram") or res.get("chat") or {}
    print(f"approved {res['kind']} {res['digest'][:16]} — commit {res['commit'][:12]} "
          f"(CONFIRMED via {res['method']} user {blk.get('user_id')}, message {blk.get('message_id')})")
    try:
        verdict = approvals.do_approved(wd, args.kind,
                                        artifact=args.artifact or res["digest"])
    except Exception as exc:
        print(f"dda_relay: recorded but the walk failed ({exc}) — gate stays closed", file=sys.stderr)
        return 1
    print(f"{args.kind} {(verdict.get('digest') or '')[:16]}: {verdict['state'].upper()} - "
          f"{approvals.method_label(verdict)}")
    print(f"  {verdict.get('reason')}")
    if not approvals.is_human(verdict.get("state")):
        print("dda_relay: walk did not come back human — gate stays closed", file=sys.stderr)
        return 1
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="dda_relay.py",
                                description="Relay Brad's chat yes into a CONFIRMED approval (SPEC §4.5).")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="peek pending Telegram updates for Brad's yes (read-only)")
    f.add_argument("--chat-id", required=True, help="Telegram chat id holding the yes")
    f.add_argument("--user-id", required=True, help="Brad's Telegram user id (exact)")
    f.add_argument("--text-contains", default="", help="only messages containing this text")
    f.add_argument("--limit", type=int, default=100)
    f.set_defaults(func=cmd_fetch)
    r = sub.add_parser("relay", help="record ids as CONFIRMED and walk the approval")
    r.add_argument("--channel", required=True, choices=("telegram", "chat"))
    r.add_argument("--user-id", required=True, help="sender id, must equal the approver's configured id")
    r.add_argument("--message-id", required=True, help="confirming message id, recorded verbatim")
    r.add_argument("--kind", required=True, help="approval kind: spec, config, ...")
    r.add_argument("--artifact", default=None)
    r.add_argument("--digest", default=None,
                   help="the digest Brad confirmed (16+ hex, required): the relay refuses "
                        "unless it matches the canonical payload")
    r.add_argument("--message", "-m", default=None, help="approval note")
    r.add_argument("workdir", help="the analysis workdir")
    r.set_defaults(func=cmd_relay)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
