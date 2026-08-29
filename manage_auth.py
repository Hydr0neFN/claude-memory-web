#!/usr/bin/env python3
"""Administer auth.json -- the OAuth sign-in config for the memory web UI.

Run it on the box, as the service user, so the file it writes is already owned
by the account that has to read it:

    sudo -u claudemem /opt/claude-memory/venv/bin/python \\
         /opt/claude-memory/manage_auth.py status

Nothing here restarts the service: main.py re-reads auth.json whenever its
contents change, because a restart is not free -- it is how every deploy
interrupts the store.

The API token is NOT managed here. It stays in .env, it is the break-glass
credential, and no command in this file can weaken it.
"""
import getpass
import json
import os
import stat
import sys
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent / "auth.json"
PROVIDERS = ("google", "github")

USAGE = """usage: manage_auth.py <command> [args]

  status                       what is configured, without printing secrets
  setup <provider> <client-id> <redirect-uri> [email ...]
                               configure a provider; the client secret is read
                               from the terminal, never from argv, so it does
                               not land in shell history or /proc
  allow <provider> <email> ...  add addresses to that provider's allowlist
  deny  <provider> <email> ...  remove addresses
  disable <provider>           forget that provider's config entirely
  sign-out-everyone            invalidate every browser session (bumps keyver)

  <provider> is one of: %s

A provider with no config, or with an empty allowlist, is simply off: its
button does not appear on the login page and its /auth/<provider> route
answers 503. The API token still signs in at / regardless.

MEMORY_AUTH_FILE overrides the file location (default: auth.json next to
main.py). It must NOT be inside data/ -- that is a git repo that keeps every
version of every file in it forever.""" % ", ".join(PROVIDERS)


def path() -> Path:
    return Path(os.environ.get("MEMORY_AUTH_FILE") or DEFAULT_PATH)


def die(message: str) -> None:
    sys.stderr.write("error: %s\n" % message)
    raise SystemExit(2)


def load() -> dict:
    p = path()
    if not p.exists():
        return {"keyver": 1}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        die("%s is not valid JSON (%s); fix or delete it" % (p, exc))
    if not isinstance(data, dict):
        die("%s must contain a JSON object" % p)
    data.setdefault("keyver", 1)
    return data


def save(data: dict) -> None:
    p = path()
    tmp = p.with_suffix(".json.tmp")
    # 0600 before any content is written: between creat() and chmod() the file
    # is world-readable, and this one holds an OAuth client secret.
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(str(tmp), str(p))
    os.chmod(str(p), 0o600)
    print("wrote %s" % p)


def check_provider(name: str) -> str:
    n = (name or "").strip().lower()
    if n not in PROVIDERS:
        die("unknown provider %r; expected one of: %s" % (name, ", ".join(PROVIDERS)))
    return n


def norm(email: str) -> str:
    e = email.strip().lower()
    if "@" not in e or e.startswith("@") or e.endswith("@"):
        die("%r does not look like an e-mail address" % email)
    return e


def cmd_status() -> None:
    p = path()
    data = load()
    print("file        %s%s" % (p, "" if p.exists() else "  (does not exist yet)"))
    if p.exists():
        mode = stat.S_IMODE(p.stat().st_mode)
        print("mode        %o%s" % (mode, "" if mode == 0o600 else "   <-- should be 600"))
    print("keyver      %s" % data.get("keyver", 1))
    for name in PROVIDERS:
        cfg = data.get(name) or {}
        if not cfg:
            print("%-11s not configured" % name)
            continue
        cid = str(cfg.get("client_id") or "")
        print("%-11s client_id  %s" % (name, ("..." + cid[-28:]) if cid else "(missing)"))
        print("            secret     %s" % ("set" if cfg.get("client_secret") else "(missing)"))
        print("            redirect   %s" % (cfg.get("redirect_uri") or "(missing)"))
        allowed = cfg.get("allowed_emails") or []
        if isinstance(allowed, str):
            allowed = [allowed]
        print("            allowed    %s"
              % (", ".join(allowed) if allowed else "(nobody -- this provider is off)"))


def cmd_setup(argv) -> None:
    if len(argv) < 3:
        die("setup needs a provider, a client id and a redirect uri")
    name = check_provider(argv[0])
    client_id, redirect_uri = argv[1].strip(), argv[2].strip()
    emails = [norm(e) for e in argv[3:]]
    if not redirect_uri.startswith("https://"):
        # Every provider here refuses a plain-http redirect outside localhost,
        # and this service is reached through the tunnel even from the LAN, so
        # an http URI is always a typo rather than a deliberate choice.
        die("redirect uri must be https")
    if not redirect_uri.endswith("/auth/%s/callback" % name):
        die("redirect uri should end with /auth/%s/callback -- that is the route "
            "that handles it" % name)
    secret = getpass.getpass("%s client secret: " % name).strip()
    if not secret:
        die("no client secret given")

    data = load()
    cfg = data.get(name) or {}
    cfg.update({"client_id": client_id, "client_secret": secret,
                "redirect_uri": redirect_uri})
    if emails:
        cfg["allowed_emails"] = emails
    cfg.setdefault("allowed_emails", [])
    data[name] = cfg
    save(data)
    if not cfg["allowed_emails"]:
        print("note: the allowlist is empty, so %s sign-in stays off." % name)
        print("      add yourself with:  manage_auth.py allow %s you@example.com" % name)
    cmd_status()


def cmd_allow(argv, add: bool) -> None:
    if len(argv) < 2:
        die("give a provider and at least one e-mail address")
    name = check_provider(argv[0])
    data = load()
    cfg = data.get(name)
    if not cfg:
        die("%s is not configured; run setup first" % name)
    current = cfg.get("allowed_emails") or []
    if isinstance(current, str):
        current = [current]
    current = [str(e).strip().lower() for e in current]
    for email in (norm(e) for e in argv[1:]):
        if add and email not in current:
            current.append(email)
        elif not add and email in current:
            current.remove(email)
    cfg["allowed_emails"] = current
    data[name] = cfg
    save(data)
    cmd_status()


def cmd_disable(argv) -> None:
    if not argv:
        die("say which provider to disable: %s" % ", ".join(PROVIDERS))
    name = check_provider(argv[0])
    data = load()
    if not data.pop(name, None):
        print("%s was not configured; nothing to do" % name)
        return
    save(data)
    print("%s sign-in disabled. The API token still signs in at /." % name)


def cmd_sign_out_everyone() -> None:
    data = load()
    data["keyver"] = int(data.get("keyver", 1)) + 1
    save(data)
    print("keyver is now %d -- every existing browser session is invalid." % data["keyver"])
    print("Agents using the bearer token are unaffected.")


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "status":
        cmd_status()
    elif cmd == "setup":
        cmd_setup(rest)
    elif cmd == "allow":
        cmd_allow(rest, True)
    elif cmd == "deny":
        cmd_allow(rest, False)
    elif cmd == "disable":
        cmd_disable(rest)
    elif cmd == "sign-out-everyone":
        cmd_sign_out_everyone()
    else:
        die("unknown command %r\n\n%s" % (cmd, USAGE))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
