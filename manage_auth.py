#!/usr/bin/env python3
"""Administer auth.json -- the Google sign-in config for the memory web UI.

Run it on the box, as the service user, so the file it writes is already owned
by the account that has to read it:

    sudo -u claudemem /opt/claude-memory/venv/bin/python \\
         /opt/claude-memory/manage_auth.py status

Nothing here restarts the service: main.py re-reads auth.json whenever its
mtime changes, because a restart is not free -- it is how every deploy
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

USAGE = """usage: manage_auth.py <command> [args]

  status                       what is configured, without printing secrets
  setup <client-id> <redirect-uri> [email ...]
                               configure Google sign-in; the client secret is
                               read from the terminal, never from argv, so it
                               does not land in shell history or /proc
  allow <email> [email ...]    add addresses to the allowlist
  deny  <email> [email ...]    remove addresses
  disable-google               forget the Google config entirely
  sign-out-everyone            invalidate every browser session (bumps keyver)

MEMORY_AUTH_FILE overrides the file location (default: auth.json next to
main.py). It must NOT be inside data/ -- that is a git repo that keeps every
version of every file in it forever."""


def path() -> Path:
    return Path(os.environ.get("MEMORY_AUTH_FILE") or DEFAULT_PATH)


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


def die(message: str) -> None:
    sys.stderr.write("error: %s\n" % message)
    raise SystemExit(2)


def norm(email: str) -> str:
    e = email.strip().lower()
    if "@" not in e or e.startswith("@") or e.endswith("@"):
        die("%r does not look like an e-mail address" % email)
    return e


def cmd_status() -> None:
    p = path()
    data = load()
    google = data.get("google") or {}
    print("file        %s%s" % (p, "" if p.exists() else "  (does not exist yet)"))
    if p.exists():
        mode = stat.S_IMODE(p.stat().st_mode)
        print("mode        %o%s" % (mode, "" if mode == 0o600 else "   <-- should be 600"))
    print("keyver      %s" % data.get("keyver", 1))
    if not google:
        print("google      not configured (token sign-in only)")
        return
    cid = str(google.get("client_id") or "")
    print("google      client_id  ...%s" % (cid[-28:] if cid else "(missing)"))
    print("            secret     %s" % ("set" if google.get("client_secret") else "(missing)"))
    print("            redirect   %s" % (google.get("redirect_uri") or "(missing)"))
    allowed = google.get("allowed_emails") or []
    print("            allowed    %s" % (", ".join(allowed) if allowed else "(nobody -- nobody can sign in)"))


def cmd_setup(argv) -> None:
    if len(argv) < 2:
        die("setup needs a client id and a redirect uri")
    client_id, redirect_uri = argv[0].strip(), argv[1].strip()
    emails = [norm(e) for e in argv[2:]]
    if not redirect_uri.startswith("https://"):
        # Google only accepts https redirect URIs outside localhost, and this
        # service is reached through the tunnel even from the LAN, so a plain
        # http URI here is always a typo rather than a deliberate choice.
        die("redirect uri must be https (Google rejects anything else here)")
    secret = getpass.getpass("Google client secret: ").strip()
    if not secret:
        die("no client secret given")

    data = load()
    google = data.get("google") or {}
    google.update({
        "client_id": client_id,
        "client_secret": secret,
        "redirect_uri": redirect_uri,
    })
    if emails:
        google["allowed_emails"] = emails
    google.setdefault("allowed_emails", [])
    data["google"] = google
    save(data)
    if not google["allowed_emails"]:
        print("note: the allowlist is empty, so nobody can sign in yet.")
        print("      add yourself with:  manage_auth.py allow you@example.com")
    cmd_status()


def cmd_allow(argv, add: bool) -> None:
    if not argv:
        die("give at least one e-mail address")
    data = load()
    google = data.get("google")
    if not google:
        die("Google sign-in is not configured; run setup first")
    current = [str(e).strip().lower() for e in (google.get("allowed_emails") or [])]
    for email in (norm(e) for e in argv):
        if add and email not in current:
            current.append(email)
        elif not add and email in current:
            current.remove(email)
    google["allowed_emails"] = current
    data["google"] = google
    save(data)
    cmd_status()


def cmd_disable_google() -> None:
    data = load()
    if not data.pop("google", None):
        print("Google sign-in was not configured; nothing to do")
        return
    save(data)
    print("Google sign-in disabled. The API token still signs in at /.")


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
    elif cmd == "disable-google":
        cmd_disable_google()
    elif cmd == "sign-out-everyone":
        cmd_sign_out_everyone()
    else:
        die("unknown command %r\n\n%s" % (cmd, USAGE))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
