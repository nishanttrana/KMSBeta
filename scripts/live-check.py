#!/usr/bin/env python3
"""Signed-in check of the running stack: every parameterless GET the dashboard
makes (docs/generated/frontend-calls.csv) is sent through the edge with a real
session token. Run it after a deploy or rebuild (CLAUDE.md).

A call fails when the service answers 401 (it could not verify a valid token;
the dashboard would sign the user out), 5xx, or the router's own 404 (the
route is not registered). 200, 403 and other 4xx pass:
the account used is the bootstrap CLI user, which holds few permissions, so
this proves each service verifies tokens and answers, not that a page's data
is right.

Each route is then asked twice more, and must not answer 2xx:
  - with no token at all, unless it is listed in PUBLIC;
  - signed in, but naming a tenant the account is not in, unless it is listed
    in SAME_FOR_EVERY_TENANT.
Until 13.0.0-beta KMIP's management API answered without a token, and
autokey, signing and KMIP answered for whichever tenant was named. A new
route that is public or platform-wide by design is added to its list with
the reason; anything else that answers is a fault.

Credentials are read from .env (AUTH_BOOTSTRAP_CLI_USERNAME / _PASSWORD,
AUTH_BOOTSTRAP_TENANT_ID) or the LIVE_CHECK_USER / LIVE_CHECK_PASSWORD /
LIVE_CHECK_TENANT environment variables. Nothing secret is printed or put on
a command line.

  scripts/live-check.py [--base https://127.0.0.1] [--ca internal-ca.crt]
"""
import argparse
import csv
import json
import os
import subprocess
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def dotenv():
    out = {}
    try:
        with open(os.path.join(ROOT, ".env"), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                out[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def running_services():
    """Compose services with a running container, or None if docker can't say."""
    try:
        res = subprocess.run(
            ["docker", "ps", "--format", '{{.Label "com.docker.compose.service"}}'],
            capture_output=True, text=True, timeout=20, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return {s.strip() for s in res.stdout.splitlines() if s.strip()}


# /svc/<name> prefixes whose compose service has another name.
COMPOSE_NAME = {"cluster": "cluster-manager"}

# Routes that answer without a token by design.
PUBLIC = {
    ("auth", "/auth/sso/providers"): "the sign-in page lists a tenant's enabled sign-in buttons before anyone is signed in",
}

# Routes whose answer holds no tenant's data: the same for whichever tenant
# is named.
SAME_FOR_EVERY_TENANT = {
    ("audit", "/audit/config"): "the audit service's own settings (fail-closed, WAL size)",
    ("auth", "/auth/sso/providers"): "public, see PUBLIC",
    ("certs", "/certs/protocols/schema"): "the protocols the service can speak",
    ("certs", "/certs/security/status"): "the service's own crypto state",
    ("compliance", "/compliance/frameworks"): "the built-in framework catalogue",
}

# A tenant no account is in. It need not exist: a route must refuse it for
# this caller before it looks anything up.
OTHER_TENANT = "live-check-not-my-tenant"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://127.0.0.1")
    ap.add_argument("--ca", default=os.environ.get("LIVE_CHECK_CA", ""))
    args = ap.parse_args()

    host = urllib.parse.urlsplit(args.base).hostname or ""
    if args.ca:
        trust = ["--cacert", args.ca]
    elif host in ("127.0.0.1", "localhost", "::1"):
        trust = ["--insecure"]  # loopback only; pass --ca elsewhere
    else:
        sys.exit("refusing an unverified connection to a non-loopback host: pass --ca")

    env = dotenv()
    user = os.environ.get("LIVE_CHECK_USER") or env.get("AUTH_BOOTSTRAP_CLI_USERNAME") or "cli-user"
    tenant = os.environ.get("LIVE_CHECK_TENANT") or env.get("AUTH_BOOTSTRAP_TENANT_ID") or "root"
    password = os.environ.get("LIVE_CHECK_PASSWORD") or env.get("AUTH_BOOTSTRAP_CLI_PASSWORD") or ""
    if not password:
        sys.exit("no credential: set LIVE_CHECK_PASSWORD or AUTH_BOOTSTRAP_CLI_PASSWORD in .env")

    def quoted(value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def call(path, token=None, body=None, as_tenant=None):
        # curl speaks TLS 1.3 where the system Python may not (the edge accepts
        # nothing older). The URL, the
        # token and the body go to it on stdin, never on its command line.
        config = [f"url = {quoted(args.base + path)}",
                  'header = "Content-Type: application/json"',
                  f"header = {quoted('X-Tenant-ID: ' + (as_tenant or tenant))}"]
        if token:
            config.append(f"header = {quoted('Authorization: Bearer ' + token)}")
        if body is not None:
            config.append(f"data = {quoted(json.dumps(body))}")
        try:
            res = subprocess.run(
                ["curl", "--silent", "--max-time", "20", *trust,
                 "--write-out", "\n%{http_code}", "--config", "-"],
                input="\n".join(config).encode(), capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError) as err:
            return 0, str(err).encode()
        raw, _, code = res.stdout.rpartition(b"\n")
        return (int(code) if code.isdigit() else 0), raw

    status, raw = call("/svc/auth/auth/login", body={"tenant_id": tenant, "username": user, "password": password})
    if status != 200:
        sys.exit(f"sign-in as {user} failed: HTTP {status}")
    token = json.loads(raw).get("access_token", "")
    if not token:
        sys.exit("sign-in returned no token")

    with open(os.path.join(ROOT, "docs/generated/frontend-calls.csv"), encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh)
                if r["method"].upper() == "GET" and "{" not in r["normalized_path"] and not r["service"].startswith("$")]
    targets = sorted({(r["service"], r["normalized_path"]) for r in rows})
    running = running_services()

    counts, failures, skipped = {}, [], set()
    for service, path in targets:
        if running is not None and COMPOSE_NAME.get(service, service) not in running:
            skipped.add(service)
            continue
        status, raw = call(f"/svc/{service}{path}?tenant_id={urllib.parse.quote(tenant)}", token=token)
        counts[status] = counts.get(status, 0) + 1
        # A plain-text 404 is the router's own: the dashboard calls a route
        # that is not registered. A JSON 404 is a handler's "not found".
        no_route = status == 404 and raw.strip() == b"404 page not found"
        if status == 401 or status >= 500 or status == 0 or no_route:
            message = ""
            try:
                message = str(json.loads(raw).get("error", {}).get("message", ""))
            except (ValueError, AttributeError):
                message = raw.decode("utf-8", "replace")
            failures.append((service, path, status, message.replace(token, "<token>")[:120]))

        # The same route with no token, and for a tenant this account is not in.
        if (service, path) not in PUBLIC:
            anon, _ = call(f"/svc/{service}{path}?tenant_id={urllib.parse.quote(tenant)}")
            if 200 <= anon < 300:
                failures.append((service, path, anon, "answers without a token"))
        if (service, path) not in SAME_FOR_EVERY_TENANT:
            other, _ = call(f"/svc/{service}{path}?tenant_id={OTHER_TENANT}", token=token, as_tenant=OTHER_TENANT)
            if 200 <= other < 300:
                failures.append((service, path, other, f"answers {user}@{tenant} for another tenant"))

    print(f"live check: {len(targets) - sum(counts.values())} skipped, {sum(counts.values())} calls as {user}@{tenant}: "
          + ", ".join(f"{n} x {s}" for s, n in sorted(counts.items())))
    print(f"each also asked with no token ({len(PUBLIC)} public by design) and for another tenant "
          f"({len(SAME_FOR_EVERY_TENANT)} the same for every tenant)")
    if skipped:
        print("not deployed (no running container): " + ", ".join(sorted(skipped)))
    for service, path, status, message in failures:
        print(f"FAIL  {status or 'no response'}  {service} {path}  {message}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
