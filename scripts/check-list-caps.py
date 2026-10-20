#!/usr/bin/env python3
"""No caller asks a list for more rows than it returns.

Most store list functions shrink a request above their maximum to a default
(`if limit <= 0 || limit > 500 { limit = 100 }`) without an error. Callers
that asked for 1000-10000 rows got 100 and took them for the whole set: the
certificate expiry sweep, the enterprise key audit and compromise-advisory
ingest, the CBOM, crypto discovery, compliance, PQC inventory, and the signing
and key-access summaries (13.21.0-beta, 13.24.0-beta). A caller that needs
everything pages through at the maximum (`allCertificates`, `allKeys`,
`AllCertificates`).

The check finds every Go function that shrinks its limit that way, and every
function whose body only passes its arguments on to one, and fails on a
non-test call to a function of that name with a numeric argument above the
maximum. Functions are matched by name and held to the smallest maximum
among them, so a same-named HTTP client is held to the store's.

  scripts/check-list-caps.py      exit 1 and list the calls on failure
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = [p for d in ("services", "pkg") for p in (ROOT / d).rglob("*.go") if not p.name.endswith("_test.go")]

FUNC = re.compile(r"^func (?:\([^)]*\) )?(\w+)\(", re.M)
SHRINK = re.compile(r"if limit <= 0 \|\| limit > (\d+) \{\s*limit = (\d+)\s*\}")
PASS_ON = re.compile(r"^\s*return \w+\.(\w+)\(")


def bodies(src):
    """(name, body) for each top-level function, the body cut at the next func."""
    starts = [(m.start(), m.group(1)) for m in FUNC.finditer(src)]
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(src)
        yield name, src[pos:end]


# A cap is any "limit > N" that resets limit, whether to a default or to N
# itself: either way a larger request silently gets fewer rows. N may be a
# constant, and the reset may be done by a helper (keycore keyPageLimit).
CAP = re.compile(r"if limit <= 0 \|\| limit > (\w+) \{\s*limit = |if limit > (\w+) \{\s*(?:limit = |return )")
HELPER_CALL = re.compile(r"limit = (\w+)\(limit\)")
CONST = re.compile(r"^\s*(?:const\s+)?(\w+)\s*=\s*(\d+)\s*$", re.M)

consts = {}
sources = {path: path.read_text(encoding="utf-8", errors="replace") for path in FILES}
for src in sources.values():
    for name, value in CONST.findall(src):
        consts.setdefault(name, int(value))


def value(token):
    return int(token) if token.isdigit() else consts.get(token)


caps = {}
helper_calls = {}
passers = {}
for path, src in sources.items():
    for name, body in bodies(src):
        head = body[:1500]
        m = CAP.search(head)
        if m:
            v = value(m.group(1) or m.group(2))
            if v:
                caps[name] = min(caps.get(name, 1 << 30), v)
                continue
        h = HELPER_CALL.search(head)
        if h:
            helper_calls.setdefault(name, set()).add(h.group(1))
            continue
        lines = [l for l in body.splitlines()[1:] if l.strip() and l.strip() != "}"]
        if len(lines) == 1:
            p = PASS_ON.match(lines[0])
            if p:
                passers.setdefault(name, set()).add(p.group(1))
for links in (helper_calls, passers):
    for name, targets in links.items():
        for t in targets:
            if t in caps:
                caps[name] = min(caps.get(name, 1 << 30), caps[t])
# A helper that only computes the page size is not itself a list.
for name in {t for ts in helper_calls.values() for t in ts}:
    caps.pop(name, None)

failures = []
call = re.compile(r"\.(\w+)\(([^()]*(?:\([^()]*\)[^()]*)*)\)")
number = re.compile(r"(?<![\w.\"])(\d{3,7})(?![\w.\"])")
for path, src in sources.items():
    for m in call.finditer(src):
        cap = caps.get(m.group(1))
        if cap is None:
            continue
        for n in number.findall(m.group(2)):
            if int(n) > cap:
                line = src.count("\n", 0, m.start()) + 1
                failures.append(f"{path.relative_to(ROOT)}:{line}: {m.group(1)}(... {n} ...) returns at most {cap}; page through instead")

if failures:
    print("FAIL [list-cap]: a list call asks for more rows than the list returns, and silently gets fewer")
    for f in failures:
        print("  " + f)
    sys.exit(1)
print(f"PASS [list-cap] ({len(caps)} capped list functions)")
