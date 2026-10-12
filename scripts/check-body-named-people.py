#!/usr/bin/env python3
"""A request body never says who is asking (CLAUDE.md rule 4,
docs/SECURITY/REQUEST_ORIGIN.md).

For every handler that decodes a body, this lists the fields that name a
person (requested_by, created_by, updated_by, requester_id, actor, ...) and
fails unless the handler assigns each one before use: from
tenantcheck.ActingFor / tenantcheck.Requester, or c.Actor() on a kernel
route. A field that is data and not the caller (a key's owner, the actor of
an ingested event) is listed, with its reason, in
scripts/body-named-people-allowlist.txt. That list only shrinks.

It reads handler source with regular expressions: a handler it can't follow
needs the assignment written where it can see it, or an allowlist row.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ALLOW = ROOT / "scripts" / "body-named-people-allowlist.txt"
TAGS = (r"(requested_by|created_by|updated_by|deleted_by|approved_by|denied_by|revoked_by|rotated_by|"
        r"acknowledged_by|resolved_by|assigned_by|requester_id|requester_email|requester_ip|actor|actor_id|"
        r"operator|performed_by|initiated_by|triggered_by|owner_id|submitted_by|issued_by|signed_by|changed_by|"
        r"modified_by|uploaded_by|cancelled_by|closed_by|opened_by|reviewed_by|voter_id|approver_id|"
        r"approver_email|voted_by|owner)")
FIELD = re.compile(r"^\s*(\w+)\s+[\w.*\[\]]+\s+`[^`]*json:\"" + TAGS + r"[\",]", re.M)
TYPE = re.compile(r"^type (\w+) struct \{\n(.*?)^\}", re.M | re.S)
FUNC = re.compile(r"^func (?:\([^)]*\) )?(\w+)\(([^)]*)\)[^{\n]*\{\n(.*?)^\}", re.M | re.S)


def assigned(body, var, field):
    # var.Field = ..., alone or in a tuple assignment.
    return re.search(r"\b" + var + r"\." + field + r"\s*(,\s*[\w.]+\s*)*=[^=]", body) is not None


def scan():
    found = []
    for svc in sorted(p for p in (ROOT / "services").iterdir() if p.is_dir()):
        files = sorted(f for f in svc.glob("*.go") if not f.name.endswith("_test.go"))
        types = {}
        for f in files:
            for m in TYPE.finditer(f.read_text()):
                fields = [x.group(1) for x in FIELD.finditer(m.group(2))]
                if fields:
                    types[m.group(1)] = fields
        for f in files:
            for fm in FUNC.finditer(f.read_text()):
                name, params, body = fm.group(1), fm.group(2), fm.group(3)
                if "http.Request" not in params and "route.Call" not in params:
                    continue
                rel = f.relative_to(ROOT).as_posix()
                for vm in re.finditer(r"\bvar (\w+) (\w+)\n", body):
                    var, typ = vm.group(1), vm.group(2)
                    if typ in types and re.search(r"[Dd]ecode\w*\([^)]*&" + var + r"\b", body):
                        found += [(rel, name, g) for g in types[typ] if not assigned(body, var, g)]
                for im in re.finditer(r"var (\w+) struct \{\n(.*?)\n\t\}", body, re.S):
                    found += [(rel, name, x.group(1)) for x in FIELD.finditer(im.group(2)) if not assigned(body, im.group(1), x.group(1))]
    return found


def allowlist():
    rows = {}
    for n, line in enumerate(ALLOW.read_text().splitlines(), 1):
        entry, _, reason = line.partition("#")
        if not entry.strip():
            continue
        parts = entry.split()
        if len(parts) != 3 or not reason.strip():
            sys.exit(f"{ALLOW.name}:{n}: want '<file> <handler> <Field>  # reason'")
        rows[tuple(parts)] = n
    return rows


def main():
    found, allowed = set(scan()), allowlist()
    bad = sorted(found - set(allowed))
    stale = sorted(set(allowed) - found)
    for rel, name, field in bad:
        print(f"  {rel}: {name} takes {field} from the request body")
    for rel, name, field in stale:
        print(f"  {ALLOW.name}: {rel} {name} {field} no longer applies; remove the row")
    if bad:
        print("  bind it: x.Field = tenantcheck.ActingFor(r.Context(), x.Field), tenantcheck.Requester(r, ...) or c.Actor()")
    sys.exit(1 if bad or stale else 0)


if __name__ == "__main__":
    main()
