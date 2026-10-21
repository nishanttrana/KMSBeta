#!/usr/bin/env python3
"""Generate the Helm chart's stack description from docker-compose.yml.

The chart (deploy/helm/vecta-kms) runs one KMS node as one pod, container for
container what docker-compose.yml runs on one host (docs/KUBERNETES.md). This
script reads the resolved compose model (`docker compose config --format json`,
made by scripts/helm-chart.sh with placeholder secrets) and writes:

  files/stack.json   every service: image, entrypoint, command, user,
                     environment, ports, health check, mounts, resources,
                     profiles; secrets as references, never values
  files/infra/...    the files compose bind-mounts (Envoy, Postgres, NATS,
                     Valkey, Consul configuration, tls-entry.sh, ...)

Usage: generate_helm_chart.py <compose.json> <repo root> <chart dir>
It fails on anything it cannot carry to Kubernetes faithfully: two services
on one port, a writable volume with no known owner, an unknown mount type.
"""
import json
import os
import re
import shutil
import sys

SECRET_RE = re.compile(r"__VECTA_SECRET_([A-Z0-9_]+)__")
VERSION_TOKEN = "__VECTA_VERSION__"

# Who writes each named volume, and the mode its directory gets. Docker gives a
# new named volume the owner of the image's directory; a Kubernetes volume is
# root's, so the chart's prepare step sets these (mirrors
# infra/scripts/compose-volumes.sh prepare_shared_volumes for the shared ones).
# None: the daemon's own entrypoint, running as root, sets ownership.
VOLUME_OWNERS = {
    "audit-data": ("100:101", "700"),
    "auth-data": ("100:101", "700"),
    "keycore-data": ("100:101", "700"),
    "certs-key-data": ("100:101", "700"),
    "internal-trust": ("100:101", "755"),
    "dashboard-tls": ("100:101", "750"),
    "infra-tls": ("100:101", "700"),
    "platform-state": ("10001", "755"),
    "hsm-integration-data": None,
    "consul-data": None,
    "nats-data": None,
    "postgres-data": None,
    "valkey-data": None,
}
# In memory (tmpfs in compose): an emptyDir with medium Memory in the pod.
MEMORY_VOLUMES = {"runtime-certs": ("100:101", "700", "32Mi")}
# infra-tls holds one subdirectory per daemon; each mounts only its own.
INFRA_TLS_SUBDIRS = ["postgres", "nats", "valkey", "consul"]

# Started first, in this order, as native sidecars (Kubernetes 1.29+): certs
# writes the TLS files the daemons wait for; services start once Postgres is
# ready, as compose's depends_on: service_healthy does.
SIDECAR_ORDER = ["certs", "postgres", "nats", "valkey", "consul"]

# Compose gives each service its own network; a pod has one. Envoy's KMIP edge
# and the kmip service both listen on 5696 there, so in the pod kmip listens
# on POD_KMIP_PORT and what reaches it is pointed there.
POD_KMIP_PORT = 25696
POD_ENV = {
    "kmip": {"KMIP_PORT": str(POD_KMIP_PORT)},
    "certs": {"CERTS_EDGE_PROBE_TARGETS": f"envoy=envoy:443,kmip=kmip:{POD_KMIP_PORT}"},
}
POD_FILE_EDITS = {
    "infra/envoy/envoy.yaml": [(
        "{ socket_address: { address: kmip, port_value: 5696 }}",
        "{ socket_address: { address: kmip, port_value: %d }}" % POD_KMIP_PORT,
    )],
}
STARTUP_PROBED = {"postgres"}


def norm(s):
    return s.replace("$$", "$") if isinstance(s, str) else s


def secret_refs(value, refs, shell=False):
    """Replace placeholder secrets with $(NAME) (Kubernetes expansion) or
    $NAME (inside a shell), recording each name."""
    def repl(m):
        refs.add(m.group(1))
        return ("$" + m.group(1)) if shell else ("$(" + m.group(1) + ")")
    return SECRET_RE.sub(repl, norm(value))


def mem(v):
    if v is None:
        return None
    n = int(v)
    for unit, size in (("Gi", 1 << 30), ("Mi", 1 << 20)):
        if n % size == 0:
            return f"{n // size}{unit}"
    return str(n)


def main():
    compose_json, root, chart = sys.argv[1:4]
    model = json.load(open(compose_json))
    services = model["services"]
    config_files = {}  # repo-relative path -> configmap key
    out = []
    ports_seen = {}
    problems = []

    def config_key(rel):
        key = re.sub(r"[^a-z0-9.-]+", "-", rel.lower()).strip("-")
        config_files[rel] = key
        return key

    for name in sorted(services, key=lambda n: (SIDECAR_ORDER.index(n) if n in SIDECAR_ORDER else 99, n)):
        s = services[name]
        refs = set()
        image = s["image"]
        vecta = image.startswith("vecta/")
        svc = {
            "name": name,
            "image": image.split(":")[0] if vecta else image,
            "vecta": vecta,
            "profiles": s.get("profiles") or [],
            "sidecar": name in SIDECAR_ORDER,
            "entrypoint": [secret_refs(x, refs) for x in s["entrypoint"]] if s.get("entrypoint") else None,
            "command": [secret_refs(x, refs) for x in s["command"]] if s.get("command") else None,
            "env": [],
            "ports": [],
            "mounts": [],
        }
        env = dict(s.get("environment") or {})
        env.update(POD_ENV.get(name, {}))
        for k, v in sorted(env.items()):
            if k in ("JWT_PUBLIC_KEY_B64",) or (isinstance(v, str) and v == f"__VECTA_SECRET_{k}__"):
                refs.add(k)
                continue
            svc["env"].append({"name": k, "value": secret_refs(v if v is not None else "", refs)})
        user = s.get("user")
        if user:
            u, _, g = user.partition(":")
            svc["runAsUser"], svc["runAsGroup"] = int(u), int(g or u)
        if s.get("group_add"):
            svc["groupAdd"] = [int(g) for g in s["group_add"]]
        if "ALL" in (s.get("cap_drop") or []):
            svc["dropAll"] = True
        if any("no-new-privileges" in o for o in (s.get("security_opt") or [])):
            svc["noNewPrivileges"] = True
        hc = s.get("healthcheck") or {}
        test = hc.get("test")
        if test and not hc.get("disable"):
            if test[0] == "CMD-SHELL":
                svc["probe"] = ["sh", "-c", secret_refs(test[1], refs, shell=True)]
            elif test[0] == "CMD":
                svc["probe"] = [secret_refs(x, refs, shell=True) for x in test[1:]]
            svc["startupProbe"] = name in STARTUP_PROBED
        res = (s.get("deploy") or {}).get("resources") or {}
        lim, req = res.get("limits") or {}, res.get("reservations") or {}
        svc["resources"] = {
            "limits": {k: v for k, v in {"cpu": lim.get("cpus"), "memory": mem(lim.get("memory"))}.items() if v},
            "requests": {k: v for k, v in {"cpu": req.get("cpus"), "memory": mem(req.get("memory"))}.items() if v},
        }
        if s.get("shm_size"):
            svc["shm"] = mem(s["shm_size"])
        listen = set()
        for p in s.get("ports") or []:
            listen.add(int(p["target"]))
        for p in s.get("expose") or []:
            listen.add(int(str(p).split("/")[0]))
        if name == "kmip":
            listen.discard(5696)
        for e in svc["env"]:
            if e["name"] in ("HTTP_PORT", "GRPC_PORT") and e["value"].isdigit():
                listen.add(int(e["value"]))
        for port in sorted(listen):
            if port in ports_seen and ports_seen[port] != name:
                problems.append(f"port {port}: {ports_seen[port]} and {name} would share one pod network")
            ports_seen[port] = name
            svc["ports"].append(port)
        for v in s.get("volumes") or []:
            ro = bool(v.get("read_only"))
            if v["type"] == "volume":
                src = v["source"]
                if src in MEMORY_VOLUMES:
                    svc["mounts"].append({"memory": src, "mountPath": v["target"], "readOnly": ro})
                    continue
                if src not in VOLUME_OWNERS:
                    problems.append(f"{name}: volume {src} has no owner in VOLUME_OWNERS")
                sub = (v.get("volume") or {}).get("subpath")
                svc["mounts"].append({"data": src + ("/" + sub if sub else ""), "mountPath": v["target"], "readOnly": ro})
            elif v["type"] == "bind":
                rel = os.path.relpath(v["source"], root)
                if rel.startswith(".."):
                    problems.append(f"{name}: bind {v['source']} is outside the repository")
                    continue
                if rel == "infra/deployment/deployment.yaml":
                    svc["mounts"].append({"deployment": True, "mountPath": v["target"]})
                    continue
                path = os.path.join(root, rel)
                if os.path.isdir(path):
                    files = sorted(f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)))
                    if any(os.path.isdir(os.path.join(path, f)) for f in os.listdir(path)):
                        problems.append(f"{name}: bind directory {rel} has subdirectories")
                    svc["mounts"].append({"configDir": config_key(rel), "files": [{"key": config_key(rel + "/" + f), "path": f} for f in files], "mountPath": v["target"]})
                else:
                    svc["mounts"].append({"config": config_key(rel), "mountPath": v["target"], "executable": rel.endswith(".sh")})
            else:
                problems.append(f"{name}: mount type {v['type']} is not supported")
        if s.get("tmpfs"):
            problems.append(f"{name}: tmpfs mounts are not carried")
        svc["secretEnv"] = sorted(refs)
        out.append(svc)

    if problems:
        sys.exit("cannot carry docker-compose.yml to the chart:\n  " + "\n  ".join(problems))

    files_dir = os.path.join(chart, "files")
    infra_dir = os.path.join(files_dir, "infra")
    if os.path.isdir(infra_dir):
        shutil.rmtree(infra_dir)
    os.makedirs(infra_dir)
    configs = {}
    for rel, key in sorted(config_files.items()):
        path = os.path.join(root, rel)
        if os.path.isfile(path):
            text = open(path).read()
            for old, new in POD_FILE_EDITS.get(rel, []):
                if old not in text:
                    sys.exit(f"{rel}: expected to find {old!r} to point it at the pod's port")
                text = text.replace(old, new)
            with open(os.path.join(infra_dir, key), "w") as f:
                f.write(text)
            configs[key] = "files/infra/" + key
    shutil.copyfile(os.path.join(root, "infra/scripts/crwk-passphrase.sh"), os.path.join(infra_dir, "crwk-passphrase.sh"))
    stack = {
        "generatedFrom": "docker-compose.yml (scripts/helm-chart.sh)",
        "services": out,
        "hostnames": sorted(services),
        "configFiles": configs,
        "volumeOwners": {k: (list(v) if v else None) for k, v in VOLUME_OWNERS.items()},
        "infraTLSSubdirs": INFRA_TLS_SUBDIRS,
        "memoryVolumes": {k: list(v) for k, v in MEMORY_VOLUMES.items()},
    }
    with open(os.path.join(files_dir, "stack.json"), "w") as f:
        json.dump(stack, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
