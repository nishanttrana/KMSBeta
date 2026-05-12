#!/usr/bin/env python3
"""Generate a living UI/API/product map from the Vecta KMS source tree.

The scanner is intentionally static and dependency-free. It does not prove that
an interaction succeeds at runtime; it creates an inventory that shows what UI
modules exist, which services they appear to call, and which backend routes are
registered in source.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "web" / "dashboard" / "src"
SERVICES_ROOT = REPO_ROOT / "services"
OUT_DIR = REPO_ROOT / "docs" / "generated"
SHELL_PATH = SRC_ROOT / "components" / "VectaDashboardV3Shell.tsx"

SERVICE_ALIASES = {
    "cluster": "cluster-manager",
}

MAX_TABLE_ROWS = 120


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def iter_files(root: Path, suffixes: Sequence[str]) -> Iterable[Path]:
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in suffixes:
            if "node_modules" in path.parts or "dist" in path.parts:
                continue
            yield path


def line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def escape_md(value: object) -> str:
    text = str(value if value is not None else "")
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
        .strip()
    )


def truncate(value: object, limit: int = 90) -> str:
    text = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def service_key(service: str) -> str:
    service = str(service or "").strip()
    return SERVICE_ALIASES.get(service, service)


def normalize_path(path: str) -> str:
    path = str(path or "").strip()
    path = re.sub(r"\$\{[^}]+\}", "{param}", path)
    path = path.split("?", 1)[0]
    path = re.sub(r"/+", "/", path)
    path = re.sub(r"\{[^}/]+\}", "{param}", path)
    if not path.startswith("/") and path:
        path = "/" + path
    return path.rstrip("/") or "/"


def route_match_key(service: str, method: str, path: str) -> Tuple[str, str, str]:
    return (service_key(service), str(method or "GET").upper(), normalize_path(path))


def node_id(prefix: str, value: str) -> str:
    raw = re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")
    if not raw:
        raw = "item"
    return f"{prefix}_{raw[:64]}"


def extract_backend_routes() -> List[Dict[str, object]]:
    routes: List[Dict[str, object]] = []
    route_re = re.compile(r"\bmux\.HandleFunc\s*\(", re.MULTILINE)
    for path in iter_files(SERVICES_ROOT, [".go"]):
        text = read_text(path)
        try:
            service = path.relative_to(SERVICES_ROOT).parts[0]
        except Exception:
            service = ""
        for match in route_re.finditer(text):
            args_text, _ = extract_call_arguments(text, match.end() - 1)
            if args_text is None:
                continue
            args = split_top_level_args(args_text)
            if len(args) < 2:
                continue
            route_match = re.match(r"\s*([\"'`])([A-Z]+)\s+([^\"'`]+)\1", args[0])
            if not route_match:
                continue
            method, route_path = route_match.group(2), route_match.group(3)
            handler = args[1].strip()
            routes.append(
                {
                    "service": service,
                    "method": method,
                    "path": route_path.strip(),
                    "normalized_path": normalize_path(route_path),
                    "handler": handler.strip(),
                    "file": rel(path),
                    "line": line_number(text, match.start()),
                    "match_key": "|".join(route_match_key(service, method, route_path)),
                }
            )
    return routes


def extract_go_imports(text: str) -> Dict[str, str]:
    imports: Dict[str, str] = {}
    block_match = re.search(r"import\s*\((.*?)\)", text, re.DOTALL)
    import_lines: List[str] = []
    if block_match:
        import_lines.extend(block_match.group(1).splitlines())
    import_lines.extend(match.group(1) for match in re.finditer(r"^\s*import\s+(.+)$", text, re.MULTILINE))

    for line in import_lines:
        line = line.split("//", 1)[0].strip().rstrip(",")
        if not line:
            continue
        match = re.match(r"(?:(\w+|\.)\s+)?\"([^\"]+)\"", line)
        if not match:
            continue
        alias, import_path = match.groups()
        if alias in ("_", "."):
            continue
        if not alias:
            alias = import_path.rstrip("/").split("/")[-1]
            alias = alias.split(".")[0]
        imports[alias] = import_path
    return imports


def extract_brace_block(text: str, open_brace: int) -> Tuple[str, int]:
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for i in range(open_brace, len(text)):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : i], i + 1
    return text[open_brace + 1 :], len(text)


def extract_go_functions() -> Dict[Tuple[str, str, str], Dict[str, object]]:
    functions: Dict[Tuple[str, str, str], Dict[str, object]] = {}
    func_re = re.compile(
        r"\bfunc\s+(?:\(\s*(\w+)\s+\*?([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        re.MULTILINE,
    )
    for path in iter_files(SERVICES_ROOT, [".go"]):
        text = read_text(path)
        imports = extract_go_imports(text)
        try:
            service = path.relative_to(SERVICES_ROOT).parts[0]
        except Exception:
            service = ""
        for match in func_re.finditer(text):
            recv_name, recv_type, func_name = match.groups()
            open_brace = text.find("{", match.end())
            if open_brace < 0:
                continue
            body, end = extract_brace_block(text, open_brace)
            receiver_type = recv_type or ""
            functions[(service, receiver_type, func_name)] = {
                "service": service,
                "receiver_name": recv_name or "",
                "receiver_type": receiver_type,
                "name": func_name,
                "file": rel(path),
                "line": line_number(text, match.start()),
                "end_line": line_number(text, end),
                "body": body,
                "imports": imports,
            }
    return functions


def unique(items: Iterable[str], limit: Optional[int] = None) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if limit is not None and len(out) >= limit:
            break
    return out


HELPER_CALL_SKIP = {
    "append",
    "bool",
    "break",
    "byte",
    "cap",
    "case",
    "close",
    "continue",
    "copy",
    "default",
    "defer",
    "delete",
    "else",
    "error",
    "fallthrough",
    "false",
    "float64",
    "for",
    "func",
    "go",
    "if",
    "int",
    "len",
    "make",
    "map",
    "new",
    "nil",
    "range",
    "return",
    "select",
    "string",
    "struct",
    "switch",
    "true",
    "var",
}


def summarize_go_function(func: Optional[Dict[str, object]], service_functions: Iterable[str]) -> Dict[str, List[str]]:
    if not func:
        return {
            "service_calls": [],
            "store_calls": [],
            "receiver_calls": [],
            "internal_package_calls": [],
            "external_package_calls": [],
            "helper_calls": [],
        }
    body = str(func.get("body") or "")
    imports = dict(func.get("imports") or {})
    service_func_names = set(service_functions)

    service_calls = unique(re.findall(r"\bh\.svc\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", body), 24)
    store_calls = unique(
        re.findall(r"\b(?:h\.svc\.store|h\.store|s\.store|svc\.store)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", body),
        24,
    )
    receiver_calls = []
    for recv, field, method in re.findall(r"\b(h|s)\.([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
        if field in {"svc", "store"}:
            continue
        receiver_calls.append(f"{recv}.{field}.{method}")
    receiver_calls = unique(receiver_calls, 24)

    internal_package_calls = []
    external_package_calls = []
    for alias, import_path in imports.items():
        if not re.search(r"\b" + re.escape(alias) + r"\.", body):
            continue
        calls = unique(re.findall(r"\b" + re.escape(alias) + r"\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", body), 12)
        if not calls:
            continue
        labels = [f"{import_path}.{call}" for call in calls]
        if import_path.startswith("vecta-kms/pkg/"):
            internal_package_calls.extend(label.replace("vecta-kms/", "") for label in labels)
        elif import_path.startswith("vecta-kms/"):
            internal_package_calls.extend(label.replace("vecta-kms/", "") for label in labels)
        else:
            external_package_calls.extend(labels)

    helper_candidates = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)
    helper_calls = unique(
        name
        for name in helper_candidates
        if name in service_func_names and name not in HELPER_CALL_SKIP and name != str(func.get("name") or "")
    )

    return {
        "service_calls": service_calls,
        "store_calls": store_calls,
        "receiver_calls": receiver_calls,
        "internal_package_calls": unique(internal_package_calls, 24),
        "external_package_calls": unique(external_package_calls, 16),
        "helper_calls": helper_calls,
    }


def handler_func_name(handler_expr: object) -> str:
    expr = str(handler_expr or "").strip()
    receiver_matches = re.findall(r"\bh\.([A-Za-z_][A-Za-z0-9_]*)", expr)
    for name in receiver_matches:
        if name.startswith("handle"):
            return name
    if receiver_matches:
        return receiver_matches[-1]
    match = re.search(r"\.([A-Za-z_][A-Za-z0-9_]*)$", expr)
    if match:
        return match.group(1)
    return expr


def build_request_flows(
    backend_routes: List[Dict[str, object]],
    frontend_calls: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    functions = extract_go_functions()
    functions_by_service_name: Dict[str, List[str]] = defaultdict(list)
    for service, _receiver, name in functions:
        functions_by_service_name[service].append(name)

    frontend_by_key: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for call in frontend_calls:
        frontend_by_key[str(call.get("match_key") or "")].append(call)

    flows: List[Dict[str, object]] = []
    for route in backend_routes:
        service = str(route.get("service") or "")
        handler_name = handler_func_name(route.get("handler"))
        handler_func = functions.get((service, "Handler", handler_name))
        service_func_names = functions_by_service_name.get(service, [])
        handler_summary = summarize_go_function(handler_func, service_func_names)

        service_method_details = []
        aggregate_store_calls: List[str] = []
        aggregate_receiver_calls: List[str] = []
        aggregate_internal_pkg_calls: List[str] = []
        aggregate_external_pkg_calls: List[str] = []
        aggregate_helper_calls: List[str] = []
        for method_name in handler_summary["service_calls"]:
            service_func = functions.get((service, "Service", method_name))
            summary = summarize_go_function(service_func, service_func_names)
            if service_func:
                service_method_details.append(
                    {
                        "name": method_name,
                        "file": service_func["file"],
                        "line": service_func["line"],
                        "store_calls": summary["store_calls"],
                        "receiver_calls": summary["receiver_calls"],
                        "internal_package_calls": summary["internal_package_calls"],
                        "external_package_calls": summary["external_package_calls"],
                        "helper_calls": summary["helper_calls"],
                    }
                )
            else:
                service_method_details.append(
                    {
                        "name": method_name,
                        "file": "",
                        "line": "",
                        "store_calls": [],
                        "receiver_calls": [],
                        "internal_package_calls": [],
                        "external_package_calls": [],
                        "helper_calls": [],
                    }
                )
            aggregate_store_calls.extend(summary["store_calls"])
            aggregate_receiver_calls.extend(summary["receiver_calls"])
            aggregate_internal_pkg_calls.extend(summary["internal_package_calls"])
            aggregate_external_pkg_calls.extend(summary["external_package_calls"])
            aggregate_helper_calls.extend(summary["helper_calls"])

        frontend_sites = frontend_by_key.get(str(route.get("match_key") or ""), [])
        flows.append(
            {
                "service": service,
                "method": route.get("method"),
                "path": route.get("path"),
                "normalized_path": route.get("normalized_path"),
                "handler": route.get("handler"),
                "handler_name": handler_name,
                "handler_file": handler_func.get("file") if handler_func else "",
                "handler_line": handler_func.get("line") if handler_func else "",
                "route_file": route.get("file"),
                "route_line": route.get("line"),
                "frontend_call_sites": [
                    {
                        "file": call.get("file"),
                        "line": call.get("line"),
                        "source": call.get("source"),
                        "expression": call.get("expression"),
                    }
                    for call in frontend_sites
                ],
                "handler_service_calls": handler_summary["service_calls"],
                "handler_store_calls": handler_summary["store_calls"],
                "handler_receiver_calls": handler_summary["receiver_calls"],
                "handler_internal_package_calls": handler_summary["internal_package_calls"],
                "handler_external_package_calls": handler_summary["external_package_calls"],
                "handler_helper_calls": handler_summary["helper_calls"],
                "service_method_details": service_method_details,
                "service_store_calls": unique(aggregate_store_calls, 32),
                "service_receiver_calls": unique(aggregate_receiver_calls, 32),
                "service_internal_package_calls": unique(aggregate_internal_pkg_calls, 32),
                "service_external_package_calls": unique(aggregate_external_pkg_calls, 24),
                "service_helper_calls": unique(aggregate_helper_calls, 32),
            }
        )
    return flows


def extract_string_consts(text: str) -> Dict[str, str]:
    consts: Dict[str, str] = {}
    for match in re.finditer(r"\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([\"'`])([^\"'`]+)\2", text):
        consts[match.group(1)] = match.group(3)
    return consts


def extract_call_arguments(text: str, open_paren: int) -> Tuple[Optional[str], int]:
    depth = 0
    quote: Optional[str] = None
    escaped = False
    i = open_paren
    while i < len(text):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        else:
            if ch in ("'", '"', "`"):
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[open_paren + 1 : i], i + 1
        i += 1
    return None, open_paren


def split_top_level_args(arg_text: str) -> List[str]:
    args: List[str] = []
    start = 0
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for i, ch in enumerate(arg_text):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            args.append(arg_text[start:i].strip())
            start = i + 1
    tail = arg_text[start:].strip()
    if tail:
        args.append(tail)
    return args


def resolve_expr(expr: str, consts: Dict[str, str]) -> Tuple[str, bool]:
    original = str(expr or "").strip()
    if not original:
        return "", True
    came_from_const = False
    if original in consts:
        value = consts[original]
        came_from_const = True
    elif len(original) >= 2 and original[0] in ("'", '"', "`") and original[-1] == original[0]:
        value = original[1:-1]
    else:
        value = original
    for name, const_value in consts.items():
        value = value.replace("${" + name + "}", const_value)
    dynamic = bool(re.search(r"\$\{[^}]+\}", value)) or not (
        came_from_const or (len(original) >= 2 and original[0] in ("'", '"', "`") and original[-1] == original[0])
    )
    value = re.sub(r"\$\{[^}]+\}", "{param}", value)
    value = value.replace('" + "', "").replace("' + '", "")
    return value, dynamic


def method_from_init(init_expr: str) -> str:
    match = re.search(r"\bmethod\s*:\s*([\"'`])([A-Z]+)\1", init_expr or "")
    if match:
        return match.group(2).upper()
    return "GET"


def parse_service_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    value = re.sub(r"\{param\}", "{param}", str(url or "").strip())
    match = re.search(r"/svc/([^/?#{}]+)([^?#]*)", value)
    if match:
        service = match.group(1)
        path = match.group(2) or "/"
        return service, normalize_path(path)
    if value.startswith("/auth/") or value in ("/auth", "/auth/"):
        return "auth-edge", normalize_path(value)
    return None, None


def find_named_calls(text: str, names: Sequence[str]) -> Iterable[Tuple[str, int, List[str]]]:
    name_re = re.compile(r"\b(" + "|".join(re.escape(name) for name in names) + r")\s*(?:<[^()]*>)?\s*\(")
    for match in name_re.finditer(text):
        args_text, _ = extract_call_arguments(text, match.end() - 1)
        if args_text is None:
            continue
        yield match.group(1), match.start(), split_top_level_args(args_text)


def add_frontend_call(
    calls: List[Dict[str, object]],
    *,
    source: str,
    file: Path,
    text: str,
    pos: int,
    service: str,
    path: str,
    method: str,
    dynamic: bool,
    expression: str,
) -> None:
    if not service or not path:
        return
    path_text = str(path).strip()
    if not path_text.startswith("/") and "{" not in path_text:
        return
    normalized = normalize_path(path)
    if normalized in ("/{param}", "/$"):
        return
    calls.append(
        {
            "source": source,
            "service": service,
            "service_key": service_key(service),
            "method": str(method or "GET").upper(),
            "path": path,
            "normalized_path": normalized,
            "dynamic": bool(dynamic),
            "expression": truncate(expression, 140),
            "file": rel(file),
            "line": line_number(text, pos),
            "match_key": "|".join(route_match_key(service, method, path)),
        }
    )


def extract_frontend_calls() -> List[Dict[str, object]]:
    calls: List[Dict[str, object]] = []
    for path in iter_files(SRC_ROOT, [".ts", ".tsx"]):
        text = read_text(path)
        consts = extract_string_consts(text)

        for name, pos, args in find_named_calls(text, ["serviceRequestRaw", "serviceRequest"]):
            if len(args) < 3:
                continue
            service, service_dynamic = resolve_expr(args[1], consts)
            service_expr = args[1].strip()
            service_is_static = service_expr in consts or (
                len(service_expr) >= 2 and service_expr[0] in ("'", '"', "`") and service_expr[-1] == service_expr[0]
            )
            if service_dynamic and not service_is_static:
                service = "$dynamic-service"
            api_path, path_dynamic = resolve_expr(args[2], consts)
            method = method_from_init(args[3] if len(args) > 3 else "")
            add_frontend_call(
                calls,
                source=name,
                file=path,
                text=text,
                pos=pos,
                service=service,
                path=api_path,
                method=method,
                dynamic=service_dynamic or path_dynamic,
                expression=f"{name}({args[1]}, {args[2]})",
            )

        for name, pos, args in find_named_calls(text, ["fetch", "trackedFetch"]):
            if not args:
                continue
            url, dynamic = resolve_expr(args[0], consts)
            service, api_path = parse_service_url(url)
            if not service or not api_path:
                continue
            method = method_from_init(args[1] if len(args) > 1 else "")
            add_frontend_call(
                calls,
                source=name,
                file=path,
                text=text,
                pos=pos,
                service=service,
                path=api_path,
                method=method,
                dynamic=dynamic,
                expression=f"{name}({args[0]})",
            )

        # Local wrappers that hide the serviceRequest call behind a helper.
        if path.name == "keycore.ts":
            for name, pos, args in find_named_calls(text, ["apiRequest"]):
                if len(args) < 2:
                    continue
                api_path, dynamic = resolve_expr(args[1], consts)
                method = method_from_init(args[2] if len(args) > 2 else "")
                add_frontend_call(
                    calls,
                    source="keycore.apiRequest",
                    file=path,
                    text=text,
                    pos=pos,
                    service="keycore",
                    path=api_path,
                    method=method,
                    dynamic=dynamic,
                    expression=f"apiRequest({args[1]})",
                )
        if path.name == "qrng.ts":
            for name, pos, args in find_named_calls(text, ["api"]):
                if not args:
                    continue
                api_path, dynamic = resolve_expr(args[0], consts)
                method = method_from_init(args[1] if len(args) > 1 else "")
                add_frontend_call(
                    calls,
                    source="qrng.api",
                    file=path,
                    text=text,
                    pos=pos,
                    service="qrng",
                    path=api_path,
                    method=method,
                    dynamic=dynamic,
                    expression=f"api({args[0]})",
                )
    return calls


def resolve_import(from_file: Path, import_path: str) -> Optional[Path]:
    if not import_path.startswith("."):
        return None
    base = (from_file.parent / import_path).resolve()
    candidates = [
        base,
        base.with_suffix(".ts"),
        base.with_suffix(".tsx"),
        base / "index.ts",
        base / "index.tsx",
    ]
    for candidate in candidates:
        try:
            candidate.relative_to(REPO_ROOT)
        except ValueError:
            continue
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def extract_imports(path: Path) -> List[Path]:
    text = read_text(path)
    imports: List[Path] = []
    for match in re.finditer(r"\bfrom\s+[\"']([^\"']+)[\"']", text):
        resolved = resolve_import(path, match.group(1))
        if resolved:
            imports.append(resolved)
    return sorted(set(imports))


def extract_shell_maps() -> Tuple[List[Dict[str, str]], Dict[str, str], Dict[str, str], Dict[str, List[Dict[str, str]]]]:
    if not SHELL_PATH.exists():
        return [], {}, {}, {}
    text = read_text(SHELL_PATH)
    shell_dir = SHELL_PATH.parent

    lazy_imports: Dict[str, str] = {}
    for match in re.finditer(r"const\s+(\w+)\s*=\s*lazy\(\(\)\s*=>\s*import\(\"([^\"]+)\"\)", text):
        component_name, import_path = match.groups()
        resolved = resolve_import(SHELL_PATH, import_path)
        lazy_imports[component_name] = rel(resolved) if resolved else str((shell_dir / import_path).as_posix())

    tab_to_component: Dict[str, str] = {}
    tabs_start = text.find("const TABS")
    titles_start = text.find("const TITLES")
    if tabs_start >= 0 and titles_start > tabs_start:
        tabs_block = text[tabs_start:titles_start]
        for match in re.finditer(r"^\s*([A-Za-z0-9_]+):\s*(\w+),?", tabs_block, re.MULTILINE):
            tab_id, component_name = match.groups()
            tab_to_component[tab_id] = lazy_imports.get(component_name, component_name)

    titles: Dict[str, str] = {}
    titles_end = text.find("const NAV")
    if titles_start >= 0 and titles_end > titles_start:
        for match in re.finditer(r"^\s*([A-Za-z0-9_]+):\s*\"([^\"]+)\"", text[titles_start:titles_end], re.MULTILINE):
            titles[match.group(1)] = match.group(2)

    nav: List[Dict[str, str]] = []
    nav_start = text.find("const NAV")
    sub_start = text.find("const SUB_PANES")
    if nav_start >= 0 and sub_start > nav_start:
        current_group = ""
        for line in text[nav_start:sub_start].splitlines():
            group_match = re.search(r"\{\s*g:\s*\"([^\"]+)\"", line)
            if group_match:
                current_group = group_match.group(1)
            item_match = re.search(r"\{\s*id:\s*\"([^\"]+)\"[^}]*label:\s*\"([^\"]+)\"", line)
            if item_match:
                nav.append({"group": current_group, "id": item_match.group(1), "label": item_match.group(2)})

    subpanes: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    export_start = text.find("export default", sub_start)
    if sub_start >= 0 and export_start > sub_start:
        current_parent = ""
        for line in text[sub_start:export_start].splitlines():
            parent_match = re.search(r"^\s*([A-Za-z0-9_]+):\s*\[", line)
            if parent_match:
                current_parent = parent_match.group(1)
            item_match = re.search(r"\{\s*id:\s*\"([^\"]+)\"[^}]*label:\s*\"([^\"]+)\"", line)
            if item_match and current_parent:
                subpanes[current_parent].append({"id": item_match.group(1), "label": item_match.group(2)})

    return nav, tab_to_component, titles, dict(subpanes)


def imported_support_files(component_file: str) -> List[str]:
    if not component_file or component_file.startswith("./"):
        return []
    path = REPO_ROOT / component_file
    if not path.exists():
        return []
    imports = []
    for imported in extract_imports(path):
        try:
            imported.relative_to(SRC_ROOT)
        except ValueError:
            continue
        rel_path = rel(imported)
        if "/lib/" in rel_path or "/modules/" in rel_path:
            imports.append(rel_path)
    return sorted(set(imports))


def build_tab_service_map(
    nav: List[Dict[str, str]],
    tab_to_component: Dict[str, str],
    calls: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    calls_by_file: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for call in calls:
        calls_by_file[str(call["file"])].append(call)

    rows: List[Dict[str, object]] = []
    seen = set()
    for item in nav:
        tab_id = item["id"]
        component_file = tab_to_component.get(tab_id, "")
        files = [component_file] if component_file else []
        files.extend(imported_support_files(component_file))
        services = sorted(
            {
                str(call["service_key"])
                for file in files
                for call in calls_by_file.get(file, [])
                if call.get("service_key")
            }
        )
        rows.append(
            {
                "group": item["group"],
                "id": tab_id,
                "label": item["label"],
                "component": component_file,
                "support_files": files[1:],
                "services": services,
                "call_count": sum(len(calls_by_file.get(file, [])) for file in files),
            }
        )
        seen.add(tab_id)
    for tab_id, component_file in sorted(tab_to_component.items()):
        if tab_id in seen:
            continue
        files = [component_file] + imported_support_files(component_file)
        services = sorted(
            {
                str(call["service_key"])
                for file in files
                for call in calls_by_file.get(file, [])
                if call.get("service_key")
            }
        )
        rows.append(
            {
                "group": "UNLISTED",
                "id": tab_id,
                "label": tab_id,
                "component": component_file,
                "support_files": files[1:],
                "services": services,
                "call_count": sum(len(calls_by_file.get(file, [])) for file in files),
            }
        )
    return rows


def clean_label(raw: str, attrs: str) -> str:
    text = re.sub(r"\{[^{}]*\}", " ", raw)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if text:
        return truncate(text, 80)
    for attr in ("aria-label", "title"):
        match = re.search(attr + r"=([\"'])([^\"']+)\1", attrs)
        if match:
            return truncate(match.group(2), 80)
    return "(icon or dynamic label)"


def extract_onclick(attrs: str) -> str:
    match = re.search(r"onClick=\{([^}\n]+(?:\}[^}\n]+)?)\}", attrs)
    if not match:
        return ""
    return truncate(match.group(1), 120)


def extract_button_inventory(tab_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    inventory: List[Dict[str, object]] = []
    component_to_tab: Dict[str, List[str]] = defaultdict(list)
    for row in tab_rows:
        component_to_tab[str(row["component"])].append(str(row["id"]))

    roots = [
        SRC_ROOT / "components" / "v3" / "tabs",
        SRC_ROOT / "modules",
        SRC_ROOT / "components",
    ]
    files = sorted({path for root in roots for path in iter_files(root, [".tsx"])})
    tag_re = re.compile(r"<(?P<tag>Btn|button)\b(?P<attrs>[^>]*)>(?P<body>.*?)</(?P=tag)>", re.DOTALL)
    for path in files:
        text = read_text(path)
        for match in tag_re.finditer(text):
            attrs = match.group("attrs")
            if "onClick" not in attrs:
                continue
            file_rel = rel(path)
            inventory.append(
                {
                    "file": file_rel,
                    "line": line_number(text, match.start()),
                    "tabs": sorted(component_to_tab.get(file_rel, [])),
                    "tag": match.group("tag"),
                    "label": clean_label(match.group("body"), attrs),
                    "handler": extract_onclick(attrs),
                }
            )
    return inventory


def make_mermaid(tab_rows: List[Dict[str, object]], route_counts: Counter) -> str:
    lines = [
        "flowchart LR",
        "  UI[Dashboard UI]",
    ]
    service_nodes = set()
    for row in tab_rows:
        services = row.get("services") or []
        if not services:
            continue
        tab_node = node_id("tab", str(row["id"]))
        lines.append(f'  {tab_node}["{str(row["label"]).replace(chr(34), "")}"]')
        lines.append(f"  UI --> {tab_node}")
        for service in services:
            service_name = str(service)
            service_node = node_id("svc", service_name)
            service_nodes.add((service_node, service_name))
            lines.append(f"  {tab_node} --> {service_node}")
    for service_node, service_name in sorted(service_nodes):
        count = route_counts.get(service_name, 0)
        label = f"{service_name} ({count} routes)" if count else service_name
        lines.append(f'  {service_node}["{label}"]')
    if len(lines) == 2:
        lines.append("  UI --> Unknown[No static service dependencies found]")
    return "\n".join(lines) + "\n"


def table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    output = []
    output.append("| " + " | ".join(headers) + " |")
    output.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        output.append("| " + " | ".join(escape_md(cell) for cell in row) + " |")
    return "\n".join(output)


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def compact_list(items: Iterable[object], limit: int = 8) -> str:
    values = unique(str(item) for item in items if str(item or "").strip())
    if len(values) <= limit:
        return ", ".join(values)
    return ", ".join(values[:limit]) + f", +{len(values) - limit} more"


def frontend_site_label(site: Dict[str, object]) -> str:
    return f"{site.get('file')}:{site.get('line')}"


def flow_table_rows(flows: Iterable[Dict[str, object]]) -> Iterable[Sequence[object]]:
    for flow in flows:
        frontend_sites = flow.get("frontend_call_sites") or []
        internal_pkg_calls = list(flow.get("handler_internal_package_calls") or []) + list(flow.get("service_internal_package_calls") or [])
        store_calls = list(flow.get("handler_store_calls") or []) + list(flow.get("service_store_calls") or [])
        receiver_calls = list(flow.get("handler_receiver_calls") or []) + list(flow.get("service_receiver_calls") or [])
        yield [
            f"{flow.get('service')}|{flow.get('method')}|{flow.get('normalized_path')}",
            f"{flow.get('method')} {flow.get('path')}",
            f"{flow.get('handler_name')} ({flow.get('handler_file')}:{flow.get('handler_line')})",
            compact_list(flow.get("handler_service_calls") or []),
            compact_list(store_calls),
            compact_list(receiver_calls),
            compact_list(internal_pkg_calls),
            compact_list(frontend_site_label(site) for site in frontend_sites),
        ]


def flow_csv_rows(flows: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for flow in flows:
        frontend_sites = flow.get("frontend_call_sites") or []
        internal_pkg_calls = list(flow.get("handler_internal_package_calls") or []) + list(flow.get("service_internal_package_calls") or [])
        external_pkg_calls = list(flow.get("handler_external_package_calls") or []) + list(flow.get("service_external_package_calls") or [])
        store_calls = list(flow.get("handler_store_calls") or []) + list(flow.get("service_store_calls") or [])
        receiver_calls = list(flow.get("handler_receiver_calls") or []) + list(flow.get("service_receiver_calls") or [])
        rows.append(
            {
                "route_key": f"{flow.get('service')}|{flow.get('method')}|{flow.get('normalized_path')}",
                "service": flow.get("service"),
                "method": flow.get("method"),
                "path": flow.get("path"),
                "normalized_path": flow.get("normalized_path"),
                "frontend_call_sites": compact_list((frontend_site_label(site) for site in frontend_sites), 24),
                "handler": flow.get("handler_name"),
                "handler_file": flow.get("handler_file"),
                "handler_line": flow.get("handler_line"),
                "handler_service_calls": compact_list(flow.get("handler_service_calls") or [], 32),
                "store_calls": compact_list(store_calls, 32),
                "receiver_client_calls": compact_list(receiver_calls, 32),
                "internal_package_calls": compact_list(internal_pkg_calls, 32),
                "external_package_calls": compact_list(external_pkg_calls, 32),
            }
        )
    return rows


def build_source_tab_index(tab_rows: List[Dict[str, object]]) -> Dict[str, List[str]]:
    index: Dict[str, List[str]] = defaultdict(list)
    for row in tab_rows:
        label = str(row.get("label") or row.get("id") or "").strip()
        if not label:
            continue
        files = [str(row.get("component") or "")] + [str(item or "") for item in (row.get("support_files") or [])]
        for file in files:
            if file:
                index[file].append(label)
    return {file: unique(labels) for file, labels in index.items()}


def basename_without_ext(path: object) -> str:
    name = Path(str(path or "")).name
    return re.sub(r"\.[^.]+$", "", name) or "unknown"


def labels_for_frontend_sites(sites: List[Dict[str, object]], source_tab_index: Dict[str, List[str]]) -> List[str]:
    labels: List[str] = []
    for site in sites:
        file = str(site.get("file") or "")
        labels.extend(source_tab_index.get(file, []))
        if not source_tab_index.get(file):
            labels.append(basename_without_ext(file))
    labels = unique(labels)
    if not labels:
        return ["API only"]
    if len(labels) > 4:
        return labels[:3] + [f"+{len(labels) - 3} tabs"]
    return labels


def visual_graph_payload(
    request_flows: List[Dict[str, object]],
    tab_rows: List[Dict[str, object]],
    generated_at: str,
) -> Dict[str, object]:
    source_tab_index = build_source_tab_index(tab_rows)
    sensitive_services = {
        "auth",
        "certs",
        "dataprotect",
        "ekm",
        "governance",
        "keyaccess",
        "keycore",
        "payment",
        "policy",
        "secrets",
        "signing",
        "workload",
    }
    destructive_methods = {"DELETE", "PATCH", "POST", "PUT"}
    flows = []
    for flow in request_flows:
        frontend_sites = list(flow.get("frontend_call_sites") or [])
        service = str(flow.get("service") or "")
        method = str(flow.get("method") or "GET")
        store_calls = list(flow.get("handler_store_calls") or []) + list(flow.get("service_store_calls") or [])
        receiver_calls = list(flow.get("handler_receiver_calls") or []) + list(flow.get("service_receiver_calls") or [])
        internal_pkg_calls = list(flow.get("handler_internal_package_calls") or []) + list(flow.get("service_internal_package_calls") or [])
        external_pkg_calls = list(flow.get("handler_external_package_calls") or []) + list(flow.get("service_external_package_calls") or [])
        complexity = len(unique(store_calls)) + len(unique(receiver_calls)) + len(unique(internal_pkg_calls))
        risk = "high" if method in {"DELETE"} or service in {"keycore", "auth", "governance", "payment"} else "medium" if method in destructive_methods or complexity >= 4 else "low"
        flows.append(
            {
                "routeKey": f"{service}|{method}|{flow.get('normalized_path')}",
                "service": service,
                "method": method,
                "path": flow.get("path"),
                "normalizedPath": flow.get("normalized_path"),
                "uiLabels": labels_for_frontend_sites(frontend_sites, source_tab_index),
                "frontendSites": [
                    {
                        "file": site.get("file"),
                        "line": site.get("line"),
                        "source": site.get("source"),
                        "expression": site.get("expression"),
                    }
                    for site in frontend_sites
                ],
                "handler": flow.get("handler_name") or "",
                "handlerFile": flow.get("handler_file") or "",
                "handlerLine": flow.get("handler_line") or "",
                "serviceCalls": unique(flow.get("handler_service_calls") or []),
                "storeCalls": unique(store_calls),
                "receiverCalls": unique(receiver_calls),
                "internalPackages": unique(internal_pkg_calls),
                "externalPackages": unique(external_pkg_calls),
                "hasFrontend": bool(frontend_sites),
                "sensitive": service in sensitive_services,
                "risk": risk,
                "complexity": complexity,
            }
        )

    services = sorted(unique(flow["service"] for flow in flows))
    methods = sorted(unique(flow["method"] for flow in flows))
    return {
        "generatedAt": generated_at,
        "summary": {
            "flows": len(flows),
            "frontendBacked": sum(1 for flow in flows if flow["hasFrontend"]),
            "services": len(services),
            "highRisk": sum(1 for flow in flows if flow["risk"] == "high"),
        },
        "services": services,
        "methods": methods,
        "flows": flows,
    }


def write_visual_graph_html(path: Path, payload: Dict[str, object]) -> None:
    data_json = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vecta KMS Request Graph</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #090a0e;
      --panel: #15161b;
      --panel-2: #202026;
      --line: #35323f;
      --muted: #9b98a8;
      --text: #f5f2ff;
      --purple: #8b5cf6;
      --purple-2: #a78bfa;
      --pink: #ff6bb5;
      --red: #ef4444;
      --amber: #f59e0b;
      --green: #34d399;
      --blue: #38bdf8;
      --node: #17181e;
      --node-hi: #29233a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      overflow: hidden;
    }}
    .app {{ display: grid; grid-template-columns: 44px 1fr; height: 100vh; }}
    .rail {{
      background: #0c0d12;
      border-right: 1px solid #1f2028;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 14px;
      padding: 14px 0;
    }}
    .rail .dot {{
      width: 24px;
      height: 24px;
      border-radius: 8px;
      display: grid;
      place-items: center;
      color: var(--muted);
      font-size: 12px;
    }}
    .rail .dot.active {{
      color: white;
      background: linear-gradient(135deg, var(--purple), #6d28d9);
      box-shadow: 0 0 18px rgba(139, 92, 246, 0.75);
    }}
    header {{
      height: 58px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 22px 0 18px;
      border-bottom: 1px solid #1e1f27;
      background: #101116;
    }}
    h1 {{ margin: 0; font-size: 20px; letter-spacing: -0.02em; }}
    .env {{
      display: flex;
      align-items: center;
      gap: 12px;
      color: var(--muted);
      font-size: 12px;
    }}
    .env select, .search, .filter {{
      background: #111218;
      color: var(--text);
      border: 1px solid #323340;
      border-radius: 8px;
      height: 34px;
      padding: 0 12px;
      outline: none;
    }}
    main {{
      height: calc(100vh - 58px);
      padding: 10px;
      background: radial-gradient(circle at 52% 40%, rgba(139, 92, 246, 0.12), transparent 34%), var(--bg);
    }}
    .surface {{
      height: 100%;
      background: #242424;
      border: 1px solid #1f2028;
      border-radius: 16px;
      overflow: hidden;
      position: relative;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 18px 60px rgba(0,0,0,0.45);
    }}
    .toolbar {{
      height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 18px;
    }}
    .pills {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
    .pill {{
      height: 32px;
      border: 1px solid #3b3b45;
      border-radius: 999px;
      padding: 0 12px;
      display: inline-flex;
      gap: 8px;
      align-items: center;
      color: #eeeaf8;
      background: rgba(12, 13, 18, 0.6);
      font-size: 12px;
    }}
    .pill.purple {{ border-color: rgba(167,139,250,.7); box-shadow: inset 0 0 0 1px rgba(139,92,246,.15); }}
    .view-toggle {{
      display: flex;
      border: 1px solid #373240;
      border-radius: 8px;
      overflow: hidden;
      background: #14151b;
    }}
    .view-toggle button {{
      height: 34px;
      border: 0;
      padding: 0 14px;
      background: transparent;
      color: var(--muted);
      cursor: pointer;
    }}
    .view-toggle button.active {{ background: rgba(139, 92, 246, 0.35); color: #fff; }}
    .body {{ display: grid; grid-template-columns: 150px 1fr 252px; height: calc(100% - 64px); }}
    .layers {{
      padding: 10px 14px 18px 18px;
      color: var(--muted);
      font-size: 12px;
    }}
    .layers h3 {{ color: #ebe8f7; font-size: 11px; margin: 8px 0 12px; }}
    .layer {{
      width: 100%;
      margin-bottom: 8px;
      padding: 9px 10px;
      border: 1px solid #4b435b;
      color: #d7cff5;
      background: rgba(139, 92, 246, .13);
      border-radius: 7px;
      text-align: left;
      cursor: pointer;
    }}
    .layer.off {{ background: rgba(14, 15, 20, .65); color: var(--muted); }}
    .graph-wrap {{ position: relative; overflow: hidden; }}
    #graph {{
      position: absolute;
      inset: 0;
      overflow: hidden;
    }}
    #edges {{
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
    }}
    .column-label {{
      position: absolute;
      top: 4px;
      transform: translateX(-50%);
      padding: 5px 10px;
      border-radius: 999px;
      background: linear-gradient(135deg, var(--purple), #6d28d9);
      font-size: 10px;
      font-weight: 700;
      color: #fff;
      box-shadow: 0 8px 20px rgba(139, 92, 246, .25);
      z-index: 4;
      white-space: nowrap;
    }}
    .node {{
      position: absolute;
      width: 190px;
      min-height: 46px;
      border: 1px solid #383641;
      background: linear-gradient(180deg, #17181e, #111218);
      border-radius: 8px;
      padding: 8px 10px;
      cursor: pointer;
      z-index: 3;
      box-shadow: 0 8px 24px rgba(0,0,0,.22);
    }}
    .node.service, .node.pkg {{ width: 128px; border-radius: 999px; text-align: center; }}
    .node.handler {{ width: 206px; }}
    .node.active {{
      border-color: var(--pink);
      box-shadow: 0 0 0 1px rgba(255,107,181,.45), 0 0 26px rgba(255,107,181,.44), 0 10px 30px rgba(0,0,0,.35);
      background: linear-gradient(180deg, #2a1d30, #17111b);
    }}
    .node-title {{ font-size: 12px; font-weight: 750; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .node-sub {{ margin-top: 2px; font-size: 10px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .badge {{
      position: absolute;
      top: -8px;
      right: -8px;
      min-width: 18px;
      height: 18px;
      padding: 0 5px;
      border-radius: 99px;
      display: grid;
      place-items: center;
      color: #fff;
      font-size: 10px;
      background: var(--red);
      border: 1px solid rgba(255,255,255,.18);
    }}
    .edge {{ fill: none; stroke: rgba(122, 114, 139, .22); stroke-width: 5; }}
    .edge.hot {{ stroke: rgba(167, 139, 250, .78); stroke-width: 5.5; filter: drop-shadow(0 0 6px rgba(167,139,250,.5)); }}
    .details {{
      padding: 10px 14px;
      border-left: 1px solid #34333b;
      color: #ddd7ee;
      overflow: auto;
      background: rgba(13, 14, 19, .35);
    }}
    .details h2 {{ font-size: 14px; margin: 6px 0 10px; }}
    .stat-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; }}
    .stat {{ padding: 8px; border: 1px solid #34333e; border-radius: 8px; background: rgba(0,0,0,.18); }}
    .stat b {{ display: block; font-size: 17px; }}
    .stat span {{ color: var(--muted); font-size: 10px; }}
    .detail-block {{ margin-top: 12px; }}
    .detail-block h4 {{ margin: 0 0 6px; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }}
    .chip {{
      display: inline-flex;
      margin: 0 5px 5px 0;
      padding: 4px 7px;
      border-radius: 999px;
      background: rgba(139,92,246,.16);
      border: 1px solid rgba(139,92,246,.35);
      font-size: 11px;
      max-width: 220px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .table-view {{
      display: none;
      height: calc(100% - 64px);
      overflow: auto;
      padding: 0 18px 18px;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
    th, td {{ border-bottom: 1px solid #373740; padding: 9px 8px; text-align: left; vertical-align: top; }}
    th {{ position: sticky; top: 0; background: #242424; z-index: 1; color: #cfc8e8; }}
    td {{ color: #ded9ec; }}
    .hidden {{ display: none !important; }}
    @media (max-width: 980px) {{
      .body {{ grid-template-columns: 1fr; }}
      .layers, .details {{ display: none; }}
      .node {{ width: 150px; }}
    }}
  </style>
</head>
<body>
  <div class="app">
    <aside class="rail">
      <div class="dot">V</div>
      <div class="dot">D</div>
      <div class="dot">S</div>
      <div class="dot active">AI</div>
      <div class="dot">K</div>
      <div class="dot">G</div>
      <div style="flex:1"></div>
      <div class="dot">?</div>
    </aside>
    <section>
      <header>
        <h1>Vecta KMS Request Graph</h1>
        <div class="env">
          <span id="generated"></span>
          <select><option>Local Source</option></select>
        </div>
      </header>
      <main>
        <div class="surface">
          <div class="toolbar">
            <div class="pills">
              <input id="search" class="search" placeholder="Search tab, route, handler, package..." />
              <select id="serviceFilter" class="filter"><option value="">All services</option></select>
              <select id="methodFilter" class="filter"><option value="">All methods</option></select>
              <button id="frontendOnly" class="pill purple">Frontend backed</button>
              <button id="sensitiveOnly" class="pill">Sensitive</button>
            </div>
            <div class="view-toggle">
              <button id="tableBtn">Table</button>
              <button id="graphBtn" class="active">Graph</button>
            </div>
          </div>
          <div id="graphView" class="body">
            <aside class="layers">
              <h3>Insight Layers</h3>
              <button class="layer" data-layer="risk">Risk Score</button>
              <button class="layer" data-layer="stores">Store Calls</button>
              <button class="layer" data-layer="packages">Packages</button>
            </aside>
            <section class="graph-wrap">
              <svg id="edges"></svg>
              <div id="graph"></div>
            </section>
            <aside class="details">
              <div class="stat-grid">
                <div class="stat"><b id="statFlows">0</b><span>visible flows</span></div>
                <div class="stat"><b id="statServices">0</b><span>services</span></div>
                <div class="stat"><b id="statRisk">0</b><span>high risk</span></div>
                <div class="stat"><b id="statFrontend">0</b><span>frontend backed</span></div>
              </div>
              <h2 id="detailTitle">Select a node</h2>
              <div id="detailBody">Click any node to see exact source files, handler, service methods, stores, and packages.</div>
            </aside>
          </div>
          <div id="tableView" class="table-view"></div>
        </div>
      </main>
    </section>
  </div>
  <script>
    const DATA = {data_json};
    const state = {{ q: "", service: "", method: "", frontendOnly: true, sensitiveOnly: false, view: "graph", active: null, layers: {{ risk: true, stores: true, packages: true }} }};
    const el = (id) => document.getElementById(id);
    const graph = el("graph");
    const edges = el("edges");
    const graphWrap = document.querySelector(".graph-wrap");
    el("generated").textContent = "Generated " + DATA.generatedAt;
    DATA.services.forEach(s => el("serviceFilter").insertAdjacentHTML("beforeend", `<option value="${{s}}">${{s}}</option>`));
    DATA.methods.forEach(m => el("methodFilter").insertAdjacentHTML("beforeend", `<option value="${{m}}">${{m}}</option>`));

    function textOf(flow) {{
      return [
        flow.routeKey, flow.service, flow.method, flow.path, flow.handler,
        flow.uiLabels.join(" "), flow.serviceCalls.join(" "), flow.storeCalls.join(" "),
        flow.receiverCalls.join(" "), flow.internalPackages.join(" "), flow.externalPackages.join(" ")
      ].join(" ").toLowerCase();
    }}
    function filteredFlows() {{
      const q = state.q.trim().toLowerCase();
      return DATA.flows.filter(flow => {{
        if (state.frontendOnly && !flow.hasFrontend) return false;
        if (state.sensitiveOnly && !flow.sensitive) return false;
        if (state.service && flow.service !== state.service) return false;
        if (state.method && flow.method !== state.method) return false;
        if (q && !textOf(flow).includes(q)) return false;
        return true;
      }});
    }}
    function addNode(nodes, id, col, title, sub, meta, risk) {{
      if (!nodes.has(id)) nodes.set(id, {{ id, col, title, sub, meta: new Set(), risk, count: 0 }});
      const node = nodes.get(id);
      node.count += 1;
      if (meta) node.meta.add(meta);
      if (risk === "high") node.risk = "high";
      else if (risk === "medium" && node.risk !== "high") node.risk = "medium";
      return id;
    }}
    function buildGraph(flows) {{
      const rows = flows.slice(0, 130);
      const nodes = new Map();
      const links = [];
      rows.forEach(flow => {{
        const routeId = addNode(nodes, `route:${{flow.routeKey}}`, 1, `${{flow.method}} ${{flow.path}}`, flow.routeKey, flow.routeKey, flow.risk);
        const serviceId = addNode(nodes, `service:${{flow.service}}`, 2, flow.service, `${{flow.method}} routes`, flow.service, flow.risk);
        const handlerId = addNode(nodes, `handler:${{flow.service}}:${{flow.handler}}`, 3, flow.handler || "(handler)", `${{flow.handlerFile}}:${{flow.handlerLine || ""}}`, flow.routeKey, flow.risk);
        flow.uiLabels.forEach(label => {{
          const uiId = addNode(nodes, `ui:${{label}}`, 0, label, "UI/module", flow.routeKey, flow.risk);
          links.push([uiId, routeId, flow.risk]);
        }});
        links.push([routeId, serviceId, flow.risk]);
        links.push([serviceId, handlerId, flow.risk]);
        const tail = [];
        if (state.layers.stores) flow.storeCalls.slice(0, 4).forEach(x => tail.push(["store", x]));
        if (state.layers.stores) flow.receiverCalls.slice(0, 3).forEach(x => tail.push(["client", x]));
        if (state.layers.packages) flow.internalPackages.slice(0, 3).forEach(x => tail.push(["pkg", x]));
        if (!tail.length && flow.serviceCalls.length) flow.serviceCalls.slice(0, 3).forEach(x => tail.push(["svc", x]));
        tail.slice(0, 5).forEach(([kind, name]) => {{
          const pkgId = addNode(nodes, `${{kind}}:${{flow.service}}:${{name}}`, 4, name, kind, flow.routeKey, flow.risk);
          links.push([handlerId, pkgId, flow.risk]);
        }});
      }});
      return {{ nodes: [...nodes.values()], links }};
    }}
    function nodeClass(node) {{
      const base = node.col === 2 ? "service" : node.col === 3 ? "handler" : node.col === 4 ? "pkg" : "";
      return `node ${{base}} ${{state.active === node.id ? "active" : ""}}`;
    }}
    function renderGraph() {{
      const flows = filteredFlows();
      const visible = flows.slice(0, 130);
      const built = buildGraph(flows);
      graph.innerHTML = "";
      edges.innerHTML = "";
      const w = graphWrap.clientWidth || 900;
      const h = graphWrap.clientHeight || 600;
      edges.setAttribute("viewBox", `0 0 ${{w}} ${{h}}`);
      const cols = [0.07, 0.27, 0.52, 0.71, 0.89].map(v => Math.round(w * v));
      ["UI", "API Calls", "Services", "Go Handlers", "Stores & Packages"].forEach((label, i) => {{
        const d = document.createElement("div");
        d.className = "column-label";
        d.style.left = `${{cols[i]}}px`;
        d.textContent = label;
        graph.appendChild(d);
      }});
      const byCol = [0,1,2,3,4].map(col => built.nodes.filter(n => n.col === col));
      const positions = new Map();
      byCol.forEach((items, col) => {{
        const top = 48;
        const gap = Math.max(54, Math.min(72, (h - 88) / Math.max(1, items.length)));
        items.forEach((node, index) => {{
          const x = cols[col] - (node.col === 2 || node.col === 4 ? 64 : node.col === 3 ? 103 : 95);
          const y = top + index * gap;
          positions.set(node.id, {{ x, y, w: node.col === 2 || node.col === 4 ? 128 : node.col === 3 ? 206 : 190, h: 46 }});
          const d = document.createElement("div");
          d.className = nodeClass(node);
          d.style.left = `${{x}}px`;
          d.style.top = `${{y}}px`;
          d.dataset.id = node.id;
          d.innerHTML = `<div class="node-title">${{escapeHtml(node.title)}}</div><div class="node-sub">${{escapeHtml(node.sub || "")}}</div>${{state.layers.risk && node.risk === "high" ? `<div class="badge">${{node.count}}</div>` : ""}}`;
          d.onclick = () => {{ state.active = node.id; renderDetails(node, flows); renderGraph(); }};
          graph.appendChild(d);
        }});
      }});
      built.links.forEach(([from, to, risk]) => {{
        const a = positions.get(from), b = positions.get(to);
        if (!a || !b) return;
        const x1 = a.x + a.w, y1 = a.y + a.h / 2;
        const x2 = b.x, y2 = b.y + b.h / 2;
        const c = Math.max(40, (x2 - x1) * 0.45);
        const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
        p.setAttribute("d", `M ${{x1}} ${{y1}} C ${{x1 + c}} ${{y1}}, ${{x2 - c}} ${{y2}}, ${{x2}} ${{y2}}`);
        p.setAttribute("class", `edge ${{risk === "high" ? "hot" : ""}}`);
        edges.appendChild(p);
      }});
      updateStats(flows, visible);
      if (!state.active) renderDetails(null, flows);
    }}
    function updateStats(flows, visible) {{
      el("statFlows").textContent = String(visible.length) + (flows.length > visible.length ? "+" : "");
      el("statServices").textContent = new Set(flows.map(f => f.service)).size;
      el("statRisk").textContent = flows.filter(f => f.risk === "high").length;
      el("statFrontend").textContent = flows.filter(f => f.hasFrontend).length;
    }}
    function renderDetails(node, flows) {{
      if (!node) {{
        el("detailTitle").textContent = "Select a node";
        el("detailBody").innerHTML = "Click any node to inspect route, handler, service, store, and package details.";
        return;
      }}
      const related = flows.filter(flow => node.meta && node.meta.has(flow.routeKey)).slice(0, 8);
      el("detailTitle").textContent = node.title;
      el("detailBody").innerHTML = related.map(flow => `
        <div class="detail-block">
          <h4>${{escapeHtml(flow.routeKey)}}</h4>
          <div class="chip">${{escapeHtml(flow.handler || "(handler)")}}</div>
          ${{flow.frontendSites.map(s => `<div class="chip">${{escapeHtml(s.file + ":" + s.line)}}</div>`).join("")}}
          ${{flow.serviceCalls.map(x => `<div class="chip">svc.${{escapeHtml(x)}}</div>`).join("")}}
          ${{flow.storeCalls.map(x => `<div class="chip">store.${{escapeHtml(x)}}</div>`).join("")}}
          ${{flow.internalPackages.map(x => `<div class="chip">${{escapeHtml(x)}}</div>`).join("")}}
        </div>
      `).join("") || "No route details for this node." ;
    }}
    function renderTable() {{
      const rows = filteredFlows();
      el("tableView").innerHTML = `<table><thead><tr><th>Route</th><th>UI / Frontend</th><th>Handler</th><th>Service methods</th><th>Stores / clients</th><th>Packages</th></tr></thead><tbody>${{rows.map(flow => `
        <tr>
          <td><b>${{escapeHtml(flow.method)}} ${{escapeHtml(flow.path)}}</b><br><span>${{escapeHtml(flow.service)}}</span></td>
          <td>${{escapeHtml(flow.uiLabels.join(", "))}}<br>${{flow.frontendSites.map(s => escapeHtml(s.file + ":" + s.line)).join("<br>")}}</td>
          <td>${{escapeHtml(flow.handler)}}<br>${{escapeHtml(flow.handlerFile + ":" + (flow.handlerLine || ""))}}</td>
          <td>${{escapeHtml(flow.serviceCalls.join(", "))}}</td>
          <td>${{escapeHtml([...flow.storeCalls, ...flow.receiverCalls].join(", "))}}</td>
          <td>${{escapeHtml(flow.internalPackages.join(", "))}}</td>
        </tr>`).join("")}}</tbody></table>`;
    }}
    function render() {{
      if (state.view === "graph") renderGraph();
      else renderTable();
    }}
    function escapeHtml(value) {{
      return String(value ?? "").replace(/[&<>"']/g, ch => ({{ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }}[ch]));
    }}
    el("search").addEventListener("input", e => {{ state.q = e.target.value; state.active = null; render(); }});
    el("serviceFilter").addEventListener("change", e => {{ state.service = e.target.value; state.active = null; render(); }});
    el("methodFilter").addEventListener("change", e => {{ state.method = e.target.value; state.active = null; render(); }});
    el("frontendOnly").onclick = () => {{ state.frontendOnly = !state.frontendOnly; el("frontendOnly").classList.toggle("purple", state.frontendOnly); state.active = null; render(); }};
    el("sensitiveOnly").onclick = () => {{ state.sensitiveOnly = !state.sensitiveOnly; el("sensitiveOnly").classList.toggle("purple", state.sensitiveOnly); state.active = null; render(); }};
    document.querySelectorAll(".layer").forEach(btn => btn.onclick = () => {{
      const key = btn.dataset.layer;
      state.layers[key] = !state.layers[key];
      btn.classList.toggle("off", !state.layers[key]);
      render();
    }});
    el("graphBtn").onclick = () => {{ state.view = "graph"; el("graphBtn").classList.add("active"); el("tableBtn").classList.remove("active"); el("graphView").classList.remove("hidden"); el("tableView").style.display = "none"; render(); }};
    el("tableBtn").onclick = () => {{ state.view = "table"; el("tableBtn").classList.add("active"); el("graphBtn").classList.remove("active"); el("graphView").classList.add("hidden"); el("tableView").style.display = "block"; render(); }};
    window.addEventListener("resize", () => {{ if (state.view === "graph") renderGraph(); }});
    render();
  </script>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    backend_routes = extract_backend_routes()
    frontend_calls = extract_frontend_calls()
    nav, tab_to_component, titles, subpanes = extract_shell_maps()
    tab_rows = build_tab_service_map(nav, tab_to_component, frontend_calls)
    button_inventory = extract_button_inventory(tab_rows)
    request_flows = build_request_flows(backend_routes, frontend_calls)

    backend_keys = {str(route["match_key"]) for route in backend_routes}
    matched_calls = [call for call in frontend_calls if str(call["match_key"]) in backend_keys]
    unmatched_calls = [call for call in frontend_calls if str(call["match_key"]) not in backend_keys]

    frontend_keys = {str(call["match_key"]) for call in frontend_calls}
    unused_routes = [route for route in backend_routes if str(route["match_key"]) not in frontend_keys]

    route_counts = Counter(str(route["service"]) for route in backend_routes)
    frontend_service_counts = Counter(str(call["service_key"]) for call in frontend_calls)
    tab_service_counts = Counter(service for row in tab_rows for service in (row.get("services") or []))
    routes_with_frontend = [flow for flow in request_flows if flow.get("frontend_call_sites")]
    routes_with_service_calls = [flow for flow in request_flows if flow.get("handler_service_calls")]
    routes_with_store_calls = [
        flow for flow in request_flows if (flow.get("handler_store_calls") or flow.get("service_store_calls"))
    ]
    routes_with_internal_pkg_calls = [
        flow
        for flow in request_flows
        if (flow.get("handler_internal_package_calls") or flow.get("service_internal_package_calls"))
    ]
    generated_at = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    mermaid = make_mermaid(tab_rows, route_counts)

    product_map_md = [
        "# Generated Product Map",
        "",
        f"Generated at `{generated_at}` by `scripts/generate_product_map.py`.",
        "",
        "This file is generated from source. Re-run the script after UI or API changes.",
        "",
        "## Summary",
        "",
        f"- Dashboard navigation items: `{len(nav)}`",
        f"- Tab/component mappings: `{len(tab_to_component)}`",
        f"- Sub-pane groups: `{len(subpanes)}`",
        f"- Backend HTTP routes discovered: `{len(backend_routes)}` across `{len(route_counts)}` services",
        f"- Frontend API call sites discovered: `{len(frontend_calls)}`",
        f"- Frontend call sites with exact backend route match: `{len(matched_calls)}`",
        f"- Frontend call sites needing review or dynamic/runtime confirmation: `{len(unmatched_calls)}`",
        f"- Clickable controls with static `onClick` handlers: `{len(button_inventory)}`",
        f"- Backend request flows with handler/service/package summaries: `{len(request_flows)}`",
        "",
        "## How To Use This For Launch",
        "",
        "1. Start with `Navigation To Services` and pick one product tab.",
        "2. Review its service dependencies and then open the linked component/support files.",
        "3. Use `Frontend Calls Needing Review` to find clicks that may hit missing, aliased, dynamic, or unimplemented routes.",
        "4. Use `Backend Routes Not Directly Called From Dashboard` to decide whether each route is API-only, hidden behind a workflow, or dead weight.",
        "5. Pair this static map with Playwright smoke tests and runtime request logging before launch.",
        "",
        "## Visual Service Map",
        "",
        "```mermaid",
        mermaid.strip(),
        "```",
        "",
        "A standalone Mermaid file is also written to `docs/generated/product-map.mmd`.",
        "",
        "## Navigation To Services",
        "",
        table(
            ["Group", "UI item", "Tab id", "Component", "Service dependencies", "Static call sites"],
            (
                [
                    row["group"],
                    row["label"],
                    row["id"],
                    row["component"],
                    ", ".join(row.get("services") or []) or "-",
                    row["call_count"],
                ]
                for row in tab_rows
            ),
        ),
        "",
        "## Backend Route Counts",
        "",
        table(
            ["Service", "Routes", "Frontend call sites"],
            (
                [service, count, frontend_service_counts.get(service, 0)]
                for service, count in sorted(route_counts.items())
            ),
        ),
        "",
        "## Frontend Calls Needing Review",
        "",
        "These are not necessarily broken. Common reasons include dynamic wrapper paths, service aliases, edge auth routes, API-only calls, or routes generated outside `mux.HandleFunc`.",
        "",
        table(
            ["Service", "Method", "Path", "Source", "File", "Line"],
            (
                [
                    call["service"],
                    call["method"],
                    call["normalized_path"],
                    call["source"],
                    call["file"],
                    call["line"],
                ]
                for call in unmatched_calls[:MAX_TABLE_ROWS]
            ),
        )
        if unmatched_calls
        else "No unmatched frontend calls found.",
        "",
        f"Showing `{min(len(unmatched_calls), MAX_TABLE_ROWS)}` of `{len(unmatched_calls)}`. Full data is in `docs/generated/product-map.json` and `docs/generated/frontend-calls.csv`.",
        "",
        "## Backend Routes Not Directly Called From Dashboard",
        "",
        "These may be public API routes, protocol integrations, routes used through SDKs, or unused implementation. They should be classified before launch.",
        "",
        table(
            ["Service", "Method", "Path", "Handler", "File", "Line"],
            (
                [
                    route["service"],
                    route["method"],
                    route["path"],
                    route["handler"],
                    route["file"],
                    route["line"],
                ]
                for route in unused_routes[:MAX_TABLE_ROWS]
            ),
        )
        if unused_routes
        else "Every backend route has at least one static dashboard call site.",
        "",
        f"Showing `{min(len(unused_routes), MAX_TABLE_ROWS)}` of `{len(unused_routes)}`. Full data is in `docs/generated/product-map.json`.",
        "",
        "## Output Files",
        "",
        "- `docs/generated/PRODUCT_MAP.md`: this human-readable summary",
        "- `docs/generated/UI_BUTTON_INVENTORY.md`: static inventory of clickable controls",
        "- `docs/generated/REQUEST_FLOW.md`: frontend route to Go handler/service/store/package flow",
        "- `docs/generated/FLOW_GRAPH.html`: interactive visual request graph",
        "- `docs/generated/product-map.mmd`: Mermaid service graph",
        "- `docs/generated/product-map.json`: machine-readable source inventory",
        "- `docs/generated/frontend-calls.csv`: call-site table for spreadsheet triage",
        "- `docs/generated/backend-routes.csv`: backend route table for spreadsheet triage",
        "- `docs/generated/request-flows.csv`: backend request-flow table for spreadsheet triage",
    ]

    button_md = [
        "# Generated UI Button Inventory",
        "",
        f"Generated at `{generated_at}` by `scripts/generate_product_map.py`.",
        "",
        "This is a static inventory of controls with `onClick` handlers. For exact runtime behavior, combine it with Playwright traces and network logs.",
        "",
        table(
            ["File", "Line", "Tabs", "Control", "Visible label", "Handler snippet"],
            (
                [
                    item["file"],
                    item["line"],
                    ", ".join(item.get("tabs") or []) or "-",
                    item["tag"],
                    item["label"],
                    item["handler"],
                ]
                for item in button_inventory
            ),
        )
        if button_inventory
        else "No static clickable controls found.",
    ]

    request_flow_md = [
        "# Generated Request Flow Map",
        "",
        f"Generated at `{generated_at}` by `scripts/generate_product_map.py`.",
        "",
        "This file connects frontend requests to backend Go processing. It is static analysis: it shows likely code paths from source, while runtime branches still need logs, traces, or Playwright network captures.",
        "",
        "## Summary",
        "",
        f"- Backend routes analyzed: `{len(request_flows)}`",
        f"- Routes with exact frontend call sites: `{len(routes_with_frontend)}`",
        f"- Routes whose handlers call `h.svc.*`: `{len(routes_with_service_calls)}`",
        f"- Routes with detected store calls: `{len(routes_with_store_calls)}`",
        f"- Routes with detected internal `pkg/*` calls: `{len(routes_with_internal_pkg_calls)}`",
        "",
        "## How To Trace One Frontend Click",
        "",
        "1. Open browser DevTools -> Network, then click the dashboard control.",
        "2. Filter for `/svc/` and open the request. Note the HTTP method, URL path, and `X-Request-ID` request header.",
        "3. Search this file or `docs/generated/request-flows.csv` for `service|METHOD|/normalized/path`, for example `keycore|POST|/keys`.",
        "4. Read the row left to right: frontend call site -> Go route -> `Handler` method -> `h.svc.*` service methods -> store/client/package calls.",
        "5. To prove the exact runtime branch, search service logs for the `X-Request-ID`. The frontend adds it in `web/dashboard/src/lib/serviceApi.ts`.",
        "",
        "## Frontend-Backed Request Flows",
        "",
        table(
            [
                "Route key",
                "Route",
                "Handler",
                "Service methods",
                "Store calls",
                "Receiver/client calls",
                "Internal package calls",
                "Frontend call sites",
            ],
            flow_table_rows(routes_with_frontend),
        )
        if routes_with_frontend
        else "No exact frontend-backed routes found.",
        "",
        "## All Backend Request Flows",
        "",
        table(
            [
                "Route key",
                "Route",
                "Handler",
                "Service methods",
                "Store calls",
                "Receiver/client calls",
                "Internal package calls",
                "Frontend call sites",
            ],
            flow_table_rows(request_flows),
        ),
    ]

    graph_payload = visual_graph_payload(request_flows, tab_rows, generated_at)

    payload = {
        "generated_at": generated_at,
        "summary": {
            "nav_items": len(nav),
            "tab_components": len(tab_to_component),
            "subpane_groups": len(subpanes),
            "backend_routes": len(backend_routes),
            "backend_services": len(route_counts),
            "frontend_call_sites": len(frontend_calls),
            "matched_frontend_call_sites": len(matched_calls),
            "unmatched_frontend_call_sites": len(unmatched_calls),
            "button_inventory": len(button_inventory),
            "request_flows": len(request_flows),
            "request_flows_with_frontend": len(routes_with_frontend),
            "request_flows_with_service_calls": len(routes_with_service_calls),
            "request_flows_with_store_calls": len(routes_with_store_calls),
            "request_flows_with_internal_package_calls": len(routes_with_internal_pkg_calls),
        },
        "navigation": nav,
        "titles": titles,
        "subpanes": subpanes,
        "tabs": tab_rows,
        "backend_routes": backend_routes,
        "frontend_calls": frontend_calls,
        "unmatched_frontend_calls": unmatched_calls,
        "backend_routes_not_directly_called_by_dashboard": unused_routes,
        "request_flows": request_flows,
        "visual_graph": graph_payload,
        "button_inventory": button_inventory,
        "service_counts": {
            "backend_routes": dict(sorted(route_counts.items())),
            "frontend_calls": dict(sorted(frontend_service_counts.items())),
            "tab_dependencies": dict(sorted(tab_service_counts.items())),
        },
    }

    (OUT_DIR / "PRODUCT_MAP.md").write_text("\n".join(product_map_md) + "\n", encoding="utf-8")
    (OUT_DIR / "UI_BUTTON_INVENTORY.md").write_text("\n".join(button_md) + "\n", encoding="utf-8")
    (OUT_DIR / "REQUEST_FLOW.md").write_text("\n".join(request_flow_md) + "\n", encoding="utf-8")
    write_visual_graph_html(OUT_DIR / "FLOW_GRAPH.html", graph_payload)
    (OUT_DIR / "product-map.mmd").write_text(mermaid, encoding="utf-8")
    (OUT_DIR / "product-map.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_csv(
        OUT_DIR / "frontend-calls.csv",
        frontend_calls,
        ["service", "service_key", "method", "path", "normalized_path", "dynamic", "source", "file", "line", "match_key"],
    )
    write_csv(
        OUT_DIR / "backend-routes.csv",
        backend_routes,
        ["service", "method", "path", "normalized_path", "handler", "file", "line", "match_key"],
    )
    write_csv(
        OUT_DIR / "request-flows.csv",
        flow_csv_rows(request_flows),
        [
            "route_key",
            "service",
            "method",
            "path",
            "normalized_path",
            "frontend_call_sites",
            "handler",
            "handler_file",
            "handler_line",
            "handler_service_calls",
            "store_calls",
            "receiver_client_calls",
            "internal_package_calls",
            "external_package_calls",
        ],
    )

    print(f"Wrote {rel(OUT_DIR / 'PRODUCT_MAP.md')}")
    print(f"Wrote {rel(OUT_DIR / 'UI_BUTTON_INVENTORY.md')}")
    print(f"Wrote {rel(OUT_DIR / 'REQUEST_FLOW.md')}")
    print(f"Wrote {rel(OUT_DIR / 'FLOW_GRAPH.html')}")
    print(f"Backend routes: {len(backend_routes)}")
    print(f"Frontend call sites: {len(frontend_calls)}")
    print(f"Clickable controls: {len(button_inventory)}")
    print(f"Request flows: {len(request_flows)}")
    print(f"Unmatched frontend call sites: {len(unmatched_calls)}")


if __name__ == "__main__":
    main()
