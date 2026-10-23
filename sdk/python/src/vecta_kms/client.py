"""The Vecta KMS client (see the package docstring)."""

import base64
import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterator, Optional


class APIError(Exception):
    """The KMS refused or failed a call. code is the KMS's reason (for example
    no_matching_grant, binding_policy, metadata_profile_violation); the KMS
    audited the call under request_id."""

    def __init__(self, status: int, code: str, message: str, request_id: str = ""):
        super().__init__(f"{status} {code}: {message} (request {request_id})")
        self.status, self.code, self.message, self.request_id = status, code, message, request_id

    @property
    def refused(self) -> bool:
        return self.status in (401, 403)

    @property
    def not_found(self) -> bool:
        return self.status == 404


@dataclass
class Ciphertext:
    key_id: str
    version: int
    ciphertext: bytes
    iv: bytes


@dataclass
class Signature:
    key_id: str
    version: int
    signature: bytes


@dataclass
class DataKey:
    """A 256-bit key for local encryption: use plaintext, keep only wrapped,
    and decrypt wrapped later."""

    plaintext: bytes
    wrapped: Ciphertext


def _b64(b: Optional[bytes]) -> str:
    return base64.b64encode(b).decode() if b else ""


def _unb64(s: Optional[str]) -> bytes:
    return base64.b64decode(s) if s else b""


def _parse_time(s: str) -> float:
    s = s.replace("Z", "+00:00")
    if "." in s:  # Python 3.9 parses at most microseconds
        head, rest = s.split(".", 1)
        n = len(rest) - len(rest.lstrip("0123456789"))
        frac, tz = rest[:n], rest[n:]
        s = f"{head}.{(frac + '000000')[:6]}{tz}"
    return datetime.fromisoformat(s).timestamp()


class Client:
    """Calls the KMS. Safe to share between threads."""

    def __init__(self, base_url: str, tenant_id: str, *, client_id: str = "", api_key: str = "",
                 token: str = "", ca_file: Optional[str] = None, token_ttl: int = 300, timeout: float = 30.0):
        parsed = urllib.parse.urlparse(base_url.rstrip("/"))
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("base_url is https://<host>")
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not token and not (client_id and api_key):
            raise ValueError("set client_id and api_key, or token")
        if not 60 <= token_ttl <= 3600:
            raise ValueError("token_ttl is between 60 and 3600 seconds")
        self._base, self._tenant = base_url.rstrip("/"), tenant_id
        self._client_id, self._api_key, self._static = client_id, api_key, token
        self._ttl, self._timeout = token_ttl, timeout
        if not ssl.HAS_TLSv1_3:
            # The KMS speaks TLS 1.3 only. macOS's system Python links LibreSSL 2.8.
            raise RuntimeError(f"this Python's SSL library ({ssl.OPENSSL_VERSION}) has no TLS 1.3, which the KMS "
                               "requires; use a Python built with OpenSSL 1.1.1 or later")
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self._ssl = ctx
        self._lock = threading.Lock()
        self._token, self._expires = token, 0.0

    # ---- transport ----

    def _send(self, method: str, url: str, body: Optional[Dict[str, Any]], headers: Dict[str, str]) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self._ssl, timeout=self._timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                err = json.loads(raw).get("error", {})
            except ValueError:
                err = {}
            raise APIError(e.code, err.get("code", ""), err.get("message", raw.decode(errors="replace").strip()),
                           err.get("request_id", "")) from None
        return json.loads(raw) if raw else {}

    def _bearer(self, renew: bool) -> str:
        if self._static:
            return self._static
        with self._lock:
            if not renew and self._token and self._expires - time.time() > 30:
                return self._token
            out = self._send("POST", self._base + "/svc/auth/auth/client-token",
                             {"tenant_id": self._tenant, "client_id": self._client_id, "ttl_seconds": self._ttl},
                             {"X-API-Key": self._api_key})
            if not out.get("access_token"):
                raise APIError(500, "no_token", "the KMS issued no token")
            self._token, self._expires = out["access_token"], _parse_time(out["expires_at"])
            return self._token

    def _call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, query: Optional[Dict[str, str]] = None) -> Any:
        q = {"tenant_id": self._tenant}
        q.update(query or {})
        url = self._base + path + "?" + urllib.parse.urlencode(q)
        for attempt in (0, 1):
            headers = {"Authorization": "Bearer " + self._bearer(attempt > 0), "X-Tenant-ID": self._tenant}
            try:
                return self._send(method, url, body, headers)
            except APIError as e:
                if attempt == 0 and e.status == 401 and not self._static:
                    continue
                raise
        raise AssertionError("unreachable")

    @staticmethod
    def _key_path(key_id: str, op: str = "") -> str:
        return "/svc/keycore/keys/" + urllib.parse.quote(key_id, safe="") + (("/" + op) if op else "")

    # ---- keys ----

    def create_key(self, name: str, algorithm: str, purpose: str, *, key_type: str = "", description: str = "",
                   labels: Optional[Dict[str, str]] = None, tags: Optional[list] = None) -> str:
        """Creates a key and returns its ID. The tenant's metadata profiles apply."""
        body: Dict[str, Any] = {"tenant_id": self._tenant, "name": name, "algorithm": algorithm, "purpose": purpose}
        for k, v in (("key_type", key_type), ("description", description), ("labels", labels), ("tags", tags)):
            if v:
                body[k] = v
        return self._call("POST", "/svc/keycore/keys", body)["key_id"]

    def get_key(self, key_id: str) -> Dict[str, Any]:
        return self._call("GET", self._key_path(key_id))["key"]

    def list_keys(self) -> Iterator[Dict[str, Any]]:
        """Every key the client can see, a page at a time."""
        query = {"limit": "200"}
        while True:
            out = self._call("GET", "/svc/keycore/keys", query=query)
            yield from out.get("items") or []
            cursor = out.get("next_cursor")
            if not out.get("has_more") or not cursor:
                return
            query = {"limit": "200", "after_created_at": cursor["after_created_at"], "after_id": cursor["after_id"]}

    def update_key(self, key_id: str, **fields: Any) -> Dict[str, Any]:
        """Changes only the named metadata (name, description, purpose, owner,
        tags, labels) and returns the key as stored. The client must manage
        the key (its creator, a key-access administrator, or a grant of "all")."""
        allowed = {"name", "description", "purpose", "owner", "tags", "labels"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"update_key takes {sorted(allowed)}, not {sorted(unknown)}")
        return self._call("PATCH", self._key_path(key_id), fields)["key"]

    def deactivate_key(self, key_id: str) -> None:
        """Stops new encryption and signing; old ciphertext still decrypts."""
        self._call("POST", self._key_path(key_id, "deactivate"), {})

    def get_key_access(self, key_id: str) -> list:
        """The key's grants: subject_type (user, group, client), subject_id, operations."""
        return self._call("GET", self._key_path(key_id, "access-policy"))["policy"].get("grants") or []

    def set_key_access(self, key_id: str, grants: list) -> None:
        """Replaces the key's grants."""
        out = self._call("PUT", self._key_path(key_id, "access-policy"), {"grants": grants})
        if out.get("status") == "pending_approval":
            raise APIError(202, "pending_approval", "the change waits for approval " + out.get("approval_request_id", ""))

    def rotate_key(self, key_id: str, reason: str = "") -> int:
        return int(self._call("POST", self._key_path(key_id, "rotate"), {"reason": reason})["version"])

    # ---- cryptographic operations ----

    def encrypt(self, key_id: str, plaintext: bytes, aad: Optional[bytes] = None) -> Ciphertext:
        out = self._call("POST", self._key_path(key_id, "encrypt"),
                         {"tenant_id": self._tenant, "plaintext": _b64(plaintext), "aad": _b64(aad)})
        return Ciphertext(out["key_id"], int(out["version"]), _unb64(out.get("ciphertext")), _unb64(out.get("iv")))

    def decrypt(self, ct: Ciphertext, aad: Optional[bytes] = None) -> bytes:
        out = self._call("POST", self._key_path(ct.key_id, "decrypt"),
                         {"tenant_id": self._tenant, "ciphertext": _b64(ct.ciphertext), "iv": _b64(ct.iv),
                          "aad": _b64(aad), "version": ct.version})
        return _unb64(out.get("plaintext"))

    def sign(self, key_id: str, data: bytes, algorithm: str = "") -> Signature:
        out = self._call("POST", self._key_path(key_id, "sign"),
                         {"tenant_id": self._tenant, "data": _b64(data), "algorithm": algorithm})
        return Signature(out["key_id"], int(out["version"]), _unb64(out.get("signature")))

    def verify(self, sig: Signature, data: bytes, algorithm: str = "") -> bool:
        out = self._call("POST", self._key_path(sig.key_id, "verify"),
                         {"tenant_id": self._tenant, "data": _b64(data), "signature": _b64(sig.signature),
                          "algorithm": algorithm, "version": sig.version})
        return bool(out.get("verified"))

    def generate_data_key(self, key_id: str, aad: Optional[bytes] = None) -> DataKey:
        out = self._call("POST", self._key_path(key_id, "generate-data-key"),
                         {"tenant_id": self._tenant, "key_bytes": 32, "aad": _b64(aad)})
        wrapped = Ciphertext(out["key_id"], int(out["version"]), _unb64(out.get("wrapped_dek")), _unb64(out.get("wrapped_dek_iv")))
        return DataKey(_unb64(out.get("plaintext_dek")), wrapped)

    # ---- secrets ----

    def get_secret_value(self, secret_id: str) -> Dict[str, Any]:
        """value, version, format and content_type of a secret's current value."""
        return self._call("GET", "/svc/secrets/secrets/" + urllib.parse.quote(secret_id, safe="") + "/value")
