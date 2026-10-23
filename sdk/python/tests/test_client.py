"""Unit tests with a stand-in transport. The real routes, over real TLS, are
checked by services/keycore's TestSDKsAgainstKeycore, which runs contract.py."""

import os
import ssl
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import vecta_kms  # noqa: E402
from vecta_kms import APIError, Client  # noqa: E402


def tls13():
    """Stand-ins for an SSL library with TLS 1.3, so these tests run on any
    Python (macOS's system Python has none)."""
    return mock.patch.multiple(ssl, HAS_TLSv1_3=True, create_default_context=mock.MagicMock())


def client(**kw):
    with tls13():
        return Client("https://kms.example.com", "acme", **kw)


class ConfigTest(unittest.TestCase):
    def test_refuses_bad_config(self):
        for kw in ({"base_url": "http://kms", "tenant_id": "t", "token": "x"},
                   {"base_url": "https://kms", "tenant_id": "", "token": "x"},
                   {"base_url": "https://kms", "tenant_id": "t"},
                   {"base_url": "https://kms", "tenant_id": "t", "token": "x", "token_ttl": 5}):
            with self.subTest(kw=kw), self.assertRaises(ValueError), tls13():
                Client(kw.pop("base_url"), kw.pop("tenant_id"), **kw)

    def test_refuses_a_python_without_tls13(self):
        with mock.patch.object(ssl, "HAS_TLSv1_3", False), self.assertRaises(RuntimeError) as cm:
            Client("https://kms.example.com", "acme", token="x")
        self.assertIn("TLS 1.3", str(cm.exception))


class TransportTest(unittest.TestCase):
    def test_token_exchange_reuse_and_renewal(self):
        c = client(client_id="release", api_key="api-key")
        calls = []
        tokens = iter(["tok-1", "tok-2"])

        def send(method, url, body, headers):
            calls.append((url, headers))
            if url.endswith("/svc/auth/auth/client-token"):
                self.assertEqual(headers["X-API-Key"], "api-key")
                self.assertEqual(body, {"tenant_id": "acme", "client_id": "release", "ttl_seconds": 300})
                return {"access_token": next(tokens), "expires_at": "2099-01-01T00:00:00.123456789Z"}
            self.assertIn("tenant_id=acme", url)
            if headers["Authorization"] == "Bearer tok-1" and len([u for u, _ in calls if "keycore" in u]) == 2:
                raise APIError(401, "unauthorized", "expired")
            return {"key": {"id": "k1", "algorithm": "AES-256"}}

        with mock.patch.object(c, "_send", side_effect=send):
            self.assertEqual(c.get_key("k1")["algorithm"], "AES-256")
            self.assertEqual(c.get_key("k1")["id"], "k1")
        exchanges = [u for u, _ in calls if u.endswith("client-token")]
        self.assertEqual(len(exchanges), 2, "one exchange, one renewal after the 401")

    def test_refusal_is_an_api_error(self):
        c = client(token="t")
        with mock.patch.object(c, "_send", side_effect=APIError(403, "no_matching_grant", "access denied", "req_1")):
            with self.assertRaises(APIError) as cm:
                c.encrypt("k2", b"x")
        self.assertTrue(cm.exception.refused)
        self.assertEqual(cm.exception.code, "no_matching_grant")
        self.assertIn("req_1", str(cm.exception))

    def test_list_keys_follows_the_cursor(self):
        c = client(token="t")
        pages = [{"items": [{"id": "a"}, {"id": "b"}], "has_more": True,
                  "next_cursor": {"after_created_at": "2026-10-23T00:00:00Z", "after_id": "b"}},
                 {"items": [{"id": "c"}], "has_more": False}]
        seen_urls = []

        def send(method, url, body, headers):
            seen_urls.append(url)
            return pages[len(seen_urls) - 1]

        with mock.patch.object(c, "_send", side_effect=send):
            self.assertEqual([k["id"] for k in c.list_keys()], ["a", "b", "c"])
        self.assertIn("after_id=b", seen_urls[1])

    def test_encrypt_sends_base64(self):
        c = client(token="t")
        sent = {}

        def send(method, url, body, headers):
            sent.update(body)
            return {"key_id": "k1", "version": 3, "ciphertext": "Y3Q=", "iv": "aXY="}

        with mock.patch.object(c, "_send", side_effect=send):
            ct = c.encrypt("k1", b"hello", aad=b"ctx")
        self.assertEqual(sent["plaintext"], "aGVsbG8=")
        self.assertEqual(sent["aad"], "Y3R4")
        self.assertEqual((ct.version, ct.ciphertext, ct.iv), (3, b"ct", b"iv"))

    def test_version(self):
        self.assertEqual(vecta_kms.__version__, "0.1.0")


if __name__ == "__main__":
    unittest.main()
