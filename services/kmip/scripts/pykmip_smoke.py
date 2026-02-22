#!/usr/bin/env python3
import argparse
import json
import sys

from kmip.core import enums
from kmip.pie.client import ProxyKmipClient


VERSIONS = {
    "1.0": enums.KMIPVersion.KMIP_1_0,
    "1.1": enums.KMIPVersion.KMIP_1_1,
    "1.2": enums.KMIPVersion.KMIP_1_2,
    "1.3": enums.KMIPVersion.KMIP_1_3,
    "1.4": enums.KMIPVersion.KMIP_1_4,
    "2.0": enums.KMIPVersion.KMIP_2_0,
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="KMIP interoperability smoke test using pykmip (create + encrypt + decrypt)."
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=5696)
    parser.add_argument("--cert", required=True, help="Client TLS certificate path")
    parser.add_argument("--key", required=True, help="Client TLS key path")
    parser.add_argument("--ca", required=True, help="Server CA certificate path")
    parser.add_argument("--version", default="1.4", choices=sorted(VERSIONS.keys()))
    parser.add_argument("--name", default="pykmip-smoke")
    parser.add_argument("--plaintext", default="kmip-smoke-data")
    return parser.parse_args()


def main():
    args = parse_args()
    plaintext = args.plaintext.encode("utf-8")

    client = ProxyKmipClient(
        hostname=args.host,
        port=args.port,
        cert=args.cert,
        key=args.key,
        ca=args.ca,
        kmip_version=VERSIONS[args.version],
    )

    try:
        with client:
            uid = client.create(
                algorithm=enums.CryptographicAlgorithm.AES,
                length=256,
                name=args.name,
                cryptographic_usage_mask=[
                    enums.CryptographicUsageMask.ENCRYPT,
                    enums.CryptographicUsageMask.DECRYPT,
                ],
            )
            client.activate(uid)
            ciphertext, iv = client.encrypt(plaintext, uid)
            roundtrip = client.decrypt(ciphertext, uid, iv_counter_nonce=iv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1

    print(
        json.dumps(
            {
                "ok": True,
                "uid": uid,
                "kmip_version": args.version,
                "ciphertext_len": len(ciphertext),
                "iv_len": 0 if iv is None else len(iv),
                "roundtrip_ok": roundtrip == plaintext,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
