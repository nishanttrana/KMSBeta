"""Run by services/keycore's TestSDKsAgainstKeycore against keycore's real
routes over TLS. Exits non-zero, saying what failed, if the SDK and keycore
disagree. Not part of the package."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from vecta_kms import APIError, Client  # noqa: E402


def main() -> None:
    env = os.environ
    c = Client(env["VECTA_URL"], env["VECTA_TENANT"], token=env["VECTA_TOKEN"], ca_file=env["VECTA_CA"])
    aes, signer, hidden = env["AES_KEY"], env["SIGN_KEY"], env["HIDDEN_KEY"]

    assert c.get_key(aes)["algorithm"] == "AES-256", "get_key"
    ct = c.encrypt(aes, b"card 4111", aad=b"order-7")
    assert c.decrypt(ct, aad=b"order-7") == b"card 4111", "decrypt"
    try:
        c.decrypt(ct, aad=b"order-8")
        raise AssertionError("decrypted under other additional data")
    except APIError:
        pass
    dk = c.generate_data_key(aes, aad=b"blob-1")
    assert len(dk.plaintext) == 32 and c.decrypt(dk.wrapped, aad=b"blob-1") == dk.plaintext, "data key"
    sig = c.sign(signer, b"release v1")
    assert c.verify(sig, b"release v1") and not c.verify(sig, b"release v2"), "sign/verify"
    seen = [k["id"] for k in c.list_keys()]
    assert hidden not in seen and aes in seen and signer in seen, f"list_keys {seen}"
    try:
        c.get_key(hidden)
        raise AssertionError("read a key not granted")
    except APIError as e:
        assert e.not_found, e
    new = c.create_key("py-pipeline-key", "AES-256", "encrypt", key_type="symmetric", labels={"team": "release"})
    assert c.rotate_key(new, "scheduled") == 2, "rotate"
    print("python contract ok")


if __name__ == "__main__":
    main()
