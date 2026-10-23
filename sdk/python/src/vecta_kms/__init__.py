"""Python client for Vecta KMS: keys, cryptographic operations and secrets.

It authenticates as a REST client (Workbench -> REST API): the client ID and
API key, exchanged for short-lived tokens it renews itself. To use keys the
client needs a role with key permissions and a key access assignment for the
client (docs/CI_CD_AUTOMATION.md, "A role for a client").

    from vecta_kms import Client
    kms = Client("https://kms.example.com", "acme",
                 client_id=os.environ["KMS_CLIENT_ID"], api_key=os.environ["KMS_API_KEY"])
    ct = kms.encrypt("key_123", b"secret", aad=b"order-7")
    assert kms.decrypt(ct, aad=b"order-7") == b"secret"

Standard library only, Python 3.9 or later.
"""

from .client import APIError, Ciphertext, Client, DataKey, Signature

__all__ = ["APIError", "Ciphertext", "Client", "DataKey", "Signature"]
__version__ = "0.1.0"
