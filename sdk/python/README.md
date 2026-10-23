# Vecta KMS Python SDK

`vecta_kms`: keys, cryptographic operations and secrets over the Vecta KMS
REST API. Standard library only, Python 3.9 or later, **with an SSL library
that has TLS 1.3** (OpenSSL 1.1.1+; macOS's system Python links LibreSSL 2.8
and is refused with a clear error).

```bash
pip install ./sdk/python
```

It authenticates as a REST client (client ID and API key, Workbench → REST
API), exchanging them for short-lived tokens it renews itself. To use keys,
grant the client a role with key permissions and assign each key to the
client ([CI_CD_AUTOMATION.md](../../docs/CI_CD_AUTOMATION.md#a-role-for-a-client-13530-beta)).

```python
from vecta_kms import APIError, Client

kms = Client("https://kms.example.com", "acme",
             client_id=os.environ["KMS_CLIENT_ID"], api_key=os.environ["KMS_API_KEY"],
             ca_file="vecta-root-ca.pem")  # when the KMS certificate is from its own CA

ct = kms.encrypt(key_id, b"card 4111", aad=b"order-7")
plain = kms.decrypt(ct, aad=b"order-7")
dk = kms.generate_data_key(key_id)        # envelope encryption: use dk.plaintext, keep dk.wrapped
sig = kms.sign(signing_key_id, b"release v1")
ok = kms.verify(sig, b"release v1")
for key in kms.list_keys():
    print(key["id"], key["name"])
value = kms.get_secret_value(secret_id)["value"]
```

`create_key`, `get_key` and `rotate_key` manage keys when the client's role
allows. A refused or failed call raises `APIError` with `status`, the KMS's
`code` (for example `no_matching_grant`) and the `request_id` it was audited
under; `e.refused` is a 401 or 403, `e.not_found` a 404.

Tests: `python3 -m unittest discover -s tests`. keycore's
`TestSDKsAgainstKeycore` runs `contract.py` against the real routes over
TLS on every CI run.
