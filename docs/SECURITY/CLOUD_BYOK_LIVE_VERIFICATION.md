# Cloud BYOK: what is verified against a real cloud

Cloud BYOK ([CLOUD_BYOK.md](CLOUD_BYOK.md)) drives each cloud's own import
protocol. Every cloud is tested against a stand-in that speaks its wire
protocol and unwraps what it receives. That shows the requests are well
formed and the cryptography is right. It does not show the real cloud
accepts them. This page records which clouds have been run for real, by
whom and when, and how to run the rest. Nothing here is marked verified
without a run.

## Status

| Cloud | Verified against the real cloud | Date | By |
|---|---|---|---|
| **AWS KMS** | not yet run: needs an AWS account | | |
| **Google Cloud KMS** | not yet run: needs a Google Cloud project | | |
| **Azure Managed HSM** (AES-256) | not yet run: needs a Managed HSM | | |
| **Azure Key Vault Premium** (RSA-3072 private key) | not yet run: needs a Key Vault Premium | | |
| **OCI Vault** | not yet run: needs an OCI tenancy with a vault | | |
| **Alibaba Cloud KMS** | not yet run: needs an Alibaba Cloud account | | |
| **Salesforce Shield** (import only) | not yet run: needs an org with Shield and a BYOK certificate | | |

No cloud credential is configured where this is built, so none of these
could be run without the owner's accounts.

Short of the real cloud, one independent check exists:

| What | Checked against | Date | By |
|---|---|---|---|
| AWS KMS import (RSA-OAEP SHA-256, 4096-bit wrapping key), encrypt and decrypt with the imported key, tags, new material with `RotateKeyOnDemand`, `DeleteImportedKeyMaterial` and the key then refusing to encrypt | LocalStack 4.14.0 (community), which unwraps the import with its own key. Runs in CI on every push | 2026-10-13 | engineering, local container |

LocalStack is not AWS. It verifies no request signature (so it cannot
refuse a wrong credential), does not expire material, and treats every
import as new material waiting for a rotation, so it takes no material
back after a delete: the restore and the renewal fail there for reasons of
its own. Those three steps are evidence only from AWS.

## What a run does

For each cloud whose settings are given, `TestLiveCloudBYOK`
(`services/cloud/byok_live_test.go`):

1. registers the account and lists its keys;
2. tries the same credential altered (same length, wrong value; for Google,
   another private key under the same key ID) and requires the cloud to
   refuse it;
3. imports fresh, random key material into a new key named
   `vecta-live-<date>-<time>`, wrapped by the same `pkg/crypto` code keycore
   uses, and checks the custody record (KMS version 1 and its KCV). It is an
   AES-256 key everywhere but Azure Key Vault Premium, which takes none:
   there it is an RSA-3072 private key. Where the
   cloud supports an expiry the material is valid for two days, so it
   lapses by itself if the clean-up cannot run;
4. uses the key in the cloud through the console: describe, encrypt and
   decrypt a message (the RSA key signs one, and a signature for another
   message must not verify), set, list and remove a tag;
5. rotates (KMS version 2 must become the cloud's current material), or
   requires the refusal on a cloud that takes no new material (Alibaba);
6. on AWS, renews the same material;
7. revokes, and requires that the key no longer works in the cloud; then
   restores and requires that it works again;
8. schedules the cloud key for deletion.

Salesforce Shield stops after step 3. Shield accepts one upload a day (one
every four hours in a sandbox), so a rotation in the same run would be
refused, and it has no revoke and no delete.

The same sequence runs on the AWS and Alibaba stand-ins, and with an RSA
key on the Azure one, in the ordinary test suite
(`TestLiveFlowRunsOnTheDoubles`,
`TestLiveFlowRunsOnTheAzureDoubleWithAnRSAKey`), so a mistake in the
sequence shows there first and not as a key left in an account.

## What it costs and what it leaves

It creates one real key per cloud. A cloud bills for a key until it is
gone, and none deletes at once:

| Cloud | After the run |
|---|---|
| AWS KMS | the key is pending deletion for 7 days, AWS's shortest wait |
| Google Cloud KMS | the key's versions are scheduled for destruction. The key ring, the key and its import jobs stay: Google deletes none of them |
| Azure Managed HSM, Key Vault Premium | the key is soft-deleted until the vault's retention period ends |
| Salesforce Shield | **one tenant secret, for good.** It becomes the org's active secret of its type and Shield deletes none. Use a sandbox or a developer org |
| OCI Vault | the key is pending deletion for 7 days, OCI's shortest wait |
| Alibaba Cloud KMS | the key is pending deletion for 7 days, Alibaba's shortest wait |

If the clean-up fails the run fails, with a line starting
`CLEAN UP BY HAND` that names the cloud and the key.

## What each credential must be allowed to do

Use a test account and give the credential only this:

- **AWS**: `kms:CreateKey`, `kms:CreateAlias`, `kms:ListKeys`,
  `kms:DescribeKey`, `kms:GetParametersForImport`, `kms:ImportKeyMaterial`,
  `kms:RotateKeyOnDemand`, `kms:ListKeyRotations`,
  `kms:DeleteImportedKeyMaterial`, `kms:Encrypt`, `kms:Decrypt`,
  `kms:TagResource`, `kms:UntagResource`, `kms:ListResourceTags`,
  `kms:ScheduleKeyDeletion`.
- **Google Cloud**: a service account with *Cloud KMS Admin* (keys, key
  rings, versions and import jobs) and *Cloud KMS CryptoKey
  Encrypter/Decrypter* (Admin does not include using a key), in a location
  that offers HSM protection. *Importer* is not needed beside Admin.
- **Azure Managed HSM**: an app registration with the local role *Managed
  HSM Crypto User* at scope `/keys`. It covers create, import, delete,
  encrypt and decrypt; *Crypto Officer* is needed only to recover or purge
  a deleted key, which the run does not do.
- **Azure Key Vault Premium**: the same app registration with *Key Vault
  Crypto Officer* on the vault.
- **OCI**: a user whose group may `manage keys` and `use keys` in the
  compartment, with an API signing key that has no passphrase.
- **Alibaba**: a RAM user allowed the KMS actions `CreateKey`, `ListKeys`,
  `DescribeKey`, `GetParametersForImport`, `ImportKeyMaterial`,
  `DeleteKeyMaterial`, `Encrypt`, `Decrypt`, `TagResource`,
  `UntagResource`, `ListResourceTags`, `ScheduleKeyDeletion`.
- **Salesforce**: a connected app and a user with *Manage Encryption Keys*,
  and a BYOK-compatible certificate created in Setup.

Checked against the vendor's documentation on 2026-10-13: the AWS import,
rotation and deletion actions, the Google roles and the Azure Managed HSM
role. Read from the calls the code makes and not checked: Key Vault
Premium, OCI, Alibaba, Salesforce. No real account has confirmed any of
them. If a cloud refuses a step, the run prints the cloud's own error,
which names the missing permission.

## Running it from CI (no credentials on a laptop)

1. In the repository's settings, add the secrets for the clouds to check.
   Names are the settings in `scripts/byok-live.env.example` with
   `BYOK_LIVE_` in place of `VECTA_TEST_BYOK_` (`BYOK_LIVE_AWS_ACCESS_KEY`,
   `BYOK_LIVE_AWS_SECRET_KEY`, `BYOK_LIVE_AWS_REGION`, ...). Two are whole
   files as one secret: `BYOK_LIVE_GCP_SERVICE_ACCOUNT_JSON` and
   `BYOK_LIVE_OCI_PRIVATE_KEY_PEM`. The full list is in
   `.github/workflows/byok-live.yml`.
2. Actions → **Cloud BYOK — live verification** → Run workflow, and type
   `create keys` to confirm.
3. The run's summary lists what passed, with the commit and time. Add
   those rows to the table above.

The workflow starts only by hand and prints no secret.

## Running it from a checkout

1. Copy `scripts/byok-live.env.example` to `.byok-live.env` in the
   repository root and `chmod 600` it. The file is ignored by git. Fill in
   only the clouds to check.
2. Run `scripts/verify-byok-live.sh`.

It prints the steps of each operation, the cloud's own error text when one
fails, and ends with `Verified: <clouds>` or a failure. It never prints,
logs or passes on a command line any value from the settings file.

## For developers: an emulator

`VECTA_TEST_BYOK_AWS_ENDPOINT` with `VECTA_TEST_BYOK_AWS_EMULATOR=1` runs
the AWS case against an emulator (CI does, with LocalStack 4.14.0:
`docker run -e SERVICES=kms -p 127.0.0.1:4566:4566
localstack/localstack:4.14.0`). The altered credential, the renewal and the
restore are left out, the log says "not AWS" on every line, and nothing it
passes is a row in the first table above. Without the emulator setting the
endpoint is taken to be AWS (a VPC endpoint) and every step runs.

## After a run

Add the row to the table above with the date and who ran it, in the same
change as anything the run led you to fix. Then remove the test credential
from the cloud account, or let it expire.
