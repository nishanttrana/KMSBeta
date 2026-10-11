# Object storage scans: what is verified against a real service

Crypto Discovery reads buckets through three wire APIs and six ways of
authenticating ([CONNECTIONS.md](CONNECTIONS.md)). This page records which
of them have been run against a real service, by whom and when, and how to
run the rest. Nothing here is marked verified without a run.

## Status

| What | Verified against | Date | By |
|---|---|---|---|
| S3 API, static access key, private bucket, least-privilege user | MinIO `RELEASE.2026-08-04` (verifies signatures); Versity S3 gateway | 2026-10-11; 2026-10-10 | engineering, local containers |
| S3 API, role assumption (signed STS `AssumeRole`, temporary credentials with a session token) | MinIO `RELEASE.2026-08-04` (verifies the STS signature and the session token) | 2026-10-11 | engineering, local container |
| S3 API, public bucket, multi-page listing | Amazon S3 (`noaa-goes16`, 4,608 objects, five pages) | 2026-10-10 | engineering |
| S3 API on Google Cloud Storage, public bucket | Google Cloud Storage | 2026-10-10 | engineering |
| Google JSON API, public bucket | Google Cloud Storage (`gcp-public-data-landsat`) | 2026-10-11 | engineering |
| Azure Blob, SAS token | Azurite emulator | 2026-10-10 | engineering, local container |
| Azure Blob, Shared Key | Azurite emulator (verifies the signature) | 2026-10-11 | engineering, local container |
| Azure Blob, Bearer token on list, read and ranged read (the storage half of Entra ID). The token came from a stand-in issuer | Azurite emulator with `--oauth basic` (refuses a missing, malformed or wrong-audience token) | 2026-10-11 | engineering, local container |
| **Amazon S3, private bucket, static key** | not yet run: needs an AWS account | | |
| **Amazon STS role assumption** | not yet run against AWS itself: needs an AWS account | | |
| **Azure Blob on Azure itself (SAS, Shared Key)** | not yet run: needs an Azure subscription | | |
| **Azure Entra ID application** | not yet run anywhere: no emulator exists; needs an Entra tenant | | |
| **Google service account (token exchange, private bucket)** | not yet run anywhere: no emulator exists; needs a Google Cloud project | | |

The rows in bold are covered by tests against stand-ins that check the
signatures independently (the AWS SDK's signer, a separate HMAC
implementation, RSA verification of the Google assertion). That shows the
requests are well formed. It does not show the real service accepts them.

## Running a check from CI (no credentials on a laptop)

1. In the repository's settings, add the secrets for the services to check.
   Names are the settings below with `STORAGE_LIVE_` in place of
   `VECTA_TEST_` (`STORAGE_LIVE_S3_ENDPOINT`, `STORAGE_LIVE_S3_BUCKET`,
   `STORAGE_LIVE_S3_ACCESS_KEY`, `STORAGE_LIVE_S3_SECRET_KEY`,
   `STORAGE_LIVE_S3_ROLE_ARN`, `STORAGE_LIVE_AZURE_ENDPOINT`,
   `STORAGE_LIVE_AZURE_CONTAINER`, `STORAGE_LIVE_AZURE_TENANT_ID`,
   `STORAGE_LIVE_AZURE_CLIENT_ID`, `STORAGE_LIVE_AZURE_CLIENT_SECRET`,
   `STORAGE_LIVE_GCS_BUCKET`, ...). The Google key is the whole JSON file
   as one secret, `STORAGE_LIVE_GCS_SERVICE_ACCOUNT_JSON`. The full list is
   in `.github/workflows/storage-live.yml`.
2. Actions → **Storage scan — live verification** → Run workflow.
3. The run's summary lists what passed, with the commit and time. Add
   those rows to the table above.

The workflow starts only by hand. Permissions each credential needs are in
the next section.

## Running a check from a checkout

1. Copy `scripts/storage-live.env.example` to `.storage-live.env` in the
   repository root and `chmod 600` it. The file is ignored by git. Fill in
   only the services to check.
2. Give each credential **list and read on one bucket, nothing more**:
   - Amazon S3 key: `s3:ListBucket` on the bucket and `s3:GetObject` on its
     objects. MinIO's built-in `readonly` policy is not enough: it does not
     allow listing.
   - Amazon role: the same two permissions on the role; the key needs only
     `sts:AssumeRole` on that role. Set `VECTA_TEST_S3_ROLE_ARN`.
   - Azure SAS: a container SAS with permissions `r` and `l`.
   - Azure Entra ID: an app registration with the role *Storage Blob Data
     Reader* on the container.
   - Azure Shared Key: the storage account key (grants the whole account;
     use a test account).
   - Google: a service account with *Storage Object Viewer* on the bucket,
     and its JSON key file.
3. Run `scripts/verify-storage-live.sh`.

For each service it scans the bucket, scans it again (the second run must
download nothing: the service's ETags say nothing changed), and then tries
a wrong credential, which the service must refuse. It prints counts, asset
locations and the service's error codes. It never prints, logs or passes on
a command line any value from the settings file, and it writes nothing to
the bucket. It ends with `Verified: <services>` or a failure.

Put a few files in the bucket first so there is something to find (a PEM
certificate, a test private key, a source file that calls a weak
algorithm). `VECTA_TEST_STORAGE_MIN_ASSETS` makes "found nothing" a failure.

The same check is in the product: Crypto Discovery → Object storage →
Buckets → **Test** lists the bucket and reads one object with the bucket's
stored credential, through the same code, and fails with the service's
error code when it can't.

## For developers: the emulators

`VECTA_TEST_AZURE_OAUTH_EMULATOR=1` with the Azure endpoint and container
of an Azurite started with `--oauth basic` runs the Bearer-token case
above. MinIO (`pgsty/minio`) serves both S3 and STS: set
`VECTA_TEST_S3_STS_URL` to its address and any role ARN.

## After a run

Add the row to the table above with the date and who ran it, in the same
change as anything the run led you to fix. Remove the test credentials
from the cloud account, or let them expire.
