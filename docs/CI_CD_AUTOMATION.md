# CI/CD and automation

How a pipeline (GitHub Actions, GitLab CI, Jenkins, Ansible, or any job
runner) uses Vecta KMS: authenticate, read a secret, rotate a key, and sign
a release. Everything here was checked against the code in 7.16.0-beta.
Every call goes through the public REST API behind Envoy, is authorised by
the route kernel, and is recorded in the Audit Log like any dashboard
action.

This page replaces the dashboard's former **DevSecOps / IaC** tab. See
[What the old tab claimed](#what-the-old-tab-claimed) for why it was removed.

## What exists

| Integration | Status |
|---|---|
| REST API (`/svc/<service>/...`) | Yes. Reference: [API_REFERENCE.md](API_REFERENCE.md), OpenAPI in Documentation → API: OpenAPI / Swagger |
| PKCS#11 and JCA providers | Yes. Documentation → API: PKCS#11/JCA |
| KMIP | Yes ([COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)) |
| Artifact signing with a CI OIDC token | Yes ([below](#sign-a-release-with-the-jobs-oidc-token)) |
| Tenant manifests and automatic key rotation | Yes, server side ([AUTOMATION_ALKM_PQC.md](AUTOMATION_ALKM_PQC.md)) |
| Terraform provider, Go/Python/Node/Java SDKs, Helm chart, KMS sidecar | **No.** None is published, so use the REST API directly |

## 1. Give the pipeline its own identity

Never use a person's login in a pipeline. There are two kinds of pipeline
identity, and they can do different things.

### REST client (secrets and signing)

In the dashboard all of this is in **Workbench → REST API → REST Client
Security**: register, approve (the key is shown once), rotate the key,
revoke. The same calls over the API:

1. Register the client (public call; it is created as `pending`):

   ```bash
   curl -sS --fail-with-body -X POST "$KMS_URL/svc/auth/auth/register" \
     -H 'Content-Type: application/json' \
     -d '{"tenant_id":"acme","client_name":"release-pipeline","interface_name":"rest","auth_mode":"api_key"}'
   ```

   The response carries `registration_id`. Registration is audited as
   `audit.auth.client_registered`.

2. An administrator holding `auth.client.activate` approves it with
   `POST /svc/auth/auth/register/{registration_id}/activate` (or **Approve**
   in the dashboard). The response contains `api_key` **once**. Store it
   straight into the CI secret store (for example as `KMS_API_KEY`) and
   never print it. Activation is audited as `audit.auth.client_activated`,
   and a refusal as `audit.auth.client_activation_refused`.

3. In each job, exchange the API key for a short-lived token (default 300 s,
   between 60 and 3600 s via `ttl_seconds`):

   ```bash
   kms_client_token() {
     printf 'X-API-Key: %s\n' "$KMS_API_KEY" |
       curl -sS --fail-with-body -X POST "$KMS_URL/svc/auth/auth/client-token" \
         -H @- -H 'Content-Type: application/json' \
         -d "{\"tenant_id\":\"$KMS_TENANT\",\"client_id\":\"$KMS_CLIENT_ID\"}" |
       jq -r .access_token
   }
   KMS_TOKEN=$(kms_client_token)
   ```

   `KMS_CLIENT_ID` is the `registration_id`. `printf` is a shell builtin,
   so the key reaches curl on stdin and never appears in a process listing
   or an echoed command ([SECRET_HANDLING.md](SECURITY/SECRET_HANDLING.md)).

**Rotating and revoking.** `POST /svc/auth/auth/clients/{id}/rotate-key`
(or **Rotate key**) issues a new key, shown once, and deletes the old one
in the same transaction: update the CI secret before the next run.
`POST /svc/auth/auth/clients/{id}/revoke` deletes the client's key and
ends its access. Both need `auth.client.write`, and both are audited
(`client_key_rotated`, `client_revoked`), refusals included. Before
7.16.0-beta, rotation returned a key that never worked and left the old
one active.

**What a client token can do.** Activation grants the key `kms.read` and
`kms.write`. The route kernel honours those two broad grants only in the
`secrets` domain (`pkg/route.CoarseDomains`). The token can therefore read
secret values and create, update, rotate or delete secrets, and it can call
artifact signing, where the signing profile's identity rules decide. It
**cannot** create, rotate or use keys in keycore: those routes need
`key.*` permissions, which a client token never holds.

A registration can instead bind the token to the caller with `oauth_mtls`,
`dpop` or `http_message_signature` (`auth_mode`). Documentation →
API: Auth covers the extra proof each mode sends.

### Dedicated user (key operations)

For a job that rotates or creates keys, create a user in Administration
whose role holds only the permissions the job needs, for example `key.rotate`
(see [KEY_ACCESS_MODEL.md](SECURITY/KEY_ACCESS_MODEL.md) and the permission
table in [API_REFERENCE.md](API_REFERENCE.md#key-and-access-management-permissions-400-beta)).
Sign in once interactively to complete the forced password change. Until
then the token holds only `auth.password.change`. Then, in the job:

```bash
kms_user_token() {
  jq -n '{tenant_id: env.KMS_TENANT, username: env.KMS_USER, password: env.KMS_PASSWORD}' |
    curl -sS --fail-with-body -X POST "$KMS_URL/svc/auth/auth/login" \
      -H 'Content-Type: application/json' --data-binary @- |
    jq -r .access_token
}
```

`jq` reads the password from the environment and curl reads the body from
stdin, so the password never appears in argv.

## 2. Call the API safely

- **TLS.** Never pass `-k`. If the edge certificate comes from the internal
  Vecta CA, export the root from the PKI tab and pass `--cacert`.
- **Token.** Send the token on stdin in the same way:
  `printf 'Authorization: Bearer %s\n' "$KMS_TOKEN" | curl -H @- ...`.
- **Tenant.** The tenant comes from the token. An `X-Tenant-ID` header,
  `tenant_id` query or body field is optional, but when present it must
  match the token, or the request is refused (`tenant_mismatch`, audited).
- **Refusals** return 401 or 403 with a `reason`, and every refusal is in
  the Audit Log. Fail the job on any non-2xx (`--fail-with-body`).

## 3. Inject a secret into a job

```bash
kms_get() {  # kms_get <path>
  printf 'Authorization: Bearer %s\n' "$KMS_TOKEN" |
    curl -sS --fail-with-body -H @- "$KMS_URL$1"
}
DB_PASSWORD=$(kms_get "/svc/secrets/secrets/$SECRET_ID/value" | jq -r .value)
echo "::add-mask::$DB_PASSWORD"   # GitHub Actions; GitLab: mark the variable masked
```

It needs `secrets.value.read` (a client token has it). Each read is audited
as the route action `value_read`, with severity `warning`.

## 4. Rotate a key

Prefer server-side rotation over pipeline-triggered rotation: a key's
rotation policy (`/svc/keycore/rotation/policies`, dashboard Rotation) and
the reconciler rotate on schedule without any credential in CI
([AUTOMATION_ALKM_PQC.md](AUTOMATION_ALKM_PQC.md)). When a pipeline has to
rotate, for example right after deploying a new consumer, call it with a
dedicated-user token that holds `key.rotate`:

```bash
printf 'Authorization: Bearer %s\n' "$KMS_TOKEN" |
  curl -sS --fail-with-body -X POST -H @- -H 'Content-Type: application/json' \
    "$KMS_URL/svc/keycore/keys/$KEY_ID/rotate" \
    -d '{"reason":"post-deploy rotation","old_version_action":"deactivate"}'
```

The response carries `version`. The previous version still decrypts what
it protected. Rotation is audited as `rotate_requested`, and a missing
permission as a refused `rotate_requested` with `permission_denied`.

## 5. Sign a release with the job's OIDC token

The signing key stays in the KMS. The pipeline sends a SHA-256 digest and
its CI OIDC token, and the signing service verifies that token itself:
issuer, subject and repository come from the verified token, never from the
request.

One-time setup, in the dashboard under Artifact Signing (or through
`POST /svc/signing/signing/profiles`):
- A profile with `identity_mode: "oidc"`, the signing `key_id`, and
  `allowed_oidc_issuers` set exactly to your CI issuer (GitHub Actions:
  `https://token.actions.githubusercontent.com`).
- `allowed_subject_patterns` (for example `repo:acme/app:ref:refs/heads/main`)
  and, if needed, `allowed_repositories` and the branch policy.
- The token audience must be `vecta-kms-signing` (the signing service's
  `SIGNING_OIDC_AUDIENCE`).

GitHub Actions job (needs `permissions: id-token: write`):

```bash
export OIDC_TOKEN=$(printf 'Authorization: bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" |
  curl -sS --fail-with-body -H @- "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=vecta-kms-signing" | jq -r .value)
export DIGEST=$(sha256sum dist/release.tar.gz | cut -d' ' -f1)

jq -n '{tenant_id: env.KMS_TENANT, profile_id: env.SIGNING_PROFILE_ID, artifact_type: "blob",
        artifact_name: "release.tar.gz", digest_sha256: env.DIGEST,
        identity_mode: "oidc", oidc_token: env.OIDC_TOKEN}' |
  { printf 'Authorization: Bearer %s\n' "$KMS_TOKEN" > "$RUNNER_TEMP/h"; \
    curl -sS --fail-with-body -X POST -H @"$RUNNER_TEMP/h" -H 'Content-Type: application/json' \
      --data-binary @- "$KMS_URL/svc/signing/signing/blob"; rm -f "$RUNNER_TEMP/h"; } |
  jq '.result' > release.sig.json
```

(stdin carries the body here, so the header goes through a runner temp
file that is deleted immediately.) Anyone can later check it with
`POST /svc/signing/signing/verify` and `{"record_id": "...",
"digest_sha256": "..."}`. `valid` is true only when the signature verifies
**and** the presented digest matches the signed one. A refused signing
request is audited as `audit.signing.sign_refused` with its `code` (for
example `oidc_token_invalid`).

## What the old tab claimed

The DevSecOps / IaC tab (removed in 7.14.0-beta) was static text with no
API calls. It presented these as available, but they do not exist:

- a Terraform provider `vecta-io/vectakms` with `vectakms_key`,
  `vectakms_cloud_binding` and `vectakms_secret` resources;
- Go, Python, Node.js and Java SDKs (`kms-go`, `vectakms`,
  `@vecta/kms-client`, `io.vecta:kms-java`);
- a Helm chart and a `vecta-io/kms-sidecar` image;
- "Download Provider Docs" and "Registry" buttons that did nothing.

Its examples were also wrong or unsafe: tokens inline on the curl command
line, signing by pulling a private key out of the secrets store onto the
runner, a compliance "score" gate, and a REST table that listed routes
that don't exist (for example a key delete by ID, `/keys/{id}/status`,
`/auth/sso/callback`). If an integration from that list is built later, it
is documented here when it ships, not before.
