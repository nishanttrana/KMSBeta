# Terraform provider

`sdk/terraform-provider-vecta` (13.57.0-beta) manages Vecta KMS keys and
their access assignments as Terraform resources. It is built on the Go SDK
(`sdk/go`) and calls the same REST routes. It isn't published to the
Terraform Registry yet, so you build it from this repository.

| Terraform name | What it is |
|---|---|
| `vecta_key` (resource) | A key: name, algorithm, purpose, description, owner, labels, tags |
| `vecta_key_access` (resource) | Every access assignment (grant) of one key |
| `vecta_key` (data source) | A key the client can see, by ID |

Key material never leaves the KMS and never enters Terraform state. State
holds only the key's ID, metadata, version number and key check value.

## Install

```sh
cd sdk/terraform-provider-vecta
go build -o "$HOME/.terraform.d/vecta/terraform-provider-vecta" .
```

Then tell Terraform where the build is, in `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "nishanttrana/vecta" = "/home/you/.terraform.d/vecta"
  }
  direct {}
}
```

With a `dev_overrides` entry, skip `terraform init` for this provider;
`plan` and `apply` use the build directly.

## Configure

Terraform signs in as a **REST client**, never as a person. Register one
and give it a role, as described in
[CI_CD_AUTOMATION.md](CI_CD_AUTOMATION.md#1-give-the-pipeline-its-own-identity).
The permissions it needs depend on which resources you use:

| Action | Permission |
|---|---|
| Create a key | `key.create` |
| Read a key (every plan) | No permission of its own; the key must be visible to the client |
| Change a key's metadata | `key.update`, and the client must manage the key: it created the key, holds `key.access.admin`, or has a grant of `all` |
| Destroy (deactivate) a key | `key.deactivate` |
| Read or set a key's grants | `key.access.read`, `key.access.manage` |

```hcl
terraform {
  required_providers {
    vecta = { source = "nishanttrana/vecta" }
  }
}

provider "vecta" {
  base_url  = "https://kms.example.com"
  tenant_id = "acme"
  client_id = "release-pipeline"
  # api_key comes from VECTA_API_KEY; keep it out of .tf files.
}
```

Leave out any setting and the provider reads it from the environment:

| Setting | Variable |
|---|---|
| `base_url` | `VECTA_URL` |
| `tenant_id` | `VECTA_TENANT_ID` |
| `client_id` | `VECTA_CLIENT_ID` |
| `api_key` | `VECTA_API_KEY` |
| `token` (a bearer token instead of client ID and key) | `VECTA_TOKEN` |
| `ca_pem` | `VECTA_CA_PEM`, or a file named by `VECTA_CA_FILE` |

Set `ca_pem` when the KMS certificate comes from the KMS's own CA rather
than a public one. Connections use TLS 1.3 only. `base_url` must be
`https://`; the provider refuses anything else.

## Example

```hcl
resource "vecta_key" "payments" {
  name        = "payments"
  algorithm   = "AES-256"
  purpose     = "encrypt"
  description = "card data"
  owner       = "payments-team"
  labels      = { cost-center = "platform" }
  tags        = ["pci"]
}

resource "vecta_key_access" "payments" {
  key_id = vecta_key.payments.id
  grant = [
    { subject_type = "client", subject_id = "payments-api", operations = ["encrypt", "decrypt"] },
    { subject_type = "group",  subject_id = "payments-oncall", operations = ["read"] },
  ]
}
```

Import an existing key, or an existing key's grants, by the key's ID:

```sh
terraform import vecta_key.payments key_8f2c...
terraform import vecta_key_access.payments key_8f2c...
```

## What each change does

| Change in the configuration | What happens in the KMS |
|---|---|
| `name`, `purpose`, `description`, `owner`, `labels` or `tags` | Updated in place with `PATCH /keys/{id}`, which sends only the changed fields. Metadata Terraform doesn't manage (cloud, region, compliance, and so on) is kept. |
| `algorithm` or `key_type` | A **new key**. The old key is deactivated. |
| The resource removed, or `terraform destroy` | The key is **deactivated, not destroyed**: no new encryption or signing, and data already encrypted still decrypts. |
| A grant added, changed or removed | The key's whole grant list is replaced (`PUT /keys/{id}/access-policy`). |
| `vecta_key_access` removed | Every grant on the key is removed. |

Terraform never destroys key material. Destroying a key is irreversible
and needs its confirmations and approvals, so you do it in the KMS
(Keys → the key → Destroy) once nothing needs the key.

Destroy reads the key first. If the key is already deactivated or
compromised, or destruction is already pending, destroy does nothing.
Otherwise it deactivates the key. If the KMS refuses (for example a
protected system key, or a key policy that forbids deactivation), Terraform
reports the error and the key stays in state, unchanged.

`vecta_key_access` owns the key's grants. A grant added in the dashboard
shows as a change in the next plan, and the apply removes it. Manage a
key's grants in one place.

When the tenant requires approval for grant changes, the apply fails with
`pending_approval` and the approval request's ID. Approve it in the KMS and
apply again.

## Metadata profiles

A tenant's [metadata profiles](KEYS.md) can require labels and fill in
default values. Leave `labels` unset and the state shows the labels the KMS
stored, defaults included. If you set `labels` and a profile adds a default,
the apply fails and the error lists the stored labels. Add them to the
configuration, then run `terraform untaint vecta_key.<name>` so Terraform
keeps that key instead of replacing it. A profile that refuses the labels
fails the apply with `metadata_profile_violation`, and no key is created.

## Drift

Every plan reads each key and its grants. A change made in the dashboard
shows as a diff. A key that is gone, or no longer visible to the client, is
removed from state and planned again; check that the client still sees it
before you apply.

## Tests

`go test ./...` in `sdk/terraform-provider-vecta` runs real Terraform plans
and applies (the test framework downloads a Terraform release and verifies
its checksum signature) against a TLS 1.3 stand-in for keycore. The tests
cover create, in-place update (only changed fields sent), drift, replacement,
import, destroy deactivating rather than deleting, a refused deactivation
failing the destroy, and profile defaults. The SDK's contract tests
(`TestGoSDKAgainstKeycore`) check the same routes against the real keycore.
CI runs the step "Terraform provider", with `go vet` and `govulncheck`.
