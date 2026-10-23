# Vecta KMS Terraform provider

Keys (`vecta_key`) and their access assignments (`vecta_key_access`) as
Terraform resources, built on the Go SDK (`../go`). Destroying a key in
Terraform deactivates it and never destroys key material.

Installing, configuring, and what each change does in the KMS:
[docs/TERRAFORM.md](../../docs/TERRAFORM.md).

```sh
go vet ./... && go test ./...   # real Terraform plans and applies against a TLS stand-in for keycore
```
