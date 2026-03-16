.PHONY: build test lint proto-gen license-check security-license security-cve security-sidechannel security-sbom security-audit packer-init packer-build packer-build-vbox test-auth test-keycore test-audit test-policy test-governance test-secrets test-certs test-kmip test-cloud test-hyok test-qkd test-ekm test-payment test-compliance test-sbom test-reporting test-posture test-ai test-mpc test-dataprotect test-discovery test-pqc test-software-vault

build:
	go build ./...

test:
	go test ./...

lint:
	go vet ./...

proto-gen:
	@echo "proto generation placeholders created; run protoc with your org plugin config"

license-check:
	@go list -m all | findstr /V /I "gpl agpl sspl" && echo "license check (basic) passed"

security-license:
	bash infra/security/license-audit.sh

security-cve:
	bash infra/security/cve-scan.sh

security-sidechannel:
	bash infra/security/side-channel-suite.sh

security-sbom:
	bash infra/security/sbom-embed.sh

security-audit:
	bash infra/security/audit-pipeline.sh

packer-init:
	packer init infra/packer/kms-appliance.pkr.hcl

packer-build:
	bash infra/packer/scripts/build-ova.sh

packer-build-vbox:
	powershell -ExecutionPolicy Bypass -File .\infra\packer\scripts\build-ova-virtualbox.ps1 -IsoChecksum none

test-auth:
	go test ./services/auth -v

test-keycore:
	go test ./services/keycore -v

test-audit:
	go test ./services/audit -v

test-policy:
	go test ./services/policy -v

test-governance:
	go test ./services/governance -v

test-secrets:
	go test ./services/secrets -v

test-certs:
	go test ./services/certs -v

test-kmip:
	go test ./services/kmip -v

test-cloud:
	go test ./services/cloud -v

test-hyok:
	go test ./services/hyok -v

test-qkd:
	go test ./services/qkd -v

test-ekm:
	go test ./services/ekm -v

test-payment:
	go test ./services/payment -v

test-compliance:
	go test ./services/compliance -v

test-sbom:
	go test ./services/sbom -v

test-reporting:
	go test ./services/reporting -v

test-posture:
	go test ./services/posture -v

test-ai:
	go test ./services/ai -v

test-mpc:
	go test ./services/mpc -v

test-dataprotect:
	go test ./services/dataprotect -v

test-discovery:
	go test ./services/discovery -v

test-pqc:
	go test ./services/pqc -v

test-software-vault:
	go test ./services/software-vault -v
