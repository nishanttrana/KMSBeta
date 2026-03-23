# Certificates & PKI

Vecta KMS ships a full-stack Public Key Infrastructure engine. It issues, renews, revokes, and tracks X.509 certificates across every protocol a modern enterprise needs — ACME, EST, SCEP, CMPv2, and KMIP — and backs every CA private key with either a software key store or a hardware security module (HSM). This document is the single authoritative reference for every certificate-related feature.

---

## Table of Contents

1. [Overview — Why Internal PKI](#1-overview--why-internal-pki)
2. [CA Hierarchy Design](#2-ca-hierarchy-design)
3. [Certificate Types and Profiles](#3-certificate-types-and-profiles)
4. [Certificate Lifecycle](#4-certificate-lifecycle)
5. [Signing External CSRs](#5-signing-external-csrs)
6. [Enrollment Protocols](#6-enrollment-protocols)
7. [STAR Subscriptions](#7-star-subscriptions-short-term-auto-renewal--rfc-8739)
8. [Renewal Intelligence (ARI)](#8-renewal-intelligence-ari--rfc-draft)
9. [Certificate Transparency (Merkle Proofs)](#9-certificate-transparency-merkle-proofs)
10. [CRL and OCSP](#10-crl-and-ocsp)
11. [Certificate Security Status](#11-certificate-security-status)
12. [Use Cases](#12-use-cases)
13. [Security Considerations](#13-security-considerations)
14. [Full API Reference](#14-full-api-reference)

---

## 1. Overview — Why Internal PKI

### 1.1 The Case for Operating Your Own CA

Public certificate authorities (Let's Encrypt, DigiCert, Sectigo, etc.) are the right choice for publicly routable domain names that must be trusted by browsers and operating systems out of the box. For everything behind the firewall — microservices, databases, IoT sensors, developer workstations, build pipelines, internal APIs — a public CA is the wrong tool for four reasons:

| Dimension | Public CA | Vecta Internal PKI |
|---|---|---|
| Cost per cert | $0 – $500 / year | Near-zero marginal cost |
| Issuance latency | Minutes to days (validation) | Milliseconds (API call) |
| Validity control | Fixed tiers (90 d, 1 yr, 2 yr) | Any period you specify |
| SAN flexibility | Must own/prove domain | Any internal FQDN, IP, email, URI |
| Key custody | CA generates or accepts CSR | HSM-backed, you own every key |
| Audit trail | None for relying parties | Immutable per-cert audit log |
| Revocation speed | CRL/OCSP depends on CA | Instant, under your control |
| PQC readiness | Vendor roadmap-dependent | ML-DSA available today |

### 1.2 Primary Use Cases

**Internal mTLS** — Service-to-service communication inside a Kubernetes cluster, a data centre, or a VPN. Every service gets a certificate; both sides present and verify certificates so there is no implicit trust on any internal network segment. Short-lived certificates (STAR, 24–48 h) eliminate the revocation problem entirely.

**Code Signing** — Build pipelines sign every binary, container image, JAR file, and PowerShell script. Deployment systems verify signatures before execution. Unsigned artifacts are rejected. Vecta's transparency log gives you a tamper-evident record of every signing event.

**Device Enrollment** — IoT sensors, switches, routers, and laptops receive certificates at manufacturing or first-boot time using EST or SCEP. The device private key never leaves the device; the CA only ever sees a CSR.

**ACME Automation** — Any host running certbot, acme.sh, or cert-manager can obtain and auto-renew certificates from Vecta's built-in ACME server. No manual intervention, no forgotten renewals.

**Email Encryption (S/MIME)** — Issue certificates to email addresses. Users can sign and encrypt email in Outlook, Apple Mail, and Thunderbird without depending on a third-party CA.

**Post-Quantum Readiness** — Issue ML-DSA (Dilithium) certificates today for internal services that must survive harvest-now/decrypt-later attacks. Dual-algorithm issuance (classic + PQC) lets relying parties choose based on capability.

### 1.3 PKI Hierarchy Design Principles

A well-designed PKI follows a trust chain where each level signs the level below it. The design principles Vecta is built around are:

1. **Minimal online exposure of root keys.** The root CA key should be created once, used to sign one or more intermediate CAs, and then taken offline or locked to HSM-only use. If the root key is compromised, every certificate in the entire hierarchy must be replaced.

2. **Separate CAs for separate trust domains.** Do not issue server certificates and code-signing certificates from the same issuing CA. Separate CA policies mean separate audit scope, separate hardware tokens, and separate revocation lists.

3. **Short validity periods at the leaves.** The longer a certificate is valid, the longer an attacker has to abuse a compromised private key. Leaf certificates should be 90 days or less for server auth. STAR subscriptions push this to 24–48 hours.

4. **Revocation must actually work.** CRL distribution points and OCSP responder URLs must be embedded in every issued certificate so relying parties can check revocation status without manual configuration. Vecta embeds both automatically.

5. **Hardware-backed CA keys.** CA private keys stored in software are one disk dump away from a total hierarchy compromise. Use the HSM backend for all CA keys in production.

---

## 2. CA Hierarchy Design

### 2.1 Three-Tier Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                        ROOT CA                                  │
│   Algorithm: RSA-4096 or ML-DSA-87                             │
│   Validity: 20 years (7300 days)                               │
│   Key backend: HSM (offline after initial setup)               │
│   Signs: Intermediate CA certificates only                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
┌─────────────▼──────────────┐  ┌──────────▼──────────────────┐
│    INTERMEDIATE CA          │  │   INTERMEDIATE CA            │
│    (TLS / mTLS)             │  │   (Code Signing)             │
│    Algorithm: EC-P384       │  │   Algorithm: EC-P384         │
│    Validity: 10 years       │  │   Validity: 10 years         │
│    Key backend: HSM         │  │   Key backend: HSM           │
└─────────────┬───────────────┘  └──────────┬──────────────────┘
              │                             │
   ┌──────────┴───────────┐      ┌──────────┴──────────────┐
   │                      │      │                          │
┌──▼────────────┐  ┌──────▼───┐  ┌──▼────────────┐  ┌──────▼────────┐
│ ISSUING CA    │  │ISSUING CA│  │ ISSUING CA    │  │ ISSUING CA    │
│ Server TLS    │  │ Client   │  │ Prod Pipeline │  │ Dev Pipeline  │
│ EC-P256/P384  │  │ mTLS     │  │ Ed25519       │  │ Ed25519       │
│ 2 yr validity │  │ 2 yr     │  │ 2 yr validity │  │ 2 yr validity │
└───────────────┘  └──────────┘  └───────────────┘  └───────────────┘
```

### 2.2 Root CA — Offline Best Practices

The root CA is the trust anchor. Once it has signed the intermediate CA certificates, it has no ongoing operational role. The following practices apply:

- **Generate and use on an air-gapped workstation.** Many organizations use a dedicated laptop that has never been connected to a network, or a hardware token (YubiKey HSM, Thales Luna Network HSM).
- **Key escrow.** Split the root CA private key using Shamir's Secret Sharing (e.g., 3-of-5 shares held by different executives). Vecta's HSM integration supports this natively.
- **Ceremony logging.** Every time the root CA is brought online, record: who was present, what operations were performed, what certificates were signed, and when it was taken offline. Store this log offline alongside the key.
- **Revoke path.** Even though the root CA is offline, it must have a CRL distribution point that can be served statically (a simple HTTP server or S3 bucket is sufficient). The root CA CRL changes very rarely — only if an intermediate CA is compromised.

### 2.3 CA Key Algorithm Selection

| CA Level | Recommended Algorithm | Rationale |
|---|---|---|
| Root CA | RSA-4096 | Maximum compatibility with legacy clients; 20-year validity means it outlives current quantum threats on a conservative timeline |
| Root CA (PQC) | ML-DSA-87 | NIST FIPS 204 standard; highest ML-DSA security level for a trust anchor |
| Intermediate CA | EC-P384 | Strong security, smaller signatures than RSA, well-supported |
| Issuing CA (TLS) | EC-P256 or EC-P384 | P256 for broadest compatibility including embedded systems; P384 for higher assurance |
| Issuing CA (Code Signing) | Ed25519 | Deterministic signatures, immune to nonce reuse, compact |
| Issuing CA (PQC) | ML-DSA-65 | NIST FIPS 204; balanced security/performance for issuing volume |

### 2.4 CA Validity Periods

| CA Level | Recommended Validity | Rationale |
|---|---|---|
| Root CA | 20 years (7300 days) | Trust anchor must outlive all issued certificates |
| Intermediate CA | 10 years (3650 days) | Must outlive all issuing CAs and their leaves |
| Issuing CA | 2–5 years (730–1825 days) | Operational lifetime; rotation is low-friction since only issuing CA certs change |
| Server Leaf | 90 days | CAB Forum maximum for public TLS; reasonable for internal |
| Client Leaf | 90–365 days | Longer acceptable because client certs have narrower trust scope |
| STAR Leaf | 24–720 hours | Short-lived; no revocation checking needed |
| Code Signing Leaf | 1–2 years | Signing keys rotated annually |

### 2.5 Creating Each Level via API

#### Step 1 — Create Root CA

```bash
curl -X POST "http://localhost:5173/svc/certs/certs/ca?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Vecta Root CA",
    "ca_type": "root",
    "algorithm": "RSA-4096",
    "key_backend": "hsm",
    "validity_days": 7300,
    "subject": {
      "cn": "Vecta Internal Root CA",
      "org": "Acme Corp",
      "ou": "Information Security",
      "country": "US",
      "state": "California",
      "locality": "San Francisco"
    },
    "constraints": {
      "path_length": 2,
      "is_ca": true
    },
    "crl_distribution_points": [
      "http://crl.internal.acme.com/root.crl"
    ],
    "ocsp_servers": [
      "http://ocsp.internal.acme.com/root"
    ]
  }'
```

**Response:**

```json
{
  "id": "ca_01HXYZ...",
  "name": "Vecta Root CA",
  "ca_type": "root",
  "status": "active",
  "algorithm": "RSA-4096",
  "key_backend": "hsm",
  "serial_number": "7f:3a:...",
  "subject_dn": "CN=Vecta Internal Root CA, O=Acme Corp, C=US",
  "not_before": "2026-03-22T00:00:00Z",
  "not_after": "2046-03-22T00:00:00Z",
  "fingerprint_sha256": "ab:cd:...",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "created_at": "2026-03-22T10:00:00Z"
}
```

#### Step 2 — Create Intermediate CA

```bash
curl -X POST "http://localhost:5173/svc/certs/certs/ca?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Vecta TLS Intermediate CA",
    "ca_type": "intermediate",
    "parent_ca_id": "ca_01HXYZ...",
    "algorithm": "EC-P384",
    "key_backend": "hsm",
    "validity_days": 3650,
    "subject": {
      "cn": "Vecta TLS Intermediate CA",
      "org": "Acme Corp",
      "ou": "Information Security",
      "country": "US",
      "state": "California",
      "locality": "San Francisco"
    },
    "constraints": {
      "path_length": 1,
      "is_ca": true
    },
    "crl_distribution_points": [
      "http://crl.internal.acme.com/intermediate-tls.crl"
    ],
    "ocsp_servers": [
      "http://ocsp.internal.acme.com/intermediate-tls"
    ]
  }'
```

#### Step 3 — Create Issuing CA

```bash
curl -X POST "http://localhost:5173/svc/certs/certs/ca?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Vecta Issuing CA — Server TLS",
    "ca_type": "issuing",
    "parent_ca_id": "ca_02HABC...",
    "algorithm": "EC-P256",
    "key_backend": "hsm",
    "validity_days": 730,
    "subject": {
      "cn": "Vecta Issuing CA — Server TLS",
      "org": "Acme Corp",
      "country": "US"
    },
    "constraints": {
      "path_length": 0,
      "is_ca": true
    },
    "permitted_dns_domains": [
      ".internal.acme.com",
      ".svc.cluster.local"
    ],
    "crl_distribution_points": [
      "http://crl.internal.acme.com/issuing-tls.crl"
    ],
    "ocsp_servers": [
      "http://ocsp.internal.acme.com/issuing-tls"
    ]
  }'
```

### 2.6 Listing and Retrieving CAs

```bash
# List all CAs
curl "http://localhost:5173/svc/certs/certs/ca?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get specific CA
curl "http://localhost:5173/svc/certs/certs/ca/{CA_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get CA certificate chain (PEM bundle)
curl "http://localhost:5173/svc/certs/certs/ca/{CA_ID}/chain?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get CA certificate in DER format
curl "http://localhost:5173/svc/certs/certs/ca/{CA_ID}/certificate?format=der&tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -o ca-cert.der
```

### 2.7 CA Rotation

When an issuing CA approaches expiry, create a new issuing CA from the same intermediate CA. Existing certificates remain valid until their own expiry. New certificates are issued from the new issuing CA.

```bash
# Rotate issuing CA (creates new CA, retires old one)
curl -X POST "http://localhost:5173/svc/certs/certs/ca/{OLD_CA_ID}/rotate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "new_validity_days": 730,
    "transition_period_days": 30,
    "auto_reissue_leaves": false
  }'
```

---

## 3. Certificate Types and Profiles

### 3.1 Built-in Certificate Types

| `cert_type` | OID / EKU | Primary Use |
|---|---|---|
| `server` | `1.3.6.1.5.5.7.3.1` (serverAuth) | TLS server authentication (HTTPS, gRPC, etc.) |
| `client` | `1.3.6.1.5.5.7.3.2` (clientAuth) | TLS client authentication (mTLS) |
| `code_signing` | `1.3.6.1.5.5.7.3.3` (codeSigning) | Binary / artifact signing |
| `email` | `1.3.6.1.5.5.7.3.4` (emailProtection) | S/MIME email signing and encryption |
| `ocsp_signing` | `1.3.6.1.5.5.7.3.9` (OCSPSigning) | OCSP responder certificates |
| `timestamp` | `1.3.6.1.5.5.7.3.8` (timeStamping) | RFC 3161 timestamp authority |
| `server_client` | serverAuth + clientAuth | Dual-purpose (microservice identity) |

### 3.2 Key Usage Codes

| Key Usage | X.509 Bit | Typical Cert Types |
|---|---|---|
| `digitalSignature` | Bit 0 | server, client, code_signing, email |
| `nonRepudiation` | Bit 1 | email, code_signing |
| `keyEncipherment` | Bit 2 | server (RSA only) |
| `dataEncipherment` | Bit 3 | email (legacy S/MIME) |
| `keyAgreement` | Bit 4 | server (ECDH) |
| `keyCertSign` | Bit 5 | CA certificates only |
| `cRLSign` | Bit 6 | CA certificates only |
| `encipherOnly` | Bit 7 | Rare; ECDH-specific |
| `decipherOnly` | Bit 8 | Rare; ECDH-specific |

### 3.3 Extended Key Usage OIDs

| EKU Name | OID | Description |
|---|---|---|
| `serverAuth` | 1.3.6.1.5.5.7.3.1 | TLS server authentication |
| `clientAuth` | 1.3.6.1.5.5.7.3.2 | TLS client authentication |
| `codeSigning` | 1.3.6.1.5.5.7.3.3 | Authenticode, JAR signing |
| `emailProtection` | 1.3.6.1.5.5.7.3.4 | S/MIME |
| `timeStamping` | 1.3.6.1.5.5.7.3.8 | RFC 3161 TSA |
| `OCSPSigning` | 1.3.6.1.5.5.7.3.9 | OCSP responder |
| `msSmartcardLogon` | 1.3.6.1.4.1.311.20.2.2 | Windows smart card login |
| `msDocumentSigning` | 1.3.6.1.4.1.311.10.3.12 | Microsoft document signing |
| `appleCodeSigning` | 1.2.840.113635.100.4.1 | Apple codesign |

### 3.4 Certificate Profiles

Profiles codify a set of defaults (validity, key usage, SAN types, policy OIDs) into a reusable template. Operators define profiles once; applications reference `profile_id` at issuance time.

#### Create a profile

```bash
curl -X POST "http://localhost:5173/svc/certs/certs/profiles?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "server-90d",
    "description": "Standard server TLS cert, 90 day validity",
    "cert_type": "server",
    "default_validity_days": 90,
    "max_validity_days": 90,
    "key_usage": ["digitalSignature", "keyAgreement"],
    "extended_key_usage": ["serverAuth"],
    "allow_san": true,
    "san_types": ["dns", "ip"],
    "require_san": true,
    "subject_fields_required": ["cn"],
    "policy_oids": ["1.3.6.1.4.1.99999.1.1"],
    "crl_distribution_points_inherit": true,
    "ocsp_servers_inherit": true
  }'
```

```bash
curl -X POST "http://localhost:5173/svc/certs/certs/profiles?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "client-mtls-365d",
    "description": "Client mTLS, 365-day, DNS and email SANs",
    "cert_type": "client",
    "default_validity_days": 365,
    "max_validity_days": 365,
    "key_usage": ["digitalSignature"],
    "extended_key_usage": ["clientAuth"],
    "allow_san": true,
    "san_types": ["dns", "email", "uri"],
    "require_san": false
  }'
```

```bash
curl -X POST "http://localhost:5173/svc/certs/certs/profiles?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "code-signing-1y",
    "description": "Code signing, Ed25519, 1 year",
    "cert_type": "code_signing",
    "default_validity_days": 365,
    "max_validity_days": 365,
    "key_usage": ["digitalSignature", "nonRepudiation"],
    "extended_key_usage": ["codeSigning"],
    "allow_san": false,
    "require_san": false
  }'
```

#### List and manage profiles

```bash
# List profiles
curl "http://localhost:5173/svc/certs/certs/profiles?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get profile
curl "http://localhost:5173/svc/certs/certs/profiles/{PROFILE_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Update profile
curl -X PUT "http://localhost:5173/svc/certs/certs/profiles/{PROFILE_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"default_validity_days": 60}'

# Delete profile
curl -X DELETE "http://localhost:5173/svc/certs/certs/profiles/{PROFILE_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

### 3.5 SAN Types

| SAN Type | `san_types` value | Example |
|---|---|---|
| DNS name | `dns` | `api.internal.acme.com` |
| IP address | `ip` | `10.0.1.50` |
| Email address | `email` | `alice@acme.com` |
| URI | `uri` | `spiffe://acme.com/ns/default/sa/api` |
| UPN (Windows) | `upn` | `alice@ACME.COM` |
| Other Name | `other_name` | Custom OID + value |

### 3.6 Policy OIDs

Policy OIDs signal the issuance policy under which a certificate was issued. Organizations may define their own policy OID arcs (under their IANA-registered Private Enterprise Number) and embed them in all certificates. Relying parties can then enforce that only certificates with a specific policy OID are accepted for a given use case.

```bash
# Common internal policy OIDs (examples)
# 1.3.6.1.4.1.{PEN}.1.1  = Low assurance (automated, no identity verification)
# 1.3.6.1.4.1.{PEN}.1.2  = Medium assurance (identity verified by directory)
# 1.3.6.1.4.1.{PEN}.1.3  = High assurance (in-person or HSM-backed)
```

---

## 4. Certificate Lifecycle

### 4.1 Lifecycle States

```
               Issue
                 │
                 ▼
          ┌─────────────┐
          │   PENDING   │  (async issuance in progress)
          └──────┬──────┘
                 │
                 ▼
          ┌─────────────┐
          │   ACTIVE    │  ◄── normal operating state
          └──────┬──────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
 ┌──────────────┐  ┌────────────────┐
 │   RENEWED    │  │    REVOKED     │
 │ (superseded  │  │  (reason code) │
 │  by new cert)│  └────────────────┘
 └──────────────┘
        │
        ▼
 ┌──────────────┐
 │   EXPIRED    │
 └──────────────┘
```

### 4.2 Issuing Certificates

```bash
# Issue a server TLS certificate (server-side key generation)
curl -X POST "http://localhost:5173/svc/certs/certs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "ISSUING_CA_ID",
    "profile_id": "server-90d",
    "subject_cn": "api.internal.acme.com",
    "sans": [
      {"type": "dns", "value": "api.internal.acme.com"},
      {"type": "dns", "value": "api-v2.internal.acme.com"},
      {"type": "ip",  "value": "10.0.1.100"}
    ],
    "cert_type": "server",
    "validity_days": 90,
    "algorithm": "EC-P256",
    "key_backend": "software",
    "metadata": {
      "team": "platform",
      "environment": "production",
      "service": "payments-api"
    }
  }'
```

**Response:**

```json
{
  "id": "cert_01HXYZ...",
  "status": "active",
  "serial_number": "1a:2b:...",
  "subject_dn": "CN=api.internal.acme.com",
  "sans": ["api.internal.acme.com", "api-v2.internal.acme.com"],
  "not_before": "2026-03-22T10:00:00Z",
  "not_after":  "2026-06-20T10:00:00Z",
  "fingerprint_sha256": "3f:4a:...",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----",
  "ca_chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "created_at": "2026-03-22T10:00:00Z"
}
```

> **Security note:** When `key_backend` is `software`, the private key is returned once in the response and is not stored by Vecta. When `key_backend` is `hsm`, the private key is generated in and never leaves the HSM; only the certificate PEM is returned.

```bash
# Issue a client certificate for mTLS (specific algorithm)
curl -X POST "http://localhost:5173/svc/certs/certs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "ISSUING_CA_ID",
    "profile_id": "client-mtls-365d",
    "subject_cn": "payment-service",
    "sans": [
      {"type": "uri", "value": "spiffe://acme.com/ns/payments/sa/payment-service"}
    ],
    "cert_type": "client",
    "validity_days": 365,
    "algorithm": "EC-P384"
  }'
```

```bash
# Issue a code signing certificate
curl -X POST "http://localhost:5173/svc/certs/certs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "CODE_SIGNING_ISSUING_CA_ID",
    "profile_id": "code-signing-1y",
    "subject_cn": "Acme Corp Build Pipeline",
    "subject": {
      "cn": "Acme Corp Build Pipeline",
      "org": "Acme Corp",
      "ou": "Engineering",
      "country": "US"
    },
    "cert_type": "code_signing",
    "validity_days": 365,
    "algorithm": "Ed25519"
  }'
```

### 4.3 Listing and Retrieving Certificates

```bash
# List all certificates with filters
curl "http://localhost:5173/svc/certs/certs?tenant_id=root&status=active&cert_type=server&page=1&per_page=50" \
  -H "Authorization: Bearer $TOKEN"

# Get specific certificate
curl "http://localhost:5173/svc/certs/certs/{CERT_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Download certificate in DER format
curl "http://localhost:5173/svc/certs/certs/{CERT_ID}/download?format=der&tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -o certificate.der

# Download PKCS#12 bundle (cert + key + chain)
curl -X POST "http://localhost:5173/svc/certs/certs/{CERT_ID}/pkcs12?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "your-p12-password"}' \
  -o bundle.p12
```

### 4.4 Renewing Certificates

Renewal issues a new certificate with the same subject and SANs. The old certificate remains valid until its natural expiry (or you revoke it). The new certificate gets a new serial number, new key pair, and updated validity period.

```bash
# Renew certificate (same validity as original)
curl -X POST "http://localhost:5173/svc/certs/certs/{CERT_ID}/renew?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Renew with custom validity
curl -X POST "http://localhost:5173/svc/certs/certs/{CERT_ID}/renew?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "validity_days": 90,
    "revoke_old": true,
    "revoke_reason": "superseded"
  }'

# Renew with updated SANs
curl -X POST "http://localhost:5173/svc/certs/certs/{CERT_ID}/renew?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "validity_days": 90,
    "sans": [
      {"type": "dns", "value": "api.internal.acme.com"},
      {"type": "dns", "value": "api-v3.internal.acme.com"}
    ]
  }'
```

### 4.5 Revoking Certificates

```bash
# Revoke certificate with reason
curl -X POST "http://localhost:5173/svc/certs/certs/{CERT_ID}/revoke?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "keyCompromise",
    "comment": "Private key found in leaked GitHub repository"
  }'
```

**Revocation reasons and when to use them:**

| Reason Code | RFC 5280 Value | When to Use |
|---|---|---|
| `unspecified` | 0 | General revocation, no specific reason |
| `keyCompromise` | 1 | Private key was stolen, leaked, or otherwise compromised |
| `caCompromise` | 2 | The signing CA's key was compromised (revokes all certs) |
| `affiliationChanged` | 3 | Subject left the organization or changed roles |
| `superseded` | 4 | A new certificate replaces this one (normal renewal) |
| `cessationOfOperation` | 5 | Service or device permanently decommissioned |
| `certificateHold` | 6 | Temporary suspension (rare, discouraged) |
| `privilegeWithdrawn` | 9 | Subject's authorization to use the cert was withdrawn |

### 4.6 Auto-Expiry Handling

Vecta runs an expiry scanner on a configurable schedule. When a certificate crosses warning or critical thresholds:

1. **Alert generated** — visible in the security status dashboard and sent to configured notification channels (webhook, email, Slack).
2. **ARI window updated** — the renewal information window shrinks, urging ACME clients to renew sooner.
3. **STAR subscriptions auto-renew** — no human intervention required for STAR-enrolled certificates.
4. **Manual certificates** — require operator action or integration with the renew API.

```bash
# Configure expiry alert policy
curl -X PUT "http://localhost:5173/svc/certs/certs/expiry-policy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "warning_days": 30,
    "critical_days": 7,
    "notification_channels": ["slack-security", "pagerduty-oncall"],
    "auto_renew_acme": true
  }'
```

---

## 5. Signing External CSRs

### 5.1 When to Sign External CSRs

Use CSR signing when:
- The private key must never leave the device or application (IoT, HSM-backed app, load balancer)
- A vendor or partner provides a CSR and you act as their CA
- You want to use an existing key pair (e.g., generated by an HSM you do not own)

Use server-side issuance when:
- You do not have strict key custody requirements
- You want Vecta to generate and optionally store the key
- Issuance speed and simplicity matter more than key custody

### 5.2 CSR Validation Rules

Before signing a CSR, Vecta validates:

1. **CSR signature** — the CSR must be self-signed by the corresponding private key (standard PKCS#10 requirement).
2. **Subject CN** — must match one of the SANs, or be explicitly allowed as a CN-only cert in the profile (not recommended).
3. **SANs** — all DNS SANs must fall within the permitted DNS domains configured on the issuing CA.
4. **Key algorithm and strength** — RSA < 2048 bits rejected by default; EC curves weaker than P-256 rejected; MD5/SHA-1 key signatures rejected.
5. **Profile constraints** — if a profile is specified, the CSR's requested extensions must be compatible with the profile.

### 5.3 Signing a CSR

```bash
# Sign a CSR with a specific profile
curl -X POST "http://localhost:5173/svc/certs/certs/sign-csr?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "ISSUING_CA_ID",
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB....\n-----END CERTIFICATE REQUEST-----",
    "profile_id": "server-90d",
    "validity_days": 90,
    "metadata": {
      "requester": "networking-team",
      "ticket": "SEC-1234"
    }
  }'
```

```bash
# Sign a CSR with explicit override (override profile defaults)
curl -X POST "http://localhost:5173/svc/certs/certs/sign-csr?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "ISSUING_CA_ID",
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----",
    "cert_type": "server",
    "validity_days": 30,
    "additional_sans": [
      {"type": "dns", "value": "api-legacy.internal.acme.com"}
    ],
    "override_subject": {
      "cn": "api.internal.acme.com",
      "org": "Acme Corp"
    }
  }'
```

### 5.4 CSR Generation Helpers

If you need to generate a CSR from the command line for testing:

```bash
# Generate EC-P256 key and CSR
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key \
  -subj "/CN=api.internal.acme.com/O=Acme Corp/C=US" \
  -addext "subjectAltName=DNS:api.internal.acme.com,DNS:api-v2.internal.acme.com" \
  -out server.csr

# Base64-encode for JSON
CSR_PEM=$(cat server.csr)

# Submit to Vecta
curl -X POST "http://localhost:5173/svc/certs/certs/sign-csr?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary "{\"ca_id\": \"ISSUING_CA_ID\", \"csr_pem\": $(jq -Rs . <<< "$CSR_PEM"), \"profile_id\": \"server-90d\", \"validity_days\": 90}"
```

---

## 6. Enrollment Protocols

Vecta implements five standard certificate enrollment protocols. Each protocol targets a different device class or automation scenario.

### 6.1 ACME (Automated Certificate Management Environment — RFC 8555)

ACME is the protocol behind Let's Encrypt. Vecta's ACME server is fully RFC 8555 compliant and supports HTTP-01 and DNS-01 challenge types. Any client that works with Let's Encrypt works with Vecta with only a configuration change (base URL).

**ACME base URL:** `https://{host}/svc/certs/acme/`

**Directory endpoint:** `GET /svc/certs/acme/directory`

```json
{
  "newNonce":   "https://kms.acme.com/svc/certs/acme/new-nonce",
  "newAccount": "https://kms.acme.com/svc/certs/acme/new-account",
  "newOrder":   "https://kms.acme.com/svc/certs/acme/new-order",
  "revokeCert": "https://kms.acme.com/svc/certs/acme/revoke-cert",
  "keyChange":  "https://kms.acme.com/svc/certs/acme/key-change",
  "renewalInfo":"https://kms.acme.com/svc/certs/acme/renewal-info",
  "meta": {
    "termsOfService": "https://kms.acme.com/acme-tos",
    "website": "https://kms.acme.com",
    "caaIdentities": ["acme.com"]
  }
}
```

#### Full ACME Flow (Manual Steps)

```bash
# Step 1 — Create account
curl -X POST "http://localhost:5173/svc/certs/acme/new-account" \
  -H "Content-Type: application/jose+json" \
  -d '{
    "email": "admin@acme.com",
    "termsOfServiceAgreed": true
  }'
# Response: account URL in Location header, account object in body

# Step 2 — Get nonce
NONCE=$(curl -I "http://localhost:5173/svc/certs/acme/new-nonce" | grep -i replay-nonce | awk '{print $2}' | tr -d '\r')

# Step 3 — Create order
curl -X POST "http://localhost:5173/svc/certs/acme/new-order" \
  -H "Content-Type: application/jose+json" \
  -d '{
    "identifiers": [
      {"type": "dns", "value": "app.acme.com"},
      {"type": "dns", "value": "app-v2.acme.com"}
    ]
  }'
# Response: order object with authorizations[] URLs and finalize URL

# Step 4 — Get authorization and challenge
curl "http://localhost:5173/svc/certs/acme/authz/{authzId}"
# Response: challenges[] — pick http-01 or dns-01

# Step 5a — Complete HTTP-01 challenge
# Provision: GET http://app.acme.com/.well-known/acme-challenge/{token}
# Returns: {token}.{account_key_thumbprint}
curl -X POST "http://localhost:5173/svc/certs/acme/challenge/{challengeId}" \
  -H "Content-Type: application/jose+json" \
  -d '{
    "order_id": "{orderId}",
    "key_authorization": "{token}.{thumbprint}"
  }'

# Step 5b — Complete DNS-01 challenge
# Provision: TXT record _acme-challenge.app.acme.com = base64url(SHA-256(key_authorization))
curl -X POST "http://localhost:5173/svc/certs/acme/challenge/{challengeId}" \
  -H "Content-Type: application/jose+json" \
  -d '{
    "order_id": "{orderId}",
    "key_authorization": "{token}.{thumbprint}"
  }'

# Step 6 — Poll authorization until valid
curl "http://localhost:5173/svc/certs/acme/authz/{authzId}"
# Wait until status = "valid"

# Step 7 — Finalize with CSR
curl -X POST "http://localhost:5173/svc/certs/acme/finalize/{orderId}" \
  -H "Content-Type: application/jose+json" \
  -d '{"csr": "BASE64URL_ENCODED_DER_CSR"}'

# Step 8 — Download certificate
curl "http://localhost:5173/svc/certs/acme/cert/{certId}"
```

#### certbot Configuration

```bash
# Install certbot
pip install certbot

# Register and obtain cert from Vecta ACME
certbot certonly \
  --standalone \
  --server "https://kms.internal.acme.com/svc/certs/acme/directory" \
  --email admin@acme.com \
  --agree-tos \
  -d app.internal.acme.com \
  -d app-v2.internal.acme.com

# Auto-renew via systemd timer or cron
certbot renew \
  --server "https://kms.internal.acme.com/svc/certs/acme/directory"
```

#### acme.sh Configuration

```bash
# Register account
acme.sh --register-account \
  -m admin@acme.com \
  --server "https://kms.internal.acme.com/svc/certs/acme/directory"

# Issue certificate
acme.sh --issue \
  -d app.internal.acme.com \
  --webroot /var/www/html \
  --server "https://kms.internal.acme.com/svc/certs/acme/directory"

# Install to nginx
acme.sh --install-cert -d app.internal.acme.com \
  --cert-file      /etc/nginx/ssl/cert.pem \
  --key-file       /etc/nginx/ssl/key.pem \
  --fullchain-file /etc/nginx/ssl/fullchain.pem \
  --reloadcmd      "systemctl reload nginx"
```

#### Kubernetes cert-manager Integration

```bash
# Install cert-manager
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true
```

```yaml
# ClusterIssuer pointing to Vecta ACME
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: vecta-acme
spec:
  acme:
    server: https://kms.internal.acme.com/svc/certs/acme/directory
    email: admin@acme.com
    privateKeySecretRef:
      name: vecta-acme-account-key
    solvers:
    - http01:
        ingress:
          class: nginx
    - dns01:
        webhook:
          groupName: acme.acme.com
          solverName: vecta-dns
```

```yaml
# Certificate resource
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: payments-api-tls
  namespace: payments
spec:
  secretName: payments-api-tls-secret
  issuerRef:
    name: vecta-acme
    kind: ClusterIssuer
  commonName: payments.internal.acme.com
  dnsNames:
  - payments.internal.acme.com
  - payments-v2.internal.acme.com
  duration: 2160h    # 90 days
  renewBefore: 720h  # renew 30 days before expiry
```

```yaml
# DNS-01 with external-dns (Route53)
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: vecta-acme-dns01
spec:
  acme:
    server: https://kms.internal.acme.com/svc/certs/acme/directory
    email: admin@acme.com
    privateKeySecretRef:
      name: vecta-acme-dns01-account-key
    solvers:
    - dns01:
        route53:
          region: us-east-1
          role: arn:aws:iam::123456789012:role/cert-manager-route53
```

---

### 6.2 EST (Enrollment over Secure Transport — RFC 7030)

EST is designed for device certificate enrollment. It operates over HTTPS and supports both initial enrollment and re-enrollment with an existing certificate as authenticator.

**EST Base URL:** `/svc/certs/est/.well-known/est/`

#### EST Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/.well-known/est/cacerts` | Retrieve CA certificate bundle (PKCS#7 DER) |
| `POST` | `/.well-known/est/simpleenroll` | Initial enrollment with PKCS#10 CSR |
| `POST` | `/.well-known/est/simplereenroll` | Re-enroll using existing certificate as auth |
| `POST` | `/.well-known/est/serverkeygen` | Server generates key and returns cert + PKCS#8 key |
| `GET` | `/.well-known/est/csrattrs` | Required CSR attributes (server's requirements) |
| `POST` | `/.well-known/est/fullcmc` | Full CMC enrollment (advanced) |

#### EST Client Setup

```bash
# Get CA certificates (PKCS#7 format)
curl -o cacerts.p7b \
  "https://kms.internal.acme.com/svc/certs/est/.well-known/est/cacerts"

# Convert PKCS#7 to PEM
openssl pkcs7 -in cacerts.p7b -inform DER -print_certs -out cacerts.pem

# Simple enroll with Basic Auth
openssl genrsa -out device.key 2048
openssl req -new -key device.key \
  -subj "/CN=sensor-001/O=Acme Corp" \
  -out device.csr

curl -X POST \
  "https://kms.internal.acme.com/svc/certs/est/.well-known/est/simpleenroll" \
  -u "device001:enrollment-password" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @device.csr \
  -o device-cert.p7c

# Convert response to PEM
openssl pkcs7 -in device-cert.p7c -inform DER -print_certs -out device-cert.pem

# Re-enroll using existing certificate (mutual TLS)
openssl req -new -key device.key \
  -subj "/CN=sensor-001/O=Acme Corp" \
  -out device-renew.csr

curl -X POST \
  "https://kms.internal.acme.com/svc/certs/est/.well-known/est/simplereenroll" \
  --cert device-cert.pem \
  --key device.key \
  -H "Content-Type: application/pkcs10" \
  --data-binary @device-renew.csr \
  -o device-renewed.p7c
```

#### EST Use Cases

**IoT Device Onboarding:** Devices come from the factory with a bootstrap credential (basic auth password or manufacturer CA cert). On first boot, they hit the EST server, authenticate with the bootstrap credential, and receive a device identity certificate. From that point, they re-enroll with mTLS.

**Network Device Enrollment:** Cisco IOS-XE, Junos, and Aruba AOS all support EST natively. Configure the EST server URL and CA certificate on the device; it handles enrollment automatically on boot.

**Windows Server (Microsoft SCEP/EST):** Windows supports EST via the NDES role or via a lightweight agent.

---

### 6.3 SCEP (Simple Certificate Enrollment Protocol — RFC 8894)

SCEP is the legacy enrollment protocol, widely supported by MDM systems, Cisco network equipment, and Windows NDES. Despite being "legacy," it remains the dominant protocol for Windows MDM and Cisco ISE.

**SCEP Endpoint:** `/svc/certs/scep`

#### SCEP Operations

| Operation | HTTP Method | Description |
|---|---|---|
| `GetCACert` | `GET` | Retrieve CA certificate(s) |
| `GetCACaps` | `GET` | Query server capabilities |
| `PKIOperation` | `POST` | Enrollment, renewal, CRL fetch |

#### SCEP Capabilities

```
GET /svc/certs/scep?operation=GetCACaps
```

Response (plain text, one capability per line):
```
AES
SHA-256
SHA-512
POSTPKIOperation
Renewal
GetNextCACert
```

#### SCEP Enrollment Flow

```bash
# Step 1 — Get CA certificate
curl "http://localhost:5173/svc/certs/scep?operation=GetCACert&message=CAIdentifier" \
  -o ca.der

# Step 2 — Generate key and CSR
openssl genrsa -out device.key 2048
openssl req -new -key device.key \
  -subj "/CN=laptop-001/O=Acme Corp" \
  -out device.csr

# Step 3 — SCEP enrollment (typically handled by SCEP client library)
# The client wraps the CSR in a PKCSReq message, encrypts with CA cert,
# signs with self-signed or existing cert, posts to PKIOperation
# Most integrations use native SCEP client libraries
```

#### MDM Integration (Microsoft Intune)

In Intune, configure a SCEP Certificate Profile:

1. **Certificate type:** PKCS #10
2. **SCEP Server URL:** `https://kms.internal.acme.com/svc/certs/scep`
3. **Challenge type:** Static (configure challenge password in Vecta) or Dynamic (Intune NDES connector)
4. **Certificate validity period:** 1 year
5. **Key size:** 2048 (RSA) or ECC 256

```bash
# Create SCEP challenge password in Vecta
curl -X POST "http://localhost:5173/svc/certs/scep/challenges?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "static-challenge-password-here",
    "description": "Intune MDM enrollment",
    "ca_id": "ISSUING_CA_ID",
    "profile_id": "client-mtls-365d",
    "expires_at": "2027-03-22T00:00:00Z"
  }'
```

#### Cisco ISE Integration

```
! On Cisco ISE, add Vecta as SCEP RA
Administration > System > Certificates > SCEP RA Profiles
URL: https://kms.internal.acme.com/svc/certs/scep
```

#### Jamf Pro Integration

In Jamf Pro, configure a SCEP payload in a Configuration Profile:

1. **URL:** `https://kms.internal.acme.com/svc/certs/scep`
2. **Name:** `Vecta Internal PKI`
3. **Subject:** `CN=$SERIALNUMBER, O=Acme Corp`
4. **Challenge:** Configure challenge in Vecta, enter here
5. **Key size:** 2048
6. **Key usage:** Signing + Encryption

---

### 6.4 CMPv2 (Certificate Management Protocol v2 — RFC 4210)

CMPv2 is the most capable PKI enrollment protocol, supporting the full certificate lifecycle through structured PKI messages. It is used primarily by PKI-aware infrastructure applications and automated certificate lifecycle systems.

**CMP Endpoint:** `/svc/certs/cmp`

#### CMPv2 Operations

| Operation | Code | Description |
|---|---|---|
| Initialization Request | `ir` | First-time certificate request (no existing cert) |
| Certification Request | `cr` | Request certificate from existing key pair |
| Key Update Request | `kur` | Update key and obtain new certificate |
| Revocation Request | `rr` | Request certificate revocation |
| CA Info Request | `genm` | Query CA information and capabilities |
| Certificate Confirmation | `certConf` | Confirm receipt of issued certificate |
| PKI Confirmation | `pkiConf` | Final acknowledgement |

#### CMPv2 over HTTP

```bash
# CMP over HTTP (RFC 6712)
# Endpoint: POST /svc/certs/cmp
# Content-Type: application/pkixcmp
# Body: DER-encoded PKIMessage

# Using openssl cmp client (OpenSSL 3.x)
openssl cmp \
  -cmd ir \
  -server kms.internal.acme.com/svc/certs/cmp \
  -path "" \
  -recipient "/CN=Vecta Issuing CA" \
  -ref "client-001" \
  -secret "enrollment-secret" \
  -subject "/CN=server-001/O=Acme Corp" \
  -newkey device.key \
  -certout device.crt \
  -chainout chain.pem
```

#### CMPv2 Use Cases

- **PKI-enabled applications** (e.g., industrial control systems, telecom equipment) that implement CMPv2 natively
- **Automated lifecycle management** for infrastructure that needs key update without human intervention
- **Cross-certification** between multiple PKI hierarchies

---

### 6.5 Runtime mTLS

Vecta issues client certificates automatically for internal service-to-service mTLS without manual enrollment. The HYOK proxy, KMIP clients, and any service configured for workload identity use runtime mTLS certificates.

**Configure runtime mTLS:**

```bash
curl -X PUT "http://localhost:5173/svc/certs/certs/protocols/runtime-mtls?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "ca_id": "ISSUING_CA_ID_FOR_CLIENTS",
    "validity_hours": 48,
    "auto_renew_before_hours": 12,
    "allowed_spiffe_trust_domain": "acme.com"
  }'
```

Runtime mTLS certificates use SPIFFE URIs as SANs (`spiffe://acme.com/ns/{namespace}/sa/{service-account}`) so that policy engines (like OPA or Istio authorization policies) can make decisions based on workload identity rather than IP addresses or service names.

---

## 7. STAR Subscriptions (Short-Term Auto-Renewal — RFC 8739)

### 7.1 What STAR Is

STAR (Short-Term, Automatically Renewed) certificates have very short validity periods — hours to a few days — and are automatically renewed before they expire. The client registers a subscription once and receives a pointer to a URL where the current certificate is always available.

**Why short-lived certificates change the security model:**

With a 90-day certificate, a stolen private key gives an attacker up to 90 days to impersonate the victim. With a 24-hour certificate, the window is 24 hours — and because auto-renewal is continuous, revocation becomes unnecessary. If the private key is compromised, you simply stop renewing; the certificate expires within hours.

| Property | 90-day Cert | STAR 24h Cert |
|---|---|---|
| Revocation required? | Yes | No (self-expiring) |
| Key compromise window | Up to 90 days | Up to 24 hours |
| CRL/OCSP infrastructure | Required | Optional |
| Renewal automation | Required | Built in |
| Certificate size | Normal | Normal |
| Suitable for CDN | Sometimes | Yes (RFC 8739 §4) |

### 7.2 STAR Subscription Fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Human-readable subscription name |
| `ca_id` | string | Issuing CA to use |
| `subject_cn` | string | Certificate subject CN |
| `sans` | array | SANs (same as regular cert issuance) |
| `cert_type` | string | `server`, `client`, `server_client` |
| `validity_hours` | integer | Cert validity in hours (24–720) |
| `renew_before_minutes` | integer | Renew this many minutes before expiry |
| `auto_renew` | boolean | Enable automatic renewal |
| `allow_delegation` | boolean | Allow CDN STAR delegation (RFC 8739 §4) |
| `algorithm` | string | Key algorithm for issued certs |
| `profile_id` | string | Optional profile override |

### 7.3 Creating and Managing STAR Subscriptions

```bash
# Create a STAR subscription for a microservice
curl -X POST "http://localhost:5173/svc/certs/certs/star/subscriptions?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payment-service-star",
    "ca_id": "ISSUING_CA_ID",
    "subject_cn": "payment.internal.acme.com",
    "sans": [
      {"type": "dns", "value": "payment.internal.acme.com"},
      {"type": "uri", "value": "spiffe://acme.com/ns/payments/sa/payment-service"}
    ],
    "cert_type": "server_client",
    "validity_hours": 48,
    "renew_before_minutes": 120,
    "auto_renew": true,
    "algorithm": "EC-P256"
  }'
```

**Response:**

```json
{
  "id": "star_01HXYZ...",
  "name": "payment-service-star",
  "status": "active",
  "current_cert_url": "https://kms.internal.acme.com/svc/certs/certs/star/subscriptions/star_01HXYZ.../current",
  "current_cert_expires_at": "2026-03-24T10:00:00Z",
  "next_renewal_at": "2026-03-24T08:00:00Z",
  "created_at": "2026-03-22T10:00:00Z"
}
```

```bash
# Fetch current certificate (always the latest valid cert)
curl "http://localhost:5173/svc/certs/certs/star/subscriptions/{STAR_ID}/current?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# List all STAR subscriptions
curl "http://localhost:5173/svc/certs/certs/star/subscriptions?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get subscription details (including renewal history)
curl "http://localhost:5173/svc/certs/certs/star/subscriptions/{STAR_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Cancel subscription (stop auto-renewing)
curl -X DELETE "http://localhost:5173/svc/certs/certs/star/subscriptions/{STAR_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

### 7.4 STAR for CDN Delegation (RFC 8739 §4)

In CDN scenarios, a content origin server delegates a STAR subscription to a CDN provider. The CDN polls the current certificate URL, always serving the freshest certificate. When the origin revokes the subscription (cancels), the CDN's certificate expires within `validity_hours` automatically.

```bash
# Create delegated STAR (CDN scenario)
curl -X POST "http://localhost:5173/svc/certs/certs/star/subscriptions?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "cdn-delegation-star",
    "ca_id": "ISSUING_CA_ID",
    "subject_cn": "static.acme.com",
    "sans": [{"type": "dns", "value": "static.acme.com"}],
    "cert_type": "server",
    "validity_hours": 24,
    "renew_before_minutes": 60,
    "auto_renew": true,
    "allow_delegation": true,
    "delegation_id": "cdn-provider-account-id"
  }'
```

### 7.5 Application Integration Patterns

**Pattern 1 — Sidecar polling (Kubernetes):**

```yaml
# Init container fetches certificate, sidecar refreshes every hour
initContainers:
- name: fetch-cert
  image: curlimages/curl:latest
  command:
  - sh
  - -c
  - |
    curl -H "Authorization: Bearer $VECTA_TOKEN" \
      "https://kms.internal.acme.com/svc/certs/certs/star/subscriptions/${STAR_ID}/current" \
      -o /certs/tls.pem
  volumeMounts:
  - name: certs
    mountPath: /certs
```

**Pattern 2 — Application fetches on startup and refreshes:**

```python
import requests, time, threading

STAR_URL = "https://kms.internal.acme.com/svc/certs/certs/star/subscriptions/{star_id}/current"
HEADERS = {"Authorization": f"Bearer {VECTA_TOKEN}"}

def refresh_cert():
    while True:
        resp = requests.get(STAR_URL, headers=HEADERS)
        cert_data = resp.json()
        write_cert(cert_data["certificate_pem"])
        # Sleep until 30 minutes before expiry
        expires_in = cert_data["expires_in_seconds"]
        time.sleep(max(0, expires_in - 1800))

threading.Thread(target=refresh_cert, daemon=True).start()
```

---

## 8. Renewal Intelligence (ARI — RFC Draft)

### 8.1 What ARI Provides

ARI (Automated Renewal Information) is a server-calculated recommendation for when a specific certificate should be renewed. Rather than every client renewing at the same fixed point (e.g., 30 days before expiry), the server suggests different windows for different certificates. This prevents thundering-herd renewal events where thousands of certificates issued on the same day all try to renew simultaneously.

### 8.2 How ARI Windows Are Calculated

For each certificate, Vecta calculates a renewal window considering:

1. **Certificate validity period** — Shorter-lived certs get proportionally earlier renewal recommendations.
2. **CA issuance load balancing** — If many certs share the same expiry date, their windows are spread across different days.
3. **Historical renewal success rates** — If a client has failed recent renewal attempts, it gets an earlier window.
4. **CRL/OCSP freshness** — Certs approaching the next CRL publication get nudged to renew.
5. **Revocation events** — A revoked cert that needs emergency replacement gets an immediate window.

### 8.3 Risk Levels

| Risk Level | Days Until Expiry | Recommended Action |
|---|---|---|
| `low` | > 90 days | No action required |
| `medium` | 30–90 days | Schedule renewal |
| `high` | 7–30 days | Renew promptly |
| `critical` | < 7 days | Renew immediately |
| `missed` | Expired | Emergency replacement required |

### 8.4 Renewal States

| State | Description |
|---|---|
| `pending` | Renewal window not yet open |
| `scheduled` | Window open; renewal recommended now |
| `renewed` | New certificate successfully issued |
| `missed` | Certificate expired without renewal |
| `emergency_rotation` | Out-of-window renewal triggered (key compromise, CA change) |

### 8.5 ARI API

```bash
# Get renewal information for a specific certificate
curl "http://localhost:5173/svc/certs/acme/renewal-info/{CERT_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**

```json
{
  "suggestedWindow": {
    "start": "2026-05-20T00:00:00Z",
    "end":   "2026-05-22T00:00:00Z"
  },
  "explanationURL": "https://kms.internal.acme.com/ari-docs",
  "risk_level": "medium",
  "renewal_state": "scheduled",
  "days_until_expiry": 45,
  "mass_renewal_bucket": "bucket-07"
}
```

```bash
# Get ARI for all certs approaching expiry
curl "http://localhost:5173/svc/certs/certs/renewal-info?tenant_id=root&risk_level=high,critical" \
  -H "Authorization: Bearer $TOKEN"

# Update ARI config
curl -X PUT "http://localhost:5173/svc/certs/certs/ari/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mass_renewal_spread_days": 7,
    "max_daily_renewal_budget": 5000,
    "emergency_rotation_enabled": true
  }'
```

### 8.6 Mass Renewal Buckets

When a large batch of certificates was issued on the same day (e.g., after a CA rotation), they all approach expiry on the same day. Mass renewal buckets distribute these across a window:

```
Expiry date: 2026-06-20
Certificates expiring that day: 10,000
Spread window: 7 days (June 13–20)
Bucket assignment: cert_id % 7 → day offset

Bucket 0: certs expiring June 13 (earliest)
Bucket 1: certs expiring June 14
...
Bucket 6: certs expiring June 20 (actual expiry — do not miss this)
```

---

## 9. Certificate Transparency (Merkle Proofs)

### 9.1 Purpose

Certificate Transparency (CT) in Vecta's internal PKI provides:

- **Tamper evidence** — An append-only Merkle tree records every certificate issuance. If the log is tampered with, the root hash changes and the mismatch is detectable.
- **Audit trail** — Any party with access to the log can verify that a certificate was issued at a specific time.
- **Non-repudiation** — The CA cannot deny having issued a certificate if an inclusion proof exists for it.

This is analogous to the public Certificate Transparency logs used in the browser ecosystem (RFC 6962), but for internal PKI.

### 9.2 Merkle Tree Structure

```
                    Root Hash (epoch root)
                   /                       \
           H(L + R)                       H(L + R)
          /         \                    /         \
      H(L+R)       H(L+R)           H(L+R)       H(L+R)
      /    \       /    \           /    \       /    \
   Leaf0  Leaf1 Leaf2  Leaf3    Leaf4  Leaf5 Leaf6  Leaf7

Each leaf = SHA-256(cert_id | serial | subject | not_before | not_after | fingerprint)
```

- **Epoch:** A completed batch of up to N leaves. Once an epoch is sealed, its root hash is immutable.
- **Leaf index:** Zero-based position of the certificate in the epoch.
- **Siblings:** The hash values needed to reconstruct the path from leaf to root.
- **Inclusion proof:** (leaf_hash, leaf_index, siblings[], root) — proves the leaf is in the tree at the given index.

### 9.3 Building and Querying Epochs

```bash
# Build a Merkle epoch (seal pending certs into an immutable batch)
curl -X POST "http://localhost:5173/svc/certs/certs/merkle/build?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "max_leaves": 10000,
    "description": "Daily batch 2026-03-22"
  }'
```

**Response:**

```json
{
  "epoch_id": "epoch_01HXYZ...",
  "leaf_count": 2847,
  "root_hash": "a1b2c3d4e5f6...",
  "sealed_at": "2026-03-22T23:59:59Z",
  "status": "sealed"
}
```

```bash
# List epochs
curl "http://localhost:5173/svc/certs/certs/merkle/epochs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get inclusion proof for a certificate
curl "http://localhost:5173/svc/certs/certs/merkle/proof/{CERT_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

**Inclusion proof response:**

```json
{
  "cert_id": "cert_01HXYZ...",
  "epoch_id": "epoch_01HABC...",
  "leaf_hash": "3f4a5b...",
  "leaf_index": 42,
  "tree_size": 2847,
  "siblings": [
    "hash_of_leaf_43",
    "hash_of_pair_44_45",
    "hash_of_group_46_47_48_49",
    "hash_of_right_subtree"
  ],
  "root": "a1b2c3d4e5f6...",
  "epoch_sealed_at": "2026-03-22T23:59:59Z"
}
```

### 9.4 Verifying an Inclusion Proof

```bash
# Verify proof
curl -X POST "http://localhost:5173/svc/certs/certs/merkle/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cert_id": "cert_01HXYZ...",
    "leaf_hash": "3f4a5b...",
    "leaf_index": 42,
    "siblings": ["hash_of_leaf_43", "hash_of_pair_44_45", "..."],
    "root": "a1b2c3d4e5f6..."
  }'
```

**Response:**

```json
{
  "valid": true,
  "recomputed_root": "a1b2c3d4e5f6...",
  "matches_epoch_root": true,
  "verification_time": "2026-03-22T15:30:00Z"
}
```

### 9.5 Verification Algorithm (Client-Side)

```python
import hashlib

def verify_inclusion(leaf_hash: str, leaf_index: int, siblings: list[str], root: str) -> bool:
    """
    Verify a Merkle inclusion proof.
    leaf_hash: hex-encoded SHA-256 of the leaf
    leaf_index: 0-based position in the tree
    siblings: list of hex-encoded sibling hashes (bottom to top)
    root: expected root hash
    """
    current = bytes.fromhex(leaf_hash)
    index = leaf_index

    for sibling in siblings:
        sibling_bytes = bytes.fromhex(sibling)
        if index % 2 == 0:
            # Current is left child
            combined = current + sibling_bytes
        else:
            # Current is right child
            combined = sibling_bytes + current
        current = hashlib.sha256(combined).digest()
        index //= 2

    return current.hex() == root
```

---

## 10. CRL and OCSP

### 10.1 Certificate Revocation List (CRL)

A CRL is a signed list of revoked certificate serial numbers. Relying parties download the CRL and check if the presented certificate's serial number appears in it.

```bash
# Download CRL for a specific CA
curl "http://localhost:5173/svc/certs/certs/crl?ca_id={CA_ID}&tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -o ca.crl

# Download CRL in DER format
curl "http://localhost:5173/svc/certs/certs/crl?ca_id={CA_ID}&format=der&tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -o ca.der.crl

# Force CRL refresh (re-sign with updated timestamp)
curl -X POST "http://localhost:5173/svc/certs/certs/crl/refresh?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ca_id": "{CA_ID}"}'
```

**CRL Configuration per CA:**

```bash
curl -X PUT "http://localhost:5173/svc/certs/certs/ca/{CA_ID}/crl-config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "crl_validity_hours": 24,
    "crl_overlap_hours": 4,
    "distribution_points": [
      "http://crl.internal.acme.com/issuing-tls.crl",
      "ldap://ldap.internal.acme.com/cn=Issuing TLS CA,dc=acme,dc=com?certificateRevocationList"
    ],
    "publish_to_s3": {
      "enabled": true,
      "bucket": "acme-pki-crls",
      "key_prefix": "crls/",
      "region": "us-east-1"
    }
  }'
```

#### Serving CRLs Publicly

CRL distribution points embedded in certificates must be reachable by all relying parties. Options:

1. **Vecta direct** — Point CDPs to `http://kms.internal.acme.com/svc/certs/certs/crl?ca_id=...`. Only works for internal relying parties.
2. **Static S3 / CloudFront** — Vecta publishes CRL to S3 on each update; a CloudFront distribution serves it at `http://crl.acme.com/issuing-tls.crl`.
3. **LDAP** — For Active Directory environments, publish CRL to an LDAP attribute.

### 10.2 OCSP (Online Certificate Status Protocol — RFC 2560)

OCSP provides real-time certificate status. Instead of downloading an entire CRL, a client sends a request for a specific certificate's status and receives a signed `good`, `revoked`, or `unknown` response.

**OCSP endpoint:** `GET` or `POST` `/svc/certs/certs/ocsp`

```bash
# GET-based OCSP request (base64url-encoded)
# In practice, clients do this automatically; this shows the mechanics:
OCSP_REQUEST=$(openssl ocsp -issuer issuing-ca.pem -cert server.pem -reqout - 2>/dev/null | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
curl "http://localhost:5173/svc/certs/certs/ocsp/${OCSP_REQUEST}" -o ocsp-response.der

# POST-based OCSP request
openssl ocsp \
  -issuer issuing-ca.pem \
  -cert server.pem \
  -url "http://localhost:5173/svc/certs/certs/ocsp" \
  -resp_text
```

#### OCSP Stapling Configuration

Configure nginx to staple OCSP responses:

```nginx
server {
    listen 443 ssl;
    server_name api.internal.acme.com;

    ssl_certificate     /etc/nginx/ssl/server.pem;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_trusted_certificate /etc/nginx/ssl/ca-chain.pem;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 valid=300s;
    resolver_timeout 5s;
}
```

```bash
# Verify OCSP stapling is working
openssl s_client -connect api.internal.acme.com:443 -status 2>/dev/null | grep -A 20 "OCSP Response"
```

#### OCSP Response Caching

Vecta pre-computes OCSP responses for all active certificates and caches them. Response validity period defaults to 24 hours. This means even if the Vecta API is momentarily unreachable, cached responses are served from an edge cache.

```bash
# Configure OCSP cache settings
curl -X PUT "http://localhost:5173/svc/certs/certs/ocsp/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "response_validity_hours": 24,
    "next_update_offset_hours": 20,
    "pre_sign_on_issuance": true,
    "cache_backend": "redis",
    "cache_ttl_seconds": 86400
  }'
```

---

## 11. Certificate Security Status

### 11.1 Security Scan

The security status endpoint runs a scan of all certificates and returns findings by severity.

```bash
# Get security status
curl "http://localhost:5173/svc/certs/certs/security/status?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**

```json
{
  "scan_time": "2026-03-22T10:00:00Z",
  "findings": {
    "critical": [
      {
        "type": "expired",
        "count": 3,
        "certs": ["cert_01...", "cert_02...", "cert_03..."]
      },
      {
        "type": "weak_algorithm",
        "detail": "SHA-1 signature",
        "count": 1,
        "certs": ["cert_legacy..."]
      }
    ],
    "high": [
      {
        "type": "expiring_soon",
        "detail": "Expires within 7 days",
        "count": 5,
        "certs": ["cert_04...", "cert_05..."]
      },
      {
        "type": "weak_key",
        "detail": "RSA-1024",
        "count": 2,
        "certs": ["cert_old..."]
      }
    ],
    "medium": [
      {
        "type": "expiring_soon",
        "detail": "Expires within 30 days",
        "count": 23
      },
      {
        "type": "no_san",
        "detail": "CN-only certificate (deprecated)",
        "count": 4
      }
    ],
    "low": [
      {
        "type": "md5_in_chain",
        "detail": "Intermediate CA uses MD5 in signature (legacy)",
        "count": 0
      }
    ]
  },
  "summary": {
    "total_active": 4821,
    "total_expired": 3,
    "total_revoked": 142,
    "expiring_30d": 23,
    "expiring_7d": 5,
    "weak_algorithm": 3
  }
}
```

### 11.2 Expiry Alert Policy

```bash
# Configure expiry alert thresholds
curl -X PUT "http://localhost:5173/svc/certs/certs/security/alert-policy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "warning_days": 30,
    "critical_days": 7,
    "scan_interval_hours": 6,
    "notification_channels": [
      {
        "type": "webhook",
        "url": "https://hooks.slack.com/services/...",
        "severity": ["critical", "high"]
      },
      {
        "type": "email",
        "addresses": ["security@acme.com", "pki-admin@acme.com"],
        "severity": ["critical", "high", "medium"]
      },
      {
        "type": "pagerduty",
        "routing_key": "your-pagerduty-routing-key",
        "severity": ["critical"]
      }
    ]
  }'
```

### 11.3 Weak Algorithm Detection

Vecta flags the following as security findings:

| Algorithm / Property | Severity | Reason |
|---|---|---|
| RSA < 2048 bits | Critical | Factoring attacks feasible |
| RSA 2048 bits | Medium | Below recommended minimum for new issuance (use 3072+) |
| EC < P-256 | Critical | Insufficient security level |
| SHA-1 signature | Critical | Collision attacks demonstrated |
| MD5 signature | Critical | Collision attacks trivial |
| No SAN (CN-only) | Medium | Deprecated by RFC 2818, rejected by modern browsers |
| Wildcard SAN | Low | Informational; limits scope of compromise |
| Validity > 825 days | Medium | Exceeds CAB Forum baseline for public TLS |

---

## 12. Use Cases

### Use Case 1 — Internal HTTPS for Microservices with mTLS and STAR

**Scenario:** A Kubernetes-based payment platform where all service-to-service communication must use mTLS. Certificates must be short-lived and auto-renewed.

**Setup:**

1. Create an issuing CA for service identities (client+server certs).
2. Create a STAR subscription per service with 48h validity.
3. Deploy a sidecar that fetches the current certificate from the STAR URL every 30 minutes.
4. Services configure TLS to use the fetched cert + key.
5. Services validate peer certificates against the CA chain.

```bash
# Create service issuing CA
curl -X POST "http://localhost:5173/svc/certs/certs/ca?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "K8s Service Identity CA",
    "ca_type": "issuing",
    "parent_ca_id": "INTERMEDIATE_CA_ID",
    "algorithm": "EC-P256",
    "validity_days": 730,
    "permitted_uri_domains": ["spiffe://acme.com"]
  }'

# Create STAR subscription per service (in CI/CD)
for SERVICE in payments inventory notifications auth; do
  curl -X POST "http://localhost:5173/svc/certs/certs/star/subscriptions?tenant_id=root" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"name\": \"${SERVICE}-star\",
      \"ca_id\": \"K8S_CA_ID\",
      \"subject_cn\": \"${SERVICE}.payments.svc.cluster.local\",
      \"sans\": [{\"type\": \"uri\", \"value\": \"spiffe://acme.com/ns/payments/sa/${SERVICE}\"}],
      \"cert_type\": \"server_client\",
      \"validity_hours\": 48,
      \"renew_before_minutes\": 120,
      \"auto_renew\": true
    }"
done
```

---

### Use Case 2 — Kubernetes cert-manager with Vecta ACME

**Scenario:** All Kubernetes ingresses use TLS, automatically provisioned by cert-manager via Vecta ACME. DNS-01 challenge used for wildcard certs.

```yaml
# ClusterIssuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: vecta-internal
spec:
  acme:
    server: https://kms.internal.acme.com/svc/certs/acme/directory
    email: platform@acme.com
    privateKeySecretRef:
      name: vecta-acme-key
    solvers:
    - http01:
        ingress:
          class: nginx
    - dns01:
        route53:
          region: us-east-1
          role: arn:aws:iam::123456789012:role/cert-manager
      selector:
        dnsZones:
        - "internal.acme.com"
---
# Wildcard certificate for all internal services
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: wildcard-internal
  namespace: istio-system
spec:
  secretName: wildcard-internal-tls
  issuerRef:
    name: vecta-internal
    kind: ClusterIssuer
  dnsNames:
  - "*.internal.acme.com"
  duration: 2160h
  renewBefore: 720h
```

---

### Use Case 3 — IoT Device Onboarding with EST

**Scenario:** 10,000 temperature sensors enrolled via EST at manufacturing time. Each device gets a unique identity certificate before shipping.

```bash
# Manufacturing line script (runs on each device)
DEVICE_SERIAL=$(cat /proc/cpuinfo | grep Serial | awk '{print $3}')

# Generate key on-device (stays on device)
openssl ecparam -name prime256v1 -genkey -noout -out /secure/device.key

# Generate CSR
openssl req -new \
  -key /secure/device.key \
  -subj "/CN=${DEVICE_SERIAL}/O=Acme Corp/OU=IoT Sensors" \
  -out /tmp/device.csr

# Enroll via EST
curl -X POST \
  "https://kms.acme.com/svc/certs/est/.well-known/est/simpleenroll" \
  -u "manufacturing:${FACTORY_EST_PASSWORD}" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @/tmp/device.csr \
  -o /tmp/device.p7c

# Convert and store
openssl pkcs7 -in /tmp/device.p7c -inform DER -print_certs \
  -out /secure/device.crt

echo "Device ${DEVICE_SERIAL} enrolled successfully"
```

---

### Use Case 4 — Windows MDM Integration with SCEP

**Scenario:** All Windows laptops automatically receive machine certificates via Microsoft Intune using SCEP.

1. Configure SCEP challenge in Vecta (static challenge for Intune).
2. In Intune, create a SCEP Certificate Profile with Vecta SCEP URL.
3. Assign profile to All Windows Devices group.
4. Intune provisions certificate to TPM-backed key store on each device.

---

### Use Case 5 — Code Signing Pipeline

**Scenario:** CI/CD pipeline signs every binary before publishing. Deployment systems verify signatures before executing.

```bash
# In CI pipeline (GitHub Actions / GitLab CI)
# Sign artifact
ARTIFACT_HASH=$(sha256sum myapp.tar.gz | awk '{print $1}')

SIGN_RESPONSE=$(curl -X POST "http://kms.internal.acme.com/svc/signing/sign?tenant_id=root" \
  -H "Authorization: Bearer $CI_VECTA_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"artifact_hash\": \"sha256:${ARTIFACT_HASH}\",
    \"artifact_type\": \"artifact\",
    \"policy_id\": \"prod-signing-policy\",
    \"metadata\": {
      \"filename\": \"myapp.tar.gz\",
      \"version\": \"${CI_COMMIT_TAG}\",
      \"pipeline\": \"${CI_PIPELINE_URL}\"
    }
  }")

SIGNATURE=$(echo $SIGN_RESPONSE | jq -r '.signature')
echo "$SIGNATURE" > myapp.tar.gz.sig

# In deployment script
DEPLOY_ARTIFACT_HASH=$(sha256sum myapp.tar.gz | awk '{print $1}')
SIGNATURE=$(cat myapp.tar.gz.sig)

VERIFY_RESULT=$(curl -X POST "http://kms.internal.acme.com/svc/signing/verify?tenant_id=root" \
  -H "Authorization: Bearer $DEPLOY_TOKEN" \
  -d "{\"artifact_hash\": \"sha256:${DEPLOY_ARTIFACT_HASH}\", \"signature\": \"${SIGNATURE}\", \"policy_id\": \"prod-signing-policy\"}")

if [ "$(echo $VERIFY_RESULT | jq -r '.valid')" != "true" ]; then
  echo "SIGNATURE VERIFICATION FAILED. Aborting deployment."
  exit 1
fi
```

---

### Use Case 6 — S/MIME Email Encryption

**Scenario:** Finance department needs to encrypt email containing financial data. All members get S/MIME certificates.

```bash
# Issue S/MIME certificate for user
curl -X POST "http://localhost:5173/svc/certs/certs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "EMAIL_ISSUING_CA_ID",
    "profile_id": "email-smime-1y",
    "subject_cn": "Alice Smith",
    "subject": {
      "cn": "Alice Smith",
      "email": "alice@acme.com",
      "org": "Acme Corp",
      "country": "US"
    },
    "sans": [{"type": "email", "value": "alice@acme.com"}],
    "cert_type": "email",
    "validity_days": 365,
    "algorithm": "RSA-2048"
  }'

# Export as PKCS#12 for import into email client
curl -X POST "http://localhost:5173/svc/certs/certs/{CERT_ID}/pkcs12?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"password": "alice-temp-password"}' \
  -o alice-smime.p12

# User imports alice-smime.p12 into Outlook / Apple Mail / Thunderbird
```

---

### Use Case 7 — Zero-Touch Network Device Enrollment

**Scenario:** New Cisco switches and routers automatically enroll using SCEP when they boot and reach the network.

```
! Cisco IOS-XE configuration for SCEP enrollment
crypto pki trustpoint VECTA-INTERNAL
  enrollment url http://kms.internal.acme.com/svc/certs/scep
  subject-name CN=switch-01.network.acme.com, O=Acme Corp
  rsakeypair VECTA-KEY 2048
  revocation-check crl
  auto-enroll 70 regenerate

crypto pki authenticate VECTA-INTERNAL
! (downloads and installs CA cert)

crypto pki enroll VECTA-INTERNAL
! (sends CSR, receives certificate)
```

---

### Use Case 8 — Post-Quantum Certificate Authority (ML-DSA)

**Scenario:** An organization wants to begin issuing ML-DSA (FIPS 204, Dilithium) certificates for internal services that must be secure against quantum computers.

```bash
# Create PQC Root CA
curl -X POST "http://localhost:5173/svc/certs/certs/ca?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Vecta PQC Root CA",
    "ca_type": "root",
    "algorithm": "ML-DSA-87",
    "key_backend": "hsm",
    "validity_days": 7300,
    "subject": {
      "cn": "Vecta PQC Root CA",
      "org": "Acme Corp",
      "country": "US"
    }
  }'

# Create PQC Issuing CA
curl -X POST "http://localhost:5173/svc/certs/certs/ca?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Vecta PQC Issuing CA",
    "ca_type": "issuing",
    "parent_ca_id": "PQC_ROOT_CA_ID",
    "algorithm": "ML-DSA-65",
    "key_backend": "hsm",
    "validity_days": 730
  }'

# Issue PQC server certificate
curl -X POST "http://localhost:5173/svc/certs/certs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "ca_id": "PQC_ISSUING_CA_ID",
    "subject_cn": "api.internal.acme.com",
    "sans": [{"type": "dns", "value": "api.internal.acme.com"}],
    "cert_type": "server",
    "validity_days": 90,
    "algorithm": "ML-DSA-65"
  }'
```

**Dual-algorithm (hybrid) issuance:** Issue both a classical EC-P256 cert and an ML-DSA cert for the same identity. Configure the TLS server to present both; clients that understand ML-DSA validate it, others fall back to EC-P256.

---

## 13. Security Considerations

### 13.1 CA Key Protection

| Recommendation | Priority | Implementation |
|---|---|---|
| Store all CA private keys in HSM | Critical | Set `key_backend: hsm` for every CA |
| Take root CA offline after setup | Critical | Disable root CA API after intermediate CA signing |
| Use HSM key access controls | Critical | Require HSM PIN + operator card for CA key operations |
| Audit all CA key usages | Critical | Every CA signing operation logged to immutable audit trail |
| Backup HSM keys to secure offline media | High | HSM key export protected by split knowledge (Shamir) |

### 13.2 Certificate Validity

- **Server certificates:** Maximum 90 days. Shorter (24–48h via STAR) preferred for high-value services.
- **Client certificates:** 90–365 days depending on revocation infrastructure maturity.
- **Code signing certificates:** 1–2 years, but sign with timestamps so signatures outlive cert validity.
- **CA certificates:** See Section 2.4.

### 13.3 SAN Validation

- Always require at least one SAN (`require_san: true` in profile).
- Never issue CN-only certificates (deprecated by RFC 2818, rejected by modern TLS stacks).
- Enforce permitted DNS domain constraints at the issuing CA level.
- Reject wildcard SANs unless explicitly approved and logged.

### 13.4 Revocation Infrastructure

| Scenario | Recommended Approach |
|---|---|
| Short-lived certs (< 7 days) | No revocation checking needed; cert expires soon |
| Medium-lived certs (7–90 days) | OCSP stapling |
| Long-lived certs (> 90 days) | OCSP stapling + CRL as fallback |
| Code signing certs | Timestamping (RFC 3161) so revocation is auditable post-signing |

### 13.5 Access Control for Certificate Operations

- Separate RBAC roles: `pki:ca:create`, `pki:cert:issue`, `pki:cert:revoke`, `pki:cert:view`.
- CA creation requires `pki:ca:create` — restrict to PKI administrators only.
- Certificate issuance may be delegated to automation accounts with profile and SAN restrictions.
- Revocation requires `pki:cert:revoke` — never allow automated systems to revoke without a secondary approval.

### 13.6 Audit Logging

Every operation generates an audit log entry:

```json
{
  "timestamp": "2026-03-22T10:00:00Z",
  "event": "certificate.issued",
  "actor": "svc-account:payments-ci",
  "tenant_id": "root",
  "resource_type": "certificate",
  "resource_id": "cert_01HXYZ...",
  "details": {
    "ca_id": "ISSUING_CA_ID",
    "subject_cn": "api.internal.acme.com",
    "validity_days": 90,
    "cert_type": "server"
  },
  "ip_address": "10.0.1.50",
  "request_id": "req_abc123"
}
```

---

## 14. Full API Reference

### CA Management Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/certs/certs/ca` | Create CA |
| `GET` | `/svc/certs/certs/ca` | List CAs |
| `GET` | `/svc/certs/certs/ca/{id}` | Get CA |
| `PUT` | `/svc/certs/certs/ca/{id}` | Update CA metadata |
| `DELETE` | `/svc/certs/certs/ca/{id}` | Deactivate CA |
| `GET` | `/svc/certs/certs/ca/{id}/chain` | Get CA chain (PEM) |
| `GET` | `/svc/certs/certs/ca/{id}/certificate` | Get CA cert (PEM or DER) |
| `POST` | `/svc/certs/certs/ca/{id}/rotate` | Rotate issuing CA |

### Certificate Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/certs/certs` | Issue certificate |
| `GET` | `/svc/certs/certs` | List certificates |
| `GET` | `/svc/certs/certs/{id}` | Get certificate |
| `GET` | `/svc/certs/certs/{id}/download` | Download cert (PEM/DER) |
| `POST` | `/svc/certs/certs/{id}/pkcs12` | Download PKCS#12 bundle |
| `POST` | `/svc/certs/certs/{id}/renew` | Renew certificate |
| `POST` | `/svc/certs/certs/{id}/revoke` | Revoke certificate |
| `POST` | `/svc/certs/certs/sign-csr` | Sign external CSR |

### Profile Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/certs/certs/profiles` | Create profile |
| `GET` | `/svc/certs/certs/profiles` | List profiles |
| `GET` | `/svc/certs/certs/profiles/{id}` | Get profile |
| `PUT` | `/svc/certs/certs/profiles/{id}` | Update profile |
| `DELETE` | `/svc/certs/certs/profiles/{id}` | Delete profile |

### ACME Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/certs/acme/directory` | ACME directory |
| `HEAD` | `/svc/certs/acme/new-nonce` | Get nonce |
| `POST` | `/svc/certs/acme/new-account` | Create ACME account |
| `POST` | `/svc/certs/acme/new-order` | Create order |
| `GET` | `/svc/certs/acme/authz/{id}` | Get authorization |
| `GET` | `/svc/certs/acme/challenge/{id}` | Get challenge |
| `POST` | `/svc/certs/acme/challenge/{id}` | Complete challenge |
| `POST` | `/svc/certs/acme/finalize/{orderId}` | Finalize order |
| `GET` | `/svc/certs/acme/cert/{certId}` | Download certificate |
| `POST` | `/svc/certs/acme/revoke-cert` | Revoke certificate |
| `GET` | `/svc/certs/acme/renewal-info/{certId}` | Get ARI |

### EST Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/certs/est/.well-known/est/cacerts` | Get CA certs |
| `POST` | `/svc/certs/est/.well-known/est/simpleenroll` | Enroll |
| `POST` | `/svc/certs/est/.well-known/est/simplereenroll` | Re-enroll |
| `POST` | `/svc/certs/est/.well-known/est/serverkeygen` | Server key generation |
| `GET` | `/svc/certs/est/.well-known/est/csrattrs` | CSR attribute requirements |

### SCEP Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/certs/scep?operation=GetCACert` | Get CA cert |
| `GET` | `/svc/certs/scep?operation=GetCACaps` | Get capabilities |
| `POST` | `/svc/certs/scep?operation=PKIOperation` | PKI operation |

### STAR Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/certs/certs/star/subscriptions` | Create subscription |
| `GET` | `/svc/certs/certs/star/subscriptions` | List subscriptions |
| `GET` | `/svc/certs/certs/star/subscriptions/{id}` | Get subscription |
| `GET` | `/svc/certs/certs/star/subscriptions/{id}/current` | Current cert |
| `DELETE` | `/svc/certs/certs/star/subscriptions/{id}` | Cancel subscription |

### CRL and OCSP Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/certs/certs/crl` | Download CRL |
| `POST` | `/svc/certs/certs/crl/refresh` | Force CRL refresh |
| `GET` | `/svc/certs/certs/ocsp` | OCSP request (GET) |
| `POST` | `/svc/certs/certs/ocsp` | OCSP request (POST) |

### Merkle / Transparency Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/certs/certs/merkle/build` | Build epoch |
| `GET` | `/svc/certs/certs/merkle/epochs` | List epochs |
| `GET` | `/svc/certs/certs/merkle/proof/{certId}` | Get inclusion proof |
| `POST` | `/svc/certs/certs/merkle/verify` | Verify proof |

### Security Status Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/certs/certs/security/status` | Security scan results |
| `PUT` | `/svc/certs/certs/security/alert-policy` | Configure alert policy |
| `GET` | `/svc/certs/certs/renewal-info` | Bulk ARI for expiring certs |

---

*Last updated: 2026-03-22 | Vecta KMS Certificate & PKI Documentation*
