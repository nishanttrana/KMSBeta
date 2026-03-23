# Identity, Confidential Computing, and Post-Quantum Cryptography

**Vecta KMS Technical Reference**

This document provides exhaustive technical documentation for three interconnected capability areas in Vecta KMS:

1. **Workload Identity** — SPIFFE/SVID-based machine authentication with token exchange to cloud IAM systems
2. **Confidential Computing and TEE Attestation** — Cryptographic proof of runtime environment before key release
3. **Key Access Justifications** — Structured audit trail of why keys are used
4. **Post-Quantum Cryptography** — NIST FIPS 203/204/205 algorithm support and migration tooling
5. **AI-Assisted Operations** — Natural language queries, policy recommendations, anomaly detection
6. **Reference Use Cases** — Eight complete, end-to-end implementation scenarios

---

## Table of Contents

- [Section 1: Workload Identity](#section-1-workload-identity)
  - [The Problem with Static API Keys](#the-problem-with-static-api-keys)
  - [SPIFFE and SVIDs](#spiffe-and-svids)
  - [Vecta as SPIFFE CA](#vecta-as-spiffe-ca)
  - [Setup Walkthrough](#setup-walkthrough)
  - [Kubernetes Attestation](#kubernetes-attestation)
  - [AWS EC2 Attestation](#aws-ec2-attestation)
  - [GCP, Docker, Unix, and TPM Attestors](#gcp-docker-unix-and-tpm-attestors)
  - [Attestation Policy Schema](#attestation-policy-schema)
  - [Token Exchange — OAuth 2.0 RFC 8693](#token-exchange--oauth-20-rfc-8693)
  - [Workload Service Endpoints](#workload-service-endpoints)
- [Section 2: Confidential Computing and TEE Attestation](#section-2-confidential-computing-and-tee-attestation)
  - [What is Confidential Computing](#what-is-confidential-computing)
  - [Attested Key Release Pattern](#attested-key-release-pattern)
  - [Intel TDX](#intel-tdx)
  - [AMD SEV-SNP](#amd-sev-snp)
  - [AWS Nitro Enclaves](#aws-nitro-enclaves)
  - [Azure Confidential VMs](#azure-confidential-vms)
  - [Attested Key Release Policy Schema](#attested-key-release-policy-schema)
  - [Full Attested Key Release Flow](#full-attested-key-release-flow)
  - [Confidential Service Endpoints](#confidential-service-endpoints)
- [Section 3: Key Access Justifications](#section-3-key-access-justifications)
- [Section 4: Post-Quantum Cryptography](#section-4-post-quantum-cryptography)
- [Section 5: AI-Assisted Operations](#section-5-ai-assisted-operations)
- [Section 6: Reference Use Cases](#section-6-reference-use-cases)

---

## Section 1: Workload Identity

### The Problem with Static API Keys

Most applications authenticate to a KMS using a long-lived API key: a secret string that is generated once, stored somewhere, and presented on every request. This model has fundamental security weaknesses that become increasingly difficult to manage at scale.

**Credential leakage is the norm, not the exception.** API keys are accidentally committed to version control, printed in CI/CD logs, embedded in container images, and stored in plaintext configuration files. GitHub's secret scanning program reports tens of millions of leaked credentials per year. Every leaked API key is a window for an attacker to impersonate your service indefinitely until the key is manually revoked.

**There is no attestation.** A static API key proves only that the holder knows the secret. It provides no evidence about what process holds the key, where it is running, what code it is executing, or whether it is the legitimate service or an attacker who copied the key from a Slack message. Two completely different processes with the same key are indistinguishable.

**Manual rotation is fragile.** Rotating API keys requires coordinating the new key across every place the old key is stored: secrets managers, environment variables, Kubernetes secrets, CI/CD pipeline variables, and often hard-coded configuration files spread across dozens of repositories. Human coordination errors cause outages. Fear of outages causes teams to skip rotation, leaving keys in place for years.

**Revocation is reactive.** Revoking a compromised static key requires knowing it was compromised — which typically happens only after a breach. The window between compromise and revocation averages hundreds of days in industry incident data.

SPIFFE (Secure Production Identity Framework For Everyone) solves each of these problems with a fundamentally different model: workloads prove their identity using short-lived cryptographic certificates issued by a trusted authority that has verified the workload's identity through platform-level attestation. There is no secret to leak, rotation is automatic, and attestation ensures that only the legitimate workload can obtain credentials.

---

### SPIFFE and SVIDs

SPIFFE defines a standard for workload identity that is platform-agnostic and interoperable across clouds, orchestration systems, and environments.

#### SPIFFE ID Format

Every workload in a SPIFFE deployment is identified by a URI called a SPIFFE ID:

```
spiffe://{trust-domain}/{path}
```

The trust domain is a DNS name that represents an administrative boundary. The path is a hierarchical identifier that encodes meaningful information about the workload.

**Common path conventions:**

```
# Kubernetes workload — namespace and service account
spiffe://example.com/ns/prod/sa/payments-service

# Kubernetes workload — namespace, deployment, and version
spiffe://example.com/ns/prod/deployment/api-gateway/v2

# Batch job
spiffe://example.com/job/nightly-backup

# Host-based identity
spiffe://example.com/host/worker-03.internal

# Cloud VM
spiffe://example.com/aws/account/123456789012/region/us-east-1/instance/i-0abc123def456789

# CI/CD pipeline
spiffe://example.com/ci/github/org/myorg/repo/payments/branch/main
```

SPIFFE IDs are not secrets. They are identifiers. The cryptographic proof of identity is carried in the SVID (SPIFFE Verifiable Identity Document), not in the ID string itself.

#### X.509 SVID

An X.509 SVID is a standard X.509 certificate with these specific properties:

- **Subject Alternative Name (SAN):** A URI SAN containing the SPIFFE ID (e.g., `spiffe://example.com/ns/prod/sa/payments-service`)
- **Key Usage:** `digitalSignature` and `keyAgreement` (for key exchange)
- **Extended Key Usage:** `serverAuth` and `clientAuth` (enabling mTLS)
- **Short TTL:** Default 1 hour. The short lifetime bounds the window of compromise for any credential that leaks.
- **No static secret:** The private key never leaves the workload's memory. It is generated fresh for each SVID.

X.509 SVIDs are the preferred credential for service-to-service mTLS because they integrate transparently with TLS stacks. No application code change is required beyond pointing TLS configuration at the SVID files.

#### JWT SVID

A JWT SVID is a standard JWT with these properties:

```json
{
  "sub": "spiffe://example.com/ns/prod/sa/payments-service",
  "aud": ["spiffe://example.com/ns/prod/sa/order-service"],
  "exp": 1740000000,
  "iat": 1739996400,
  "iss": "https://vecta.example.com"
}
```

Key fields:
- **`sub`:** The SPIFFE ID of the workload
- **`aud`:** One or more audience identifiers (the intended recipient services)
- **`exp`:** Expiration — typically 1 hour from issuance
- **Signature:** RS256 or ES256 signed by the Vecta CA

JWT SVIDs are useful for HTTP-based authentication where mTLS is not available, for token exchange flows (exchanging a Kubernetes SA token for a Vecta JWT, then exchanging that for a cloud IAM token), and for authorization decisions where a service needs to verify the caller's SPIFFE identity without terminating TLS.

#### Workload API

The Workload API is a local UNIX domain socket (`/run/spiffe/workload.sock` by default) provided by the vecta-agent sidecar or DaemonSet. Applications retrieve SVIDs by connecting to this socket. The Workload API is:

- **Transparent to applications:** No API key, no secret, no configuration beyond the socket path
- **Streaming:** SVIDs are pushed to the application before expiry, enabling seamless rotation
- **Authenticated by the kernel:** Socket access is controlled by filesystem permissions — no network exposure

The agent handles all communication with the Vecta CA, certificate rotation, and trust bundle distribution. The application simply reads certificates from the socket and uses them.

---

### Vecta as SPIFFE CA

Vecta KMS acts as the SPIFFE Certificate Authority for your trust domain. It:

1. **Maintains the root CA** for the trust domain, stored in the KMS key store
2. **Issues SVIDs** signed by the intermediate CA, with TTLs configured per attestation policy
3. **Enforces attestation policies** — SVIDs are only issued after verifying the workload's platform identity
4. **Manages trust bundles** — the set of CA certificates that should be trusted in the domain, distributed to all workloads
5. **Federates with external SPIFFE authorities** — enabling cross-domain trust with other SPIFFE deployments

Default SVID TTL is 3600 seconds (1 hour). The vecta-agent renews SVIDs automatically when they reach 50% of their lifetime.

---

### Setup Walkthrough

#### Step 1: Configure Trust Domain

Create the trust domain in Vecta:

```bash
curl -s -X POST http://localhost:5173/svc/workload/workload-identity/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "trust_domain": "example.com",
    "default_svid_ttl_secs": 3600,
    "jwt_svid_ttl_secs": 3600,
    "enable_x509": true,
    "enable_jwt": true,
    "federation_enabled": false
  }'
```

Expected response:

```json
{
  "config": {
    "tenant_id": "root",
    "trust_domain": "example.com",
    "default_svid_ttl_secs": 3600,
    "jwt_svid_ttl_secs": 3600,
    "enable_x509": true,
    "enable_jwt": true,
    "federation_enabled": false,
    "ca_key_id": "ca-workload-identity-root",
    "updated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_001"
}
```

#### Step 2: Install vecta-agent

The vecta-agent can be deployed as:
- A **sidecar container** alongside each workload pod
- A **DaemonSet** running once per Kubernetes node (preferred for production)
- A **system service** on bare-metal or VM hosts

See the Kubernetes attestation section below for the complete DaemonSet manifest.

Basic agent configuration file (`/etc/vecta-agent/config.yaml`):

```yaml
server:
  address: "https://vecta.example.com"
  token_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"

workload_api:
  socket_path: "/run/spiffe/workload.sock"

trust_domain: "example.com"

attestor:
  type: "kubernetes"
  kubernetes:
    node_name_env: "MY_NODE_NAME"
    token_audience: "vecta-kms"
```

#### Step 3: Define Attestation Policies

Create attestation policies that map platform identities to SPIFFE IDs. See the [Attestation Policy Schema](#attestation-policy-schema) section for all fields.

#### Step 4: Configure Applications

Applications need only the socket path. Example in Go:

```go
import "github.com/spiffe/go-spiffe/v2/workloadapi"

source, err := workloadapi.NewX509Source(ctx,
    workloadapi.WithClientOptions(workloadapi.WithAddr("unix:/run/spiffe/workload.sock")),
)
```

For environments without a SPIFFE SDK, the agent also writes SVID files to disk:

```
/run/spiffe/svids/cert.pem      # PEM-encoded X.509 SVID certificate
/run/spiffe/svids/key.pem       # PEM-encoded private key
/run/spiffe/svids/bundle.pem    # Trust bundle (CA certificates)
```

#### Step 5: Test with svid-tool

```bash
# Fetch the current X.509 SVID
svid-tool fetch x509 --socket /run/spiffe/workload.sock

# Fetch a JWT SVID for a specific audience
svid-tool fetch jwt \
  --socket /run/spiffe/workload.sock \
  --audience "spiffe://example.com/ns/prod/sa/order-service"

# Display decoded SVID contents
svid-tool show x509 --socket /run/spiffe/workload.sock
```

---

### Kubernetes Attestation

Kubernetes attestation is the most common deployment pattern. The vecta-agent verifies workload identity using the Kubernetes Service Account Token Projection, which provides a cryptographically verifiable pod identity token.

#### How Kubernetes Attestation Works

1. A pod starts on a Kubernetes node
2. The projected service account token is mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`
3. The vecta-agent on the node reads this token and sends it to Vecta KMS
4. Vecta KMS calls the Kubernetes TokenReview API to verify the token
5. The TokenReview response includes the pod's namespace and service account
6. Vecta matches the pod against an attestation policy
7. If the policy matches, Vecta issues an SVID with the SPIFFE ID from the policy template

#### Production DaemonSet Manifest

```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vecta-agent
  namespace: vecta-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vecta-agent
rules:
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["pods", "nodes"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vecta-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: vecta-agent
subjects:
  - kind: ServiceAccount
    name: vecta-agent
    namespace: vecta-system
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: vecta-agent
  namespace: vecta-system
  labels:
    app: vecta-agent
spec:
  selector:
    matchLabels:
      app: vecta-agent
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: vecta-agent
    spec:
      serviceAccountName: vecta-agent
      hostPID: false
      hostNetwork: false
      tolerations:
        - key: "node-role.kubernetes.io/control-plane"
          operator: "Exists"
          effect: "NoSchedule"
      containers:
        - name: vecta-agent
          image: vecta/agent:latest
          imagePullPolicy: Always
          args:
            - "--config=/etc/vecta-agent/config.yaml"
          env:
            - name: MY_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: MY_POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          ports:
            - name: workload-api
              containerPort: 8081
              protocol: TCP
            - name: health
              containerPort: 8082
              protocol: TCP
          volumeMounts:
            - name: config
              mountPath: /etc/vecta-agent
              readOnly: true
            - name: workload-socket-dir
              mountPath: /run/spiffe
            - name: agent-token
              mountPath: /var/run/agent-token
              readOnly: true
          livenessProbe:
            httpGet:
              path: /healthz
              port: health
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /readyz
              port: health
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: "50m"
              memory: "64Mi"
            limits:
              cpu: "200m"
              memory: "256Mi"
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
      volumes:
        - name: config
          configMap:
            name: vecta-agent-config
        - name: workload-socket-dir
          hostPath:
            path: /run/spiffe
            type: DirectoryOrCreate
        - name: agent-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 7200
                  audience: "vecta-kms"
```

#### Pod Annotation for Custom SPIFFE IDs

Override the SPIFFE ID for a specific pod using annotations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: payments-api
  namespace: prod
  annotations:
    vecta.io/spiffe-id: "spiffe://example.com/ns/prod/sa/payments-service"
    vecta.io/svid-ttl: "1800"
```

The annotation value supports template variables resolved at issuance time:
- `{{.Namespace}}` — Kubernetes namespace
- `{{.ServiceAccount}}` — Service account name
- `{{.PodName}}` — Pod name
- `{{.NodeName}}` — Node name

Default template (when no annotation is set): `spiffe://{{.TrustDomain}}/ns/{{.Namespace}}/sa/{{.ServiceAccount}}`

---

### AWS EC2 Attestation

AWS EC2 attestation uses the Instance Identity Document (IID) available from the EC2 Instance Metadata Service (IMDS). The IID is a JSON document signed by AWS that proves the instance's identity, account, region, and AMI.

#### Attestation Flow

1. The vecta-agent on the EC2 instance calls `http://169.254.169.254/latest/dynamic/instance-identity/document` to retrieve the IID
2. It also retrieves the IID signature from `http://169.254.169.254/latest/dynamic/instance-identity/signature`
3. The agent sends both to Vecta KMS
4. Vecta verifies the IID signature against the AWS certificate for the region
5. Vecta extracts the instance ID, account ID, region, AMI ID, and IAM role
6. The policy conditions are evaluated
7. If matched, Vecta issues an SVID

#### Attestor Configuration

```json
{
  "name": "aws-prod-attestor",
  "attestorType": "aws_iid",
  "spiffeIdTemplate": "spiffe://example.com/aws/account/{{.AccountID}}/role/{{.IAMRole}}",
  "conditions": {
    "accountId": "123456789012",
    "region": "^us-(east|west)-[12]$",
    "allowedAmiIds": [
      "ami-0abcdef1234567890",
      "ami-0fedcba9876543210"
    ],
    "iamRolePattern": "^arn:aws:iam::123456789012:instance-profile/prod-.*$",
    "instanceTags": {
      "Environment": "production",
      "Service": ".*"
    }
  },
  "maxSvidTtl": 3600,
  "allowedSvidTypes": ["x509", "jwt"]
}
```

> **Security Note:** Always specify `allowedAmiIds` in production environments. Without this constraint, any instance in the account with the matching IAM role can obtain an SVID. Specifying known-good AMI IDs ensures only properly built machine images can authenticate.

#### IAM Role to SPIFFE ID Mapping

```json
{
  "conditions": {
    "iamRolePattern": "^arn:aws:iam::123456789012:instance-profile/svc-(?P<ServiceName>[a-z-]+)$"
  },
  "spiffeIdTemplate": "spiffe://example.com/aws/svc/{{.NamedCapture.ServiceName}}"
}
```

Named capture groups from the `iamRolePattern` regex are available in the SPIFFE ID template via `{{.NamedCapture.<GroupName>}}`.

---

### GCP, Docker, Unix, and TPM Attestors

#### GCP Attestor

```json
{
  "name": "gcp-prod-attestor",
  "attestorType": "gcp_iit",
  "spiffeIdTemplate": "spiffe://example.com/gcp/project/{{.ProjectID}}/zone/{{.Zone}}/instance/{{.InstanceName}}",
  "conditions": {
    "projectId": "my-project-123456",
    "zonePattern": "^us-central1-.*$",
    "serviceAccountPattern": "^svc-.*@my-project-123456.iam.gserviceaccount.com$"
  },
  "maxSvidTtl": 3600
}
```

#### Docker Attestor

```json
{
  "name": "docker-dev-attestor",
  "attestorType": "docker",
  "spiffeIdTemplate": "spiffe://example.com/docker/image/{{.ImageName}}",
  "conditions": {
    "imageNamePattern": "^registry.example.com/.*:prod$",
    "labelMatches": {
      "com.example.env": "production"
    },
    "allowedUsers": ["1000", "1001"]
  },
  "maxSvidTtl": 1800
}
```

#### Unix Process Attestor

```json
{
  "name": "unix-service-attestor",
  "attestorType": "unix",
  "spiffeIdTemplate": "spiffe://example.com/unix/uid/{{.UID}}",
  "conditions": {
    "uid": "1500",
    "gid": "1500",
    "binarySha256": "sha256:a1b2c3d4e5f6..."
  },
  "maxSvidTtl": 3600
}
```

> **Security Note:** The `binarySha256` condition pins the attestation to a specific binary. Include this in production to prevent attesting a modified or replaced binary. Update the hash as part of your deployment pipeline.

#### TPM 2.0 Attestor

```json
{
  "name": "tpm-server-attestor",
  "attestorType": "tpm2",
  "spiffeIdTemplate": "spiffe://example.com/tpm/ek/{{.EKCertFingerprint}}",
  "conditions": {
    "allowedEKCertIssuers": [
      "CN=Infineon OPTIGA(TM) TPM 2.0 ECC CA 059"
    ],
    "allowedPCRValues": {
      "0": "sha256:d4e5f6...",
      "1": "sha256:a1b2c3..."
    }
  },
  "maxSvidTtl": 86400
}
```

---

### Attestation Policy Schema

#### Complete Schema

```json
{
  "name": "k8s-prod-policy",
  "description": "Issues SVIDs for production Kubernetes workloads",
  "attestorType": "kubernetes",
  "spiffeIdTemplate": "spiffe://example.com/ns/{{.Namespace}}/sa/{{.ServiceAccount}}",
  "conditions": {
    "namespace": "^(prod|staging)$",
    "serviceaccount": ".*",
    "nodeLabels": {
      "node-role": "worker"
    },
    "podLabels": {
      "app.kubernetes.io/managed-by": "helm"
    }
  },
  "maxSvidTtl": 3600,
  "minSvidTtl": 300,
  "allowedSvidTypes": ["x509", "jwt"],
  "jwtAudiences": ["spiffe://example.com"],
  "enabled": true,
  "priority": 100,
  "labels": {
    "env": "production",
    "team": "platform"
  }
}
```

#### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique name for this policy within the tenant. Must be 1–128 characters. |
| `description` | string | no | Human-readable description of the policy's purpose. |
| `attestorType` | string | yes | Platform attestor. One of: `kubernetes`, `aws_iid`, `gcp_iit`, `docker`, `unix`, `tpm2`, `azure_msi`. |
| `spiffeIdTemplate` | string | yes | Go template for the SPIFFE ID. Template variables are attestor-specific. Must produce a valid `spiffe://` URI. |
| `conditions` | object | yes | Attestor-specific conditions (logical AND). Regular expressions follow RE2 syntax. |
| `maxSvidTtl` | integer | no | Maximum SVID lifetime in seconds. Default: 3600. Range: 60–86400. |
| `minSvidTtl` | integer | no | Minimum SVID lifetime a workload may request. Default: 60. |
| `allowedSvidTypes` | array[string] | no | Which SVID types this policy may issue. Values: `x509`, `jwt`. Default: both. |
| `jwtAudiences` | array[string] | no | Allowed JWT audience values. If set, JWT SVIDs may only be issued for audiences in this list. |
| `enabled` | boolean | no | Whether this policy is active. Default: true. |
| `priority` | integer | no | Policy evaluation order. Higher values are evaluated first. Default: 0. |
| `labels` | object | no | Arbitrary key-value metadata for grouping and filtering. |

---

### Token Exchange — OAuth 2.0 RFC 8693

Vecta implements OAuth 2.0 Token Exchange (RFC 8693) to bridge workload identity with cloud IAM systems.

#### Pattern 1: Kubernetes SA Token → Vecta JWT SVID

```bash
K8S_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

curl -s -X POST http://localhost:5173/svc/workload/workload-identity/token/exchange \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\": \"$K8S_TOKEN\",
    \"subject_token_type\": \"urn:ietf:params:oauth:token-type:jwt\",
    \"requested_token_type\": \"urn:ietf:params:oauth:token-type:jwt\",
    \"audience\": \"spiffe://example.com/ns/prod/sa/order-service\",
    \"tenant_id\": \"root\"
  }"
```

Response:

```json
{
  "result": {
    "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
    "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_type": "Bearer",
    "expires_in": 3600,
    "spiffe_id": "spiffe://example.com/ns/prod/sa/payments-service"
  },
  "request_id": "req_010"
}
```

#### Pattern 2: Vecta JWT SVID → AWS STS AssumeRoleWithWebIdentity

```bash
VECTA_JWT=$(curl -s -X POST http://localhost:5173/svc/workload/workload-identity/issue \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{"svid_type": "jwt", "audience": "sts.amazonaws.com", "tenant_id": "root"}' \
  | jq -r '.result.jwt_svid')

aws sts assume-role-with-web-identity \
  --role-arn "arn:aws:iam::123456789012:role/payments-service-role" \
  --role-session-name "payments-service" \
  --web-identity-token "$VECTA_JWT" \
  --duration-seconds 3600
```

#### Pattern 3: Vecta JWT SVID → GCP Access Token

```bash
GCP_TOKEN=$(curl -s -X POST \
  "https://sts.googleapis.com/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
&audience=//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/my-pool/providers/vecta\
&scope=https://www.googleapis.com/auth/cloud-platform\
&requested_token_type=urn:ietf:params:oauth:token-type:access_token\
&subject_token_type=urn:ietf:params:oauth:token-type:jwt\
&subject_token=$VECTA_JWT" \
  | jq -r '.access_token')
```

#### Pattern 4: Vecta JWT SVID → Azure Managed Identity Token

```bash
curl -s -X POST \
  "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$AZURE_CLIENT_ID\
&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer\
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
&client_assertion=$VECTA_JWT\
&scope=https://vault.azure.net/.default\
&requested_token_use=on_behalf_of"
```

> **Tip:** Azure Federated Identity Credentials must be configured in the Azure portal under the app registration for your service, pointing to your Vecta OIDC issuer and with the workload's SPIFFE ID as the subject claim.

---

### Workload Service Endpoints

All workload endpoints use the service prefix `/svc/workload`. All requests require `Authorization: Bearer $TOKEN` and `X-Tenant-ID: root`.

#### GET /svc/workload/workload-identity/settings

```bash
curl -s "http://localhost:5173/svc/workload/workload-identity/settings?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "config": {
    "tenant_id": "root",
    "trust_domain": "example.com",
    "default_svid_ttl_secs": 3600,
    "jwt_svid_ttl_secs": 3600,
    "enable_x509": true,
    "enable_jwt": true,
    "federation_enabled": false,
    "ca_key_id": "ca-workload-identity-root",
    "oidc_issuer": "https://vecta.example.com",
    "jwks_uri": "https://vecta.example.com/.well-known/jwks.json",
    "updated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_100"
}
```

#### POST /svc/workload/workload-identity/registrations

```bash
curl -s -X POST \
  "http://localhost:5173/svc/workload/workload-identity/registrations?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "payments-service",
    "spiffe_id": "spiffe://example.com/ns/prod/sa/payments-service",
    "attestor_type": "kubernetes",
    "attestation_policy_id": "k8s-prod-policy",
    "svid_ttl_secs": 3600,
    "allowed_svid_types": ["x509", "jwt"],
    "key_ids": ["key-payments-encryption"]
  }'
```

Response:

```json
{
  "item": {
    "id": "reg_a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "tenant_id": "root",
    "name": "payments-service",
    "spiffe_id": "spiffe://example.com/ns/prod/sa/payments-service",
    "attestor_type": "kubernetes",
    "status": "active",
    "created_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_101"
}
```

#### POST /svc/workload/workload-identity/issue

Issues an SVID after attestation.

```bash
curl -s -X POST \
  "http://localhost:5173/svc/workload/workload-identity/issue?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "svid_type": "x509",
    "spiffe_id": "spiffe://example.com/ns/prod/sa/payments-service",
    "ttl_secs": 3600,
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQY...\n-----END PUBLIC KEY-----"
  }'
```

Response:

```json
{
  "result": {
    "svid_type": "x509",
    "spiffe_id": "spiffe://example.com/ns/prod/sa/payments-service",
    "x509_svid": {
      "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIICpDCCAYwCCQD...\n-----END CERTIFICATE-----",
      "bundle_pem": "-----BEGIN CERTIFICATE-----\nMIIDCzCCAfOgAwIB...\n-----END CERTIFICATE-----",
      "not_before": "2026-03-23T00:00:00Z",
      "not_after": "2026-03-23T01:00:00Z"
    },
    "expires_at": "2026-03-23T01:00:00Z"
  },
  "request_id": "req_102"
}
```

#### POST /svc/workload/workload-identity/token/exchange

```bash
curl -s -X POST \
  "http://localhost:5173/svc/workload/workload-identity/token/exchange?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<kubernetes-sa-token>",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "audience": "spiffe://example.com/ns/prod/sa/order-service",
    "tenant_id": "root"
  }'
```

#### GET /svc/workload/workload-identity/graph

```bash
curl -s "http://localhost:5173/svc/workload/workload-identity/graph?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "graph": {
    "nodes": [
      {
        "id": "spiffe://example.com/ns/prod/sa/payments-service",
        "type": "workload",
        "name": "payments-service",
        "status": "active",
        "last_seen": "2026-03-23T00:00:00Z"
      },
      {
        "id": "key-payments-encryption",
        "type": "key",
        "name": "payments-encryption",
        "algorithm": "AES-256-GCM"
      }
    ],
    "edges": [
      {
        "from": "spiffe://example.com/ns/prod/sa/payments-service",
        "to": "key-payments-encryption",
        "permissions": ["encrypt", "decrypt"],
        "granted_via": "policy:workload-key-access"
      }
    ]
  },
  "request_id": "req_105"
}
```

---

## Section 2: Confidential Computing and TEE Attestation

### What is Confidential Computing

Confidential computing uses CPU-enforced hardware isolation to create a Trusted Execution Environment (TEE): a protected region where code runs and data is processed with encrypted memory that is inaccessible to the host operating system, hypervisor, and cloud provider administrators.

Even if a cloud operator has full root access to the physical host, they cannot read or tamper with memory inside a TEE. This is enforced by the CPU hardware itself, not by software controls that can be bypassed.

**The key properties of a TEE are:**

- **Memory encryption:** All TEE memory is encrypted with a key that only the CPU holds. The hypervisor and host OS see only ciphertext.
- **Isolation:** The TEE cannot be read or modified by software outside it, including the host kernel.
- **Attestation:** The CPU generates a cryptographically signed report proving: (1) what software is running, measured as a hash of its code and configuration; (2) that the hardware is genuine (not a simulator); and (3) the security version of the firmware and software stack.

**Why this matters for key management:**

In a standard KMS deployment, if an attacker compromises the host OS or hypervisor (through an insider threat, supply chain attack, or misconfiguration), they can potentially extract keys from memory. With TEE attestation, the KMS can enforce that a key is only ever decrypted or used inside a verified TEE running a known, trusted application image — even if the host is compromised.

### Attested Key Release Pattern

The attested key release pattern ensures a cryptographic key is only released to a workload that can prove:

1. It is running inside a genuine hardware TEE (not a simulator)
2. The software image running inside the TEE matches an expected measurement (hash)
3. The request is fresh (not a replayed old attestation report)

**Why measurement matters more than identity:**

Workload identity (SPIFFE/SVID) proves *who* is requesting a key. TEE attestation proves *what code* is running. These are orthogonal properties. A legitimate service account could be compromised and used by malicious code. TEE attestation ensures the key is only released to a specific, verified version of the application binary.

**Nonce-based anti-replay:**

Attestation reports are not bound to a specific request by default. An attacker could record a valid attestation report and replay it hours later. Vecta's attested key release requires a nonce — a random value generated fresh for each release request — to be embedded in the TEE's attestation report (in the `REPORT_DATA` field). Vecta verifies that the nonce in the report matches the nonce it issued for that specific request, preventing replay attacks.

---

### Intel TDX

Intel Trust Domain Extensions (TDX) isolates entire virtual machines as hardware-protected Trust Domains (TDs). Unlike SGX (which isolates individual processes), TDX isolates a full guest VM including its kernel and all processes.

#### TDX Measurement Registers

TDX maintains several measurement registers that are included in the attestation quote:

| Register | Description | What It Measures |
|----------|-------------|-----------------|
| `MRTD` | Measurement of the Trust Domain | Initial contents of the TD (firmware + kernel) at launch time |
| `MRCONFIGID` | Configuration identity | TD configuration supplied by the host |
| `MROWNER` | TD owner identity | Identity of the entity that owns/controls the TD |
| `MROWNERCONFIG` | Owner-supplied configuration | Additional owner-provided configuration |
| `RTMR0` | Runtime Measurement Register 0 | BIOS/UEFI extensions measured during boot |
| `RTMR1` | Runtime Measurement Register 1 | Host OS kernel and initrd |
| `RTMR2` | Runtime Measurement Register 2 | OS configuration and drivers |
| `RTMR3` | Runtime Measurement Register 3 | Application-layer measurements |

For attested key release, `MRTD` is typically the most important: it captures the exact version of the VM image. RTMRs capture runtime state that evolves during boot.

#### REPORT_DATA Field

The 64-byte `REPORT_DATA` field in a TDX attestation report is controlled by the TD software. Vecta uses this field to bind the attestation report to a specific nonce:

```
REPORT_DATA = SHA256(challenge_nonce || request_id) || 0x00...  (zero-padded to 64 bytes)
```

#### TDX Quote Structure

A TDX attestation quote contains:
- **Quote Header:** Version, attestation key type, TEE type
- **TDX Report Body:** All measurement registers, REPORT_DATA, TD attributes, XFAM
- **Quote Signature Data:** ECDSA signature by the Attestation Key (AK)
- **AK Certificate Chain:** AK certificate → PCK certificate → Intel CA

Vecta verifies the quote by:
1. Verifying the ECDSA signature on the quote body
2. Verifying the PCK certificate chain up to the Intel Root CA
3. Checking the PCK certificate against the Intel PCS (Platform Certification Service) or local DCAP cache
4. Verifying `MRTD` matches the expected value in the attested key release policy
5. Verifying `REPORT_DATA` contains the SHA256 of the expected nonce

---

### AMD SEV-SNP

AMD Secure Encrypted Virtualization — Secure Nested Paging (SEV-SNP) protects guest VM memory with hardware-enforced encrypted pages, and uses Nested Page Table (NPT) integrity to prevent the hypervisor from remapping encrypted guest pages.

#### SNP Report Fields

An SNP attestation report contains:

| Field | Size | Description |
|-------|------|-------------|
| `VERSION` | 4 bytes | Report format version |
| `GUEST_SVN` | 4 bytes | Guest Security Version Number (monotonically increasing) |
| `POLICY` | 8 bytes | Guest policy flags (debug allowed, SMT allowed, etc.) |
| `FAMILY_ID` | 16 bytes | Family identifier of the guest image |
| `IMAGE_ID` | 16 bytes | Image identifier of the guest image |
| `VMPL` | 4 bytes | VM Privilege Level that requested the report |
| `SIGNATURE_ALGO` | 4 bytes | Algorithm used to sign the report (ECDSA P-384 with SHA-384) |
| `CURRENT_TCB` | 8 bytes | Current Trusted Computing Base version |
| `PLATFORM_INFO` | 8 bytes | Platform configuration flags |
| `MEASUREMENT` | 48 bytes | SHA-384 hash of the initial guest memory contents |
| `HOST_DATA` | 32 bytes | Host-provided data included in the report |
| `ID_KEY_DIGEST` | 48 bytes | SHA-384 of the ID key used to sign the guest launch |
| `AUTHOR_KEY_DIGEST` | 48 bytes | SHA-384 of the author key |
| `REPORT_ID` | 32 bytes | Unique identifier for this report |
| `REPORT_ID_MA` | 32 bytes | Report ID of the migration agent |
| `REPORTED_TCB` | 8 bytes | TCB version used to sign the report |
| `CHIP_ID` | 64 bytes | Unique identifier for the AMD processor chip |
| `REPORT_DATA` | 64 bytes | Guest-supplied data (nonce goes here) |
| `SIGNATURE` | 512 bytes | ECDSA P-384 signature |

The `MEASUREMENT` field is the primary integrity measurement: a SHA-384 hash of the guest's initial memory state, essentially a fingerprint of the software image.

#### VCEK Trust Chain

AMD uses a Versioned Chip Endorsement Key (VCEK) hierarchy:

```
AMD Root Key (ARK)
    └── AMD SEV Key (ASK)
            └── Versioned Chip Endorsement Key (VCEK)
                    └── Signs SNP attestation reports
```

The VCEK is unique per chip and per TCB version. Vecta retrieves VCEK certificates from the AMD Key Distribution Service (KDS):

```
https://kds.amd.com/vcek/<platform>/<chip_id>?blSPL=<bl>&teeSPL=<tee>&snpSPL=<snp>&ucodeSPL=<ucode>
```

#### Vecta Policy for SEV-SNP

```json
{
  "name": "sev-snp-ml-inference",
  "teeType": "sev_snp",
  "measurements": {
    "MEASUREMENT": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "POLICY": "0x30000",
    "GUEST_SVN": "5"
  },
  "allowedKeyIds": ["key-ml-model-weights"],
  "maxKeyAgeSecs": 3600,
  "requireFreshNonce": true,
  "nonceTimeWindowSecs": 300,
  "allowedOperations": ["decrypt"]
}
```

---

### AWS Nitro Enclaves

AWS Nitro Enclaves are isolated compute environments created from EC2 instances. They have no persistent storage, no external network access, and no interactive access. The only communication channel is a local vsock connection to the parent EC2 instance.

This isolation model makes Nitro Enclaves an excellent choice for processing sensitive data: even a fully compromised parent EC2 instance cannot read enclave memory or intercept enclave network traffic (because there is no network).

#### Nitro Attestation Document

The Nitro attestation document is a CBOR-encoded, COSE_Sign1-signed structure:

```
COSE_Sign1 {
  protected: {algorithm: ES384},
  payload: {
    module_id: "i-0abc123def456789-enc01234567890abcdef",
    timestamp: 1740000000000,
    digest: "SHA384",
    pcrs: {
      0: <96-hex-char SHA384 hash>,   # Image measurement
      1: <96-hex-char SHA384 hash>,   # Kernel + boot ramdisk
      2: <96-hex-char SHA384 hash>,   # Application
      3: <96-hex-char SHA384 hash>,   # IAM role ARN
      4: <96-hex-char SHA384 hash>,   # Instance ID document
      8: <96-hex-char SHA384 hash>    # User-provided data
    },
    certificate: <DER-encoded attestation cert>,
    cabundle: [<DER-encoded CA certs>],
    public_key: <DER-encoded ephemeral public key>,
    user_data: <bytes: nonce goes here>
  },
  signature: <ES384 signature>
}
```

#### PCR Register Reference

| PCR | Description | Stability |
|-----|-------------|-----------|
| PCR0 | Hash of the enclave image (EIF file) | Changes only when the image is rebuilt |
| PCR1 | Hash of the Linux kernel and bootstrap ramdisk | Changes on kernel update |
| PCR2 | Hash of the user application and its dependencies | Changes on app update |
| PCR3 | Hash of the IAM role ARN attached to the parent instance | Changes on role change |
| PCR4 | Hash of the parent instance ID | Changes on instance replacement |
| PCR8 | Hash of the signing certificate used to sign the EIF | Changes on certificate rotation |

> **Tip:** In attested key release policies, PCR0 is the most reliable measurement for locking a key release to a specific application version. PCR3 lets you additionally constrain which IAM role (and therefore which AWS account) can release the key.

#### Nonce in Nitro

The `user_data` field in the attestation document carries the nonce. The enclave application sets `user_data` when calling the `NSM_GetAttestationDoc` API:

```python
import nsm
import json

# nonce received from Vecta
challenge = b"8a3f2b1c9d7e4f6a..."  # 32 hex bytes

# Generate attestation document with nonce in user_data
doc = nsm.get_attestation_doc(
    user_data=challenge,
    public_key=ephemeral_public_key_der
)
```

---

### Azure Confidential VMs

Azure Confidential VMs run AMD SEV-SNP guests and use Microsoft Azure Attestation (MAA) as the attestation service. The attestation flow differs from AMD KDS because MAA acts as an intermediary that verifies the SNP report and issues a signed JWT.

#### Azure Confidential VM Attestation Flow

1. The CVM requests an SNP attestation report from the vTPM (virtual TPM)
2. The CVM sends the SNP report to the MAA endpoint for the region: `https://<region>.attest.azure.net`
3. MAA verifies the SNP report against AMD's certificate chain
4. MAA issues a signed JWT (the "MAA token") containing:
   - `x-ms-attestation-type`: "sevsnpvm"
   - `x-ms-compliance-status`: "azure-compliant-uvm"
   - `x-ms-runtime`: guest runtime claims
   - `x-ms-tee`: TEE-specific claims including the SNP measurement
   - `x-ms-sevsnpvm-guestsvn`: Guest SVN
   - `x-ms-sevsnpvm-launchmeasurement`: The SNP `MEASUREMENT` value

5. The CVM sends the MAA JWT to Vecta instead of the raw SNP report
6. Vecta verifies the MAA JWT signature against MAA's JWKS endpoint: `https://<region>.attest.azure.net/certs`
7. Vecta extracts claims from the MAA JWT and evaluates the attested key release policy

#### Vecta Policy for Azure CVM

```json
{
  "name": "azure-cvm-database",
  "teeType": "azure_tdx",
  "measurements": {
    "launchMeasurement": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
    "complianceStatus": "azure-compliant-uvm",
    "guestSvn": "1"
  },
  "attestationProvider": "microsoft_maa",
  "maaEndpoint": "https://sharedeus2.eus2.attest.azure.net",
  "allowedKeyIds": ["key-db-master"],
  "requireFreshNonce": true,
  "nonceTimeWindowSecs": 300,
  "allowedOperations": ["decrypt", "unwrap"]
}
```

---

### Attested Key Release Policy Schema

The attested key release policy defines the exact conditions under which Vecta will release a key to a TEE.

#### Complete Schema

```json
{
  "name": "nitro-payment-processor",
  "description": "Payment processing key released only to verified Nitro enclave",
  "teeType": "nitro",
  "measurements": {
    "PCR0": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "PCR1": "*",
    "PCR2": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "PCR3": "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1"
  },
  "allowedKeyIds": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
  "maxKeyAgeSecs": 3600,
  "requireFreshNonce": true,
  "nonceTimeWindowSecs": 300,
  "allowedOperations": ["decrypt", "sign"],
  "keyWrappingEnabled": true,
  "keyWrappingAlgorithm": "RSA-OAEP-256",
  "enabled": true,
  "labels": {
    "team": "payments",
    "compliance": "pci-dss"
  }
}
```

#### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique policy name within the tenant. 1–128 characters. |
| `description` | string | no | Human-readable description of the policy's purpose. |
| `teeType` | string | yes | The TEE technology. One of: `nitro`, `tdx`, `sev_snp`, `azure_tdx`, `azure_snp`. |
| `measurements` | object | yes | Map of register name to expected value. Use `"*"` to accept any value for a register (wildcard). All specified non-wildcard values must match exactly. Values are hex-encoded. |
| `allowedKeyIds` | array[string] | yes | List of key IDs that may be released under this policy. Use `["*"]` to allow any key (not recommended). |
| `maxKeyAgeSecs` | integer | no | Maximum age of the key material in seconds. Keys older than this are not released. Default: 86400. |
| `requireFreshNonce` | boolean | no | Whether a fresh nonce (issued by Vecta within `nonceTimeWindowSecs`) must be present in the attestation report. Default: true. Setting to false disables anti-replay protection — do not do this in production. |
| `nonceTimeWindowSecs` | integer | no | Maximum age of the nonce in seconds. Requests with nonces older than this are rejected. Default: 300. |
| `allowedOperations` | array[string] | no | Operations the released key may perform. Values: `encrypt`, `decrypt`, `sign`, `verify`, `wrap`, `unwrap`. Default: all operations permitted by the key's own policy. |
| `keyWrappingEnabled` | boolean | no | Whether the released key material is wrapped (encrypted) under the TEE's ephemeral public key before transmission. Default: true. Should only be false for testing. |
| `keyWrappingAlgorithm` | string | no | Algorithm for wrapping the key. One of: `RSA-OAEP-256`, `RSA-OAEP-512`, `ECDH-ES`. Default: `RSA-OAEP-256`. |
| `enabled` | boolean | no | Whether this policy is active. Default: true. |
| `labels` | object | no | Arbitrary key-value metadata. |

---

### Full Attested Key Release Flow

The following is the complete attested key release flow for an AWS Nitro Enclave. The same pattern applies to other TEE types with different attestation document formats.

#### Step 1: Enclave Generates an Ephemeral Key Pair

The enclave generates an ephemeral RSA key pair. The public key will be embedded in the attestation report so Vecta can wrap the released key material under it. Only the enclave holds the private key.

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate ephemeral RSA-2048 key pair inside the enclave
ephemeral_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
ephemeral_public_key_der = ephemeral_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

#### Step 2: Request a Challenge Nonce from Vecta

```bash
curl -s -X POST \
  "http://localhost:5173/svc/confidential/confidential/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "action": "get_nonce",
    "policy_id": "nitro-payment-processor"
  }'
```

Response:

```json
{
  "result": {
    "nonce": "8a3f2b1c9d7e4f6a5b2c3d1e0f9a8b7c",
    "nonce_id": "nonce_xyz789",
    "expires_at": "2026-03-23T00:05:00Z"
  },
  "request_id": "req_200"
}
```

#### Step 3: Enclave Generates Attestation Report with Nonce

The enclave embeds the nonce (and its ephemeral public key) in the attestation document:

```python
import nsm
import base64

nonce_bytes = bytes.fromhex("8a3f2b1c9d7e4f6a5b2c3d1e0f9a8b7c")

# Get Nitro attestation document
# The NSM API embeds public_key in the document and nonce in user_data
attestation_doc_bytes = nsm.get_attestation_doc(
    user_data=nonce_bytes,
    public_key=ephemeral_public_key_der,
    nonce=None  # user_data is used as the nonce field
)

attestation_doc_b64 = base64.b64encode(attestation_doc_bytes).decode()
```

#### Step 4: Send Attestation Evidence to Vecta

```bash
curl -s -X POST \
  "http://localhost:5173/svc/confidential/confidential/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"root\",
    \"action\": \"key_release\",
    \"policy_id\": \"nitro-payment-processor\",
    \"key_id\": \"3fa85f64-5717-4562-b3fc-2c963f66afa6\",
    \"tee_type\": \"nitro\",
    \"nonce_id\": \"nonce_xyz789\",
    \"attestation_evidence\": {
      \"type\": \"nitro_document\",
      \"document\": \"$ATTESTATION_DOC_B64\"
    },
    \"requested_operations\": [\"decrypt\"]
  }"
```

#### Step 5: Vecta Verifies and Returns Wrapped Key

Vecta performs the following verification:
1. Decodes the CBOR/COSE_Sign1 attestation document
2. Verifies the ECDSA signature using the Nitro CA certificate chain (pinned in Vecta's trust store)
3. Extracts PCR values and verifies each non-wildcard value against the policy
4. Extracts `user_data` and verifies it matches the nonce issued for `nonce_xyz789`
5. Verifies the nonce was issued within `nonceTimeWindowSecs` seconds
6. Extracts the enclave's `public_key` from the attestation document
7. Retrieves the key material for `3fa85f64-5717-4562-b3fc-2c963f66afa6`
8. Wraps the key material under the enclave's ephemeral public key using RSA-OAEP-256
9. Returns the wrapped key

Response:

```json
{
  "result": {
    "decision": "allow",
    "policy_id": "nitro-payment-processor",
    "key_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "wrapped_key_material": "base64-encoded-RSA-OAEP-256-wrapped-key-bytes...",
    "wrapping_algorithm": "RSA-OAEP-256",
    "key_algorithm": "AES-256-GCM",
    "allowed_operations": ["decrypt"],
    "verified_measurements": {
      "PCR0": "matched",
      "PCR1": "wildcard",
      "PCR2": "matched",
      "PCR3": "matched"
    },
    "release_id": "release_abc123",
    "expires_at": "2026-03-23T01:00:00Z"
  },
  "request_id": "req_201"
}
```

#### Step 6: Enclave Decrypts the Key Material

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

wrapped_key = base64.b64decode(response["result"]["wrapped_key_material"])

# Decrypt using the ephemeral private key (never leaves the enclave)
aes_key_bytes = ephemeral_private_key.decrypt(
    wrapped_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# aes_key_bytes is now the raw AES-256-GCM key material
# Use it for decryption operations inside the enclave
```

> **Security Note:** The ephemeral private key never leaves the enclave memory. The wrapped key material sent over the network is useless without the private key. Even if the network traffic is captured, the attacker cannot unwrap the key without compromising the enclave — which requires breaking TEE isolation.

---

### Confidential Service Endpoints

Service prefix: `/svc/confidential/confidential`. All requests require `Authorization: Bearer $TOKEN` and `X-Tenant-ID: root`.

#### GET /svc/confidential/confidential/policy

Returns the tenant's global confidential compute policy settings.

```bash
curl -s "http://localhost:5173/svc/confidential/confidential/policy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "config": {
    "tenant_id": "root",
    "enabled": true,
    "default_action": "deny",
    "allowed_tee_types": ["nitro", "tdx", "sev_snp", "azure_tdx"],
    "require_nonce": true,
    "max_nonce_age_secs": 300,
    "audit_all_releases": true,
    "updated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_300"
}
```

#### PUT /svc/confidential/confidential/policy

```bash
curl -s -X PUT \
  "http://localhost:5173/svc/confidential/confidential/policy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "default_action": "deny",
    "allowed_tee_types": ["nitro", "tdx", "sev_snp"],
    "require_nonce": true,
    "max_nonce_age_secs": 300,
    "audit_all_releases": true
  }'
```

#### POST /svc/confidential/confidential/evaluate

The core attested key release endpoint. Handles both nonce issuance and key release.

**Sub-action: get_nonce**

```bash
curl -s -X POST \
  "http://localhost:5173/svc/confidential/confidential/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "action": "get_nonce",
    "policy_id": "nitro-payment-processor"
  }'
```

**Sub-action: key_release (Nitro)**

```bash
curl -s -X POST \
  "http://localhost:5173/svc/confidential/confidential/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "action": "key_release",
    "policy_id": "nitro-payment-processor",
    "key_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "tee_type": "nitro",
    "nonce_id": "nonce_xyz789",
    "attestation_evidence": {
      "type": "nitro_document",
      "document": "<base64-encoded CBOR/COSE_Sign1 document>"
    },
    "requested_operations": ["decrypt"]
  }'
```

**Sub-action: key_release (TDX)**

```bash
curl -s -X POST \
  "http://localhost:5173/svc/confidential/confidential/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "action": "key_release",
    "policy_id": "tdx-inference-server",
    "key_id": "key-model-weights",
    "tee_type": "tdx",
    "nonce_id": "nonce_abc123",
    "attestation_evidence": {
      "type": "tdx_quote",
      "quote": "<base64-encoded TDX quote>",
      "collateral": {
        "pck_cert_chain": "<base64-encoded PEM chain>",
        "tcb_info": "<base64-encoded TCBInfo JSON>",
        "qe_identity": "<base64-encoded QEIdentity JSON>"
      }
    },
    "requested_operations": ["decrypt"]
  }'
```

**Sub-action: key_release (SEV-SNP)**

```bash
curl -s -X POST \
  "http://localhost:5173/svc/confidential/confidential/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "action": "key_release",
    "policy_id": "sev-snp-ml-inference",
    "key_id": "key-ml-model-weights",
    "tee_type": "sev_snp",
    "nonce_id": "nonce_def456",
    "attestation_evidence": {
      "type": "snp_report",
      "report": "<base64-encoded 1184-byte SNP report>",
      "vcek_certificate": "<base64-encoded DER VCEK certificate>",
      "cert_chain": {
        "ask": "<base64-encoded DER ASK certificate>",
        "ark": "<base64-encoded DER ARK certificate>"
      }
    },
    "requested_operations": ["decrypt"]
  }'
```

**Sub-action: key_release (Azure CVM via MAA)**

```bash
curl -s -X POST \
  "http://localhost:5173/svc/confidential/confidential/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "action": "key_release",
    "policy_id": "azure-cvm-database",
    "key_id": "key-db-master",
    "tee_type": "azure_snp",
    "nonce_id": "nonce_ghi789",
    "attestation_evidence": {
      "type": "maa_token",
      "token": "<MAA JWT from https://region.attest.azure.net>",
      "maa_endpoint": "https://sharedeus2.eus2.attest.azure.net"
    },
    "requested_operations": ["decrypt", "unwrap"]
  }'
```

**Sub-action: verify (dry-run without key release)**

```bash
curl -s -X POST \
  "http://localhost:5173/svc/confidential/confidential/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "action": "verify",
    "policy_id": "nitro-payment-processor",
    "tee_type": "nitro",
    "nonce_id": "nonce_xyz789",
    "attestation_evidence": {
      "type": "nitro_document",
      "document": "<base64-encoded document>"
    }
  }'
```

Response (verify):

```json
{
  "result": {
    "decision": "would_allow",
    "policy_id": "nitro-payment-processor",
    "verified_measurements": {
      "PCR0": "matched",
      "PCR1": "wildcard",
      "PCR2": "matched",
      "PCR3": "matched"
    },
    "nonce_valid": true,
    "signature_valid": true,
    "cert_chain_valid": true,
    "failure_reasons": []
  },
  "request_id": "req_202"
}
```

#### GET /svc/confidential/confidential/releases

Lists all attested key release events.

```bash
curl -s "http://localhost:5173/svc/confidential/confidential/releases?tenant_id=root&limit=50&offset=0" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "items": [
    {
      "id": "release_abc123",
      "tenant_id": "root",
      "policy_id": "nitro-payment-processor",
      "key_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "tee_type": "nitro",
      "decision": "allow",
      "requested_operations": ["decrypt"],
      "verified_measurements": {
        "PCR0": "matched",
        "PCR2": "matched",
        "PCR3": "matched"
      },
      "released_at": "2026-03-23T00:00:00Z",
      "expires_at": "2026-03-23T01:00:00Z",
      "released_by": "svc:payments-enclave"
    }
  ],
  "total": 1,
  "request_id": "req_203"
}
```

---

## Section 3: Key Access Justifications

### What Key Access Justifications Are

Key Access Justifications require callers to declare a structured business reason before Vecta will allow sensitive key operations. Every decrypt, sign, wrap, unwrap, or export call on a justification-governed key must carry a reason code explaining *why* the key is being used — not just proof that the caller has permission to use it.

This is the difference between access control and access accountability. Access control answers "can this caller use this key?" Justifications answer "why did this caller use this key at this moment?" The second question is what auditors, compliance teams, and incident investigators actually need.

**Three things justifications provide:**

1. **Structured audit trail.** Every governed key operation is logged with a reason code, optional detail text, and optional ticket reference. Audit queries can answer "show me all decryptions of the customer-data key last quarter attributed to AUDIT_REVIEW" in seconds rather than requiring manual log correlation.

2. **Enforcement gate.** In enforce mode, operations without a valid justification code are blocked outright, not just logged. This prevents accidental or unauthorized access even by callers who have permission on the key.

3. **Approval escalation.** Sensitive codes (such as `BREAKGLASS_EMERGENCY` or `LEGAL_HOLD`) can be configured to require manager approval before the operation proceeds. The approval request flows through Vecta's Governance engine and is itself audited.

**Compliance relevance:**
- **SOX:** Requires evidence that access to financial data encryption keys was authorized and for a documented business purpose
- **HIPAA:** Requires audit controls that record who accessed PHI encryption keys and why
- **PCI DSS Requirement 10:** Requires logging of all access to cardholder data encryption keys
- **FedRAMP AU-2 / AU-3:** Requires audit record content including the reason for events

---

### Justification Code Reference

Vecta ships with 17 built-in reason codes organized into categories. Organizations can also define custom codes with the `CUSTOM_` prefix.

| Code | Category | Description | Typical Use |
|------|----------|-------------|-------------|
| `CUSTOMER_INITIATED_ACCESS` | Customer | Customer explicitly requested access to their own data | Self-service data export, customer data portability request |
| `CUSTOMER_INITIATED_SUPPORT` | Customer | Customer opened a support ticket requiring access to their data | Support engineer accessing encrypted data to debug customer issue |
| `VENDOR_INITIATED_MAINTENANCE` | Vendor | Vendor-side maintenance requires access | Scheduled platform maintenance by SaaS provider |
| `SECURITY_INVESTIGATION` | Security | Active security investigation requires key use | SOC analyst decrypting logs during incident investigation |
| `LEGAL_HOLD` | Legal | Data subject to legal hold requires access | Legal team preserving data responsive to litigation |
| `LEGAL_RESPONSE` | Legal | Responding to a court order, subpoena, or regulatory demand | Fulfilling a law enforcement request |
| `BREAKGLASS_EMERGENCY` | Emergency | Emergency access bypassing normal approval flows | Production outage requiring immediate access to encrypted data |
| `SCHEDULED_MAINTENANCE` | Operations | Scheduled, pre-approved maintenance window | Key rotation ceremony, quarterly maintenance |
| `INCIDENT_RESPONSE` | Operations | Unplanned incident response requires key access | On-call engineer responding to a production incident |
| `DATA_MIGRATION` | Operations | Data migration between systems or regions | Moving encrypted data to a new storage backend |
| `AUDIT_REVIEW` | Compliance | Internal or external audit requires data access | External auditor reviewing encrypted financial records |
| `COMPLIANCE_REPORTING` | Compliance | Generating compliance reports requiring key use | Quarterly SOX report generation |
| `TESTING_AND_VALIDATION` | Development | Testing or validation in a non-production environment | QA team testing encryption/decryption in staging |
| `ANALYTICS_PROCESSING` | Analytics | Authorized analytics pipeline processing | Data warehouse ETL job decrypting for aggregation |
| `BACKUP_AND_RECOVERY` | Operations | Backup creation or disaster recovery | Nightly backup job wrapping data keys |
| `THIRD_PARTY_ACCESS` | External | Authorized third-party access to data | Business partner given temporary access to shared data |
| `CUSTOM_*` | Custom | Organization-defined codes with the `CUSTOM_` prefix | Any business-specific reason not covered above |

> **Security Note:** `BREAKGLASS_EMERGENCY` should always be configured in enforce mode with `requireManagerApproval: true`. Unrestricted breakglass access defeats the purpose of justification controls. Every breakglass event should trigger an alert and post-incident review.

---

### Justification Rule Schema

A justification rule defines which keys and operations require justification, which codes are accepted, and what enforcement mode applies.

#### Complete Schema

```json
{
  "name": "financial-data-decrypt-rule",
  "description": "All decryption of financial keys requires a documented justification",
  "applyToKeyIds": [
    "key-financial-records-enc",
    "key-payment-card-data-enc"
  ],
  "applyToOperations": ["decrypt", "unwrap", "export"],
  "requiredCodes": [
    "AUDIT_REVIEW",
    "COMPLIANCE_REPORTING",
    "CUSTOMER_INITIATED_ACCESS",
    "CUSTOMER_INITIATED_SUPPORT",
    "LEGAL_HOLD",
    "LEGAL_RESPONSE",
    "BREAKGLASS_EMERGENCY"
  ],
  "mode": "enforce",
  "requireDetail": true,
  "requireTicketId": false,
  "requireManagerApproval": false,
  "managerApprovalCodes": ["BREAKGLASS_EMERGENCY", "LEGAL_HOLD"],
  "managerApprovalGroups": ["security-leads", "legal-approvers"],
  "enabled": true,
  "labels": {
    "compliance": "sox",
    "data-class": "financial"
  }
}
```

#### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique rule name within the tenant. 1–128 characters. |
| `description` | string | no | Human-readable description. |
| `applyToKeyIds` | array[string] | yes | Key IDs governed by this rule. Use `["*"]` to apply to all keys in the tenant. Specific key IDs take precedence over wildcards when multiple rules match. |
| `applyToOperations` | array[string] | yes | Operations that trigger this rule. Values: `encrypt`, `decrypt`, `sign`, `verify`, `wrap`, `unwrap`, `export`, `derive`. |
| `requiredCodes` | array[string] | no | Accepted justification codes. If empty, any code is accepted. If set, only listed codes are valid. |
| `mode` | string | yes | Enforcement mode. `"log_only"`: operation proceeds regardless, justification is logged. `"enforce"`: operation is blocked if no valid justification is provided. |
| `requireDetail` | boolean | no | Whether the `detail` field in the justification body is required (non-empty string). Default: false. |
| `requireTicketId` | boolean | no | Whether a `ticketId` must be provided in the justification body. Default: false. |
| `requireManagerApproval` | boolean | no | Whether any request triggers a manager approval flow. If true for all codes, every governed operation requires approval. |
| `managerApprovalCodes` | array[string] | no | Specific codes that require manager approval (overrides `requireManagerApproval` per-code). Other codes in `requiredCodes` proceed without approval. |
| `managerApprovalGroups` | array[string] | no | KMS group IDs whose members can approve requests routed to the approval queue. |
| `enabled` | boolean | no | Whether this rule is active. Default: true. |
| `labels` | object | no | Arbitrary key-value metadata. |

---

### How to Pass Justifications

#### Via HTTP Header

For simple cases where only the code is needed:

```bash
curl -s -X POST http://localhost:5173/api/keys/key-financial-records-enc/decrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -H "X-Key-Access-Justification: AUDIT_REVIEW" \
  -d '{"ciphertext": "base64-ciphertext..."}'
```

#### Via Request Body

For richer justifications including detail text and ticket references:

```bash
curl -s -X POST http://localhost:5173/api/keys/key-financial-records-enc/decrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "base64-ciphertext...",
    "justification": {
      "code": "AUDIT_REVIEW",
      "detail": "Q1 2026 external SOX audit — auditor Ernst & Young requires sample of 50 decrypted records for control testing",
      "ticketId": "AUDIT-2026-Q1-SOX-042",
      "requestedBy": "auditor@ernst-young.com"
    }
  }'
```

When both the header and body are present, the body justification takes precedence.

> **Tip:** Configure your service's HTTP client to inject the `X-Key-Access-Justification` header automatically for all KMS calls, pulled from a context value that your request middleware populates from the originating user's session or ticket system. This ensures justifications flow through automatically without requiring every call site to be updated.

---

### Key Access Justification Endpoints

Service prefix: `/svc/keyaccess`. All requests require `Authorization: Bearer $TOKEN` and `X-Tenant-ID: root`.

#### GET /svc/keyaccess/key-access/settings

```bash
curl -s "http://localhost:5173/svc/keyaccess/key-access/settings?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "config": {
    "tenant_id": "root",
    "enabled": true,
    "default_mode": "log_only",
    "require_code": true,
    "require_detail": false,
    "updated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_400"
}
```

#### PUT /svc/keyaccess/key-access/settings

```bash
curl -s -X PUT \
  "http://localhost:5173/svc/keyaccess/key-access/settings" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "default_mode": "enforce",
    "require_code": true,
    "require_detail": false
  }'
```

Response:

```json
{
  "config": {
    "tenant_id": "root",
    "enabled": true,
    "default_mode": "enforce",
    "require_code": true,
    "require_detail": false,
    "updated_at": "2026-03-23T00:00:01Z"
  },
  "request_id": "req_401"
}
```

#### GET /svc/keyaccess/key-access/codes

Lists all justification rules (referred to as "codes" in the API).

```bash
curl -s "http://localhost:5173/svc/keyaccess/key-access/codes?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "items": [
    {
      "id": "rule_fin_decrypt_001",
      "name": "financial-data-decrypt-rule",
      "applyToKeyIds": ["key-financial-records-enc", "key-payment-card-data-enc"],
      "applyToOperations": ["decrypt", "unwrap", "export"],
      "requiredCodes": ["AUDIT_REVIEW", "COMPLIANCE_REPORTING", "BREAKGLASS_EMERGENCY"],
      "mode": "enforce",
      "requireDetail": true,
      "enabled": true,
      "created_at": "2026-03-23T00:00:00Z"
    }
  ],
  "total": 1,
  "request_id": "req_402"
}
```

#### POST /svc/keyaccess/key-access/codes

Create a new justification rule.

```bash
curl -s -X POST \
  "http://localhost:5173/svc/keyaccess/key-access/codes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "pii-decrypt-rule",
    "description": "PII key decryption requires customer or support justification",
    "applyToKeyIds": ["key-user-pii-enc"],
    "applyToOperations": ["decrypt"],
    "requiredCodes": [
      "CUSTOMER_INITIATED_ACCESS",
      "CUSTOMER_INITIATED_SUPPORT",
      "LEGAL_HOLD",
      "LEGAL_RESPONSE",
      "BREAKGLASS_EMERGENCY"
    ],
    "mode": "enforce",
    "requireDetail": true,
    "requireTicketId": true,
    "managerApprovalCodes": ["BREAKGLASS_EMERGENCY"],
    "managerApprovalGroups": ["privacy-leads"],
    "enabled": true
  }'
```

Response:

```json
{
  "item": {
    "id": "rule_pii_decrypt_002",
    "name": "pii-decrypt-rule",
    "tenant_id": "root",
    "mode": "enforce",
    "enabled": true,
    "created_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_403"
}
```

#### PUT /svc/keyaccess/key-access/codes/{id}

Update a justification rule.

```bash
curl -s -X PUT \
  "http://localhost:5173/svc/keyaccess/key-access/codes/rule_pii_decrypt_002" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "enforce",
    "requireDetail": true,
    "requireTicketId": true
  }'
```

#### DELETE /svc/keyaccess/key-access/codes/{id}

```bash
curl -s -X DELETE \
  "http://localhost:5173/svc/keyaccess/key-access/codes/rule_pii_decrypt_002?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

#### GET /svc/keyaccess/key-access/decisions

Lists evaluated justification decisions. Each decision record captures the full context of a governed operation: who called, which key, which operation, which code was provided, what decision was made, and why.

```bash
curl -s "http://localhost:5173/svc/keyaccess/key-access/decisions?tenant_id=root&key_id=key-financial-records-enc&limit=20" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "items": [
    {
      "id": "dec_a1b2c3d4",
      "tenant_id": "root",
      "key_id": "key-financial-records-enc",
      "operation": "decrypt",
      "justification_code": "AUDIT_REVIEW",
      "justification_detail": "Q1 2026 SOX audit sample",
      "ticket_id": "AUDIT-2026-Q1-SOX-042",
      "decision": "allow",
      "rule_id": "rule_fin_decrypt_001",
      "actor": "auditor@ernst-young.com",
      "actor_ip": "10.0.0.1",
      "decided_at": "2026-03-23T00:00:00Z"
    },
    {
      "id": "dec_b2c3d4e5",
      "tenant_id": "root",
      "key_id": "key-financial-records-enc",
      "operation": "decrypt",
      "justification_code": null,
      "decision": "deny",
      "deny_reason": "No justification provided. Rule 'financial-data-decrypt-rule' requires code in: [AUDIT_REVIEW, COMPLIANCE_REPORTING, BREAKGLASS_EMERGENCY]",
      "rule_id": "rule_fin_decrypt_001",
      "actor": "svc-account-pipeline@internal",
      "decided_at": "2026-03-23T00:01:00Z"
    }
  ],
  "total": 2,
  "request_id": "req_404"
}
```

#### GET /svc/keyaccess/key-access/summary

Returns aggregate justification statistics for dashboard and compliance use.

```bash
curl -s "http://localhost:5173/svc/keyaccess/key-access/summary?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "summary": {
    "tenant_id": "root",
    "total_requests": 1240,
    "allowed": 1180,
    "denied": 42,
    "approval_held": 8,
    "unjustified_requests": 35,
    "bypass_signals": 2,
    "top_codes": [
      {"code": "AUDIT_REVIEW", "count": 480},
      {"code": "CUSTOMER_INITIATED_SUPPORT", "count": 310},
      {"code": "COMPLIANCE_REPORTING", "count": 190}
    ],
    "top_keys": [
      {"key_id": "key-financial-records-enc", "count": 620},
      {"key_id": "key-user-pii-enc", "count": 420}
    ],
    "period_start": "2026-03-01T00:00:00Z",
    "period_end": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_405"
}
```

---

## Section 4: Post-Quantum Cryptography

### The Quantum Threat

Classical public-key cryptography — RSA, DSA, ECDSA, ECDH, EdDSA — relies on mathematical problems that are computationally hard for classical computers: integer factorization (RSA) and the discrete logarithm problem (ECC). These algorithms underpin virtually all secure communications today, including TLS, code signing, key wrapping, and digital certificates.

**Shor's algorithm** (1994) demonstrates that a sufficiently powerful quantum computer can solve both integer factorization and discrete logarithm in polynomial time. A quantum computer capable of running Shor's algorithm against RSA-2048 would break that key pair in hours, rendering all signatures and encrypted data protected only by RSA or ECC insecure.

**Grover's algorithm** provides a quadratic speedup for searching unstructured spaces. Applied to symmetric cryptography and hash functions, it effectively halves the security level in quantum terms: AES-128 offers approximately 64 bits of quantum security, and AES-256 offers approximately 128 bits. AES-256 remains safe; AES-128 is borderline and should be avoided for new long-lived data.

**Harvest now, decrypt later (HNDL):** The most urgent near-term threat is not a quantum computer that exists today — it is adversaries who are recording TLS sessions, encrypted backups, and key material *now*, with the intention of decrypting it once a sufficiently capable quantum computer exists. Any data encrypted today that must remain confidential beyond the next 10–15 years is at risk from HNDL attacks against RSA and ECC key exchange.

**Timeline:**
- NSA CNSA 2.0 (2022): mandates transition to PQC algorithms for all National Security Systems by 2030 for new systems, 2035 for all systems
- NIST FIPS 203, 204, 205: published August 2024 — the first finalized PQC standards
- NIST IR 8413: recommends organizations begin inventory and migration planning immediately

---

### NIST PQC Standards

#### FIPS 203 — ML-KEM (Module-Lattice Key Encapsulation Mechanism)

Formerly known as CRYSTALS-Kyber. ML-KEM is a Key Encapsulation Mechanism based on the hardness of the Module Learning With Errors (MLWE) problem — a lattice problem believed to be hard for both classical and quantum computers.

ML-KEM is **not** a signature algorithm. It generates a shared secret (used for key exchange or key wrapping), analogous to ECDH. It replaces RSA key transport and ECDH key agreement.

**Algorithm comparison — Key Exchange:**

| Parameter Set | NIST Security Level | Public Key | Secret Key | Ciphertext | Classical Equiv. |
|---------------|--------------------:|------------|------------|------------|-----------------|
| ML-KEM-512 | 1 | 800 B | 1632 B | 768 B | ~128-bit |
| ML-KEM-768 | 3 | 1184 B | 2400 B | 1088 B | ~192-bit |
| ML-KEM-1024 | 5 | 1568 B | 3168 B | 1568 B | ~256-bit |
| ECDH P-256 *(classical)* | — | 65 B | 32 B | 65 B | 128-bit |
| ECDH P-384 *(classical)* | — | 97 B | 48 B | 97 B | 192-bit |

**Recommendation:** Use ML-KEM-768 as the default. It provides NIST Level 3 security and has a reasonable size/performance profile. Use ML-KEM-1024 for data requiring the highest long-term security (root key wrapping, archival encryption).

#### FIPS 204 — ML-DSA (Module-Lattice Digital Signature Algorithm)

Formerly known as CRYSTALS-Dilithium. ML-DSA is a digital signature algorithm based on the Module Learning With Errors and Module Short Integer Solution problems.

**Algorithm comparison — Signatures:**

| Parameter Set | NIST Security Level | Public Key | Secret Key | Signature | Classical Equiv. |
|---------------|--------------------:|------------|------------|-----------|-----------------|
| ML-DSA-44 | 2 | 1312 B | 2528 B | 2420 B | ~128-bit |
| ML-DSA-65 | 3 | 1952 B | 4000 B | 3293 B | ~192-bit |
| ML-DSA-87 | 5 | 2592 B | 4864 B | 4595 B | ~256-bit |
| ECDSA P-256 *(classical)* | — | 64 B | 32 B | 64 B | 128-bit |
| Ed25519 *(classical)* | — | 32 B | 64 B | 64 B | ~128-bit |
| RSA-2048 *(classical)* | — | 256 B | 1193 B | 256 B | ~112-bit |

**Recommendation:** Use ML-DSA-65 as the default for most signing workloads. Use ML-DSA-87 for root CA signatures and other high-value, long-lived signatures. Signature sizes are substantially larger than classical algorithms — account for this in TLS handshakes, JWTs, and X.509 certificate chains.

#### FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

Formerly known as SPHINCS+. SLH-DSA is a digital signature algorithm based *only* on hash functions. It makes no lattice assumptions — its security relies entirely on the pre-image resistance and collision resistance of SHA-256 or SHAKE-256. This makes it the most conservative PQC choice: if lattice assumptions are ever unexpectedly broken, SLH-DSA remains secure as long as hash functions are secure.

**Trade-offs:** SLH-DSA produces much larger signatures and is significantly slower to sign than ML-DSA. Verification is fast.

| Parameter Set | Security | Public Key | Signature | Sign Time | Verify Time |
|---------------|----------|------------|-----------|-----------|-------------|
| SLH-DSA-SHA2-128f | 128-bit | 32 B | 17,088 B | ~3 ms | ~1 ms |
| SLH-DSA-SHA2-128s | 128-bit | 32 B | 7,856 B | ~300 ms | ~1 ms |
| SLH-DSA-SHA2-192f | 192-bit | 48 B | 35,664 B | ~5 ms | ~2 ms |
| SLH-DSA-SHA2-256f | 256-bit | 64 B | 49,856 B | ~8 ms | ~3 ms |
| SLH-DSA-SHA2-256s | 256-bit | 64 B | 29,792 B | ~600 ms | ~3 ms |

The `f` suffix means "fast" (optimized for signing speed, larger signatures). The `s` suffix means "small" (optimized for signature size, slower signing). Use SLH-DSA for root CA self-signatures, archival document signatures, and any context where signing is infrequent and the highest cryptographic conservatism is required. Do not use it for high-frequency signing (TLS, JWT issuance, code-signing pipelines).

---

### Hybrid Modes

Hybrid key exchange and hybrid signatures combine a classical algorithm with a PQC algorithm in a single operation. Both must be broken for the combined scheme to be compromised. During the transition period, hybrid modes provide a safety net: even if ML-KEM is broken, X25519 still protects the session, and vice versa.

**X25519 + ML-KEM-768** — recommended for general use. Used in TLS 1.3 via the `X25519MLKEM768` key share group.

**P-256 + ML-KEM-512** — for FIPS environments where X25519 is not approved.

**Ed25519 + ML-DSA-65** — hybrid signatures where both algorithms sign the same message and both signatures must verify.

#### Creating Hybrid Keys in Vecta

```bash
curl -s -X POST http://localhost:5173/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tls-hybrid-kem",
    "algorithm": "HYBRID_X25519_MLKEM768",
    "purpose": "key_agreement",
    "hybridMode": true,
    "labels": {"use": "tls", "pqc": "true"}
  }'
```

Response:

```json
{
  "key": {
    "id": "key_hybrid_kem_001",
    "name": "tls-hybrid-kem",
    "algorithm": "HYBRID_X25519_MLKEM768",
    "purpose": "key_agreement",
    "hybridMode": true,
    "componentKeyIds": {
      "classical": "key_x25519_001",
      "pqc": "key_mlkem768_001"
    },
    "status": "active",
    "created_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_500"
}
```

---

### PQC Key Creation Examples

#### Create ML-KEM-768 Key

```bash
curl -s -X POST http://localhost:5173/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "backup-encryption-kem",
    "algorithm": "ML-KEM-768",
    "purpose": "key_encapsulation",
    "labels": {"pqc": "true", "use": "backup-key-wrapping"}
  }'
```

Response:

```json
{
  "key": {
    "id": "key_mlkem768_backup_001",
    "name": "backup-encryption-kem",
    "algorithm": "ML-KEM-768",
    "purpose": "key_encapsulation",
    "nist_security_level": 3,
    "public_key_size_bytes": 1184,
    "status": "active",
    "created_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_501"
}
```

#### Create ML-DSA-65 Signing Key

```bash
curl -s -X POST http://localhost:5173/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "code-signing-pqc",
    "algorithm": "ML-DSA-65",
    "purpose": "signing",
    "labels": {"pqc": "true", "use": "artifact-signing"}
  }'
```

Response:

```json
{
  "key": {
    "id": "key_mldsa65_codesign_001",
    "name": "code-signing-pqc",
    "algorithm": "ML-DSA-65",
    "purpose": "signing",
    "nist_security_level": 3,
    "public_key_size_bytes": 1952,
    "status": "active",
    "created_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_502"
}
```

#### Create SLH-DSA-SHA2-128f Key

```bash
curl -s -X POST http://localhost:5173/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "root-ca-pqc-signing",
    "algorithm": "SLH-DSA-SHA2-128f",
    "purpose": "signing",
    "labels": {"pqc": "true", "use": "root-ca", "conservative": "true"}
  }'
```

Response:

```json
{
  "key": {
    "id": "key_slhdsa_rootca_001",
    "name": "root-ca-pqc-signing",
    "algorithm": "SLH-DSA-SHA2-128f",
    "purpose": "signing",
    "nist_security_level": 1,
    "public_key_size_bytes": 32,
    "status": "active",
    "created_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_503"
}
```

---

### PQC Migration Framework

A PQC migration is an operational program, not a one-time flag flip. Vecta structures the migration into five phases.

#### Phase 1: Inventory

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/inventory?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "inventory": {
    "tenant_id": "root",
    "summary": {
      "total_assets": 87,
      "classical_only": 64,
      "hybrid": 12,
      "pqc_ready": 11,
      "pqc_readiness_percent": 13
    },
    "by_algorithm": {
      "RSA-2048": 18,
      "RSA-4096": 8,
      "ECDSA-P256": 22,
      "ECDSA-P384": 16,
      "Ed25519": 12,
      "ML-DSA-65": 8,
      "ML-KEM-768": 3
    },
    "generated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_504"
}
```

#### Phase 2: Risk Assessment

**Risk table by asset type:**

| Asset Type | Quantum Risk | Rationale |
|-----------|-------------|-----------|
| Root CA signing key (RSA/ECC) | CRITICAL | Signs all subordinate certificates; compromise cascades to entire PKI |
| Long-lived data encryption keys | HIGH | HNDL: ciphertext captured now, decrypted later |
| Code signing keys | HIGH | Signed artifacts may be trusted for years after signing |
| TLS server certificates | MEDIUM | Short-lived; HNDL risk lower but certs themselves may be long-lived |
| Ephemeral TLS sessions | NONE | Ephemeral ECDH keys — no stored ciphertext to harvest |
| AES-256 symmetric keys | NONE | Grover: AES-256 → 128-bit quantum security (safe) |
| AES-128 symmetric keys | LOW | Grover: AES-128 → 64-bit quantum security (marginal) |

```bash
curl -s -X POST \
  "http://localhost:5173/svc/pqc/pqc/assess" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "root", "include_remediation": true}'
```

Response:

```json
{
  "result": {
    "assessment_id": "assess_2026_q1_001",
    "findings_count": 18,
    "critical_count": 3,
    "high_count": 11,
    "findings": [
      {
        "id": "finding_001",
        "asset_id": "key-root-ca-rsa4096",
        "risk": "CRITICAL",
        "title": "Root CA uses RSA-4096 — vulnerable to Shor's algorithm",
        "remediation": "Migrate to ML-DSA-87 or hybrid RSA-4096+ML-DSA-87"
      }
    ]
  },
  "request_id": "req_505"
}
```

#### Phase 3–5: Pilot, Migrate, Monitor

Generate a prioritized migration plan:

```bash
curl -s -X POST \
  "http://localhost:5173/svc/pqc/pqc/migration/plan" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "target_profile": "hybrid",
    "priority_filter": ["CRITICAL", "HIGH"]
  }'
```

Response:

```json
{
  "plan": {
    "id": "plan_mig_2026_q1",
    "tenant_id": "root",
    "target_profile": "hybrid",
    "total_assets": 26,
    "steps": [
      {
        "step": 1,
        "asset_id": "key-root-ca-rsa4096",
        "current_algorithm": "RSA-4096",
        "recommended_algorithm": "ML-DSA-87",
        "hybrid_pair": "RSA-4096 + ML-DSA-87",
        "risk": "CRITICAL",
        "estimated_effort": "high"
      },
      {
        "step": 2,
        "asset_id": "key-financial-records-enc",
        "current_algorithm": "RSA-2048",
        "recommended_algorithm": "ML-KEM-768",
        "risk": "HIGH",
        "estimated_effort": "medium"
      }
    ],
    "generated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_506"
}
```

Enforce PQC policy after migration is complete:

```bash
curl -s -X PUT \
  "http://localhost:5173/svc/pqc/pqc/policy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "mode": "enforce",
    "requireHybrid": true,
    "algorithmAllowlist": [
      "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
      "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
      "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s",
      "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256s",
      "HYBRID_X25519_MLKEM768", "HYBRID_P256_MLKEM512",
      "AES-128-GCM", "AES-256-GCM"
    ],
    "exemptions": []
  }'
```

---

### PQC Service Endpoints

Service prefix: `/svc/pqc/pqc`. All requests require `Authorization: Bearer $TOKEN` and `X-Tenant-ID: root`.

#### GET/PUT /svc/pqc/pqc/policy

Returns or updates the tenant PQC enforcement policy. See examples above.

#### GET /svc/pqc/pqc/inventory

Returns full PQC asset inventory. Query params: `?asset_type=key|certificate|tls_interface`, `?risk=CRITICAL|HIGH|MEDIUM|LOW|NONE`, `?status=classical|hybrid|pqc_ready`.

#### GET /svc/pqc/pqc/inventory/{resourceId}

Returns the PQC classification for a single asset.

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/inventory/key-root-ca-rsa4096?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "item": {
    "resource_id": "key-root-ca-rsa4096",
    "resource_type": "key",
    "algorithm": "RSA-4096",
    "pqc_status": "classical",
    "quantum_risk": "CRITICAL",
    "risk_rationale": "Root CA key signs all subordinate certificates. Compromise via Shor's algorithm cascades to entire PKI.",
    "recommended_action": "Migrate to ML-DSA-87 or hybrid RSA-4096+ML-DSA-87",
    "harvest_risk": "HIGH",
    "migration_urgency": "immediate"
  },
  "request_id": "req_507"
}
```

#### GET /svc/pqc/pqc/algorithms

Returns metadata for all PQC algorithms supported by Vecta, including NIST level, key/signature sizes, and hybrid pairing options.

#### POST /svc/pqc/pqc/migration/plan

Generates a prioritized migration plan. See Phase 3–5 example above.

#### GET /svc/pqc/pqc/migration/plans

Lists all previously generated migration plans for the tenant.

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/migration/plans?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

#### GET /svc/pqc/pqc/migration/plans/{id}

Returns a specific migration plan by ID.

#### POST /svc/pqc/pqc/assess

Runs a PQC risk assessment. See Phase 2 example above.

#### GET /svc/pqc/pqc/findings

Lists all open PQC findings for the tenant.

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/findings?tenant_id=root&risk=CRITICAL" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "items": [
    {
      "id": "finding_001",
      "asset_id": "key-root-ca-rsa4096",
      "risk": "CRITICAL",
      "title": "Root CA uses RSA-4096 — vulnerable to Shor's algorithm",
      "status": "open",
      "detected_at": "2026-03-23T00:00:00Z",
      "remediation": "Migrate to ML-DSA-87 or hybrid RSA-4096+ML-DSA-87 before 2030"
    }
  ],
  "total": 3,
  "request_id": "req_508"
}
```

#### GET /svc/pqc/pqc/readiness

Returns the tenant's PQC readiness score and framework alignment.

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/readiness?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "readiness": {
    "tenant_id": "root",
    "score": 23,
    "score_label": "early_migration",
    "critical_assets_migrated": 0,
    "critical_assets_total": 3,
    "high_assets_migrated": 2,
    "high_assets_total": 14,
    "pqc_ready_percent": 13,
    "framework_alignment": {
      "nist_cnsa2": "non_compliant",
      "fips_203_ready": true,
      "fips_204_ready": true,
      "fips_205_ready": true
    }
  },
  "request_id": "req_509"
}
```

#### GET /svc/pqc/pqc/migration/report

Returns a migration status report showing completed, pending, and blocked migrations.

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/migration/report?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "report": {
    "tenant_id": "root",
    "generated_at": "2026-03-23T00:00:00Z",
    "overall_status": "in_progress",
    "completed_migrations": 11,
    "pending_migrations": 15,
    "blocked_migrations": 2,
    "blocked_reasons": [
      {
        "asset_id": "key-legacy-payment-terminal",
        "reason": "Hardware constraint — awaiting PCI waiver"
      }
    ],
    "recent_activity": [
      {
        "asset_id": "key-tls-api-gateway",
        "from_algorithm": "ECDSA-P256",
        "to_algorithm": "ML-DSA-65",
        "migrated_at": "2026-03-20T00:00:00Z",
        "migrated_by": "ops-admin"
      }
    ]
  },
  "request_id": "req_510"
}
```

---

## Section 5: AI-Assisted Operations

### What the AI Service Provides

The Vecta AI service connects a configured LLM backend (Claude, GPT-4o, or any OpenAI-compatible endpoint) to a governance-aware context assembly layer. Before any prompt is sent to the provider, Vecta assembles relevant KMS context — recent audit events, current posture findings, key inventory, unresolved alerts — and redacts sensitive fields (key material, password hashes, API secrets). The result is an assistant that understands your specific KMS state without ever exposing raw secrets to the LLM.

**Capabilities:**
- **Natural language audit queries:** Ask questions like "show all decrypt operations on the payments key last week" without writing filter syntax
- **Policy recommendations:** Describe what you need in plain English and receive a draft key policy or access rule
- **PQC migration guidance:** Get a prioritized migration plan explained in plain language with rationale per asset
- **Posture recommendations:** Ask for the highest-priority security actions for your current posture state
- **Incident analysis:** Submit an incident description and receive an AI-generated explanation with suggested investigation steps

Service prefix: `/svc/ai/ai`. All requests require `Authorization: Bearer $TOKEN` and `X-Tenant-ID: root`.

---

### GET /svc/ai/ai/config

Returns the current AI configuration for the tenant.

```bash
curl -s "http://localhost:5173/svc/ai/ai/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

Response:

```json
{
  "config": {
    "tenant_id": "root",
    "backend": "claude",
    "endpoint": "https://api.anthropic.com/v1/messages",
    "model": "claude-sonnet-4-6",
    "provider_auth": {
      "required": true,
      "type": "bearer"
    },
    "mcp": {
      "enabled": false,
      "endpoint": ""
    },
    "max_context_tokens": 8000,
    "temperature": 0.3,
    "context_sources": {
      "keys": {"enabled": true, "limit": 25, "fields": ["id", "name", "algorithm", "status"]},
      "policies": {"enabled": true, "all": false, "limit": 20},
      "audit": {"enabled": true, "last_hours": 24, "limit": 100},
      "posture": {"enabled": true, "current": true},
      "alerts": {"enabled": true, "unresolved": true, "limit": 50}
    },
    "redaction_fields": ["encrypted_material", "wrapped_dek", "pwd_hash", "api_key", "passphrase"],
    "updated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_600"
}
```

---

### POST /svc/ai/ai/query

Submits a natural language query. Vecta assembles context from the configured sources, redacts sensitive fields, builds the prompt, and returns the LLM answer.

#### Example: Audit log query

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "query": "Show all decrypt operations in the last week on the key named customer-data-enc, grouped by actor",
    "include_context": true
  }'
```

Response:

```json
{
  "result": {
    "action": "query",
    "tenant_id": "root",
    "answer": "Over the past 7 days, there were 84 decrypt operations on customer-data-enc. Breakdown by actor:\n- payments-service (SPIFFE): 71 operations (85%)\n- admin@example.com: 8 operations (10%)\n- audit-pipeline: 5 operations (6%)\n\nAll operations had valid justification codes. The spike on 2026-03-19 (31 decrypts in one hour by payments-service) aligns with the scheduled batch processing window.",
    "backend": "claude",
    "model": "claude-sonnet-4-6",
    "redactions_applied": 3,
    "context_summary": {
      "audit_events": 84,
      "keys": 1,
      "alerts": 0
    },
    "generated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_601"
}
```

#### Example: Policy recommendation

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "query": "I need a key for encrypting user PII, accessed only by the payments-service workload in the prod namespace. What key policy and justification rule should I create?",
    "include_context": true
  }'
```

Response:

```json
{
  "result": {
    "answer": "For a PII encryption key accessed only by payments-service in prod, I recommend:\n\n**Key:** AES-256-GCM, purpose=encrypt, rotation every 365 days, labels: data-class=pii, team=payments\n\n**Access policy:** Allow encrypt+decrypt only for SPIFFE ID spiffe://example.com/ns/prod/sa/payments-service. Deny all other identities including admin roles (break-glass should go through justification escalation).\n\n**Justification rule:** Apply to this key for decrypt operations. Required codes: CUSTOMER_INITIATED_ACCESS, CUSTOMER_INITIATED_SUPPORT, LEGAL_HOLD, BREAKGLASS_EMERGENCY. Mode: enforce. Require detail text. Route BREAKGLASS_EMERGENCY to privacy-leads for approval.\n\nDraft curl commands for each are below...",
    "backend": "claude",
    "model": "claude-sonnet-4-6",
    "generated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_602"
}
```

---

### POST /svc/ai/ai/recommend/posture

Builds posture guidance for a specific focus area.

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/recommend/posture \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "focus": "pqc-migration"
  }'
```

Response:

```json
{
  "result": {
    "action": "recommend_posture",
    "answer": "Your tenant has 3 CRITICAL and 11 HIGH risk assets still using classical algorithms. Immediate priorities:\n\n1. **key-root-ca-rsa4096 (CRITICAL):** Migrate to ML-DSA-87 hybrid. This is the highest-blast-radius asset — compromise cascades to all 23 subordinate certificates. Estimated effort: 2 days (ceremony + re-signing).\n\n2. **key-financial-records-enc (HIGH):** Migrate wrapping key to ML-KEM-768. 84 decrypts/week means this is actively used. Plan a maintenance window.\n\n3. **TLS interfaces (MEDIUM, 12 total):** Enable X25519+ML-KEM-768 hybrid key share in your TLS config. No key rotation required — just reconfigure cipher preferences.\n\nAt the current migration rate, you will reach CNSA 2.0 compliance by approximately Q3 2028.",
    "generated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_603"
}
```

---

### POST /svc/ai/ai/analyze/incident

Produces an AI explanation for a security or governance event.

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/analyze/incident \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "incident_id": "inc-2026-003",
    "title": "Unauthorized key export attempt on production signing key",
    "description": "A service account attempted to export the raw private key material for key-code-signing-prod at 03:14 UTC.",
    "details": {
      "key_id": "key-code-signing-prod",
      "actor": "svc-ci-runner@internal",
      "approval_status": "missing",
      "time_utc": "2026-03-23T03:14:00Z"
    }
  }'
```

Response:

```json
{
  "result": {
    "action": "analyze_incident",
    "answer": "This event warrants immediate investigation. Key findings:\n\n1. **The actor is anomalous for this operation.** svc-ci-runner has 340 prior sign operations on key-code-signing-prod over the past 90 days but zero prior export attempts. Export of private key material is not a normal CI pipeline operation.\n\n2. **Time is suspicious.** 03:14 UTC is outside business hours and outside the scheduled CI pipeline windows (06:00–22:00 UTC).\n\n3. **No approval or justification.** The key policy requires governance approval for export operations. None was present.\n\n**Recommended immediate actions:**\n- Suspend svc-ci-runner credentials pending investigation\n- Review svc-ci-runner's recent audit trail for unusual access patterns\n- Check if svc-ci-runner credentials were recently used from an unexpected IP\n- Initiate key rotation for key-code-signing-prod as a precautionary measure",
    "generated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_604"
}
```

---

### POST /svc/ai/ai/explain/policy

Explains an existing policy in plain English.

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/explain/policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "policy_id": "policy-pii-key-access"
  }'
```

Response:

```json
{
  "result": {
    "action": "explain_policy",
    "answer": "This policy controls access to all keys tagged data-class=pii. Here is what it does in plain English:\n\n- Only the payments-service workload (identified by SPIFFE ID) can encrypt or decrypt. All other identities — including human administrators — are denied by default.\n- Decrypt operations require a justification code. Acceptable codes are CUSTOMER_INITIATED_ACCESS, CUSTOMER_INITIATED_SUPPORT, LEGAL_HOLD, and BREAKGLASS_EMERGENCY.\n- BREAKGLASS_EMERGENCY decrypts are held for approval by the privacy-leads group before proceeding.\n- Keys under this policy rotate automatically every 365 days.\n- The policy is currently active and was last updated by ops-admin on 2026-03-15.",
    "generated_at": "2026-03-23T00:00:00Z"
  },
  "request_id": "req_605"
}
```

---

## Section 6: Reference Use Cases

### Use Case 1: Zero-Trust Workload Authentication in Kubernetes

**Context:** A payments microservice needs to decrypt cardholder data stored in an encrypted database. Currently it uses a static API key checked into a Kubernetes Secret. The key has been rotating manually every 6 months and was accidentally logged in a CI/CD run 3 weeks ago.

**Prerequisites:**
- Vecta KMS running with the workload identity feature enabled
- Kubernetes cluster with vecta-agent DaemonSet deployed
- Payments service runs in the `prod` namespace with service account `payments-service`

**Compliance mapping:** PCI DSS 8.6 (service account credentials), 10.2 (audit individual access), NIST SP 800-207 (zero trust architecture).

**Steps:**

1. Configure trust domain and enable JWT SVIDs:

```bash
curl -s -X POST http://localhost:5173/svc/workload/workload-identity/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "root", "trust_domain": "example.com", "enable_jwt": true, "default_svid_ttl_secs": 3600}'
```

2. Create Kubernetes attestation policy for the prod namespace:

```bash
curl -s -X POST http://localhost:5173/svc/workload/workload-identity/registrations \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "payments-service-k8s",
    "spiffe_id": "spiffe://example.com/ns/prod/sa/payments-service",
    "attestor_type": "kubernetes",
    "attestation_policy_id": "k8s-prod-payments",
    "key_ids": ["key-cardholder-data-enc"]
  }'
```

3. Apply a key access policy granting decrypt only to the payments SPIFFE ID:

```bash
curl -s -X POST http://localhost:5173/api/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payments-cardholder-access",
    "keyIds": ["key-cardholder-data-enc"],
    "rules": [
      {
        "principals": ["spiffe://example.com/ns/prod/sa/payments-service"],
        "operations": ["decrypt"],
        "effect": "allow"
      }
    ]
  }'
```

4. Deploy vecta-agent DaemonSet (see Section 1 for full manifest). Remove the static Kubernetes Secret containing the old API key.

5. Update the payments service to use the Workload API socket instead of a static key:

```python
# Before: static API key
headers = {"Authorization": f"Bearer {os.environ['KMS_API_KEY']}"}

# After: JWT SVID from Workload API (no secrets in environment)
import subprocess, json
svid_json = subprocess.check_output([
    "svid-tool", "fetch", "jwt",
    "--socket", "/run/spiffe/workload.sock",
    "--audience", "https://vecta.example.com"
])
jwt = json.loads(svid_json)["svids"][0]["svid"]
headers = {"Authorization": f"Bearer {jwt}"}
```

6. Verify in the workload identity graph that payments-service is active with no expired SVIDs:

```bash
curl -s "http://localhost:5173/svc/workload/workload-identity/graph?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" | jq '.graph.nodes[] | select(.name == "payments-service")'
```

**Outcome:** The payments service authenticates with a 1-hour JWT SVID that is automatically rotated by the vecta-agent. There is no static secret. The audit log records every decrypt with the SPIFFE ID as actor. Over-permissioned or expired workloads surface immediately in the posture dashboard.

---

### Use Case 2: Confidential ML Inference — Model Key Released Only to Verified Nitro Enclave

**Context:** An ML inference service loads a proprietary model whose weights are encrypted. The model weights represent significant IP. The key must never be accessible outside a verified Nitro enclave running the exact approved inference binary.

**Prerequisites:**
- AWS account with Nitro Enclave support enabled on the EC2 instance type
- Model weights encrypted with `key-ml-model-weights` in Vecta
- Known-good PCR0 value for the inference enclave image

**Compliance mapping:** SOC 2 CC6.1 (logical access), NIST CSF PR.DS-1 (data at rest protection).

**Steps:**

1. Register the attested key release policy pinned to the enclave image PCR:

```bash
curl -s -X POST http://localhost:5173/svc/confidential/confidential/policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "nitro-inference-policy",
    "teeType": "nitro",
    "measurements": {
      "PCR0": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
      "PCR1": "*",
      "PCR2": "*",
      "PCR3": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5"
    },
    "allowedKeyIds": ["key-ml-model-weights"],
    "requireFreshNonce": true,
    "nonceTimeWindowSecs": 300,
    "allowedOperations": ["decrypt"]
  }'
```

2. Inside the enclave startup script, implement the attested key release flow:

```python
# Get nonce from Vecta
nonce_resp = requests.post(
    "http://vecta.internal:5173/svc/confidential/confidential/evaluate",
    headers={"Authorization": f"Bearer {svc_token}", "X-Tenant-ID": "root"},
    json={"tenant_id": "root", "action": "get_nonce", "policy_id": "nitro-inference-policy"}
)
nonce_id = nonce_resp.json()["result"]["nonce_id"]
nonce_bytes = bytes.fromhex(nonce_resp.json()["result"]["nonce"])

# Generate ephemeral key pair and get attestation document
ephemeral_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
epk_der = ephemeral_key.public_key().public_bytes(DER, SubjectPublicKeyInfo)
att_doc = nsm.get_attestation_doc(user_data=nonce_bytes, public_key=epk_der)

# Request key release
release_resp = requests.post(
    "http://vecta.internal:5173/svc/confidential/confidential/evaluate",
    headers={"Authorization": f"Bearer {svc_token}", "X-Tenant-ID": "root"},
    json={
        "tenant_id": "root",
        "action": "key_release",
        "policy_id": "nitro-inference-policy",
        "key_id": "key-ml-model-weights",
        "tee_type": "nitro",
        "nonce_id": nonce_id,
        "attestation_evidence": {
            "type": "nitro_document",
            "document": base64.b64encode(att_doc).decode()
        },
        "requested_operations": ["decrypt"]
    }
)

# Unwrap model key using ephemeral private key
wrapped = base64.b64decode(release_resp.json()["result"]["wrapped_key_material"])
model_key = ephemeral_key.decrypt(wrapped, OAEP(MGF1(SHA256()), SHA256(), None))
```

3. Verify the release appears in the release audit log:

```bash
curl -s "http://localhost:5173/svc/confidential/confidential/releases?tenant_id=root&policy_id=nitro-inference-policy" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Outcome:** The model key is only ever decrypted inside a verified Nitro enclave running the exact approved inference binary (PCR0 pinned). Any attempt to release the key to a different binary or outside an enclave fails the measurement check and is logged as a denial.

---

### Use Case 3: SOX Compliance — Justification Required for All Financial Data Decryption

**Context:** The company is subject to SOX. External auditors require evidence that every access to the financial records encryption key was for a documented, approved business purpose. There have been two incidents in the past year of undocumented decryption by pipeline service accounts.

**Prerequisites:**
- `key-financial-records-enc` already in Vecta
- Audit log retention configured for 7 years

**Compliance mapping:** SOX Section 404 (internal controls over financial reporting), COSO Principle 12 (control activities via information technology).

**Steps:**

1. Enable Key Access Justifications in enforce mode:

```bash
curl -s -X PUT http://localhost:5173/svc/keyaccess/key-access/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "root", "enabled": true, "default_mode": "enforce", "require_code": true}'
```

2. Create the justification rule for financial key decryption:

```bash
curl -s -X POST http://localhost:5173/svc/keyaccess/key-access/codes \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "sox-financial-decrypt",
    "applyToKeyIds": ["key-financial-records-enc"],
    "applyToOperations": ["decrypt", "unwrap", "export"],
    "requiredCodes": [
      "AUDIT_REVIEW", "COMPLIANCE_REPORTING",
      "CUSTOMER_INITIATED_ACCESS", "CUSTOMER_INITIATED_SUPPORT",
      "LEGAL_HOLD", "LEGAL_RESPONSE", "BREAKGLASS_EMERGENCY"
    ],
    "mode": "enforce",
    "requireDetail": true,
    "managerApprovalCodes": ["BREAKGLASS_EMERGENCY", "LEGAL_HOLD"],
    "managerApprovalGroups": ["finance-leads", "legal-approvers"]
  }'
```

3. All callers now pass a justification header:

```bash
curl -s -X POST http://localhost:5173/api/keys/key-financial-records-enc/decrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -H "X-Key-Access-Justification: AUDIT_REVIEW" \
  -d '{
    "ciphertext": "base64-ciphertext...",
    "justification": {
      "code": "AUDIT_REVIEW",
      "detail": "Q1 2026 SOX audit — Ernst & Young control testing sample",
      "ticketId": "AUDIT-2026-Q1-042"
    }
  }'
```

4. Pull the justification audit trail for the auditor:

```bash
curl -s "http://localhost:5173/svc/keyaccess/key-access/decisions?tenant_id=root&key_id=key-financial-records-enc&start=2026-01-01T00:00:00Z&end=2026-03-31T23:59:59Z" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

5. Generate an evidence pack report for the auditor:

```bash
curl -s -X POST http://localhost:5173/svc/reporting/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "root", "template_id": "evidence_pack", "scope": {"key_ids": ["key-financial-records-enc"], "period_start": "2026-01-01", "period_end": "2026-03-31"}}'
```

**Outcome:** Every decrypt of the financial key has a structured reason code, detail text, and optional ticket reference in the audit log. Undocumented decrypts are blocked at the API layer. The evidence pack gives auditors a single artifact containing all access events, justification codes, and approval records for the period.

---

### Use Case 4: PQC Migration for Root CA (RSA-4096 → ML-DSA-87 Hybrid)

**Context:** The company's internal Root CA uses RSA-4096. The CISO has received a directive to begin PQC migration. The Root CA is the CRITICAL priority item identified in the PQC assessment.

**Prerequisites:**
- `key-root-ca-rsa4096` is the current Root CA signing key
- CA infrastructure (ACME, PKCS#11, or internal CA) can be updated

**Compliance mapping:** NSA CNSA 2.0, NIST SP 800-208 (recommendation for stateful hash-based signature schemes).

**Steps:**

1. Run PQC assessment to confirm the Root CA is the top priority:

```bash
curl -s -X POST http://localhost:5173/svc/pqc/pqc/assess \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "root", "include_remediation": true}'
```

2. Create the ML-DSA-87 key for the new hybrid Root CA:

```bash
curl -s -X POST http://localhost:5173/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "root-ca-mldsa87",
    "algorithm": "ML-DSA-87",
    "purpose": "signing",
    "labels": {"pqc": "true", "use": "root-ca", "nist-level": "5"}
  }'
```

3. Create the hybrid key handle linking RSA-4096 + ML-DSA-87:

```bash
curl -s -X POST http://localhost:5173/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "root-ca-hybrid",
    "algorithm": "HYBRID_RSA4096_MLDSA87",
    "purpose": "signing",
    "hybridMode": true,
    "componentKeyIds": {
      "classical": "key-root-ca-rsa4096",
      "pqc": "key-root-ca-mldsa87"
    }
  }'
```

4. Generate the new Root CA self-signed certificate using the hybrid key (quorum ceremony if MPC is configured):

```bash
curl -s -X POST http://localhost:5173/api/certificates/self-signed \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-root-ca-hybrid",
    "subject": "CN=Example Root CA G2,O=Example Corp,C=US",
    "validity_days": 7300,
    "is_ca": true,
    "path_length": 1
  }'
```

5. Re-sign all intermediate CA certificates under the new Root CA. Update trust anchors in all systems.

6. Update the PQC migration record:

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/migration/report?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Outcome:** The Root CA now signs with both RSA-4096 and ML-DSA-87. Relying parties that support hybrid signatures get quantum-resistant assurance. Classical-only relying parties continue to verify the RSA-4096 signature. The PQC inventory updates the Root CA from `CRITICAL/classical` to `hybrid`.

---

### Use Case 5: Hybrid KEM for Long-Lived Encrypted Backups

**Context:** Nightly database backups are encrypted with a data encryption key (DEK) that is wrapped under an RSA-2048 key encryption key (KEK). Backups are retained for 7 years. The HNDL risk means that an adversary recording today's backups could decrypt them in ~10 years using a quantum computer.

**Steps:**

1. Create an ML-KEM-768 + X25519 hybrid KEK:

```bash
curl -s -X POST http://localhost:5173/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "backup-kek-hybrid-kem",
    "algorithm": "HYBRID_X25519_MLKEM768",
    "purpose": "key_encapsulation",
    "hybridMode": true,
    "labels": {"use": "backup-kek", "pqc": "true", "retention": "7yr"}
  }'
```

2. Create a justification rule requiring a backup justification code for all wrap/unwrap operations:

```bash
curl -s -X POST http://localhost:5173/svc/keyaccess/key-access/codes \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "backup-kek-wrap-rule",
    "applyToKeyIds": ["key-backup-kek-hybrid-kem"],
    "applyToOperations": ["wrap", "unwrap"],
    "requiredCodes": ["BACKUP_AND_RECOVERY", "INCIDENT_RESPONSE", "BREAKGLASS_EMERGENCY"],
    "mode": "enforce",
    "requireDetail": false
  }'
```

3. Update the backup pipeline to use the hybrid KEK with a justification header:

```bash
curl -s -X POST http://localhost:5173/api/keys/key-backup-kek-hybrid-kem/wrap \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -H "X-Key-Access-Justification: BACKUP_AND_RECOVERY" \
  -d '{"keyToWrap": "base64-dek-bytes...", "wrappingAlgorithm": "HYBRID_X25519_MLKEM768_HKDF"}'
```

**Outcome:** Backups created today are protected against HNDL attacks by the ML-KEM-768 component. Even if X25519 is broken by a future quantum computer, ML-KEM-768 remains secure. Backups created before the migration (wrapped under RSA-2048) remain at risk — prioritize re-wrapping the most recent retained backups under the new hybrid KEK.

---

### Use Case 6: Multi-Cloud Workload Identity Federation

**Context:** A data processing service runs in both AWS (EC2) and GCP (GCE). It needs to access Vecta KMS using its platform identity in each cloud, without any static secrets. The service processes data for which the cloud providers should not be trusted.

**Steps:**

1. Create AWS IID attestation policy:

```bash
curl -s -X POST http://localhost:5173/svc/workload/workload-identity/registrations \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "data-processor-aws",
    "spiffe_id": "spiffe://example.com/cloud/aws/data-processor",
    "attestor_type": "aws_iid",
    "attestation_policy_id": "aws-data-processor-policy"
  }'
```

2. Create GCP IIT attestation policy:

```bash
curl -s -X POST http://localhost:5173/svc/workload/workload-identity/registrations \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "data-processor-gcp",
    "spiffe_id": "spiffe://example.com/cloud/gcp/data-processor",
    "attestor_type": "gcp_iit",
    "attestation_policy_id": "gcp-data-processor-policy"
  }'
```

3. Create a single key access policy granting decrypt to both SPIFFE IDs:

```bash
curl -s -X POST http://localhost:5173/api/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "data-processor-multicloud-access",
    "keyIds": ["key-processed-data-enc"],
    "rules": [
      {
        "principals": [
          "spiffe://example.com/cloud/aws/data-processor",
          "spiffe://example.com/cloud/gcp/data-processor"
        ],
        "operations": ["decrypt"],
        "effect": "allow"
      }
    ]
  }'
```

4. Each cloud instance uses the vecta-agent with the appropriate attestor and gets an SVID automatically. The same key access policy applies regardless of which cloud the workload is running in.

**Outcome:** The data processing service uses platform identity in both clouds with no static secrets. The key access policy is written once and applied uniformly. The workload identity graph shows both SPIFFE IDs connected to the same key.

---

### Use Case 7: TEE-Attested Database Key — Azure Confidential VM Only

**Context:** A database server stores encrypted PII. The database decryption key must only ever be available inside an Azure Confidential VM running the approved database image. No other process — not even Azure support or administrators — should be able to access the key.

**Steps:**

1. Obtain the expected launch measurement from the Azure CVM image. This is the `x-ms-sevsnpvm-launchmeasurement` claim from a known-good MAA attestation token for the approved image.

2. Create the attested key release policy:

```bash
curl -s -X PUT http://localhost:5173/svc/confidential/confidential/policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "allowed_tee_types": ["azure_snp"],
    "require_nonce": true
  }'
```

```bash
curl -s -X POST http://localhost:5173/svc/confidential/confidential/policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "azure-cvm-db-policy",
    "teeType": "azure_snp",
    "measurements": {
      "launchMeasurement": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
      "complianceStatus": "azure-compliant-uvm"
    },
    "attestationProvider": "microsoft_maa",
    "maaEndpoint": "https://sharedeus2.eus2.attest.azure.net",
    "allowedKeyIds": ["key-db-pii-master"],
    "requireFreshNonce": true,
    "nonceTimeWindowSecs": 300,
    "allowedOperations": ["decrypt", "unwrap"]
  }'
```

3. Inside the CVM, the database startup script fetches the MAA token and requests key release following the pattern in Section 2.

4. Verify releases are being logged:

```bash
curl -s "http://localhost:5173/svc/confidential/confidential/releases?tenant_id=root&policy_id=azure-cvm-db-policy" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Outcome:** The PII database decryption key is only released to the verified, measured CVM image. Even an Azure administrator with full access to the host cannot read the key from memory or extract it. The release audit log provides continuous evidence for compliance purposes.

---

### Use Case 8: Automated PQC Compliance Report for NIST Readiness

**Context:** The CISO needs a quarterly PQC readiness report for the board, showing progress against the NIST CNSA 2.0 timeline and identifying any new classical-only assets created since the last report.

**Steps:**

1. Run the PQC inventory and assessment:

```bash
# Get inventory snapshot
curl -s "http://localhost:5173/svc/pqc/pqc/inventory?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" > pqc_inventory_q1_2026.json

# Run fresh assessment
curl -s -X POST http://localhost:5173/svc/pqc/pqc/assess \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "root", "include_remediation": true}' > pqc_assessment_q1_2026.json
```

2. Get the migration report:

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/migration/report?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" > pqc_migration_q1_2026.json
```

3. Get the readiness score:

```bash
curl -s "http://localhost:5173/svc/pqc/pqc/readiness?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" > pqc_readiness_q1_2026.json
```

4. Use AI to generate the executive summary:

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "query": "Generate an executive summary of our PQC readiness status for a board-level audience, including: current readiness score, CNSA 2.0 compliance status, top 3 risks, migration progress since last quarter, and estimated timeline to full compliance.",
    "include_context": true
  }'
```

5. Generate the evidence pack for auditors:

```bash
curl -s -X POST http://localhost:5173/svc/reporting/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "template_id": "evidence_pack",
    "scope": {
      "domains": ["pqc"],
      "period_start": "2026-01-01",
      "period_end": "2026-03-31"
    }
  }'
```

**Outcome:** A complete, auditable PQC status package is produced in minutes rather than days: inventory snapshot, risk findings, migration progress, readiness score, CNSA 2.0 gap analysis, and an AI-generated board summary. The evidence pack is signed and timestamped, suitable for regulatory submission.

---

## Related References

- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture and service topology
- [ADMIN_GUIDE.md](ADMIN_GUIDE.md) — Deployment, configuration, and operational procedures
- [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md) — Feature overview and adoption guidance
- [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md) — Complete REST API surface reference
- [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md) — Additional workflow examples
- [openapi/README.md](openapi/README.md) — Machine-readable OpenAPI specifications
