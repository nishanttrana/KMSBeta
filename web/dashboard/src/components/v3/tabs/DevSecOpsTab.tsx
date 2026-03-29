// @ts-nocheck
import React, { useState } from "react";
import {
  BookOpen,
  Check,
  Code2,
  Copy,
  Download,
  GitBranch,
  Package,
  Server,
  Terminal,
  Wrench,
} from "lucide-react";
import { B, Btn, Tabs } from "../legacyPrimitives";
import { C } from "../theme";

// ─── Code block component ─────────────────────────────────────────────────────
function CodeBlock({ code, language = "bash", title }: { code: string; language?: string; title?: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div style={{ position: "relative", borderRadius: 9, overflow: "hidden", border: `1px solid ${C.border}` }}>
      {/* Code block header */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        background: "#161b22",
        padding: "7px 14px",
        borderBottom: `1px solid ${C.border}`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {title && <span style={{ fontSize: 10, color: "#8b949e", fontWeight: 600 }}>{title}</span>}
          <span style={{
            fontSize: 9,
            color: "#8b949e",
            background: "#21262d",
            padding: "1px 7px",
            borderRadius: 4,
            fontFamily: "'JetBrains Mono',monospace",
          }}>{language}</span>
        </div>
        <button
          onClick={handleCopy}
          style={{
            background: copied ? "#1a4731" : "#21262d",
            border: `1px solid ${copied ? "#2ea043" : "#30363d"}`,
            borderRadius: 5,
            padding: "3px 10px",
            color: copied ? "#3fb950" : "#8b949e",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: 5,
            fontSize: 10,
            fontWeight: 600,
            transition: "all .15s",
          }}
        >
          {copied ? <Check size={10} /> : <Copy size={10} />}
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
      {/* Code content */}
      <pre style={{
        background: "#0d1117",
        margin: 0,
        padding: "16px 20px",
        overflowX: "auto",
        fontSize: 12,
        fontFamily: "'JetBrains Mono',monospace",
        color: "#e6edf3",
        lineHeight: 1.6,
        whiteSpace: "pre",
      }}>
        {code}
      </pre>
    </div>
  );
}

// ─── Hero banner ──────────────────────────────────────────────────────────────
function HeroBanner({ icon: Icon, iconColor = C.accent, gradient, title, subtitle }: any) {
  return (
    <div style={{
      borderRadius: 12,
      padding: "24px 28px",
      marginBottom: 24,
      background: gradient || `linear-gradient(135deg, ${C.surface} 0%, ${C.accentTint} 100%)`,
      border: `1px solid ${C.borderHi}`,
      display: "flex",
      alignItems: "center",
      gap: 18,
    }}>
      <div style={{
        width: 50,
        height: 50,
        borderRadius: 13,
        background: iconColor + "18",
        border: `1px solid ${iconColor}33`,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexShrink: 0,
      }}>
        <Icon size={22} color={iconColor} />
      </div>
      <div>
        <div style={{ fontSize: 20, fontWeight: 800, color: C.text, letterSpacing: -0.6, marginBottom: 4 }}>{title}</div>
        <div style={{ fontSize: 12, color: C.dim, lineHeight: 1.5, maxWidth: 600 }}>{subtitle}</div>
      </div>
    </div>
  );
}

// ─── Step section ─────────────────────────────────────────────────────────────
function Step({ number, title, children }: { number: number; title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <div style={{
          width: 28,
          height: 28,
          borderRadius: 14,
          background: C.accentDim,
          border: `1px solid ${C.accent}44`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: C.accent }}>{number}</span>
        </div>
        <span style={{ fontSize: 13, fontWeight: 700, color: C.text, letterSpacing: -0.2 }}>{title}</span>
      </div>
      <div style={{ marginLeft: 40 }}>{children}</div>
    </div>
  );
}

// ─── Method badge ─────────────────────────────────────────────────────────────
function MethodBadge({ method }: { method: string }) {
  const styles: Record<string, { bg: string; color: string }> = {
    GET: { bg: C.greenDim, color: C.green },
    POST: { bg: C.blueDim, color: C.blue },
    PUT: { bg: C.amberDim, color: C.amber },
    PATCH: { bg: C.purpleDim, color: C.purple },
    DELETE: { bg: C.redDim, color: C.red },
  };
  const s = styles[method] || { bg: C.accentDim, color: C.accent };
  return (
    <span style={{
      background: s.bg,
      color: s.color,
      borderRadius: 4,
      padding: "2px 7px",
      fontSize: 9,
      fontWeight: 700,
      fontFamily: "'JetBrains Mono',monospace",
      letterSpacing: 0.3,
      display: "inline-block",
      minWidth: 50,
      textAlign: "center",
    }}>
      {method}
    </span>
  );
}

// ─── Inline code ──────────────────────────────────────────────────────────────
function IC({ children }: { children: React.ReactNode }) {
  return (
    <code style={{
      background: C.surface,
      border: `1px solid ${C.border}`,
      borderRadius: 4,
      padding: "1px 6px",
      fontSize: 11,
      fontFamily: "'JetBrains Mono',monospace",
      color: C.accent,
    }}>
      {children}
    </code>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Terraform snippets
// ═════════════════════════════════════════════════════════════════════════════

const TF_PROVIDER = `terraform {
  required_providers {
    vectakms = {
      source  = "vecta-io/vectakms"
      version = "~> 1.0"
    }
  }
}

provider "vectakms" {
  endpoint   = "https://your-kms.example.com"
  tenant_id  = var.tenant_id
  token      = var.kms_token      # or use VECTAKMS_TOKEN env var
}`;

const TF_CREATE_KEY = `resource "vectakms_key" "db_encryption_key" {
  name      = "prod-db-encryption"
  algorithm = "AES-256-GCM"
  purpose   = "encrypt"

  rotation_policy {
    period_days        = 90
    auto_rotate        = true
    notify_before_days = 7
  }

  tags = {
    environment = "production"
    data_class  = "confidential"
    owner       = "platform-team"
  }
}

output "db_key_id" {
  value     = vectakms_key.db_encryption_key.id
  sensitive = false
}`;

const TF_BYOK = `resource "vectakms_cloud_binding" "aws_byok" {
  key_id   = vectakms_key.db_encryption_key.id
  provider = "aws"
  region   = "us-east-1"

  account {
    account_id = var.aws_account_id
    role_arn   = var.aws_kms_admin_role_arn
  }
}

# Use in AWS RDS
resource "aws_db_instance" "app_db" {
  kms_key_id = vectakms_cloud_binding.aws_byok.cloud_key_arn
  # ...
}`;

const TF_SECRET = `resource "vectakms_secret" "db_password" {
  name        = "app/prod/db-password"
  secret_type = "database_credentials"
  value       = var.db_password

  lease_ttl_seconds = 86400  # 24 hours

  labels = {
    app = "my-service"
  }
}

# Reference in Kubernetes Secret
resource "kubernetes_secret" "db_creds" {
  data = {
    password = vectakms_secret.db_password.value
  }
}`;

// ═════════════════════════════════════════════════════════════════════════════
// CI/CD snippets
// ═════════════════════════════════════════════════════════════════════════════

const GITHUB_ACTIONS = `name: Deploy with KMS Key Rotation

on:
  push:
    branches: [main]

jobs:
  rotate-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Rotate encryption key
        run: |
          curl -s -X POST \\
            -H "Authorization: Bearer \${{ secrets.KMS_TOKEN }}" \\
            -H "X-Tenant-ID: \${{ vars.TENANT_ID }}" \\
            https://your-kms.example.com/svc/keycore/keys/\${{ vars.APP_KEY_ID }}/rotate

      - name: Get signing key for artifact signing
        id: get-key
        run: |
          KEY_VALUE=\$(curl -s \\
            -H "Authorization: Bearer \${{ secrets.KMS_TOKEN }}" \\
            -H "X-Tenant-ID: \${{ vars.TENANT_ID }}" \\
            "https://your-kms.example.com/svc/secrets/secrets/build-signing-key/value" \\
            | jq -r '.value')
          echo "::add-mask::\$KEY_VALUE"
          echo "key=\$KEY_VALUE" >> \$GITHUB_OUTPUT

      - name: Sign release artifact
        run: |
          echo "\${{ steps.get-key.outputs.key }}" > signing.key
          gpg --import signing.key
          gpg --detach-sign dist/release.tar.gz`;

const GITLAB_CI = `stages:
  - security
  - deploy

kms-compliance-gate:
  stage: security
  script:
    - |
      POSTURE=\$(curl -s \\
        -H "Authorization: Bearer \$KMS_TOKEN" \\
        -H "X-Tenant-ID: \$TENANT_ID" \\
        "\$KMS_ENDPOINT/svc/compliance/compliance/posture?tenant_id=\$TENANT_ID" \\
        | jq '.posture.overall_score')
      echo "Compliance score: \$POSTURE"
      if [ "\$POSTURE" -lt 60 ]; then
        echo "Compliance score too low (\$POSTURE/100) — blocking deployment"
        exit 1
      fi
  only:
    - main`;

const JENKINS_PIPELINE = `pipeline {
  agent any
  environment {
    KMS_TOKEN  = credentials('kms-api-token')
    TENANT_ID  = credentials('kms-tenant-id')
    KMS_ENDPOINT = 'https://your-kms.example.com'
  }
  stages {
    stage('Security Gate') {
      steps {
        sh '''
          curl -sf \\
            -H "Authorization: Bearer \$KMS_TOKEN" \\
            -H "X-Tenant-ID: \$TENANT_ID" \\
            "\$KMS_ENDPOINT/svc/compliance/risk/summary" | \\
            jq -e '.overall_level != "critical"'
        '''
      }
    }
    stage('Rotate Key') {
      steps {
        sh 'curl -sf -X POST -H "Authorization: Bearer \$KMS_TOKEN" -H "X-Tenant-ID: \$TENANT_ID" \$KMS_ENDPOINT/svc/keycore/keys/\$APP_KEY_ID/rotate'
      }
    }
  }
}`;

// ═════════════════════════════════════════════════════════════════════════════
// Ansible / Helm snippets
// ═════════════════════════════════════════════════════════════════════════════

const ANSIBLE_PLAYBOOK = `- name: Rotate KMS key and update application
  hosts: app_servers
  vars:
    kms_endpoint: "https://your-kms.example.com"
    tenant_id: "{{ lookup('env', 'TENANT_ID') }}"
    kms_token: "{{ lookup('env', 'KMS_TOKEN') }}"

  tasks:
    - name: Rotate application encryption key
      uri:
        url: "{{ kms_endpoint }}/svc/keycore/keys/{{ app_key_id }}/rotate"
        method: POST
        headers:
          Authorization: "Bearer {{ kms_token }}"
          X-Tenant-ID: "{{ tenant_id }}"
        status_code: 200
      register: rotation_result

    - name: Update application config with new key version
      template:
        src: app_config.j2
        dest: /etc/myapp/config.yml
      vars:
        key_version: "{{ rotation_result.json.version }}"

    - name: Restart application
      service:
        name: myapp
        state: restarted`;

const HELM_VALUES = `# values.yaml — KMS Helm integration
vectakms:
  enabled: true
  endpoint: "https://your-kms.example.com"
  tenantId: "your-tenant-id"
  # Store token in Kubernetes Secret, not here
  tokenSecretRef:
    name: "kms-credentials"
    key: "token"

encryption:
  keyId: "key_abc123"       # Key used for encrypting app data
  signingKeyId: "key_xyz"   # Key used for signing JWTs

sidecar:
  enabled: true              # Deploy KMS sidecar for local caching
  cacheTTL: 300              # 5-minute cache TTL
  image: vecta-io/kms-sidecar:latest`;

// ═════════════════════════════════════════════════════════════════════════════
// SDK snippets
// ═════════════════════════════════════════════════════════════════════════════

const SDK_GO = `package main

import (
  "context"
  "fmt"
  "os"

  kms "github.com/vecta-io/kms-go"
)

func main() {
  client := kms.New(kms.Config{
    Endpoint: "https://your-kms.example.com",
    Token:    os.Getenv("KMS_TOKEN"),
    TenantID: os.Getenv("TENANT_ID"),
  })

  ctx := context.Background()
  keyID := os.Getenv("APP_KEY_ID")
  plaintext := []byte("sensitive-data")

  // Encrypt
  result, err := client.Encrypt(ctx, keyID, plaintext, nil)
  if err != nil {
    panic(err)
  }
  fmt.Printf("Ciphertext: %s\\n", result.Ciphertext)

  // Decrypt
  decrypted, err := client.Decrypt(ctx, keyID, result.Ciphertext, nil)
  if err != nil {
    panic(err)
  }
  fmt.Printf("Plaintext: %s\\n", decrypted.Plaintext)
}`;

const SDK_PYTHON = `import os
from vectakms import Client

client = Client(
    endpoint="https://your-kms.example.com",
    token=os.environ["KMS_TOKEN"],
    tenant_id=os.environ["TENANT_ID"],
)

key_id = os.environ["APP_KEY_ID"]
plaintext = b"sensitive-data"

# Encrypt
result = client.encrypt(key_id=key_id, plaintext=plaintext)
print(f"Ciphertext: {result.ciphertext}")

# Decrypt
decrypted = client.decrypt(key_id=key_id, ciphertext=result.ciphertext)
print(f"Plaintext: {decrypted.plaintext}")

# Create a key
key = client.keys.create(
    name="my-service-key",
    algorithm="AES-256-GCM",
    purpose="encrypt",
)
print(f"Key ID: {key.id}")`;

const SDK_NODE = `import { KMSClient } from '@vecta/kms-client';

const client = new KMSClient({
  endpoint: process.env.KMS_ENDPOINT,
  token: process.env.KMS_TOKEN,
  tenantId: process.env.TENANT_ID,
});

const keyId = process.env.APP_KEY_ID;
const plaintext = Buffer.from('sensitive-data');

// Encrypt
const encrypted = await client.encrypt(keyId, plaintext);
console.log('Ciphertext:', encrypted.ciphertext);

// Decrypt
const decrypted = await client.decrypt(keyId, encrypted.ciphertext);
console.log('Plaintext:', decrypted.plaintext.toString());

// Create a key
const key = await client.keys.create({
  name: 'my-service-key',
  algorithm: 'AES-256-GCM',
  purpose: 'encrypt',
});
console.log('Key ID:', key.id);`;

const SDK_JAVA = `import io.vecta.kms.VectaKMSClient;
import io.vecta.kms.model.*;

public class KMSExample {
  public static void main(String[] args) throws Exception {
    VectaKMSClient client = VectaKMSClient.builder()
      .endpoint(System.getenv("KMS_ENDPOINT"))
      .token(System.getenv("KMS_TOKEN"))
      .tenantId(System.getenv("TENANT_ID"))
      .build();

    String keyId = System.getenv("APP_KEY_ID");
    byte[] plaintext = "sensitive-data".getBytes();

    // Encrypt
    EncryptResult enc = client.encrypt(EncryptRequest.builder()
      .keyId(keyId)
      .plaintext(plaintext)
      .build());
    System.out.println("Ciphertext: " + enc.getCiphertext());

    // Decrypt
    DecryptResult dec = client.decrypt(DecryptRequest.builder()
      .keyId(keyId)
      .ciphertext(enc.getCiphertext())
      .build());
    System.out.println("Plaintext: " + new String(dec.getPlaintext()));
  }
}`;

// ═════════════════════════════════════════════════════════════════════════════
// API reference data
// ═════════════════════════════════════════════════════════════════════════════

const API_ENDPOINTS = [
  // Key Management
  { group: "Key Management", method: "GET",    path: "/svc/keycore/keys",                   desc: "List all cryptographic keys",               auth: true },
  { group: "Key Management", method: "POST",   path: "/svc/keycore/keys",                   desc: "Create a new cryptographic key",            auth: true },
  { group: "Key Management", method: "GET",    path: "/svc/keycore/keys/{id}",              desc: "Get key details and metadata",              auth: true },
  { group: "Key Management", method: "PUT",    path: "/svc/keycore/keys/{id}",              desc: "Update key metadata or rotation policy",    auth: true },
  { group: "Key Management", method: "DELETE", path: "/svc/keycore/keys/{id}",              desc: "Delete / revoke a key",                     auth: true },
  { group: "Key Management", method: "POST",   path: "/svc/keycore/keys/{id}/encrypt",      desc: "Encrypt data envelope with key",            auth: true },
  { group: "Key Management", method: "POST",   path: "/svc/keycore/keys/{id}/decrypt",      desc: "Decrypt ciphertext using key",              auth: true },
  { group: "Key Management", method: "POST",   path: "/svc/keycore/keys/{id}/sign",         desc: "Sign message hash with asymmetric key",     auth: true },
  { group: "Key Management", method: "POST",   path: "/svc/keycore/keys/{id}/verify",       desc: "Verify a signature",                        auth: true },
  { group: "Key Management", method: "POST",   path: "/svc/keycore/keys/{id}/rotate",       desc: "Trigger key rotation (new version)",        auth: true },
  { group: "Key Management", method: "GET",    path: "/svc/keycore/keys/{id}/status",       desc: "Get key lifecycle status",                  auth: true },
  // Secrets
  { group: "Secrets",        method: "GET",    path: "/svc/secrets/secrets",                desc: "List application secrets",                  auth: true },
  { group: "Secrets",        method: "POST",   path: "/svc/secrets/secrets",                desc: "Create a new secret",                       auth: true },
  { group: "Secrets",        method: "GET",    path: "/svc/secrets/secrets/{id}/value",     desc: "Retrieve secret plaintext value",           auth: true },
  { group: "Secrets",        method: "DELETE", path: "/svc/secrets/secrets/{id}",           desc: "Delete a secret",                           auth: true },
  { group: "Secrets",        method: "POST",   path: "/svc/secrets/secrets/{id}/rotate",    desc: "Rotate secret value",                       auth: true },
  // Compliance
  { group: "Compliance",     method: "GET",    path: "/svc/compliance/compliance/posture",  desc: "Overall compliance posture score",          auth: true },
  { group: "Compliance",     method: "GET",    path: "/svc/compliance/evidence/export",     desc: "Export compliance evidence report",         auth: true },
  { group: "Compliance",     method: "GET",    path: "/svc/compliance/risk/keys",           desc: "Risk-ranked key inventory (DRI)",           auth: true },
  { group: "Compliance",     method: "GET",    path: "/svc/compliance/risk/summary",        desc: "Overall data risk summary",                 auth: true },
  { group: "Compliance",     method: "GET",    path: "/svc/compliance/risk/remediation",    desc: "Guided remediation action items",           auth: true },
  // Discovery
  { group: "Discovery",      method: "POST",   path: "/svc/discovery/scans",                desc: "Start a new discovery scan",                auth: true },
  { group: "Discovery",      method: "GET",    path: "/svc/discovery/scans",                desc: "List past discovery scans",                 auth: true },
  { group: "Discovery",      method: "GET",    path: "/svc/discovery/assets",               desc: "List discovered crypto assets",             auth: true },
  { group: "Discovery",      method: "POST",   path: "/svc/discovery/pii/scan",             desc: "Scan content for PII / PAN / PHI",         auth: true },
  { group: "Discovery",      method: "GET",    path: "/svc/discovery/summary",              desc: "Discovery fleet summary stats",             auth: true },
  { group: "Discovery",      method: "GET",    path: "/svc/discovery/lineage/{id}",         desc: "Data lineage for a specific asset",         auth: true },
  // TDE
  { group: "TDE",            method: "GET",    path: "/svc/kmip/tde/databases",             desc: "List TDE-registered databases",             auth: true },
  { group: "TDE",            method: "POST",   path: "/svc/kmip/tde/databases",             desc: "Register a database for TDE",               auth: true },
  { group: "TDE",            method: "POST",   path: "/svc/kmip/tde/databases/{id}/provision", desc: "Provision / rotate TDE master key",     auth: true },
  { group: "TDE",            method: "POST",   path: "/svc/kmip/tde/databases/{id}/revoke", desc: "Revoke TDE key for a database",             auth: true },
  { group: "TDE",            method: "GET",    path: "/svc/kmip/tde/status",                desc: "TDE fleet status summary",                  auth: true },
  // TFE
  { group: "TFE",            method: "GET",    path: "/svc/tfe/agents",                     desc: "List registered TFE agents",                auth: true },
  { group: "TFE",            method: "POST",   path: "/svc/tfe/agents",                     desc: "Register a new TFE agent",                  auth: true },
  { group: "TFE",            method: "DELETE", path: "/svc/tfe/agents/{id}",                desc: "Unregister / remove a TFE agent",           auth: true },
  { group: "TFE",            method: "GET",    path: "/svc/tfe/policies",                   desc: "List file encryption policies",             auth: true },
  { group: "TFE",            method: "POST",   path: "/svc/tfe/policies",                   desc: "Create a file encryption policy",           auth: true },
  { group: "TFE",            method: "GET",    path: "/svc/tfe/summary",                    desc: "TFE fleet summary statistics",              auth: true },
  // DAM
  { group: "DAM",            method: "POST",   path: "/svc/dam/activity/events",            desc: "Ingest an activity / access event",         auth: true },
  { group: "DAM",            method: "GET",    path: "/svc/dam/activity/events",            desc: "Query activity events with filters",        auth: true },
  { group: "DAM",            method: "GET",    path: "/svc/dam/activity/stats",             desc: "Activity statistics and actor summary",     auth: true },
  { group: "DAM",            method: "GET",    path: "/svc/dam/activity/actors",            desc: "Get top actors / access patterns",          auth: true },
  // AI Protect
  { group: "AI Protect",     method: "POST",   path: "/svc/aiprotect/scan",                 desc: "Scan AI prompt / response for PII",         auth: true },
  { group: "AI Protect",     method: "POST",   path: "/svc/aiprotect/redact",               desc: "Redact sensitive data from AI content",     auth: true },
  { group: "AI Protect",     method: "GET",    path: "/svc/aiprotect/policies",             desc: "List AI content inspection policies",       auth: true },
  { group: "AI Protect",     method: "POST",   path: "/svc/aiprotect/policies",             desc: "Create an AI content inspection policy",    auth: true },
  // Auth
  { group: "Auth",           method: "POST",   path: "/svc/auth/login",                     desc: "Authenticate and receive bearer token",     auth: false },
  { group: "Auth",           method: "POST",   path: "/svc/auth/sso/callback",              desc: "SSO OAuth callback handler",                auth: false },
  { group: "Auth",           method: "GET",    path: "/svc/auth/tenants",                   desc: "List tenants for authenticated user",       auth: true },
  { group: "Auth",           method: "POST",   path: "/svc/auth/tenants",                   desc: "Create a new tenant",                       auth: true },
  { group: "Auth",           method: "POST",   path: "/svc/auth/logout",                    desc: "Invalidate current session token",          auth: true },
];

const API_GROUPS = [...new Set(API_ENDPOINTS.map(e => e.group))];

// ═════════════════════════════════════════════════════════════════════════════
// Main component
// ═════════════════════════════════════════════════════════════════════════════

export const DevSecOpsTab = ({ session, onToast }: any) => {
  const [view, setView] = useState<"terraform" | "cicd" | "api" | "ansible" | "sdk">("terraform");
  const [sdkLang, setSdkLang] = useState("Go");
  const [apiGroupFilter, setApiGroupFilter] = useState("all");

  const tabDefs = [
    { id: "terraform" as const, label: "Terraform / IaC", icon: Package },
    { id: "cicd" as const, label: "CI/CD Pipelines", icon: GitBranch },
    { id: "api" as const, label: "REST API", icon: Server },
    { id: "ansible" as const, label: "Ansible / Helm", icon: Wrench },
    { id: "sdk" as const, label: "SDK Reference", icon: Code2 },
  ];

  const filteredEndpoints = apiGroupFilter === "all"
    ? API_ENDPOINTS
    : API_ENDPOINTS.filter(e => e.group === apiGroupFilter);

  const sdkSnippets: Record<string, string> = {
    "Go": SDK_GO,
    "Python": SDK_PYTHON,
    "Node.js": SDK_NODE,
    "Java": SDK_JAVA,
  };

  return (
    <div style={{ padding: "20px 24px", fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* ── Tab navigation ──────────────────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 0, marginBottom: 0, borderBottom: `1px solid ${C.border}` }}>
        {tabDefs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setView(id)}
            style={{
              padding: "9px 18px",
              border: "none",
              background: "transparent",
              cursor: "pointer",
              fontSize: 11,
              fontWeight: view === id ? 700 : 400,
              color: view === id ? C.accent : C.muted,
              borderBottom: view === id ? `2px solid ${C.accent}` : "2px solid transparent",
              marginBottom: -1,
              letterSpacing: 0.1,
              display: "flex",
              alignItems: "center",
              gap: 6,
              transition: "color .15s",
            }}
          >
            <Icon size={12} />
            {label}
          </button>
        ))}
      </div>

      <div style={{ paddingTop: 24 }}>

        {/* ════════════════════════════════════════════════════════════════
            TERRAFORM VIEW
        ════════════════════════════════════════════════════════════════ */}
        {view === "terraform" && (
          <div>
            <HeroBanner
              icon={Package}
              iconColor={C.purple}
              gradient={`linear-gradient(135deg, ${C.surface} 0%, ${C.purpleTint} 100%)`}
              title="Infrastructure as Code"
              subtitle="Declare and manage cryptographic keys, secrets, BYOK bindings, and compliance policies using the official Vecta KMS Terraform provider. Install via the Terraform registry: vecta-io/vectakms."
            />

            <Step number={1} title="Provider Configuration">
              <p style={{ fontSize: 12, color: C.dim, marginBottom: 10, marginTop: 0 }}>
                Add the Vecta KMS provider to your Terraform configuration and supply your endpoint, tenant ID, and token. The token can also be set via the <IC>VECTAKMS_TOKEN</IC> environment variable.
              </p>
              <CodeBlock code={TF_PROVIDER} language="terraform" title="main.tf" />
            </Step>

            <Step number={2} title="Create a KMS Key">
              <p style={{ fontSize: 12, color: C.dim, marginBottom: 10, marginTop: 0 }}>
                Declare a key resource with a rotation policy. The key ID is available as a Terraform output to reference in other resources.
              </p>
              <CodeBlock code={TF_CREATE_KEY} language="terraform" title="keys.tf" />
            </Step>

            <Step number={3} title="Bind BYOK to a Cloud Provider">
              <p style={{ fontSize: 12, color: C.dim, marginBottom: 10, marginTop: 0 }}>
                Use <IC>vectakms_cloud_binding</IC> to push your key into AWS KMS, Azure Key Vault, or GCP Cloud KMS, enabling BYOK for cloud-native services.
              </p>
              <CodeBlock code={TF_BYOK} language="terraform" title="byok.tf" />
            </Step>

            <Step number={4} title="Secret Lifecycle Management">
              <p style={{ fontSize: 12, color: C.dim, marginBottom: 10, marginTop: 0 }}>
                Manage application secrets as Terraform resources. Secrets are stored encrypted and can be referenced directly in Kubernetes Secrets, environment variables, and config maps.
              </p>
              <CodeBlock code={TF_SECRET} language="terraform" title="secrets.tf" />
            </Step>

            <div style={{ marginTop: 20, display: "flex", gap: 10 }}>
              <Btn primary>
                <Download size={11} />
                Download Provider Docs
              </Btn>
              <Btn>
                <BookOpen size={11} />
                Registry: vecta-io/vectakms
              </Btn>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════
            CI/CD VIEW
        ════════════════════════════════════════════════════════════════ */}
        {view === "cicd" && (
          <div>
            <HeroBanner
              icon={GitBranch}
              iconColor={C.green}
              gradient={`linear-gradient(135deg, ${C.surface} 0%, ${C.greenTint} 100%)`}
              title="CI/CD Pipeline Integration"
              subtitle="Automate key rotation, secret injection, compliance gating, and artifact signing directly in your GitHub Actions, GitLab CI, and Jenkins pipelines."
            />

            <Step number={1} title="GitHub Actions — Key Rotation + Artifact Signing">
              <CodeBlock code={GITHUB_ACTIONS} language="yaml" title=".github/workflows/deploy.yml" />
            </Step>

            <Step number={2} title="GitLab CI — Compliance Score Gate">
              <p style={{ fontSize: 12, color: C.dim, marginBottom: 10, marginTop: 0 }}>
                Block deployments when your compliance posture score drops below a threshold (e.g., 60/100).
              </p>
              <CodeBlock code={GITLAB_CI} language="yaml" title=".gitlab-ci.yml" />
            </Step>

            <Step number={3} title="Jenkins Pipeline — Security Gate + Key Rotation">
              <CodeBlock code={JENKINS_PIPELINE} language="groovy" title="Jenkinsfile" />
            </Step>

            {/* Environment variables reference */}
            <div style={{ marginTop: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12, letterSpacing: -0.2 }}>Required Environment Variables</div>
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Variable", "Description", "Storage Recommendation"].map(h => (
                        <th key={h} style={{ padding: "8px 14px", fontSize: 9, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: "0.1em", textAlign: "left", background: C.surface, borderBottom: `1px solid ${C.border}` }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { name: "KMS_TOKEN", desc: "API bearer token for authentication", rec: "CI secrets vault (never in code)" },
                      { name: "TENANT_ID", desc: "Your Vecta KMS tenant identifier", rec: "CI variable (non-secret)" },
                      { name: "KMS_ENDPOINT", desc: "Base URL of your KMS deployment", rec: "CI variable or Terraform output" },
                      { name: "APP_KEY_ID", desc: "Key ID used for application data encryption", rec: "CI variable or Terraform output" },
                    ].map(({ name, desc, rec }, idx) => (
                      <tr key={name} style={{ background: idx % 2 === 0 ? "transparent" : C.surface, borderBottom: `1px solid ${C.border}22` }}>
                        <td style={{ padding: "9px 14px" }}>
                          <code style={{ fontSize: 11, color: C.accent, fontFamily: "'JetBrains Mono',monospace" }}>{name}</code>
                        </td>
                        <td style={{ padding: "9px 14px", fontSize: 11, color: C.dim }}>{desc}</td>
                        <td style={{ padding: "9px 14px", fontSize: 11, color: C.muted }}>{rec}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════
            REST API VIEW
        ════════════════════════════════════════════════════════════════ */}
        {view === "api" && (
          <div>
            <HeroBanner
              icon={Server}
              iconColor={C.blue}
              gradient={`linear-gradient(135deg, ${C.surface} 0%, ${C.blueTint} 100%)`}
              title="REST API Quick Reference"
              subtitle={<>
                All endpoints are prefixed with <IC>/svc/&lt;service&gt;</IC> and require{" "}
                <IC>Authorization: Bearer &lt;token&gt;</IC> and <IC>X-Tenant-ID: &lt;tenant&gt;</IC>{" "}
                headers on every request.
              </>}
            />

            {/* Group filter */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
              <span style={{ fontSize: 10, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.6 }}>Filter by service:</span>
              {["all", ...API_GROUPS].map(g => (
                <button
                  key={g}
                  onClick={() => setApiGroupFilter(g)}
                  style={{
                    padding: "4px 10px",
                    borderRadius: 5,
                    border: `1px solid ${apiGroupFilter === g ? C.accent : C.border}`,
                    background: apiGroupFilter === g ? C.accentDim : "transparent",
                    color: apiGroupFilter === g ? C.accent : C.muted,
                    cursor: "pointer",
                    fontSize: 10,
                    fontWeight: apiGroupFilter === g ? 700 : 400,
                  }}
                >
                  {g === "all" ? "All Services" : g}
                </button>
              ))}
              <span style={{ fontSize: 10, color: C.muted, marginLeft: 4 }}>
                {filteredEndpoints.length} endpoint{filteredEndpoints.length !== 1 ? "s" : ""}
              </span>
            </div>

            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["Method", "Endpoint", "Description", "Auth"].map(h => (
                      <th key={h} style={{ padding: "8px 14px", fontSize: 9, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: "0.1em", textAlign: "left", background: C.surface, borderBottom: `1px solid ${C.border}` }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredEndpoints.map((ep, idx) => {
                    const showGroupHeader = idx === 0 || filteredEndpoints[idx - 1].group !== ep.group;
                    return (
                      <React.Fragment key={ep.method + ep.path}>
                        {showGroupHeader && (
                          <tr>
                            <td colSpan={4} style={{ padding: "10px 14px 6px", background: C.surface + "88" }}>
                              <span style={{ fontSize: 9, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: 0.8 }}>
                                {ep.group}
                              </span>
                            </td>
                          </tr>
                        )}
                        <tr
                          style={{ background: idx % 2 === 0 ? "transparent" : C.surface + "44", borderBottom: `1px solid ${C.border}22` }}
                          onMouseEnter={e => { e.currentTarget.style.background = C.cardHover; }}
                          onMouseLeave={e => { e.currentTarget.style.background = idx % 2 === 0 ? "transparent" : C.surface + "44"; }}
                        >
                          <td style={{ padding: "8px 14px", width: 80 }}>
                            <MethodBadge method={ep.method} />
                          </td>
                          <td style={{ padding: "8px 14px" }}>
                            <code style={{ fontSize: 11, color: C.accent, fontFamily: "'JetBrains Mono',monospace" }}>{ep.path}</code>
                          </td>
                          <td style={{ padding: "8px 14px", fontSize: 11, color: C.dim }}>{ep.desc}</td>
                          <td style={{ padding: "8px 14px" }}>
                            <B c={ep.auth ? "amber" : "green"}>{ep.auth ? "Required" : "Public"}</B>
                          </td>
                        </tr>
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════
            ANSIBLE / HELM VIEW
        ════════════════════════════════════════════════════════════════ */}
        {view === "ansible" && (
          <div>
            <HeroBanner
              icon={Wrench}
              iconColor={C.orange}
              gradient={`linear-gradient(135deg, ${C.surface} 0%, ${C.orangeDim} 100%)`}
              title="Configuration Management"
              subtitle="Automate KMS operations with Ansible playbooks for key rotation and lifecycle management, and inject KMS configuration into Kubernetes workloads via Helm."
            />

            <Step number={1} title="Ansible Playbook — Key Rotation and App Restart">
              <p style={{ fontSize: 12, color: C.dim, marginBottom: 10, marginTop: 0 }}>
                This playbook rotates the application encryption key, updates the app config with the new key version, and restarts the service to pick it up.
              </p>
              <CodeBlock code={ANSIBLE_PLAYBOOK} language="yaml" title="rotate-key.yml" />
            </Step>

            <Step number={2} title="Helm values.yaml — KMS Sidecar Injection">
              <p style={{ fontSize: 12, color: C.dim, marginBottom: 10, marginTop: 0 }}>
                Deploy the KMS sidecar container alongside your application for local key caching and transparent envelope encryption without modifying app code.
              </p>
              <CodeBlock code={HELM_VALUES} language="yaml" title="values.yaml" />
            </Step>

            {/* Tips */}
            <div style={{ marginTop: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12, letterSpacing: -0.2 }}>Best Practices</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {[
                  { title: "Use Ansible Vault for KMS tokens", desc: "Never commit the KMS token in plaintext. Use ansible-vault encrypt_string or pull from a secrets manager." },
                  { title: "Idempotent rotation playbooks", desc: "Check the current key version before rotating. Skip rotation if the key was rotated within the policy window." },
                  { title: "Helm: use secretRef for tokens", desc: "Configure the KMS token as a Kubernetes Secret and reference it via tokenSecretRef. Never put it in values.yaml." },
                  { title: "Set sidecar cache TTL", desc: "Use a 300s cache TTL for key metadata. This reduces KMS API calls without compromising security." },
                ].map(({ title, desc }) => (
                  <div key={title} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 9, padding: "12px 14px" }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 4 }}>{title}</div>
                    <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.5 }}>{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════
            SDK REFERENCE VIEW
        ════════════════════════════════════════════════════════════════ */}
        {view === "sdk" && (
          <div>
            <HeroBanner
              icon={Code2}
              iconColor={C.cyan}
              gradient={`linear-gradient(135deg, ${C.surface} 0%, ${C.cyanDim} 100%)`}
              title="SDK Integration"
              subtitle="Vecta KMS provides idiomatic client libraries for Go, Python, Node.js, and Java. All SDKs wrap the REST API with automatic retry, token refresh, circuit breaking, and envelope encryption support."
            />

            {/* Language tabs */}
            <div style={{ marginBottom: 16 }}>
              <Tabs tabs={["Go", "Python", "Node.js", "Java"]} active={sdkLang} onChange={setSdkLang} />
            </div>

            {/* Install command */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 8, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.6 }}>Install</div>
              <CodeBlock
                code={{
                  "Go": "go get github.com/vecta-io/kms-go",
                  "Python": "pip install vectakms",
                  "Node.js": "npm install @vecta/kms-client",
                  "Java": "// Maven\n<dependency>\n  <groupId>io.vecta</groupId>\n  <artifactId>kms-java</artifactId>\n  <version>1.0.0</version>\n</dependency>\n\n// Gradle\nimplementation 'io.vecta:kms-java:1.0.0'",
                }[sdkLang] || ""}
                language={{ "Go": "bash", "Python": "bash", "Node.js": "bash", "Java": "xml" }[sdkLang] || "bash"}
              />
            </div>

            {/* Code snippet */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 8, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.6 }}>Key Creation + Encrypt / Decrypt</div>
              <CodeBlock
                code={sdkSnippets[sdkLang] || ""}
                language={{ "Go": "go", "Python": "python", "Node.js": "typescript", "Java": "java" }[sdkLang] || "bash"}
                title={{ "Go": "main.go", "Python": "example.py", "Node.js": "index.ts", "Java": "KMSExample.java" }[sdkLang]}
              />
            </div>

            {/* Design principles */}
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 14, letterSpacing: -0.2 }}>Integration Best Practices</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {[
                  { num: "01", title: "Never store keys in code", desc: "Reference key IDs only. Key material stays in the KMS — your app receives encrypted data, never the raw key bytes." },
                  { num: "02", title: "Use envelope encryption for bulk data", desc: "Generate a DEK per operation, encrypt data with the DEK, then wrap the DEK with a KEK. Store only the wrapped DEK alongside ciphertext." },
                  { num: "03", title: "Cache with TTL, not indefinitely", desc: "Key metadata (not material) can be cached up to 5 minutes. The SDK handles this automatically. Never cache decrypted key material." },
                  { num: "04", title: "Rotate on schedule, not just on compromise", desc: "Use rotation policies: 90 days for data keys, 365 days for KEKs. Rotate immediately on suspected compromise." },
                  { num: "05", title: "Handle errors gracefully", desc: "The SDK includes automatic retry with exponential backoff. Implement circuit breakers at the application level for resilience." },
                  { num: "06", title: "Audit everything", desc: "Every encrypt/decrypt call is recorded. Feed the audit log APIs to your SIEM. Enable alert rules for anomalous access patterns." },
                ].map(({ num, title, desc }) => (
                  <div key={num} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 9, padding: "14px 16px", display: "flex", gap: 12 }}>
                    <div style={{ width: 26, height: 26, borderRadius: 7, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      <span style={{ fontSize: 9, fontWeight: 800, color: C.accent }}>{num}</span>
                    </div>
                    <div>
                      <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 4 }}>{title}</div>
                      <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.5 }}>{desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
