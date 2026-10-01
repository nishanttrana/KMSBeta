// Produced by services/discovery against a real TLS server (httptest), a
// real SSH server (golang.org/x/crypto/ssh), an HTTPS server serving a git
// archive at GitLab's API path, the cloud and certs test clients and an
// uploaded PEM bundle: StartScan, ScanUpload, SaveSchedule, ListAssets,
// ListScans, Sources, ListTargets, ListRepositories and Summary. The
// "storage" source is as Sources reports it with no bucket added. Loopback
// addresses were replaced with customer-looking ones (the service refuses
// loopback in production).
export const discoveryFixture = {
  "assets": [
    {
      "id": "asset_14c18f791694b659",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "tls_endpoint",
      "name": "api.example.com:443",
      "location": "api.example.com:443",
      "source": "network",
      "algorithm": "X25519-ML-KEM-768-HYBRID",
      "strength_bits": 0,
      "status": "active",
      "classification": "strong",
      "pqc_ready": true,
      "qsl_score": 100,
      "metadata": {
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "key_exchange": "X25519-ML-KEM-768-HYBRID",
        "protocol": "TLS 1.3"
      },
      "first_seen": "2026-10-01T09:54:08.803895Z",
      "last_seen": "2026-10-01T09:54:08.803895Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_1d95cc4042c4a59f",
      "tenant_id": "root",
      "scan_id": "scan_1f0ec40ffcf01410",
      "asset_type": "private_key_material",
      "name": "bundle.pem",
      "location": "bundle.pem:10",
      "source": "upload",
      "algorithm": "RSA-2048",
      "strength_bits": 112,
      "status": "active",
      "classification": "exposed",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "file": "bundle.pem",
        "fingerprint_sha256_prefix": "05dc2206db2d",
        "line": 10
      },
      "first_seen": "2026-10-01T09:54:11.856594Z",
      "last_seen": "2026-10-01T09:54:11.856594Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_3f88e7e3195b7678",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "ssh_host_key",
      "name": "10.20.30.14:22 ecdsa-sha2-nistp256",
      "location": "10.20.30.14:22",
      "source": "network",
      "algorithm": "ECDSA-P256",
      "strength_bits": 128,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "fingerprint": "SHA256:FgkI4llh/j1/3j5s4tkNcr78WSBSjsNSHFQetizIZjk",
        "key_type": "ecdsa-sha2-nistp256"
      },
      "first_seen": "2026-10-01T09:54:08.789998Z",
      "last_seen": "2026-10-01T09:54:08.789998Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_4340a62f2ae9e87a",
      "tenant_id": "root",
      "scan_id": "scan_1f0ec40ffcf01410",
      "asset_type": "certificate",
      "name": "api.example.com",
      "location": "bundle.pem:1",
      "source": "upload",
      "algorithm": "ECDSA-P256",
      "strength_bits": 128,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "dns_names": [
          "api.example.com"
        ],
        "file": "bundle.pem",
        "fingerprint": "ab68ceb8c34b6fc38995490c2e0c2807d5d01a3adb0d64dffa43e60e113eca79",
        "is_ca": false,
        "issuer": "CN=api.example.com",
        "line": 1,
        "not_after": "2026-10-13T09:54:11Z",
        "not_before": "2026-10-01T08:54:11Z",
        "self_signed": true,
        "serial": "7",
        "signature_algorithm": "ECDSA-SHA256",
        "subject": "CN=api.example.com"
      },
      "first_seen": "2026-10-01T09:54:11.856594Z",
      "last_seen": "2026-10-01T09:54:11.856594Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_760766d53116421b",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "ssh_host_key",
      "name": "10.20.30.14:22 ssh-ed25519",
      "location": "10.20.30.14:22",
      "source": "network",
      "algorithm": "ED25519",
      "strength_bits": 128,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "fingerprint": "SHA256:4j29xFGODTvs+JNKGQq2bcVnJESRv7oN8dUh5WZIWYA",
        "key_type": "ssh-ed25519"
      },
      "first_seen": "2026-10-01T09:54:08.789998Z",
      "last_seen": "2026-10-01T09:54:08.789998Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_7fe34b94fc0090d9",
      "tenant_id": "root",
      "scan_id": "scan_1f0ec40ffcf01410",
      "asset_type": "ssh_public_key",
      "name": "deploy@ci",
      "location": "bundle.pem:38",
      "source": "upload",
      "algorithm": "RSA-2048",
      "strength_bits": 112,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "file": "bundle.pem",
        "fingerprint": "SHA256:bOmLxjeLTY5IfhCTI/dflzj1/Rvu7a6TTknWpeIRqjA",
        "key_type": "ssh-rsa",
        "line": 38
      },
      "first_seen": "2026-10-01T09:54:11.856594Z",
      "last_seen": "2026-10-01T09:54:11.856594Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_b440659bdde389c8",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "ssh_host_key",
      "name": "10.20.30.14:22 ssh-rsa",
      "location": "10.20.30.14:22",
      "source": "network",
      "algorithm": "RSA-2048",
      "strength_bits": 112,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "fingerprint": "SHA256:Z3j3KZGRVJdMQaX32PPWl54AaiIKW6iRkFciP4+zjGU",
        "key_type": "ssh-rsa"
      },
      "first_seen": "2026-10-01T09:54:08.789998Z",
      "last_seen": "2026-10-01T09:54:08.789998Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_bd5fbbe32c9f14fd",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "ssh_endpoint",
      "name": "10.20.30.14:22",
      "location": "10.20.30.14:22",
      "source": "network",
      "algorithm": "ECDH-P256",
      "strength_bits": 128,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "ciphers_offered": [
          "aes128-gcm@openssh.com",
          "aes256-gcm@openssh.com",
          "aes128-ctr",
          "aes192-ctr",
          "aes256-ctr"
        ],
        "host_key_algorithms": [
          "ssh-ed25519",
          "rsa-sha2-256",
          "rsa-sha2-512",
          "ssh-rsa",
          "ecdsa-sha2-nistp256"
        ],
        "key_exchange_offered": [
          "ecdh-sha2-nistp256"
        ],
        "macs_offered": [
          "hmac-sha2-256-etm@openssh.com",
          "hmac-sha2-512-etm@openssh.com",
          "hmac-sha2-256",
          "hmac-sha2-512"
        ],
        "protocol": "SSH-2.0",
        "selection": "strongest offered",
        "server": "Go",
        "weak_ciphers_offered": [],
        "weak_key_exchange_offered": [],
        "weak_macs_offered": []
      },
      "first_seen": "2026-10-01T09:54:08.789998Z",
      "last_seen": "2026-10-01T09:54:08.789998Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_db2c762d38a9dbe2",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "tls_certificate",
      "name": "example.com",
      "location": "api.example.com:443",
      "source": "network",
      "algorithm": "RSA-2048",
      "strength_bits": 112,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "chain_trusted": false,
        "issuer": "O=Acme Co",
        "not_after": "2084-01-29T16:00:00Z",
        "signature_algorithm": "SHA256-RSA",
        "subject": "O=Acme Co"
      },
      "first_seen": "2026-10-01T09:54:08.803895Z",
      "last_seen": "2026-10-01T09:54:08.803895Z",
      "created_at": "2026-10-01T09:54:11Z",
      "updated_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "asset_092724eaa3b5041e",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "certificate",
      "name": "pqc.vecta.local",
      "location": "pqc.vecta.local",
      "source": "certs",
      "algorithm": "ML-DSA-65",
      "strength_bits": 192,
      "status": "active",
      "classification": "strong",
      "pqc_ready": true,
      "qsl_score": 100,
      "metadata": {
        "cert_id": "c2",
        "not_after": ""
      },
      "first_seen": "2026-10-01T09:54:08.78121Z",
      "last_seen": "2026-10-01T09:54:08.78121Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_1682073d7aaa5853",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "hex_secret",
      "name": ".env.production",
      "location": "gitlab.example.com/acme/app@main/config/.env.production:3",
      "source": "git",
      "algorithm": "",
      "strength_bits": 0,
      "status": "active",
      "classification": "exposed",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "file": "gitlab.example.com/acme/app@main/config/.env.production",
        "fingerprint_sha256_prefix": "7b3d979ca833",
        "line": 3,
        "path": "config/.env.production",
        "ref": "main",
        "repository": "https://gitlab.example.com/acme/app"
      },
      "first_seen": "2026-10-01T09:54:08.790629Z",
      "last_seen": "2026-10-01T09:54:08.790629Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_346a79343c403a93",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "certificate",
      "name": "api.vecta.local",
      "location": "api.vecta.local",
      "source": "certs",
      "algorithm": "RSA-3072",
      "strength_bits": 128,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "cert_id": "c1",
        "not_after": ""
      },
      "first_seen": "2026-10-01T09:54:08.78119Z",
      "last_seen": "2026-10-01T09:54:08.781191Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_3c7020bb53e25531",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "kms_key",
      "name": "k-1",
      "location": "aws/us-east-1",
      "source": "cloud",
      "algorithm": "SYMMETRIC_DEFAULT",
      "strength_bits": 0,
      "status": "enabled",
      "classification": "unknown",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "account_id": "acct-1",
        "cloud_key_ref": "",
        "managed_by_vecta": null,
        "provider": "aws"
      },
      "first_seen": "2026-10-01T09:54:08.781186Z",
      "last_seen": "2026-10-01T09:54:08.781186Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_6801f182e5ce8710",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "private_key_material",
      "name": "id_rsa",
      "location": "gitlab.example.com/acme/app@main/deploy/id_rsa:1",
      "source": "git",
      "algorithm": "RSA-2048",
      "strength_bits": 112,
      "status": "active",
      "classification": "exposed",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "file": "gitlab.example.com/acme/app@main/deploy/id_rsa",
        "fingerprint_sha256_prefix": "ecde3cd536a0",
        "line": 1,
        "path": "deploy/id_rsa",
        "ref": "main",
        "repository": "https://gitlab.example.com/acme/app"
      },
      "first_seen": "2026-10-01T09:54:08.790382Z",
      "last_seen": "2026-10-01T09:54:08.790382Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_6b2dbba92af456f2",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "cloud_access_key",
      "name": ".env.production",
      "location": "gitlab.example.com/acme/docs/config/.env.production:2",
      "source": "git",
      "algorithm": "",
      "strength_bits": 0,
      "status": "active",
      "classification": "exposed",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "file": "gitlab.example.com/acme/docs/config/.env.production",
        "fingerprint_sha256_prefix": "457643f44d19",
        "line": 2,
        "path": "config/.env.production",
        "repository": "https://gitlab.example.com/acme/docs"
      },
      "first_seen": "2026-10-01T09:54:08.790317Z",
      "last_seen": "2026-10-01T09:54:08.790317Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_8787dd835907977e",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "hex_secret",
      "name": ".env.production",
      "location": "gitlab.example.com/acme/docs/config/.env.production:3",
      "source": "git",
      "algorithm": "",
      "strength_bits": 0,
      "status": "active",
      "classification": "exposed",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "file": "gitlab.example.com/acme/docs/config/.env.production",
        "fingerprint_sha256_prefix": "7b3d979ca833",
        "line": 3,
        "path": "config/.env.production",
        "repository": "https://gitlab.example.com/acme/docs"
      },
      "first_seen": "2026-10-01T09:54:08.790317Z",
      "last_seen": "2026-10-01T09:54:08.790317Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_9990e096a679136c",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "cloud_access_key",
      "name": ".env.production",
      "location": "gitlab.example.com/acme/app@main/config/.env.production:2",
      "source": "git",
      "algorithm": "",
      "strength_bits": 0,
      "status": "active",
      "classification": "exposed",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "file": "gitlab.example.com/acme/app@main/config/.env.production",
        "fingerprint_sha256_prefix": "457643f44d19",
        "line": 2,
        "path": "config/.env.production",
        "ref": "main",
        "repository": "https://gitlab.example.com/acme/app"
      },
      "first_seen": "2026-10-01T09:54:08.790629Z",
      "last_seen": "2026-10-01T09:54:08.790629Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_ac39cf5476009a8f",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "private_key_material",
      "name": "id_rsa",
      "location": "gitlab.example.com/acme/docs/deploy/id_rsa:1",
      "source": "git",
      "algorithm": "RSA-2048",
      "strength_bits": 112,
      "status": "active",
      "classification": "exposed",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "file": "gitlab.example.com/acme/docs/deploy/id_rsa",
        "fingerprint_sha256_prefix": "ecde3cd536a0",
        "line": 1,
        "path": "deploy/id_rsa",
        "repository": "https://gitlab.example.com/acme/docs"
      },
      "first_seen": "2026-10-01T09:54:08.789849Z",
      "last_seen": "2026-10-01T09:54:08.789849Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_bc7993c74efcea73",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "certificate",
      "name": "api.example.com",
      "location": "gitlab.example.com/acme/app@main/certs/server.crt:1",
      "source": "git",
      "algorithm": "ECDSA-P256",
      "strength_bits": 128,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "dns_names": [
          "api.example.com"
        ],
        "file": "gitlab.example.com/acme/app@main/certs/server.crt",
        "fingerprint": "47cb84a84fd0a018fa998ea0474b3af8013aa435973d3b96400af776a87a5756",
        "is_ca": false,
        "issuer": "CN=api.example.com",
        "line": 1,
        "not_after": "2026-12-30T09:54:08Z",
        "not_before": "2026-10-01T08:54:08Z",
        "path": "certs/server.crt",
        "ref": "main",
        "repository": "https://gitlab.example.com/acme/app",
        "self_signed": true,
        "serial": "7",
        "signature_algorithm": "ECDSA-SHA256",
        "subject": "CN=api.example.com"
      },
      "first_seen": "2026-10-01T09:54:08.790595Z",
      "last_seen": "2026-10-01T09:54:08.790595Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "asset_bd4174cd31957e77",
      "tenant_id": "root",
      "scan_id": "scan_90300bbbc9524d63",
      "asset_type": "certificate",
      "name": "api.example.com",
      "location": "gitlab.example.com/acme/docs/certs/server.crt:1",
      "source": "git",
      "algorithm": "ECDSA-P256",
      "strength_bits": 128,
      "status": "active",
      "classification": "quantum_vulnerable",
      "pqc_ready": false,
      "qsl_score": 0,
      "metadata": {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "dns_names": [
          "api.example.com"
        ],
        "file": "gitlab.example.com/acme/docs/certs/server.crt",
        "fingerprint": "47cb84a84fd0a018fa998ea0474b3af8013aa435973d3b96400af776a87a5756",
        "is_ca": false,
        "issuer": "CN=api.example.com",
        "line": 1,
        "not_after": "2026-12-30T09:54:08Z",
        "not_before": "2026-10-01T08:54:08Z",
        "path": "certs/server.crt",
        "repository": "https://gitlab.example.com/acme/docs",
        "self_signed": true,
        "serial": "7",
        "signature_algorithm": "ECDSA-SHA256",
        "subject": "CN=api.example.com"
      },
      "first_seen": "2026-10-01T09:54:08.790234Z",
      "last_seen": "2026-10-01T09:54:08.790234Z",
      "created_at": "2026-10-01T09:54:08Z",
      "updated_at": "2026-10-01T09:54:08Z"
    }
  ],
  "repositories": [
    {
      "id": "repo_app",
      "tenant_id": "root",
      "url": "https://gitlab.example.com/acme/app",
      "ref": "main",
      "provider": "gitlab",
      "connection_id": "pbconn_git1",
      "created_by": "admin",
      "created_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "repo_docs",
      "tenant_id": "root",
      "url": "https://gitlab.example.com/acme/docs",
      "ref": "",
      "provider": "gitlab",
      "connection_id": "",
      "created_by": "admin",
      "created_at": "2026-10-01T09:54:08Z"
    }
  ],
  "scans": [
    {
      "id": "scan_1f0ec40ffcf01410",
      "tenant_id": "root",
      "scan_type": "upload",
      "status": "completed",
      "trigger": "upload",
      "stats": {
        "assets_discovered": 3,
        "bytes": 2588,
        "file": "bundle.pem",
        "sources_done": [
          "upload"
        ],
        "upload_assets": 3
      },
      "started_at": "2026-10-01T09:54:11.856005Z",
      "completed_at": "2026-10-01T09:54:11.856868Z",
      "created_at": "2026-10-01T09:54:11Z"
    },
    {
      "id": "scan_90300bbbc9524d63",
      "tenant_id": "root",
      "scan_type": "network,cloud,certs,git,code",
      "status": "completed_with_errors",
      "trigger": "manual",
      "stats": {
        "assets_discovered": 17,
        "certs_assets": 2,
        "cloud_assets": 1,
        "code_assets": 0,
        "errors": {
          "code": "scan source not configured: mount the source tree and set WORKSPACE_ROOT to scan code"
        },
        "git_assets": 8,
        "git_files": 8,
        "git_repositories": 2,
        "network_assets": 6,
        "network_endpoints": 16,
        "network_no_service": 14,
        "network_skipped": 0,
        "sources_done": [
          "code",
          "cloud",
          "certs",
          "git",
          "network"
        ]
      },
      "started_at": "2026-10-01T09:54:08.780867Z",
      "completed_at": "2026-10-01T09:54:11.786394Z",
      "created_at": "2026-10-01T09:54:08Z"
    }
  ],
  "schedule": {
    "tenant_id": "root",
    "enabled": true,
    "interval_hours": 24,
    "sources": [
      "network",
      "cloud",
      "certs",
      "git"
    ],
    "authorized_by": "admin",
    "next_run_at": "2026-10-02T09:54:11.856913Z",
    "last_run_at": "0001-01-01T00:00:00Z",
    "last_scan_id": "",
    "paused_reason": "",
    "updated_at": "2026-10-01T09:54:11Z"
  },
  "sources": [
    {
      "id": "network",
      "configured": true,
      "detail": {
        "addresses": 16,
        "hosts": 1,
        "operator_endpoints": 0,
        "ranges": 1,
        "ssh": 1,
        "targets": 2
      },
      "last_scan": {
        "scan_id": "scan_90300bbbc9524d63",
        "started_at": "2026-10-01T09:54:08.780867Z",
        "at": "2026-10-01T09:54:11.786394Z",
        "assets": 6
      }
    },
    {
      "id": "cloud",
      "configured": true,
      "detail": {
        "accounts": 1,
        "providers": [
          "aws"
        ]
      },
      "last_scan": {
        "scan_id": "scan_90300bbbc9524d63",
        "started_at": "2026-10-01T09:54:08.780867Z",
        "at": "2026-10-01T09:54:11.786394Z",
        "assets": 1
      }
    },
    {
      "id": "certs",
      "configured": true,
      "detail": {
        "certificates": 2
      },
      "last_scan": {
        "scan_id": "scan_90300bbbc9524d63",
        "started_at": "2026-10-01T09:54:08.780867Z",
        "at": "2026-10-01T09:54:11.786394Z",
        "assets": 2
      }
    },
    {
      "id": "git",
      "configured": true,
      "detail": {
        "private": 1,
        "repositories": 2
      },
      "last_scan": {
        "scan_id": "scan_90300bbbc9524d63",
        "started_at": "2026-10-01T09:54:08.780867Z",
        "at": "2026-10-01T09:54:11.786394Z",
        "assets": 8
      }
    },
    {
      "id": "storage",
      "configured": false,
      "detail": {
        "buckets": 0,
        "private": 0
      }
    },
    {
      "id": "code",
      "configured": false,
      "detail": {},
      "last_scan": {
        "scan_id": "scan_90300bbbc9524d63",
        "started_at": "2026-10-01T09:54:08.780867Z",
        "at": "2026-10-01T09:54:11.786394Z",
        "assets": 0,
        "error": "scan source not configured: mount the source tree and set WORKSPACE_ROOT to scan code"
      }
    },
    {
      "id": "upload",
      "configured": true,
      "detail": {
        "max_bytes": 2097152
      },
      "last_scan": {
        "scan_id": "scan_1f0ec40ffcf01410",
        "started_at": "2026-10-01T09:54:11.856005Z",
        "at": "2026-10-01T09:54:11.856868Z",
        "assets": 3
      }
    }
  ],
  "summary": {
    "tenant_id": "root",
    "total_assets": 20,
    "source_distribution": {
      "certs": 2,
      "cloud": 1,
      "git": 8,
      "network": 6,
      "upload": 3
    },
    "algorithm_distribution": {
      "": 4,
      "ECDH-P256": 1,
      "ECDSA-P256": 4,
      "ED25519": 1,
      "ML-DSA-65": 1,
      "RSA-2048": 6,
      "RSA-3072": 1,
      "SYMMETRIC_DEFAULT": 1,
      "X25519-ML-KEM-768-HYBRID": 1
    },
    "classification_counts": {
      "exposed": 7,
      "quantum_vulnerable": 10,
      "strong": 2,
      "unknown": 1,
      "weak": 0
    },
    "pqc_ready_count": 2,
    "pqc_readiness_percent": 10,
    "algorithm_classes": {
      "": {
        "exposed": 4
      },
      "ECDH-P256": {
        "quantum_vulnerable": 1
      },
      "ECDSA-P256": {
        "quantum_vulnerable": 4
      },
      "ED25519": {
        "quantum_vulnerable": 1
      },
      "ML-DSA-65": {
        "strong": 1
      },
      "RSA-2048": {
        "exposed": 3,
        "quantum_vulnerable": 3
      },
      "RSA-3072": {
        "quantum_vulnerable": 1
      },
      "SYMMETRIC_DEFAULT": {
        "unknown": 1
      },
      "X25519-ML-KEM-768-HYBRID": {
        "strong": 1
      }
    },
    "source_classification": {
      "certs": {
        "quantum_vulnerable": 1,
        "strong": 1
      },
      "cloud": {
        "unknown": 1
      },
      "git": {
        "exposed": 6,
        "quantum_vulnerable": 2
      },
      "network": {
        "quantum_vulnerable": 5,
        "strong": 1
      },
      "upload": {
        "exposed": 1,
        "quantum_vulnerable": 2
      }
    },
    "expiring_30d": 1
  },
  "targets": [
    {
      "id": "target_rng",
      "tenant_id": "root",
      "host": "10.20.30.0/28",
      "port": 443,
      "protocol": "tls",
      "created_by": "admin",
      "created_at": "2026-10-01T09:54:08Z"
    },
    {
      "id": "target_ssh",
      "tenant_id": "root",
      "host": "10.20.30.14",
      "port": 22,
      "protocol": "ssh",
      "created_by": "admin",
      "created_at": "2026-10-01T09:54:08Z"
    }
  ]
} as const;
