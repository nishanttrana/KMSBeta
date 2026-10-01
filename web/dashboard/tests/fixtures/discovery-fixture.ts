// Produced by services/discovery against a real TLS server (httptest), a
// real SSH server (golang.org/x/crypto/ssh), the cloud and certs test
// clients and an uploaded PEM bundle: StartScan, ScanUpload, ListAssets,
// ListScans, Sources, ListTargets and Summary. Loopback addresses were
// replaced with customer-looking ones (the service refuses loopback in
// production).
export const discoveryFixture = {
  "assets": [
    {
      "id": "asset_1c532fe2d0ec61e5",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
      "first_seen": "2026-10-01T05:09:08.308315Z",
      "last_seen": "2026-10-01T05:09:08.308315Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_32389fcfe11d3ace",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
      "first_seen": "2026-10-01T05:09:08.308315Z",
      "last_seen": "2026-10-01T05:09:08.308315Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_3d32a8d0ea1d9e98",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
      "first_seen": "2026-10-01T05:09:08.291716Z",
      "last_seen": "2026-10-01T05:09:08.291716Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_58582c640dc10919",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
        "fingerprint": "SHA256:BRsmaZOTi8dGgGBpGu2P4sS69zgXo5ta7GfMg1hNT0M",
        "key_type": "ecdsa-sha2-nistp256"
      },
      "first_seen": "2026-10-01T05:09:08.291716Z",
      "last_seen": "2026-10-01T05:09:08.291716Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_79695ec7a46fefc4",
      "tenant_id": "root",
      "scan_id": "scan_8dd6f9cfd746a011",
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
        "fingerprint": "ada7c17fb0d9e124796d97c1f89757f665e90da6ed7ba4c2c83d4d7a21a53941",
        "is_ca": false,
        "issuer": "CN=api.example.com",
        "line": 1,
        "not_after": "2026-10-13T05:09:11Z",
        "not_before": "2026-10-01T04:09:11Z",
        "self_signed": true,
        "serial": "7",
        "signature_algorithm": "ECDSA-SHA256",
        "subject": "CN=api.example.com"
      },
      "first_seen": "2026-10-01T05:09:11.512691Z",
      "last_seen": "2026-10-01T05:09:11.512691Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_92f85626a6904789",
      "tenant_id": "root",
      "scan_id": "scan_8dd6f9cfd746a011",
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
        "fingerprint": "SHA256:Hl4LMmoz2+rY1jJIhik9wPdAmjhYTRDNb3VdMjySv8Q",
        "key_type": "ssh-rsa",
        "line": 38
      },
      "first_seen": "2026-10-01T05:09:11.512691Z",
      "last_seen": "2026-10-01T05:09:11.512691Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_de35bdfe5a1ad237",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
        "fingerprint": "SHA256:JeKEVSm3B+yL80WmeO1w9V7sZ16GFQFiF7JzxwYle28",
        "key_type": "ssh-rsa"
      },
      "first_seen": "2026-10-01T05:09:08.291716Z",
      "last_seen": "2026-10-01T05:09:08.291716Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_ea03b7b131845f0c",
      "tenant_id": "root",
      "scan_id": "scan_8dd6f9cfd746a011",
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
        "fingerprint_sha256_prefix": "72f09c1408ed",
        "line": 10
      },
      "first_seen": "2026-10-01T05:09:11.512691Z",
      "last_seen": "2026-10-01T05:09:11.512691Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_ea32dfd6374ea86a",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
        "fingerprint": "SHA256:xQJ6rtg+EGtY18hqJjW7NWLZZffSgxRTq4ee9H6DDYo",
        "key_type": "ssh-ed25519"
      },
      "first_seen": "2026-10-01T05:09:08.291716Z",
      "last_seen": "2026-10-01T05:09:08.291716Z",
      "created_at": "2026-10-01T05:09:11Z",
      "updated_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "asset_092724eaa3b5041e",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
      "first_seen": "2026-10-01T05:09:08.283176Z",
      "last_seen": "2026-10-01T05:09:08.283176Z",
      "created_at": "2026-10-01T05:09:08Z",
      "updated_at": "2026-10-01T05:09:08Z"
    },
    {
      "id": "asset_346a79343c403a93",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
      "first_seen": "2026-10-01T05:09:08.283169Z",
      "last_seen": "2026-10-01T05:09:08.28317Z",
      "created_at": "2026-10-01T05:09:08Z",
      "updated_at": "2026-10-01T05:09:08Z"
    },
    {
      "id": "asset_3c7020bb53e25531",
      "tenant_id": "root",
      "scan_id": "scan_c433fdcfaaeea450",
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
      "first_seen": "2026-10-01T05:09:08.28315Z",
      "last_seen": "2026-10-01T05:09:08.28315Z",
      "created_at": "2026-10-01T05:09:08Z",
      "updated_at": "2026-10-01T05:09:08Z"
    }
  ],
  "scans": [
    {
      "id": "scan_8dd6f9cfd746a011",
      "tenant_id": "root",
      "scan_type": "upload",
      "status": "completed",
      "trigger": "upload",
      "stats": {
        "assets_discovered": 3,
        "bytes": 2592,
        "file": "bundle.pem",
        "sources_done": [
          "upload"
        ],
        "upload_assets": 3
      },
      "started_at": "2026-10-01T05:09:11.512294Z",
      "completed_at": "2026-10-01T05:09:11.513148Z",
      "created_at": "2026-10-01T05:09:11Z"
    },
    {
      "id": "scan_c433fdcfaaeea450",
      "tenant_id": "root",
      "scan_type": "network,cloud,certs,code",
      "status": "completed_with_errors",
      "trigger": "manual",
      "stats": {
        "assets_discovered": 9,
        "certs_assets": 2,
        "cloud_assets": 1,
        "code_assets": 0,
        "errors": {
          "code": "scan source not configured: mount the source tree and set WORKSPACE_ROOT to scan code"
        },
        "network_assets": 6,
        "network_endpoints": 16,
        "network_no_service": 14,
        "network_skipped": 0,
        "sources_done": [
          "code",
          "cloud",
          "certs",
          "network"
        ]
      },
      "started_at": "2026-10-01T05:09:08.282396Z",
      "completed_at": "2026-10-01T05:09:11.285601Z",
      "created_at": "2026-10-01T05:09:08Z"
    }
  ],
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
        "scan_id": "scan_c433fdcfaaeea450",
        "started_at": "2026-10-01T05:09:08.282396Z",
        "at": "2026-10-01T05:09:11.285601Z",
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
        "scan_id": "scan_c433fdcfaaeea450",
        "started_at": "2026-10-01T05:09:08.282396Z",
        "at": "2026-10-01T05:09:11.285601Z",
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
        "scan_id": "scan_c433fdcfaaeea450",
        "started_at": "2026-10-01T05:09:08.282396Z",
        "at": "2026-10-01T05:09:11.285601Z",
        "assets": 2
      }
    },
    {
      "id": "code",
      "configured": false,
      "detail": {},
      "last_scan": {
        "scan_id": "scan_c433fdcfaaeea450",
        "started_at": "2026-10-01T05:09:08.282396Z",
        "at": "2026-10-01T05:09:11.285601Z",
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
        "scan_id": "scan_8dd6f9cfd746a011",
        "started_at": "2026-10-01T05:09:11.512294Z",
        "at": "2026-10-01T05:09:11.513148Z",
        "assets": 3
      }
    }
  ],
  "summary": {
    "tenant_id": "root",
    "total_assets": 12,
    "source_distribution": {
      "certs": 2,
      "cloud": 1,
      "network": 6,
      "upload": 3
    },
    "algorithm_distribution": {
      "ECDH-P256": 1,
      "ECDSA-P256": 2,
      "ED25519": 1,
      "ML-DSA-65": 1,
      "RSA-2048": 4,
      "RSA-3072": 1,
      "SYMMETRIC_DEFAULT": 1,
      "X25519-ML-KEM-768-HYBRID": 1
    },
    "classification_counts": {
      "exposed": 1,
      "quantum_vulnerable": 8,
      "strong": 2,
      "unknown": 1,
      "weak": 0
    },
    "pqc_ready_count": 2,
    "pqc_readiness_percent": 16.67,
    "algorithm_classes": {
      "ECDH-P256": {
        "quantum_vulnerable": 1
      },
      "ECDSA-P256": {
        "quantum_vulnerable": 2
      },
      "ED25519": {
        "quantum_vulnerable": 1
      },
      "ML-DSA-65": {
        "strong": 1
      },
      "RSA-2048": {
        "exposed": 1,
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
      "created_at": "2026-10-01T05:09:08Z"
    },
    {
      "id": "target_ssh",
      "tenant_id": "root",
      "host": "10.20.30.14",
      "port": 22,
      "protocol": "ssh",
      "created_by": "admin",
      "created_at": "2026-10-01T05:09:08Z"
    }
  ]
} as const;
