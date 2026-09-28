# Generated Product Map

Generated at `2026-09-28T08:27:40Z` by `scripts/generate_product_map.py`.

This file is generated from source. Re-run the script after UI or API changes.

## Summary

- Dashboard navigation items: `27`
- Tab/component mappings: `35`
- Sub-pane groups: `8`
- Backend HTTP routes discovered: `930` across `30` services
- Backend routes on the `pkg/route` kernel: `182` (permission and audit action in `backend-routes.csv`)
- Frontend API call sites discovered: `578`
- Frontend call sites with exact backend route match: `531`
- Frontend call sites needing review or dynamic/runtime confirmation: `47`
- Clickable controls with static `onClick` handlers: `766`
- Backend request flows with handler/service/package summaries: `930`

## How To Use This For Launch

1. Start with `Navigation To Services` and pick one product tab.
2. Review its service dependencies and then open the linked component/support files.
3. Use `Frontend Calls Needing Review` to find clicks that may hit missing, aliased, dynamic, or unimplemented routes.
4. Use `Backend Routes Not Directly Called From Dashboard` to decide whether each route is API-only, hidden behind a workflow, or dead weight.
5. Pair this static map with Playwright smoke tests and runtime request logging before launch.

## Visual Service Map

```mermaid
flowchart LR
  UI[Dashboard UI]
  tab_home["Command Center"]
  UI --> tab_home
  tab_home --> svc_auth_edge
  tab_recommendations["Recommendations"]
  UI --> tab_recommendations
  tab_recommendations --> svc_auth_edge
  tab_ops["Operations"]
  UI --> tab_ops
  tab_ops --> svc_audit
  tab_ops --> svc_auth_edge
  tab_ops --> svc_certs
  tab_ops --> svc_cluster_manager
  tab_ops --> svc_compliance
  tab_ops --> svc_governance
  tab_ops --> svc_keycore
  tab_ops --> svc_reporting
  tab_ops --> svc_secrets
  tab_keys["Key Management"]
  UI --> tab_keys
  tab_keys --> svc_auth
  tab_keys --> svc_keycore
  tab_crypto_agility["Crypto Agility"]
  UI --> tab_crypto_agility
  tab_crypto_agility --> svc_keycore
  tab_certs["Certificates / PKI"]
  UI --> tab_certs
  tab_certs --> svc_certs
  tab_certs --> svc_keycore
  tab_vault["Secret Vault"]
  UI --> tab_vault
  tab_vault --> svc_auth_edge
  tab_vault --> svc_secrets
  tab_ekm["Enterprise KM"]
  UI --> tab_ekm
  tab_ekm --> svc_ekm
  tab_ekm --> svc_tfe
  tab_hsm["HSM"]
  UI --> tab_hsm
  tab_hsm --> svc_auth
  tab_ai_gateway["AI Security Gateway"]
  UI --> tab_ai_gateway
  tab_ai_gateway --> svc_ai
  tab_ai_gateway --> svc_ai_gateway
  tab_audit["Audit Log"]
  UI --> tab_audit
  tab_audit --> svc_audit
  tab_alerts["Alert Center"]
  UI --> tab_alerts
  tab_alerts --> svc_auth_edge
  tab_alerts --> svc_reporting
  tab_approvals["Approvals"]
  UI --> tab_approvals
  tab_approvals --> svc_compliance
  tab_approvals --> svc_governance
  tab_posture["Posture"]
  UI --> tab_posture
  tab_posture --> svc_auth
  tab_posture --> svc_autokey
  tab_posture --> svc_keyaccess
  tab_posture --> svc_posture
  tab_posture --> svc_signing
  tab_posture --> svc_workload
  tab_compliance["Compliance"]
  UI --> tab_compliance
  tab_compliance --> svc_auth
  tab_compliance --> svc_autokey
  tab_compliance --> svc_certs
  tab_compliance --> svc_compliance
  tab_compliance --> svc_keyaccess
  tab_compliance --> svc_keycore
  tab_compliance --> svc_pqc
  tab_compliance --> svc_reporting
  tab_compliance --> svc_signing
  tab_compliance --> svc_workload
  tab_sbom["SBOM / CBOM"]
  UI --> tab_sbom
  tab_sbom --> svc_sbom
  tab_cluster["Cluster"]
  UI --> tab_cluster
  tab_cluster --> svc_auth_edge
  tab_cluster --> svc_cluster_manager
  tab_backup["Backup & Restore"]
  UI --> tab_backup
  tab_backup --> svc_backup
  tab_byok["byok"]
  UI --> tab_byok
  tab_byok --> svc_cloud
  tab_crypto["crypto"]
  UI --> tab_crypto
  tab_crypto --> svc_keycore
  tab_hyok["hyok"]
  UI --> tab_hyok
  tab_hyok --> svc_hyok
  tab_payment["payment"]
  UI --> tab_payment
  tab_payment --> svc_payment
  tab_pkcs11["pkcs11"]
  UI --> tab_pkcs11
  tab_pkcs11 --> svc_ekm
  tab_pkcs11 --> svc_tfe
  tab_restapi["restapi"]
  UI --> tab_restapi
  tab_restapi --> svc_auth
  tab_restapi --> svc_auth_edge
  tab_restapi --> svc_certs
  tab_restapi --> svc_secrets
  svc_ai["ai"]
  svc_ai_gateway["ai-gateway (31 routes)"]
  svc_audit["audit (51 routes)"]
  svc_auth["auth (86 routes)"]
  svc_auth_edge["auth-edge"]
  svc_autokey["autokey (15 routes)"]
  svc_backup["backup (11 routes)"]
  svc_certs["certs (68 routes)"]
  svc_cloud["cloud (14 routes)"]
  svc_cluster_manager["cluster-manager (21 routes)"]
  svc_compliance["compliance (58 routes)"]
  svc_ekm["ekm (64 routes)"]
  svc_governance["governance (35 routes)"]
  svc_hyok["hyok (21 routes)"]
  svc_keyaccess["keyaccess (9 routes)"]
  svc_keycore["keycore (163 routes)"]
  svc_payment["payment (42 routes)"]
  svc_posture["posture (12 routes)"]
  svc_pqc["pqc (16 routes)"]
  svc_reporting["reporting (33 routes)"]
  svc_sbom["sbom (18 routes)"]
  svc_secrets["secrets (25 routes)"]
  svc_signing["signing (11 routes)"]
  svc_tfe["tfe"]
  svc_workload["workload (16 routes)"]
```

A standalone Mermaid file is also written to `docs/generated/product-map.mmd`.

## Navigation To Services

| Group | UI item | Tab id | Component | Service dependencies | Static call sites |
| --- | --- | --- | --- | --- | --- |
| Overview | Command Center | home | web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | auth-edge | 4 |
| Overview | Recommendations | recommendations | web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | auth-edge | 4 |
| Overview | Operations | ops | web/dashboard/src/components/v3/tabs/DashboardTab.tsx | audit, auth-edge, certs, cluster-manager, compliance, governance, keycore, reporting, secrets | 206 |
| Overview | Workbench | workbench | web/dashboard/src/components/v3/tabs/WorkbenchTab.tsx | - | 0 |
| Overview | Analytics | key_analytics | web/dashboard/src/components/v3/tabs/KeyAnalyticsTab.tsx | - | 0 |
| Keys & lifecycle | Key Management | keys | web/dashboard/src/components/v3/tabs/KeysTab.tsx | auth, keycore | 98 |
| Keys & lifecycle | Rotation & Scheduling | rotation | web/dashboard/src/components/v3/tabs/RotationSchedulingTab.tsx | - | 0 |
| Keys & lifecycle | Crypto Agility | crypto_agility | web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | keycore | 5 |
| PKI & certificates | Certificates / PKI | certs | web/dashboard/src/components/v3/tabs/CertsTab.tsx | certs, keycore | 104 |
| Data & integrations | Secret Vault | vault | web/dashboard/src/components/v3/tabs/VaultTab.tsx | auth-edge, secrets | 14 |
| Data & integrations | Data Protection | dataprotection | web/dashboard/src/components/v3/tabs/DataProtectionTabs.tsx | - | 0 |
| Data & integrations | Cloud Key Control | cloudctl | web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | - | 0 |
| Data & integrations | Enterprise KM | ekm | web/dashboard/src/components/v3/tabs/EKMTab.tsx | ekm, tfe | 46 |
| Data & integrations | HSM | hsm | web/dashboard/src/components/v3/tabs/HSMTab.tsx | auth | 45 |
| Data & integrations | AI Security Gateway | ai_gateway | web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | ai, ai-gateway | 26 |
| Security & compliance | Audit Log | audit | web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | audit | 16 |
| Security & compliance | Alert Center | alerts | web/dashboard/src/components/v3/tabs/AlertsTab.tsx | auth-edge, reporting | 26 |
| Security & compliance | Approvals | approvals | web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | compliance, governance | 24 |
| Security & compliance | Posture | posture | web/dashboard/src/components/v3/tabs/PostureTab.tsx | auth, autokey, keyaccess, posture, signing, workload | 91 |
| Security & compliance | Compliance | compliance | web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | auth, autokey, certs, compliance, keyaccess, keycore, pqc, reporting, signing, workload | 179 |
| Security & compliance | SBOM / CBOM | sbom | web/dashboard/src/components/v3/tabs/SBOMTab.tsx | sbom | 16 |
| Security & compliance | Playbooks | playbooks | web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | - | 0 |
| Platform | Cluster | cluster | web/dashboard/src/components/v3/tabs/ClusterTab.tsx | auth-edge, cluster-manager | 15 |
| Platform | Backup & Restore | backup | web/dashboard/src/components/v3/tabs/BackupTab.tsx | backup | 10 |
| Platform | DevSecOps / IaC | devsecops | web/dashboard/src/components/v3/tabs/DevSecOpsTab.tsx | - | 0 |
| Platform | Administration | admin | web/dashboard/src/components/v3/tabs/AdminTab.tsx | - | 0 |
| Platform | Documentation | docs | web/dashboard/src/components/v3/tabs/DocsViewTab.tsx | - | 0 |
| UNLISTED | byok | byok | web/dashboard/src/components/v3/tabs/BYOKTab.tsx | cloud | 10 |
| UNLISTED | crypto | crypto | web/dashboard/src/components/v3/tabs/CryptoTab.tsx | keycore | 53 |
| UNLISTED | dataenc | dataenc | web/dashboard/src/components/v3/tabs/DataProtectionTabs.tsx | - | 0 |
| UNLISTED | hyok | hyok | web/dashboard/src/components/v3/tabs/HYOKTab.tsx | hyok | 7 |
| UNLISTED | payment | payment | web/dashboard/src/components/v3/tabs/PaymentTab.tsx | payment | 27 |
| UNLISTED | pkcs11 | pkcs11 | web/dashboard/src/components/v3/tabs/ClientSDKTab.tsx | ekm, tfe | 46 |
| UNLISTED | restapi | restapi | web/dashboard/src/components/v3/tabs/RestAPITab.tsx | auth, auth-edge, certs, secrets | 110 |
| UNLISTED | tokenize | tokenize | web/dashboard/src/components/v3/tabs/DataProtectionTabs.tsx | - | 0 |

## Backend Route Counts

| Service | Routes | Frontend call sites |
| --- | --- | --- |
| ai-gateway | 31 | 23 |
| audit | 51 | 27 |
| auth | 86 | 45 |
| autokey | 15 | 11 |
| backup | 11 | 10 |
| certs | 68 | 52 |
| cloud | 14 | 10 |
| cluster-manager | 21 | 11 |
| compliance | 58 | 19 |
| confidential | 7 | 6 |
| dataprotect | 50 | 29 |
| discovery | 12 | 6 |
| ekm | 64 | 45 |
| governance | 35 | 23 |
| hsm-connector | 12 | 0 |
| hyok | 21 | 7 |
| keyaccess | 9 | 6 |
| keycore | 163 | 113 |
| kmip | 14 | 11 |
| payment | 42 | 27 |
| policy | 12 | 0 |
| posture | 12 | 8 |
| pqc | 16 | 6 |
| reconciler | 1 | 1 |
| reporting | 33 | 23 |
| sbom | 18 | 16 |
| secrets | 25 | 10 |
| signing | 11 | 9 |
| watchdog | 2 | 2 |
| workload | 16 | 12 |

## Frontend Calls Needing Review

These are not necessarily broken. Common reasons include dynamic wrapper paths, service aliases, edge auth routes, API-only calls, or routes generated outside `mux.HandleFunc`.

| Service | Method | Path | Source | File | Line |
| --- | --- | --- | --- | --- | --- |
| ai | GET | /ai/protect/policies | serviceRequest | web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 395 |
| ai | POST | /ai/protect/policies | serviceRequest | web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 610 |
| ai | DELETE | /ai/protect/policies/{param} | serviceRequest | web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 623 |
| audit | PUT | /alerts/{param}/acknowledge | serviceRequest | web/dashboard/src/lib/audit.ts | 285 |
| audit | PUT | /alerts/{param}/resolve | serviceRequest | web/dashboard/src/lib/audit.ts | 301 |
| keycore | GET | /audit/chain | trackedFetch | web/dashboard/src/lib/auditChain.ts | 6 |
| keycore | POST | /audit/chain/verify | trackedFetch | web/dashboard/src/lib/auditChain.ts | 12 |
| keycore | POST | /audit/chain/anchor | trackedFetch | web/dashboard/src/lib/auditChain.ts | 21 |
| keycore | GET | /audit/events | trackedFetch | web/dashboard/src/lib/auditChain.ts | 30 |
| audit | POST | /audit/events | serviceRequest | web/dashboard/src/lib/auditLogger.ts | 20 |
| auth-edge | POST | /auth/logout | trackedFetch | web/dashboard/src/lib/auth.ts | 148 |
| auth-edge | POST | /auth/login | trackedFetch | web/dashboard/src/lib/auth.ts | 190 |
| auth-edge | POST | /auth/change-password | trackedFetch | web/dashboard/src/lib/auth.ts | 277 |
| auth-edge | POST | /auth/refresh | trackedFetch | web/dashboard/src/lib/auth.ts | 324 |
| auth | GET | /auth/identity/providers/{param}/users{param}` : ""} | serviceRequest | web/dashboard/src/lib/authAdmin.ts | 898 |
| auth | GET | /auth/identity/providers/{param}/groups{param}` : ""} | serviceRequest | web/dashboard/src/lib/authAdmin.ts | 928 |
| auth | GET | /auth/identity/providers/{param}/groups/{param}/members{param}` : ""} | serviceRequest | web/dashboard/src/lib/authAdmin.ts | 954 |
| cloud | GET | /cloud/accounts{param} | serviceRequest | web/dashboard/src/lib/cloud.ts | 127 |
| cloud | GET | /cloud/region-mappings{param} | serviceRequest | web/dashboard/src/lib/cloud.ts | 163 |
| cloud | GET | /cloud/inventory{param} | serviceRequest | web/dashboard/src/lib/cloud.ts | 242 |
| cloud | GET | /cloud/bindings{param} | serviceRequest | web/dashboard/src/lib/cloud.ts | 263 |
| keycore | GET | /cost/metrics | trackedFetch | web/dashboard/src/lib/costOptimization.ts | 6 |
| keycore | GET | /cost/suggestions | trackedFetch | web/dashboard/src/lib/costOptimization.ts | 12 |
| keycore | POST | /cost/suggestions/{param}/apply | trackedFetch | web/dashboard/src/lib/costOptimization.ts | 18 |
| ekm | GET | /ekm/agents/{param}/validate-deploy | serviceRequest | web/dashboard/src/lib/ekm.ts | 981 |
| tfe | GET | /tfe/file-encrypt/download | serviceRequest | web/dashboard/src/lib/ekm.ts | 1028 |
| hyok | POST | /hyok/{param}/v1/keys/{param}/{param} | serviceRequest | web/dashboard/src/lib/hyok.ts | 180 |
| keycore | GET | /analytics/keys | trackedFetch | web/dashboard/src/lib/keyAnalytics.ts | 7 |
| keycore | GET | /analytics/report | trackedFetch | web/dashboard/src/lib/keyAnalytics.ts | 13 |
| keycore | GET | /analytics/usage-timeline | trackedFetch | web/dashboard/src/lib/keyAnalytics.ts | 19 |
| keycore | GET | /federation/peers | trackedFetch | web/dashboard/src/lib/keyFederation.ts | 6 |
| keycore | POST | /federation/peers | trackedFetch | web/dashboard/src/lib/keyFederation.ts | 12 |
| keycore | POST | /federation/peers/{param}/sync | trackedFetch | web/dashboard/src/lib/keyFederation.ts | 22 |
| keycore | DELETE | /federation/peers/{param} | trackedFetch | web/dashboard/src/lib/keyFederation.ts | 31 |
| keycore | GET | /health/scores | trackedFetch | web/dashboard/src/lib/keyHealth.ts | 6 |
| keycore | POST | /health/scores/{param}/refresh | trackedFetch | web/dashboard/src/lib/keyHealth.ts | 12 |
| keycore | GET | /inventory/export | trackedFetch | web/dashboard/src/lib/keyInventory.ts | 18 |
| keycore | GET | /ml/anomalies | trackedFetch | web/dashboard/src/lib/mlAnomaly.ts | 6 |
| keycore | POST | /ml/detect | trackedFetch | web/dashboard/src/lib/mlAnomaly.ts | 12 |
| keycore | GET | /ml/access-heatmap | trackedFetch | web/dashboard/src/lib/mlAnomaly.ts | 21 |
| keycore | POST | /ml/anomalies/{param}/dismiss | trackedFetch | web/dashboard/src/lib/mlAnomaly.ts | 27 |
| keycore | GET | /compliance/regulatory | trackedFetch | web/dashboard/src/lib/regulatory.ts | 6 |
| keycore | GET | /compliance/dashboard | trackedFetch | web/dashboard/src/lib/regulatory.ts | 12 |
| keycore | GET | /compliance/report | trackedFetch | web/dashboard/src/lib/regulatory.ts | 18 |
| reporting | PUT | /alerts/{param}/acknowledge | serviceRequest | web/dashboard/src/lib/reporting.ts | 236 |
| reporting | PUT | /alerts/{param}/escalate | serviceRequest | web/dashboard/src/lib/reporting.ts | 275 |
| keycore | GET | /rotation/runs{param} | serviceRequest | web/dashboard/src/lib/rotationScheduler.ts | 88 |

Showing `47` of `47`. Full data is in `docs/generated/product-map.json` and `docs/generated/frontend-calls.csv`.

## Backend Routes Not Directly Called From Dashboard

These may be public API routes, protocol integrations, routes used through SDKs, or unused implementation. They should be classified before launch.

| Service | Method | Path | Handler | Permission | File | Line |
| --- | --- | --- | --- | --- | --- | --- |
| ai-gateway | POST | /ai-gateway/v1/chat/completions | h.handleChatCompletions |  | services/ai-gateway/handler.go | 30 |
| ai-gateway | POST | /ai-gateway/v1/completions | h.handleCompletions |  | services/ai-gateway/handler.go | 31 |
| ai-gateway | POST | /ai-gateway/v1/embeddings | h.handleEmbeddings |  | services/ai-gateway/handler.go | 32 |
| ai-gateway | GET | /ai-gateway/v1/policies/{id} | h.handleGetPolicy |  | services/ai-gateway/handler.go | 42 |
| ai-gateway | PUT | /ai-gateway/v1/policies/{id} | h.handleUpdatePolicy |  | services/ai-gateway/handler.go | 43 |
| ai-gateway | PUT | /ai-gateway/v1/models/{id} | h.handleUpdateModel |  | services/ai-gateway/handler.go | 49 |
| ai-gateway | GET | /ai-gateway/v1/audit/{id} | h.handleGetAudit |  | services/ai-gateway/handler.go | 72 |
| ai-gateway | GET | /ai-gateway/v1/metrics | h.handleMetrics |  | services/ai-gateway/handler.go | 76 |
| audit | POST | /audit/publish | h.handlePublish |  | services/audit/handler.go | 81 |
| audit | POST | /audit/search | h.handleSearch |  | services/audit/handler.go | 87 |
| audit | GET | /audit/stats | h.handleAuditStats |  | services/audit/handler.go | 89 |
| audit | GET | /audit/stream | h.handleStream |  | services/audit/handler.go | 90 |
| audit | GET | /alerts/{id} | h.handleAlert |  | services/audit/handler.go | 94 |
| audit | PUT | /alerts/{id}/{action} | h.handleAlertActionPath |  | services/audit/handler.go | 95 |
| audit | GET | /alerts/stream | h.handleAlertStream |  | services/audit/handler.go | 97 |
| audit | POST | /alerts/rules | h.handleCreateRule |  | services/audit/handler.go | 98 |
| audit | GET | /alerts/rules | h.handleListRules |  | services/audit/handler.go | 99 |
| audit | PUT | /alerts/rules/{id} | h.handleUpdateRule |  | services/audit/handler.go | 100 |
| audit | DELETE | /alerts/rules/{id} | h.handleDeleteRule |  | services/audit/handler.go | 101 |
| audit | POST | /alerts/test-rule | h.handleTestRule |  | services/audit/handler.go | 102 |
| audit | GET | /alerts/channels | h.handleGetChannels |  | services/audit/handler.go | 103 |
| audit | PUT | /alerts/channels | h.handleUpdateChannels |  | services/audit/handler.go | 104 |
| audit | POST | /alerts/channels/test | h.handleTestChannel |  | services/audit/handler.go | 105 |
| audit | GET | /audit/merkle/epochs/{id} | h.handleMerkleEpoch |  | services/audit/handler.go | 110 |
| audit | POST | /audit/cluster/signing-key/join-key | h.handleClusterKeyJoinKey |  | services/audit/handler.go | 116 |
| audit | POST | /audit/cluster/signing-key/export | h.handleClusterKeyExport |  | services/audit/handler.go | 117 |
| audit | POST | /audit/cluster/signing-key/import | h.handleClusterKeyImport |  | services/audit/handler.go | 118 |
| audit | GET | /ops-metrics/timeseries | h.handleGetOpsTimeSeries |  | services/audit/handler.go | 125 |
| audit | GET | /audit/fips/boundary | h.handleFIPSBoundary |  | services/audit/handler.go | 131 |
| audit | GET | /audit/cbom/inventory | h.handleCBOMInventory |  | services/audit/handler.go | 134 |
| audit | GET | /audit/cbom/diff | h.handleCBOMDiff |  | services/audit/handler.go | 135 |
| audit | GET | /metrics | h.handlePrometheusMetrics |  | services/audit/handler.go | 138 |
| auth | POST | /auth/delegated/authority | h.delegatedAuthority | authenticated | services/auth/delegated.go | 69 |
| auth | POST | /auth/delegated/users/{id}/disable | h.delegatedDisableUser | authenticated | services/auth/delegated.go | 70 |
| auth | POST | /auth/delegated/api-keys/{id}/revoke | h.delegatedRevokeAPIKey | authenticated | services/auth/delegated.go | 71 |
| auth | POST | /auth/delegated/clients/{id}/revoke | h.delegatedRevokeClient | authenticated | services/auth/delegated.go | 72 |
| auth | POST | /auth/register | h.handleRegister |  | services/auth/handler.go | 64 |
| auth | GET | /auth/register/{id}/status | h.handleRegistrationStatus |  | services/auth/handler.go | 65 |
| auth | POST | /auth/login | h.handleLogin |  | services/auth/handler.go | 66 |
| auth | POST | /auth/client-token | h.handleClientToken |  | services/auth/handler.go | 67 |
| auth | POST | /auth/cluster/mint | h.handleClusterMint |  | services/auth/handler.go | 68 |
| auth | POST | /auth/workload-token | h.handleIssueWorkloadToken |  | services/auth/handler.go | 69 |
| auth | POST | /auth/refresh | h.withAuth(h.handleRefresh, "auth.token.refresh") |  | services/auth/handler.go | 72 |
| auth | POST | /auth/change-password | h.withAuth(h.handleChangePassword, "") |  | services/auth/handler.go | 73 |
| auth | POST | /auth/register/{id}/activate | h.withAuth(h.handleActivateRegistration, "auth.client.activate") |  | services/auth/handler.go | 75 |
| auth | POST | /auth/logout | h.withAuth(h.handleLogout, "auth.session.logout") |  | services/auth/handler.go | 76 |
| auth | GET | /auth/me | h.withAuth(h.handleMe, "auth.self.read") |  | services/auth/handler.go | 77 |
| auth | GET | /tenants/{id} | h.withAuth(h.handleGetTenant, "auth.tenant.read", "super-admin") |  | services/auth/handler.go | 81 |
| auth | POST | /tenants/{id}/roles | h.withAuth(h.handleCreateTenantRole, "auth.role.write", "super-admin") |  | services/auth/handler.go | 86 |
| auth | PUT | /tenants/{id}/roles/{name} | h.withAuth(h.handleUpdateTenantRole, "auth.role.write", "super-admin") |  | services/auth/handler.go | 87 |
| auth | DELETE | /tenants/{id}/roles/{name} | h.withAuth(h.handleDeleteTenantRole, "auth.role.write", "super-admin") |  | services/auth/handler.go | 88 |
| auth | GET | /auth/users | h.withAuth(h.handleListUsers, "auth.user.read") |  | services/auth/handler.go | 90 |
| auth | GET | /auth/identity/providers/{provider} | h.withAuth(h.handleGetIdentityProviderConfig, "auth.user.read") |  | services/auth/handler.go | 93 |
| auth | GET | /auth/identity/providers/{provider}/users | h.withAuth(h.handleListIdentityProviderUsers, "auth.user.read") |  | services/auth/handler.go | 96 |
| auth | GET | /auth/identity/providers/{provider}/groups | h.withAuth(h.handleListIdentityProviderGroups, "auth.user.read") |  | services/auth/handler.go | 97 |
| auth | GET | /auth/identity/providers/{provider}/groups/{id}/members | h.withAuth(h.handleListIdentityProviderGroupMembers, "auth.user.read") |  | services/auth/handler.go | 98 |
| auth | POST | /auth/api-keys | h.withAuth(h.handleCreateAPIKey, "auth.api_key.write") |  | services/auth/handler.go | 121 |
| auth | DELETE | /auth/api-keys/{id} | h.withAuth(h.handleDeleteAPIKey, "auth.api_key.write") |  | services/auth/handler.go | 122 |
| auth | POST | /auth/sso/{provider}/callback | h.handleSSOCallback |  | services/auth/handler.go | 127 |
| auth | GET | /auth/sso/{provider}/callback | h.handleSSOCallback |  | services/auth/handler.go | 128 |
| auth | GET | /auth/sso/saml/metadata | h.handleSAMLMetadata |  | services/auth/handler.go | 129 |
| auth | GET | /scim/v2/ServiceProviderConfig | h.handleSCIMServiceProviderConfig |  | services/auth/handler.go | 137 |
| auth | GET | /scim/v2/Schemas | h.handleSCIMSchemas |  | services/auth/handler.go | 138 |
| auth | GET | /scim/v2/ResourceTypes | h.handleSCIMResourceTypes |  | services/auth/handler.go | 139 |
| auth | GET | /scim/v2/Users | h.handleSCIMListUsers |  | services/auth/handler.go | 140 |
| auth | POST | /scim/v2/Users | h.handleSCIMCreateUser |  | services/auth/handler.go | 141 |
| auth | GET | /scim/v2/Users/{id} | h.handleSCIMGetUser |  | services/auth/handler.go | 142 |
| auth | PUT | /scim/v2/Users/{id} | h.handleSCIMReplaceUser |  | services/auth/handler.go | 143 |
| auth | PATCH | /scim/v2/Users/{id} | h.handleSCIMPatchUser |  | services/auth/handler.go | 144 |
| auth | DELETE | /scim/v2/Users/{id} | h.handleSCIMDeleteUser |  | services/auth/handler.go | 145 |
| auth | GET | /scim/v2/Groups | h.handleSCIMListGroups |  | services/auth/handler.go | 146 |
| auth | POST | /scim/v2/Groups | h.handleSCIMCreateGroup |  | services/auth/handler.go | 147 |
| auth | GET | /scim/v2/Groups/{id} | h.handleSCIMGetGroup |  | services/auth/handler.go | 148 |
| auth | PUT | /scim/v2/Groups/{id} | h.handleSCIMReplaceGroup |  | services/auth/handler.go | 149 |
| auth | PATCH | /scim/v2/Groups/{id} | h.handleSCIMPatchGroup |  | services/auth/handler.go | 150 |
| auth | DELETE | /scim/v2/Groups/{id} | h.handleSCIMDeleteGroup |  | services/auth/handler.go | 151 |
| autokey | POST | /autokey/templates | h.handleUpsertTemplate |  | services/autokey/handler.go | 34 |
| autokey | PUT | /autokey/templates/{id} | h.handleUpsertTemplate |  | services/autokey/handler.go | 35 |
| autokey | POST | /autokey/service-policies | h.handleUpsertServicePolicy |  | services/autokey/handler.go | 38 |
| autokey | PUT | /autokey/service-policies/{service} | h.handleUpsertServicePolicy |  | services/autokey/handler.go | 39 |
| backup | GET | /healthz | h.handleHealth |  | services/backup/handler.go | 48 |
| certs | GET | /certs/{id} | h.handleGetCert |  | services/certs/handler.go | 45 |
| certs | POST | /certs/profiles | h.handleCreateProfile |  | services/certs/handler.go | 50 |
| certs | GET | /certs/profiles/{id} | h.handleGetProfile |  | services/certs/handler.go | 52 |
| certs | POST | /certs/ocsp | h.handleOCSP |  | services/certs/handler.go | 55 |
| certs | GET | /certs/clm/policy | h.handleGetCLMPolicy |  | services/certs/handler.go | 60 |
| certs | GET | /certs/merkle/epochs/{id} | h.handleMerkleEpoch |  | services/certs/handler.go | 79 |
| certs | GET | /acme/directory | h.handleACMEDirectory |  | services/certs/handler.go | 83 |
| certs | HEAD | /acme/new-nonce | h.handleACMENonce |  | services/certs/handler.go | 84 |
| certs | POST | /acme/new-nonce | h.handleACMENonce |  | services/certs/handler.go | 85 |
| certs | GET | /acme/renewal-info/{id} | h.handleACMERenewalInfo |  | services/certs/handler.go | 88 |
| certs | GET | /acme/cert/{id} | h.handleACMECertDownload |  | services/certs/handler.go | 92 |
| certs | GET | /est/.well-known/est/cacerts | h.handleESTCACerts |  | services/certs/handler.go | 94 |
| certs | POST | /est/.well-known/est/simplereenroll | h.handleESTSimpleReenroll |  | services/certs/handler.go | 97 |
| certs | POST | /v1/enroll | <inline func> | public | services/certs/internal_tls.go | 184 |
| cloud | GET | /cloud/accounts | h.handleListAccounts |  | services/cloud/handler.go | 31 |
| cloud | GET | /cloud/region-mappings | h.handleListRegionMappings |  | services/cloud/handler.go | 34 |
| cloud | GET | /cloud/inventory | h.handleInventory |  | services/cloud/handler.go | 38 |
| cloud | GET | /cloud/bindings | h.handleListBindings |  | services/cloud/handler.go | 39 |
| cloud | GET | /cloud/bindings/{id} | h.handleGetBinding |  | services/cloud/handler.go | 40 |
| cluster-manager | GET | /healthz | h.handleHealth |  | services/cluster-manager/handler.go | 32 |
| cluster-manager | GET | /cluster/members | h.handleMembers |  | services/cluster-manager/handler.go | 35 |
| cluster-manager | GET | /cluster/nodes | h.handleNodes |  | services/cluster-manager/handler.go | 36 |
| cluster-manager | GET | /cluster/profiles | h.handleListProfiles |  | services/cluster-manager/handler.go | 38 |
| cluster-manager | POST | /cluster/join/complete | h.handleJoinComplete |  | services/cluster-manager/handler.go | 43 |
| cluster-manager | POST | /cluster/join/exchange | h.handleJoinExchange |  | services/cluster-manager/handler.go | 44 |
| cluster-manager | POST | /cluster/nodes/{id}/heartbeat | h.handleNodeHeartbeat |  | services/cluster-manager/handler.go | 49 |
| cluster-manager | POST | /cluster/sync/events | h.handlePublishSyncEvent |  | services/cluster-manager/handler.go | 53 |
| cluster-manager | POST | /cluster/sync/ack | h.handleSyncAck |  | services/cluster-manager/handler.go | 55 |
| cluster-manager | GET | /cluster/replication/status | h.handleReplicationStatus |  | services/cluster-manager/handler.go | 58 |
| compliance | POST | /compliance/connections/{id}/resolve | h.resolveConnection | authenticated | services/compliance/connections_service.go | 63 |
| compliance | POST | /compliance/connections/import | h.importConnection | authenticated | services/compliance/connections_service.go | 64 |
| compliance | GET | /compliance/posture | h.handlePosture |  | services/compliance/handler.go | 51 |
| compliance | GET | /compliance/posture/history | h.handlePostureHistory |  | services/compliance/handler.go | 52 |
| compliance | GET | /compliance/templates/{id} | h.handleGetComplianceTemplate |  | services/compliance/handler.go | 62 |
| compliance | GET | /compliance/frameworks/{id}/controls | h.handleFrameworkControls |  | services/compliance/handler.go | 66 |
| compliance | GET | /compliance/keys/orphaned | h.handleOrphaned |  | services/compliance/handler.go | 70 |
| compliance | GET | /compliance/keys/expired | h.handleExpired |  | services/compliance/handler.go | 71 |
| compliance | GET | /compliance/audit/correlations | h.handleAuditCorrelations |  | services/compliance/handler.go | 73 |
| compliance | GET | /compliance/sbom | h.handleSBOM |  | services/compliance/handler.go | 76 |

Showing `120` of `394`. Full data is in `docs/generated/product-map.json`.

## Output Files

- `docs/generated/PRODUCT_MAP.md`: this human-readable summary
- `docs/generated/UI_BUTTON_INVENTORY.md`: static inventory of clickable controls
- `docs/generated/REQUEST_FLOW.md`: frontend route to Go handler/service/store/package flow
- `docs/generated/FLOW_GRAPH.html`: interactive visual request graph
- `docs/generated/product-map.mmd`: Mermaid service graph
- `docs/generated/product-map.json`: machine-readable source inventory
- `docs/generated/frontend-calls.csv`: call-site table for spreadsheet triage
- `docs/generated/backend-routes.csv`: backend route table for spreadsheet triage
- `docs/generated/request-flows.csv`: backend request-flow table for spreadsheet triage
