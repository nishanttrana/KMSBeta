# Generated UI Button Inventory

Generated at `2026-09-26T15:02:41Z` by `scripts/generate_product_map.py`.

This is a static inventory of controls with `onClick` handlers. For exact runtime behavior, combine it with Playwright traces and network logs.

| File | Line | Tabs | Control | Visible label | Handler snippet |
| --- | --- | --- | --- | --- | --- |
| web/dashboard/src/components/AppErrorBoundary.tsx | 81 | - | button | Try again | this.handleReload |
| web/dashboard/src/components/AppErrorBoundary.tsx | 96 | - | button | window.location.reload()} style={ } > Reload page |  |
| web/dashboard/src/components/IdleWarningModal.tsx | 95 | - | Btn | Logout Now | onLogout |
| web/dashboard/src/components/IdleWarningModal.tsx | 98 | - | Btn | Stay Active | onStayActive |
| web/dashboard/src/components/LoginScreen.tsx | 369 | - | button | {loading ? ( <> Authenticating… ) : ( <> Sign In )} | handleLogin |
| web/dashboard/src/components/LoginScreen.tsx | 405 | - | button | handleSSOLogin(sp.provider)} disabled= className="w-full rounded-lg border bo... |  |
| web/dashboard/src/components/LoginScreen.tsx | 441 | - | button | setShowPolicyHint((v) => !v)} className="text-cyber-accent transition-colors... |  |
| web/dashboard/src/components/LoginScreen.tsx | 473 | - | button | {savingPassword ? ( <> Applying… ) : ( <> Update Password and Continue )} | handlePasswordChange |
| web/dashboard/src/components/ThemeToggle.tsx | 17 | - | button | {isDark ? : } | toggle |
| web/dashboard/src/components/ThemeToggle.tsx | 31 | - | button | } onMouseLeave={(e) => } > {isDark ? : } | toggle |
| web/dashboard/src/components/ToastStack.tsx | 84 | - | button | dismiss(toast.id)} aria-label="Dismiss notification" style={ } > × |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 737 | - | button | setCollapsed((v) => !v)} title= className="vk-icon-btn" style={{ width: 22, h... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 897 | - | button | Sign out | onLogout |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 948 | - | button | togglePin(tab)} title= style={{ display: "inline-flex", alignItems: "center",... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 971 | - | button | setPaletteOpen(true)} title="Command palette (⌘K)" className="vk-search-btn"... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 1021 | - | Btn | selectTab("admin")} style={cliEnabled ? : }> |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 1058 | - | button | } className="vk-icon-btn" aria-label="About this KMS build" aria-expanded= ti... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 1093 | - | button | } className="vk-icon-btn" style={{ display: "inline-flex", alignItems: "cente... |  |
| web/dashboard/src/components/primitives.tsx | 23 | - | button | (icon or dynamic label) | onClick |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 56 | - | button | Close | onClose} aria-label="Close" style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", pa... |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 164 | - | Btn | (icon or dynamic label) | cancel |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 165 | - | Btn | (icon or dynamic label) | submit |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 537 | - | button | { if (!disabled) }} onFocus= onBlur= onMouseDown= onKeyDown= style={{ backgro... |  |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 650 | - | button | (icon or dynamic label) | onClick} disabled={disabled |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 677 | - | button | onChange(t)} style={{ background: active === t ? C.accentDim : "transparent",... |  |
| web/dashboard/src/components/v3/runtimeUtils.tsx | 66 | - | button | Retry | reset} style={{ border: "1px solid #243656", borderRadius: 6, padding: "4px 10px", background: "transparent", color:... |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 759 | ai_gateway | Btn | Refresh | refreshAll} disabled={loadingModels |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 769 | ai_gateway | button | setErr("")} style={ }>Dismiss |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 783 | ai_gateway | button | { setView(vc.key); if (vc.key === "governance" && accessRules.length === 0) i... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 938 | ai_gateway | Btn | { setView(s.target); if (s.target === "dlp_policies") void loadDlpPolicies();... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 948 | ai_gateway | Btn | }>View All |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 981 | ai_gateway | Btn | setView("models")}> Register Model |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 982 | ai_gateway | Btn | } style={{ background: C.blueDim, border: `1px solid $ 33`, color: C.blue }}>... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 985 | ai_gateway | Btn | setView("scan")} style={{ background: C.purpleDim, border: `1px solid $ 33`,... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 988 | ai_gateway | Btn | setView("realtime")} style={{ background: C.greenDim, border: `1px solid $ 33... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1047 | ai_gateway | Btn | (icon or dynamic label) | doCreateModel} disabled={modelFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1055 | ai_gateway | Btn | (icon or dynamic label) | loadModels} disabled={loadingModels |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1091 | ai_gateway | Btn | doTestModel(m.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1094 | ai_gateway | Btn | doDeleteModel(m.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1126 | ai_gateway | button | { setAccessForm(f => ( )); }} style={{ padding: "3px 8px", fontSize: 10, bord... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1147 | ai_gateway | button | { setAccessForm(f => ( )); }} style={{ padding: "4px 10px", fontSize: 10, bor... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1176 | ai_gateway | Btn | (icon or dynamic label) | doCreateAccessRule} disabled={accessFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1183 | ai_gateway | Btn | (icon or dynamic label) | loadRules} disabled={loadingRules |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1207 | ai_gateway | Btn | doDeleteAccessRule(r.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1269 | ai_gateway | Btn | (icon or dynamic label) | doCreateBudget} disabled={budgetFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1276 | ai_gateway | Btn | (icon or dynamic label) | loadBudgets} disabled={loadingBudgets |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1372 | ai_gateway | Btn | (icon or dynamic label) | doCreateGuardrail} disabled={guardrailFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1387 | ai_gateway | Btn | (icon or dynamic label) | doTestGuardrail} disabled={guardrailTestBusy \|\| !guardrailTestText.trim() |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1410 | ai_gateway | Btn | (icon or dynamic label) | loadGuardrails} disabled={loadingGuardrails |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1440 | ai_gateway | Btn | doDeleteGuardrail(g.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1473 | ai_gateway | button | setDlpPolicyForm(f => ( ))} style={{ background: C.accentDim, border: `1px so... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1477 | ai_gateway | button | setDlpPolicyForm(f => ( ))} style={{ background: "transparent", border: `1px... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1543 | ai_gateway | Btn | (icon or dynamic label) | doCreateDlpPolicy} disabled={dlpPolicyFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1553 | ai_gateway | Btn | (icon or dynamic label) | loadDlpPolicies} disabled={loadingDlpPolicies |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1590 | ai_gateway | Btn | doDeleteDlpPolicy(p.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1611 | ai_gateway | button | setScanMode(m)} style={{ padding: "8px 18px", fontSize: 11, fontWeight: scanM... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1636 | ai_gateway | Btn | doScan("scan")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1639 | ai_gateway | Btn | doScan("redact")} disabled= style={{ background: C.purpleDim, border: `1px so... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1642 | ai_gateway | Btn | doScan("evaluate")} disabled= style={{ background: C.amberDim, border: `1px s... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1769 | ai_gateway | Btn | (icon or dynamic label) | doSimulateGateway} disabled={scanning |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1881 | ai_gateway | Btn | (icon or dynamic label) | loadRealtimeFeed |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1929 | ai_gateway | button | setReportPeriod(val)} style={{ padding: "6px 14px", fontSize: 10, borderRadiu... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1937 | ai_gateway | Btn | Export JSON | exportReportJSON |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2029 | ai_gateway | button | } style={{ padding: "3px 10px", fontSize: 10, borderRadius: 4, cursor: "point... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2037 | ai_gateway | Btn | Refresh | loadAudit} disabled={loadingAudit |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2038 | ai_gateway | Btn | Export | exportReportJSON |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2090 | ai_gateway | Btn | setAuditPage(p => Math.max(0, p - 1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2092 | ai_gateway | Btn | setAuditPage(p => Math.min(totalAuditPages - 1, p + 1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 418 | alerts | Btn | void refresh(false)}> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 419 | alerts | Btn | void ackAllAlerts()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 429 | alerts | Btn | setActiveFilter(tab.id)} style={{ background:activeFilter===tab.id?(palette[`... |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 466 | alerts | Btn | void ackAlert(item)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 467 | alerts | Btn | void escalateOne(item)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 488 | alerts | Btn | setPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 490 | alerts | Btn | setPageIndex((prev)=>Math.min(totalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 244 | - | Btn | void load(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 245 | - | Btn | void saveSettings()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 272 | - | Btn | void submitSign()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 314 | - | Btn | void saveProfile()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 354 | - | Btn | editProfile(item)}>Edit |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 355 | - | Btn | void removeProfile(item)}>Delete |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 378 | - | Btn | void verifyRecord(item)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 646 | audit | Btn | void exportEventsAsCEF(filteredEvents, signingKeyId ? session : undefined, si... |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 647 | audit | Btn | (icon or dynamic label) | verifyChain} disabled={chainVerifying |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 650 | audit | Btn | load()} disabled= >Refresh |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 741 | audit | Btn | setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 742 | audit | Btn | setOffset(offset + PAGE_SIZE)}>Next |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 936 | audit | Btn | handleAcknowledge(al.id)}>Ack |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 939 | audit | Btn | handleResolve(al.id)}>Resolve |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 970 | audit | Btn | (icon or dynamic label) | loadForensic} disabled={forensicLoading |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 1078 | audit | Btn | }> View Timeline ( ) |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 1083 | audit | Btn | }> View Session ( ) |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 1088 | audit | Btn | }> View Correlation ( ) |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 371 | - | Btn | refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 372 | - | Btn | Save Settings | saveSettings} disabled={busy \|\| loading |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 476 | - | Btn | Save Settings | saveSettings} disabled={busy |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 517 | - | Btn | setTemplateDraft(DEFAULT_TEMPLATE)}>Reset |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 518 | - | Btn | Save Template | saveTemplate} disabled={busy |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 539 | - | Btn | setTemplateDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 545 | - | Btn | removeTemplate(String(item?.id \|\| ""))}>Delete |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 592 | - | Btn | setPolicyDraft(DEFAULT_POLICY)}>Reset |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 593 | - | Btn | Save Service Default | savePolicy} disabled={busy |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 615 | - | Btn | setPolicyDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 621 | - | Btn | removePolicy(String(item?.service_name \|\| ""))}>Delete |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 662 | - | Btn | Submit Request | submitRequest} disabled={busy |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 482 | byok | Btn | setConnectorView("cards")} title="Card view"> |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 483 | byok | Btn | setConnectorView("list")} title="List view"> |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 484 | byok | Btn | void refresh()} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 485 | byok | Btn | }> Region Mappings |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 486 | byok | Btn | setModal("add")}>+ Add Connector |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 512 | byok | button | setExpandedProvider(isExpanded ? null : card.provider)} style={ }> {isExpande... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 530 | byok | Btn | } disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 536 | byok | Btn | { const activeAccount = card.accounts[0]; if (activeAccount) }} disabled= >Im... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 545 | byok | Btn | } disabled= > Inventory |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 548 | byok | Btn | void deleteConnector(card.provider, card.accounts[0])} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 571 | byok | button | setConnectorMenu(menuOpen ? "" : String(card.provider))} style={{ border: `1p... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 575 | byok | button | } disabled= style={ }>Sync Now |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 576 | byok | button | } disabled= style={ }>Import Keys |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 577 | byok | button | } disabled= style={ }>Browse Inventory |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 578 | byok | button | } disabled= style={ }>Delete Connector |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 628 | byok | button | copyToClipboard(binding.cloud_key_ref \|\| binding.cloud_key_id)} style={ } tit... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 636 | byok | Btn | void rotateBindingAction(binding)} disabled= > {rotatingBinding === binding.i... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 696 | byok | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 697 | byok | Btn | void submitAddConnector()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 739 | byok | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 740 | byok | Btn | void submitImport()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 791 | byok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 792 | byok | Btn | void submitRegionMapping()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 827 | byok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 127 | backup | button | Refresh | load} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 131 | backup | button | setShowCreate(true)} style={ }> New Policy |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 149 | backup | button | setSection(s.id as any)} style={{ padding: "8px 16px", border: "none", backgr... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 197 | backup | button | handleTrigger(p.id)} disabled title= style={{ padding: "4px 8px", borderRadiu... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 200 | backup | button | deletePolicy(session, p.id).then(load)} style={{ padding: "4px 6px", borderRa... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 279 | backup | button | handleRestore(p.id)} disabled title= style={{ padding: "4px 10px", borderRadi... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 337 | backup | button | setShowCreate(false)} style={{ padding: "7px 16px", borderRadius: 6, border:... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 338 | backup | button | (icon or dynamic label) | handleCreate} disabled={creating \|\| !form.name |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1484 | certs | button | toggleCA(caID)} style={ }> {open? : } : |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1498 | certs | Btn | void actCRL(ca)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1499 | certs | Btn | void actDeleteCA(ca)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1505 | certs | button | toggleIssued(caID)} style={ }> {issuedOpen? : } Issued Certificates ( ) |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1735 | certs | Btn | openProtocolModal(meta.name)}> Configure |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1736 | certs | Btn | void runProtocolTest(meta.name)} > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1744 | certs | Btn | setModal("acme-wizard")}> ACME Wizard |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1745 | certs | Btn | setModal("acme-star")}> STAR |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1746 | certs | Btn | setModal("est-wizard")}> EST Enroll |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1747 | certs | Btn | setModal("scep-wizard")}> SCEP Enroll |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1748 | certs | Btn | setModal("cmpv2-wizard")}> CMPv2 Request |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1764 | certs | Btn | setCAStatusView("all")} style={ }>{`All $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1765 | certs | Btn | setCAStatusView("active")} style={ }>{`Active $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1766 | certs | Btn | setCAStatusView("revoked")} style={ }>{`Revoked $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1767 | certs | Btn | void refreshCAs()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1768 | certs | Btn | setModal("create-ca")}> Create CA |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1860 | certs | Btn | void refreshRenewalIntel()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1886 | certs | Btn | void refreshSTARIntel()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1887 | certs | Btn | setModal("acme-star")}>New |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1915 | certs | Btn | void actRefreshSTARSubscription(item,true)} disabled={rowActionBusy===`star-r... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1916 | certs | Btn | void actDeleteSTARSubscription(item)} disabled={rowActionBusy===`star-delete-... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1943 | certs | Btn | setModal("issue")} style={ }> Issue Certificate |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1944 | certs | Btn | setModal("sign-csr")} style={ }> Sign CSR |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1945 | certs | Btn | setModal("issue-pqc")} style={ }> PQC Issue |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1946 | certs | Btn | setModal("upload-3p")} style={ }> Upload 3rd-Party |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1947 | certs | Btn | setModal("cert-alert-policy")} style={ }> Alert Policy |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1948 | certs | Btn | setModal("cert-clm-policy")} style={ }> CLM 47-Day |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1956 | certs | Btn | { setCTBuilding(true); try{ const res=await buildCertMerkleEpoch(session,500)... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1970 | certs | Btn | }>Refresh |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2004 | certs | Btn | { const id=ctProofCertId.trim(); if(!id) try{ const proof=await getCertMerkle... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2063 | certs | Btn | setCertStatusView("all")} style={ }> {`All ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2066 | certs | Btn | setCertStatusView("active")} style={ }> {`Active ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2069 | certs | Btn | setCertStatusView("revoked")} style={ }> {`Revoked ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2073 | certs | Btn | void refreshCerts()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2104 | certs | button | openCertActionMenu(e,certID)} aria-label="Certificate actions" style={{ backg... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2136 | certs | button | } onMouseEnter={(e)=> } onMouseLeave={(e)=> } style={ } > Download |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2150 | certs | button | } disabled={busy===`renew-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } st... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2163 | certs | button | } disabled={busy===`revoke-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } s... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2176 | certs | button | } disabled={busy===`ocsp-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } sty... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2191 | certs | button | } disabled={busy===`delete-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } s... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2227 | certs | Btn | setCertPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2229 | certs | Btn | setCertPageIndex((prev)=>Math.min(certTotalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2295 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2296 | certs | Btn | void submitCreateCA()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2378 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2379 | certs | Btn | void submitIssueCert(modal==="issue-pqc")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2441 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2442 | certs | Btn | void submitSignCSR()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2471 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2472 | certs | Btn | void submitDownloadCert()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2496 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2497 | certs | Btn | void submitUpload()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2516 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2517 | certs | Btn | void saveAlertPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2555 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2556 | certs | Btn | void saveCLMPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2582 | certs | Btn | setProtocolConfigText(JSON.stringify(protocolDefaultConfigs[String(protocolNa... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2584 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2585 | certs | Btn | void saveProtocol()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2659 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2660 | certs | Btn | void submitCreateSTARSubscription()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2703 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2704 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const email=String... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2769 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2770 | certs | Btn | { if(!session)return; try{ const attrs=await estCSRAttributes(session); onToa... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2777 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const cn=String((d... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2829 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2830 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const msgType=Stri... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2892 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2893 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const msgType=Stri... |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 30 | cloudctl | Btn | selectSubtab("byok")}>BYOK |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 31 | cloudctl | Btn | selectSubtab("hyok")}>HYOK |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 32 | cloudctl | Btn | selectSubtab("google-cse")}>Google CSE |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 33 | cloudctl | Btn | selectSubtab("azure")}>Azure EKM |  |
| web/dashboard/src/components/v3/tabs/ClusterJoinPanel.tsx | 53 | - | Btn | setMode("issue")}>On this primary: add a node |  |
| web/dashboard/src/components/v3/tabs/ClusterJoinPanel.tsx | 54 | - | Btn | setMode("join")}>On a new node: join a cluster |  |
| web/dashboard/src/components/v3/tabs/ClusterJoinPanel.tsx | 65 | - | Btn | void issue()}> |  |
| web/dashboard/src/components/v3/tabs/ClusterJoinPanel.tsx | 79 | - | Btn | void join()}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 121 | - | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 272 | - | Btn | setAddNodeModalOpen(true)}>Add Instance |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 273 | - | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 334 | - | Btn | void updateNodeRoleAction(node)} > |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 339 | - | Btn | void removeNodeAction(node)}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 350 | - | Btn | setAddNodeModalOpen(true)}>Add First Instance |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 425 | - | Btn | void saveProfile()}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 443 | - | Btn | void removeProfile(profile)}>Delete |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 474 | - | Btn | void refreshSyncEvents()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 564 | - | Btn | void refreshClusterLogs()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 577 | - | Btn | void refreshClusterLogs()}>Apply |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 164 | home, recommendations | button | setOpen((v) => !v)} aria-expanded= style={ } > {r.frameworks.map((f) => ( ))} |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 180 | home, recommendations | button | onNavigate(r.action.tab)} style={ } > |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 187 | home, recommendations | button | setOpen((v) => !v)} aria-label="Details" style={ }> |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 202 | home, recommendations | button | onSnooze(r.id)} style={{ marginTop: 10, fontSize: 12, color: C.muted, backgro... |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 307 | home, recommendations | button | void refresh()} disabled= style={{ display: "inline-flex", alignItems: "cente... |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 347 | home, recommendations | button | onNavigate("recommendations")} style={ }>View all → |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 362 | home, recommendations | button | onNavigate("ops")} style={ }> Operations dashboard |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 393 | home, recommendations | button | void refresh()} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 398 | home, recommendations | button | setSev("all")}>All ( ) |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 400 | home, recommendations | button | setSev(s)}> ( ) |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 407 | home, recommendations | button | Show snoozed | unsnoozeAll |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 761 | compliance | Btn | setView("assessment")} style={ }>Assessment |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 762 | compliance | Btn | setView("reporting")} style={ }>Reporting |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 763 | compliance | Btn | setView("inventory")} style={ }>Crypto Inventory |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 766 | compliance | Btn | void loadInventory()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 893 | compliance | Btn | setView("assessment")} style={ }>Assessment |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 894 | compliance | Btn | setView("reporting")} style={ }>Reporting |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 895 | compliance | Btn | setView("inventory")} style={ }>Crypto Inventory |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 898 | compliance | Btn | void loadReporting()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1031 | compliance | Btn | void triggerReportNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1059 | compliance | Btn | void createScheduleReport()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1079 | compliance | Btn | void downloadJob(job)} disabled= >Download |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1080 | compliance | Btn | void deleteJob(job)}>Delete |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1114 | compliance | Btn | setView("assessment")} style={ }>Assessment |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1115 | compliance | Btn | setView("reporting")} style={ }>Reporting |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1116 | compliance | Btn | setView("inventory")} style={ }>Crypto Inventory |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1127 | compliance | Btn | void createTemplate()} disabled= >+ Template |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1128 | compliance | Btn | void saveTemplate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1129 | compliance | Btn | void removeTemplate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1130 | compliance | Btn | void loadAssessment( )} disabled= >Refresh |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1131 | compliance | Btn | void exportEvidencePack("pdf")} disabled= >Evidence Pack |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1132 | compliance | Btn | void runNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1138 | compliance | Btn | void saveSchedule()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1156 | compliance | Btn | void runNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1991 | compliance | Btn | { setEvidenceBusy(true); try { await downloadEvidenceReport(session, ); onToa... |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 292 | - | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 322 | - | Btn | void refresh(false)}>Reload |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 323 | - | Btn | void savePolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 429 | - | Btn | void runEvaluation()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 602 | - | Btn | void refresh(false)}>Refresh History |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 205 | crypto_agility | button | Cancel | onClose} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 206 | crypto_agility | button | (icon or dynamic label) | handleSave |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 288 | crypto_agility | button | load(true)} disabled= style={{ background: C.card, border: `1px solid $ `, bo... |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 296 | crypto_agility | button | setShowModal(true)} style={ } > Create Migration Plan |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 711 | crypto | button | selectAlgorithmFromRail(String(name),fipsApproved)} disabled= style={{ displa... |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 745 | crypto | button | { if(tabAllowed) }} disabled= style={{ background:op===item.id?C.accent:"tran... |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 868 | crypto | button | {busy?`Execute $ ...`:`Execute $ `} | runOperation |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 896 | crypto | Btn | Hex | renderResultAsHex |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 897 | crypto | Btn | Base64 | renderResultAsBase64 |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 898 | crypto | Btn | Download | downloadResult |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 230 | - | Btn | onNavigate?.("certs")}>View Certificates → |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 257 | - | button | onUnpinTab?.(tabId)} title={`Unpin $ `} style={ } > |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 267 | - | button | onNavigate?.(tabId)} style={{ display: "inline-flex", alignItems: "center", g... |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 433 | - | Btn | void submitHomeApprovalVote(item, "approved")} disabled={approvalVoteBusy ===... |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 434 | - | Btn | void submitHomeApprovalVote(item, "denied")} disabled={approvalVoteBusy === `... |  |
| web/dashboard/src/components/v3/tabs/DevSecOpsTab.tsx | 50 | devsecops | button | {copied ? : } | handleCopy |
| web/dashboard/src/components/v3/tabs/DevSecOpsTab.tsx | 641 | devsecops | button | setView(id)} style={{ padding: "9px 18px", border: "none", background: "trans... |  |
| web/dashboard/src/components/v3/tabs/DevSecOpsTab.tsx | 806 | devsecops | button | setApiGroupFilter(g)} style={{ padding: "4px 10px", borderRadius: 5, border:... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 735 | ekm | Btn | setDbView(dbView==="cards"?"list":"cards")} style={ }>{dbView==="cards"? : } |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 736 | ekm | Btn | Deploy Agent | openDeploy |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 737 | ekm | Btn | Register Database | openDbRegister |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 738 | ekm | Btn | setModal("setup-guide")}>Setup Guide |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 739 | ekm | Btn | refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 800 | ekm | Btn | runRotate(agent)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 801 | ekm | Btn | openLogs(agent)} style={ }>Logs |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 802 | ekm | Btn | openHealthDetail(agent)} style={ }>Health |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 829 | ekm | Btn | } disabled= style={ }>Rotate |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 830 | ekm | Btn | } style={ }>Logs |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 868 | ekm | Btn | openHealthDetail(agent)} style={ }>Full Health |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 869 | ekm | Btn | runDelete(agent)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 899 | ekm | Btn | setExpandedTdeGuide(prev=>( ))} style={ }>Guide |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 900 | ekm | Btn | runRevokeTDE(db)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 919 | ekm | Btn | loadAgentKeyAccessLogs(expandedAgent)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 957 | ekm | Btn | setBitLockerView(bitLockerView==="cards"?"list":"cards")} style={ }>{bitLocke... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 958 | ekm | Btn | Register Client | openBitLockerDeploy |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 959 | ekm | Btn | Network Scan | openBitLockerScan |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 960 | ekm | Btn | refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 984 | ekm | Btn | runBitLockerOperation(client,op)} disabled={bitLockerOpClientID===`$ :$ `} st... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 985 | ekm | Btn | openBitLockerActivity(client)} style={ }>Activity |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 986 | ekm | Btn | openBitLockerDelete(client)} style={ }>Delete |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1007 | ekm | Btn | openBitLockerActivity(client)} style={ }>Activity |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1008 | ekm | Btn | openBitLockerOptions(client)} style={ }>Ops |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1009 | ekm | Btn | openBitLockerDelete(client)} style={ }>Del |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1036 | ekm | Btn | setModal("azure-add-config")}>+ Add Azure Vault |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1037 | ekm | Btn | setModal("azure-add-mapping")}>+ Add Key Mapping |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1038 | ekm | Btn | refresh(true)} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1059 | ekm | Btn | { setAzureTestResults(prev=>({...prev,[cfg.id]: })); try{ const res=await tes... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1067 | ekm | Btn | { setAzureSyncing(cfg.id); try{ const res=await syncAzureKeys(session,cfg.id)... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1075 | ekm | Btn | { if(!confirm("Delete this Azure vault configuration?")) return; try catch(e)... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1110 | ekm | Btn | { setAzureOpLoading(`import-$ `); try{const res=await importKeyToAzure(sessio... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1114 | ekm | Btn | { setAzureOpLoading(`rotate-$ `); try{const res=await rotateAzureKey(session,... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1118 | ekm | Btn | {setModal("azure-wrap");setAzureMappingForm(prev=>( ));}} style={ }>Wrap |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1119 | ekm | Btn | {setModal("azure-unwrap");setAzureMappingForm(prev=>( ));}} style={ }>Unwrap |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1120 | ekm | Btn | { if(!confirm("Delete this key mapping?")) return; try catch(e){onToast?.(`De... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1158 | ekm | Btn | { setGoogleCSELoading(true); try{ const domains=googleCSEConfigForm.allowed_d... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1189 | ekm | Btn | { if(!confirm("Delete this Google CSE config?")) return; try catch(e){onToast... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1218 | ekm | Btn | { setGoogleCSELoading(true); try{ await createGoogleCSEKey(session, ); onToas... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1246 | ekm | Btn | { if(!confirm("Delete this CSE key?")) return; try catch(e){onToast?.(`Delete... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1280 | ekm | Btn | setGuideEngine(eng)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1363 | ekm | Btn | (icon or dynamic label) | submitDbRegister} disabled={dbRegistering |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1364 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1394 | ekm | Btn | (icon or dynamic label) | submitDeploy} disabled={deploying |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1395 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1410 | ekm | Btn | downloadText(file.path,file.content)} style={ }>Download |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1425 | ekm | Btn | { const agentId=String(deployPackage?.agent_id\|\|"").trim(); if(!agentId) setV... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1479 | ekm | Btn | (icon or dynamic label) | submitBitLockerDeploy} disabled={bitLockerDeploying |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1480 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1487 | ekm | Btn | downloadText(file.path,file.content)} style={ }>Download |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1505 | ekm | Btn | (icon or dynamic label) | submitBitLockerDelete} disabled={bitLockerDeleteSubmitting\|\|!bitLockerDeleteConfirmBackup |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1506 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1523 | ekm | Btn | (icon or dynamic label) | runBitLockerScan} disabled={bitLockerScanRunning |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1539 | ekm | Btn | (icon or dynamic label) | onboardScannedBitLocker} disabled={bitLockerOnboarding |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1540 | ekm | Btn | {const all= ;bitLockerScanCandidates.forEach(r=> );setBitLockerScanSelected(a... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1582 | ekm | Btn | } disabled={bitLockerOpClientID===`$ :$ `} style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1613 | ekm | Btn | { setAzureLoading(true); try{ await createAzureEKMConfig(session,azureConfigF... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1623 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1642 | ekm | Btn | { setAzureLoading(true); try{ await createAzureKeyMapping(session,azureMappin... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1652 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1660 | ekm | Btn | { setAzureLoading(true); try{ const res=await wrapAzureKey(session,azureMappi... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1668 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1680 | ekm | Btn | { setAzureLoading(true); try{ const res=await unwrapAzureKey(session,azureMap... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1688 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 80 | envelope_enc | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 181 | envelope_enc | button | setShowRewrap(true)} style={ }> Start Rewrap |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 182 | envelope_enc | button | setShowCreateKEK(true)} style={ }> Create KEK |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 183 | envelope_enc | button | (icon or dynamic label) | load} style={{ ...btnSecondary, padding: "9px 10px" |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 200 | envelope_enc | button | setSection(t.key)} style={{ background: "none", border: "none", borderBottom:... |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 222 | envelope_enc | button | } style={ }> Rotate KEK |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 223 | envelope_enc | button | } style={ }> Rewrap |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 327 | envelope_enc | button | setShowCreateKEK(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 328 | envelope_enc | button | (icon or dynamic label) | handleCreateKEK} disabled={saving \|\| !newKEKName.trim() |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 357 | envelope_enc | button | setShowRewrap(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 358 | envelope_enc | button | (icon or dynamic label) | handleStartRewrap} disabled={saving \|\| !rewrapOld \|\| !rewrapNew \|\| rewrapOld === rewrapNew |
| web/dashboard/src/components/v3/tabs/FeatureForgeTab.tsx | 170 | feature_forge | Btn | void refresh()} disabled= >Refresh |  |
| web/dashboard/src/components/v3/tabs/FeatureForgeTab.tsx | 189 | feature_forge | Btn | void submit()} disabled= > Forge feature |  |
| web/dashboard/src/components/v3/tabs/FeatureForgeTab.tsx | 273 | feature_forge | Btn | void approve(it.id)} disabled= > Approve (2nd principal) |  |
| web/dashboard/src/components/v3/tabs/FeatureForgeTab.tsx | 278 | feature_forge | Btn | void promote(it.id)} disabled= > {it.stage === "awaiting_prod" ? ( <> Re-chec... |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 318 | approvals | Btn | openPolicyModal()}>Create Policy |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 319 | approvals | Btn | Configure | openSettingsModal |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 320 | approvals | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 386 | approvals | Btn | void doVote(r, "approved")}> {voteBusy === `$ :approved` ? "..." : "Approve"} |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 389 | approvals | Btn | void doVote(r, "denied")}> {voteBusy === `$ :denied` ? "..." : "Deny"} |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 436 | approvals | Btn | openPolicyModal()}>Create Policy |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 454 | approvals | Btn | openPolicyModal(p)}>Edit |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 466 | approvals | Btn | Configure | openSettingsModal |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 544 | approvals | Btn | setPolicyModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 545 | approvals | Btn | (icon or dynamic label) | savePolicy} disabled={policySaving \|\| !policyName.trim() |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 592 | approvals | Btn | { try catch (e: any) { onToast?.(`SMTP test failed: $ `); } }}>Test SMTP |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 601 | approvals | Btn | { try catch (e: any) { onToast?.(`Slack test failed: $ `); } }}>Test |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 611 | approvals | Btn | { try catch (e: any) { onToast?.(`Teams test failed: $ `); } }}>Test |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 619 | approvals | Btn | setSettingsModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 620 | approvals | Btn | (icon or dynamic label) | saveSettings} disabled={settingsSaving |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 272 | hsm | Btn | void refreshCLIHints()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 316 | hsm | Btn | void openSSHSession()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 352 | hsm | Btn | void loadProviderConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 378 | hsm | Btn | void autoFetchPartitions()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 379 | hsm | Btn | void persistProviderConfig( , )} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 380 | hsm | Btn | setModal("gen")} disabled= >Generate Key in HSM |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 553 | hsm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 554 | hsm | Btn | { onToast?.(`HSM key generation requested: $ label="$ " partition="$ " [extra... |  |
| web/dashboard/src/components/v3/tabs/HYOKLiveTestPane.tsx | 166 | - | Btn | void executeTest()} disabled= style={ }> {executing ? "Executing..." : `Execu... |  |
| web/dashboard/src/components/v3/tabs/HYOKLiveTestPane.tsx | 173 | - | button | copyToClipboard(testOutput)} style={ } title="Copy output"> |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 402 | hyok | Btn | void refresh(false)} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 403 | hyok | Btn | }> Endpoint URLs |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 404 | hyok | Btn | }> Setup Guide |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 441 | hyok | Btn | openConfig(protocol)}>Configure |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 442 | hyok | Btn | }>URLs |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 443 | hyok | Btn | }>Guide |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 444 | hyok | Btn | void runDelete(protocol)}>Reset |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 582 | hyok | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 583 | hyok | Btn | void submitConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 608 | hyok | button | copyToClipboard(url.path)} style={ } title="Copy URL path"> |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 615 | hyok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 657 | hyok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/HealthTab.tsx | 63 | health | button | Refresh | load |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 558 | - | Btn | setCapsExpanded(p=>!p)}> |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 636 | - | Btn | downloadText(`$ .crt.pem`,issuedBundle.cert)}>Download Cert |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 637 | - | Btn | downloadText(`$ .key.pem`,issuedBundle.key)}>Download Key |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 638 | - | Btn | setIssuedBundle(null)}>Dismiss |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 647 | - | Btn | void refresh()}> |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 648 | - | Btn | setModal("profile")}>+ Add Profile |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 665 | - | Btn | void removeProfile(p)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 678 | - | Btn | void refresh(true)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 679 | - | Btn | setModal("client")}>+ Add Client |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 697 | - | Btn | void removeClient(c)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 711 | - | Btn | void refresh(true)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 712 | - | Btn | setModal("interop-target")}>+ Add Target |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 736 | - | Btn | void runInteropValidation(target)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 739 | - | Btn | void removeInteropTarget(target)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 827 | - | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 828 | - | Btn | void saveProfile()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 913 | - | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 914 | - | Btn | void saveClient()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 966 | - | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 967 | - | Btn | void saveInteropTarget()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 174 | - | Btn | void load(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 175 | - | Btn | void saveSettings()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 250 | - | Btn | void saveRule()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 288 | - | Btn | editRule(item)}>Edit |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 289 | - | Btn | void removeRule(item)}>Delete |  |
| web/dashboard/src/components/v3/tabs/KeyAnalyticsTab.tsx | 15 | key_analytics | button | (icon or dynamic label) | onClick} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", bor... |
| web/dashboard/src/components/v3/tabs/KeyAnalyticsTab.tsx | 64 | key_analytics | Btn | Export JSON | handleExport |
| web/dashboard/src/components/v3/tabs/KeyAnalyticsTab.tsx | 65 | key_analytics | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/KeyDerivationPanel.tsx | 53 | - | Btn | void load()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/KeyDerivationPanel.tsx | 77 | - | Btn | void run(k.key_id, "start migration", () => kdfTransition(session, k.key_id,... |  |
| web/dashboard/src/components/v3/tabs/KeyDerivationPanel.tsx | 81 | - | Btn | void run(k.key_id, "re-protect vault tokens", () => kdfReprotectVault(session... |  |
| web/dashboard/src/components/v3/tabs/KeyDerivationPanel.tsx | 83 | - | Btn | void run(k.key_id, "abort", () => kdfTransition(session, k.key_id, "abort"))}... |  |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 16 | - | button | (icon or dynamic label) | disabled ? undefined : onClick} disabled={disabled |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 83 | - | Btn | setShowForm(!showForm)} small> New Job |  |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 84 | - | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 110 | - | Btn | (icon or dynamic label) | handleCreate} disabled={saving \|\| !form.key_id |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 111 | - | Btn | setShowForm(false)} variant="ghost">Cancel |  |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 130 | - | Btn | handleToggle(j)}>{j.enabled ? : } |  |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 133 | - | Btn | handleDelete(j.id)}> |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1846 | keys | Btn | void refreshKeyInventory()} style={{height:40,padding:"0 16px",borderRadius:1... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1849 | keys | Btn | } primary style={ } > Create Key |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1856 | keys | Btn | setModal("form-key")} style={{height:40,padding:"0 20px",borderRadius:10,font... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1859 | keys | Btn | } style={{height:40,padding:"0 20px",borderRadius:10,fontSize:12,fontWeight:7... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1862 | keys | Btn | setModal("generate-pqc")} style={{height:40,padding:"0 20px",borderRadius:10,... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1872 | keys | button | { e.stopPropagation(); const next=!showColumnMenu; if(next) setShowColumnMenu... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2000 | keys | button | { e.stopPropagation(); const isOpen=openActionMenuId===k.id; if(isOpen) const... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2042 | keys | button | } style={ } > Edit Key Policy |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2051 | keys | button | } style={ } > Rotate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2064 | keys | button | } style={ } > Verify Integrity |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2070 | keys | button | } style={ } > Attest |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2076 | keys | button | } disabled= style={ } > Deactivate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2086 | keys | button | } disabled= style={ } > Activate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2096 | keys | button | } disabled= style={ } > Disable |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2106 | keys | button | } style={ } > Export |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2119 | keys | button | } style={ } > Delete |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2152 | keys | Btn | setPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2154 | keys | Btn | setPageIndex((prev)=>Math.min(totalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2275 | keys | button | setCreateTags((prev)=>prev.filter((t)=>t!==tag))} style={ } > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2285 | keys | Btn | setShowCreateTagPicker(!showCreateTagPicker)}>Add More Tags |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2303 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2304 | keys | Btn | (icon or dynamic label) | addCustomerKey} disabled={creating |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2425 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2426 | keys | Btn | (icon or dynamic label) | submitFormKey} disabled={forming |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2532 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2533 | keys | Btn | (icon or dynamic label) | submitImportKey} disabled={importing |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2591 | keys | Btn | updateKeyStatus(comp,"deactivated")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2592 | keys | Btn | updateKeyStatus(comp,"active")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2593 | keys | Btn | updateKeyStatus(comp,"disabled")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2614 | keys | Btn | }> Rotate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2615 | keys | Btn | }> Export |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2616 | keys | Btn | openPolicyEditor(selectedKey)}>Edit Key Policy |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2617 | keys | Btn | updateKeyStatus(selectedKey,"deactivated")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2618 | keys | Btn | updateKeyStatus(selectedKey,"active")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2619 | keys | Btn | updateKeyStatus(selectedKey,"disabled")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2620 | keys | Btn | }> Delete |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2686 | keys | Btn | Add Assignment | addPolicyGrant |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2708 | keys | Btn | removePolicyGrant(subjectType,subjectID)}>Remove |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2730 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2731 | keys | Btn | (icon or dynamic label) | saveKeyPolicy} disabled={policySaving |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2756 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2756 | keys | Btn | (icon or dynamic label) | rotateSelectedKey} disabled={rotating |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2786 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2787 | keys | Btn | (icon or dynamic label) | exportSelectedKey} disabled={exporting |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2812 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2813 | keys | Btn | (icon or dynamic label) | destroySelectedKey} disabled={!destroyReady |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2840 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2840 | keys | Btn | (icon or dynamic label) | generatePQCKey} disabled={pqcGenerating |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2846 | keys | Btn | setAttestResult(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2853 | keys | Btn | {const b=new Blob([JSON.stringify(attestResult,null,2)], );const a=document.c... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2854 | keys | Btn | navigator.clipboard?.writeText(JSON.stringify(attestResult,null,2))}>Copy |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 215 | - | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 216 | - | Btn | (icon or dynamic label) | submit} disabled={busy |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 339 | - | button | setError("")} style={ }> |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 356 | - | Btn | void load(false)}> |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 357 | - | Btn | setAddOpen(true)}>+ Add Target |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 407 | - | Btn | void handleScan(t.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 410 | - | Btn | void handleDelete(t.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 503 | - | Btn | void handleResolve(f.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 526 | - | Btn | void load(false)}> Refresh |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 798 | lineage | Btn | Export | exportGraphJSON} disabled={!graph |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 801 | lineage | Btn | void loadGraph()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 826 | lineage | button | setView(key)} style={{ padding: "8px 16px", border: "none", background: "tran... |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 848 | lineage | button | } style={{ background: timeFilter === tf.value ? C.accentDim : "transparent",... |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 880 | lineage | button | setSelectedNode(null)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 916 | lineage | Btn | }>View Timeline |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 917 | lineage | Btn | }>View Dependencies |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 918 | lineage | Btn | }>Impact Analysis |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 926 | lineage | button | setSelectedEdge(null)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1045 | lineage | Btn | (icon or dynamic label) | doSearch} disabled={searching |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1257 | lineage | Btn | (icon or dynamic label) | doRecordEvent} disabled={recording |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1281 | lineage | Btn | (icon or dynamic label) | loadTimeline} disabled={loadingTimeline |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1332 | lineage | button | toggleEntry(entry.event_id)} style={ }> {isExpanded ? : } |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1384 | lineage | Btn | (icon or dynamic label) | loadDependencies} disabled={loadingDeps |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1439 | lineage | Btn | }>Explore |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1517 | lineage | Btn | } disabled= > |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1831 | lineage | Btn | } disabled= > |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1834 | lineage | Btn | Export JSON | exportAuditJSON} disabled={!auditEvents \|\| auditEvents.length === 0 |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 1938 | lineage | Btn | (icon or dynamic label) | loadProvenance} disabled={loadingProv |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 2155 | lineage | Btn | (icon or dynamic label) | loadDataflow} disabled={loadingDf |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 2347 | lineage | Btn | } disabled= > |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 2424 | lineage | button | setHeatmapDetail(null)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 2540 | lineage | Btn | }> View History |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 2613 | lineage | Btn | (icon or dynamic label) | loadForensics} disabled={loadingFor |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 2711 | lineage | button | toggleAnomaly(i)} style={ }> {isExpanded ? : } |  |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 2829 | lineage | Btn | (icon or dynamic label) | loadCustody} disabled={loadingCust |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 2971 | lineage | Btn | (icon or dynamic label) | verifyCustodyIntegrity} disabled={loadingVerify |
| web/dashboard/src/components/v3/tabs/LineageTab.tsx | 3018 | lineage | Btn | Export Full Report (JSON) | exportCustodyJSON |
| web/dashboard/src/components/v3/tabs/OpsMetricsTab.tsx | 92 | ops_metrics | button | setTimeWindow(w)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/OpsMetricsTab.tsx | 99 | ops_metrics | button | Refresh | load} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/OpsMetricsTab.tsx | 121 | ops_metrics | button | setSection(s.id as any)} style={{ padding: "8px 16px", border: "none", backgr... |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 199 | pkcs11 | Btn | void createSDKJWT()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 202 | pkcs11 | Btn | void loadOverview()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 209 | pkcs11 | Btn | setShowJWT((v)=>!v)}> |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 210 | pkcs11 | Btn | void copySDKJWT()}>Copy JWT |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 260 | pkcs11 | Btn | void downloadArtifact("pkcs11",pkcsTarget as any)} disabled={downloading===`p... |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 287 | pkcs11 | Btn | void downloadArtifact("jca",jcaTarget as any)} disabled={downloading===`jca:$... |  |
| web/dashboard/src/components/v3/tabs/PaymentPolicyTab.tsx | 453 | - | Btn | void loadAll(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PaymentPolicyTab.tsx | 454 | - | Btn | (icon or dynamic label) | saveAll} disabled={loading \|\| saving |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 824 | payment | Btn | void refreshAP2Profile()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 825 | payment | Btn | void saveAP2Profile()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 917 | payment | Btn | void refreshInjectionData()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 931 | payment | Btn | void registerTerminal()} disabled= >Register Terminal |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 944 | payment | Btn | void issueChallenge()} disabled= >Issue Challenge |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 945 | payment | Btn | void verifyChallenge()} disabled= >Verify Challenge |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 967 | payment | Btn | { if(op==="Payment Key Injection") if(op==="AP2 Agent Payments") void runPaym... |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 89 | playbooks | button | (icon or dynamic label) | disabled ? undefined : onClick} style={{ ...base, ...styles[variant] |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 490 | playbooks | Btn | { if (v === "create") setView(v); }}> {v === "create" ? <> New : v === "playb... |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 496 | playbooks | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 592 | playbooks | Btn | }> New Playbook |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 604 | playbooks | button | toggleRow(pb.id)} style={ }> {expandedRows.has(pb.id) ? : } |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 613 | playbooks | button | handleToggleEnabled(pb)} style={ }> {pb.enabled ? : } |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 621 | playbooks | Btn | handleEdit(pb)}> Edit |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 622 | playbooks | Btn | handleRun(pb.id)} disabled= > Run |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 623 | playbooks | Btn | handleDelete(pb.id)}> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 696 | playbooks | button | removeAction(i)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 712 | playbooks | Btn | Add Action | addAction |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 714 | playbooks | Btn | (icon or dynamic label) | handleCreate} disabled={creating |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 717 | playbooks | Btn | }>Cancel |  |
| web/dashboard/src/components/v3/tabs/PostQuantumTab.tsx | 133 | - | Btn | void refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostQuantumTab.tsx | 134 | - | Btn | void scanNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostQuantumTab.tsx | 135 | - | Btn | void savePolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 536 | posture | Btn | load(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 537 | posture | Btn | (icon or dynamic label) | runScan} disabled={running |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 946 | posture | Btn | setFindingEngine("")} style={ }>Clear engine filter |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1182 | posture | Btn | patchFinding(selectedFinding, "acknowledged")} disabled= >Acknowledge |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1183 | posture | Btn | patchFinding(selectedFinding, "resolved")} disabled= >Resolve |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1184 | posture | Btn | patchFinding(selectedFinding, "reopened")}>Reopen |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1185 | posture | Btn | setSelectedFinding(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1274 | posture | Btn | executeAction(selectedAction)}> Execute |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1276 | posture | Btn | setSelectedAction(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 477 | restapi | Btn | (icon or dynamic label) | executeRequest} disabled={running |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 508 | restapi | Btn | void loadClientSecurity(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 515 | restapi | button | setSelectedClientID(String(item?.id\|\|""))} style={{ textAlign:"left", border:... |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 611 | restapi | Btn | setClientDraft(selectedClient? :null)}>Reset |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 612 | restapi | Btn | (icon or dynamic label) | saveClientSecurity} disabled={clientSaving |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 733 | restapi | Btn | Refresh cURL | buildPreview |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 734 | restapi | Btn | (icon or dynamic label) | executeRequest} disabled={running |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 239 | - | Btn | Create Policy | openCreateModal |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 241 | - | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 296 | - | Btn | void doTrigger(p.id, p.name)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 299 | - | Btn | openEditModal(p)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 302 | - | Btn | void doDelete(p)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 360 | - | Btn | void doTrigger(u.policy_id, u.policy_name)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 463 | - | Btn | setPolicyModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 464 | - | Btn | (icon or dynamic label) | savePolicy} disabled={pSaving \|\| !pName.trim() |
| web/dashboard/src/components/v3/tabs/RotationSchedulingTab.tsx | 22 | rotation | button | setView(id)} style={{ display: "inline-flex", alignItems: "center", gap: 6, p... |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 634 | sbom | Btn | { void loadData( ).then(() => loadVulnerabilities( )); }} disabled= > |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 743 | sbom | Btn | void exportSBOMFile("cyclonedx")} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 746 | sbom | Btn | void exportSBOMFile("spdx")} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 750 | sbom | Btn | setExportMenuOpen((prev) => !prev)} disabled= style={ }>Export |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 752 | sbom | Btn | } disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 755 | sbom | Btn | } disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 760 | sbom | Btn | void openSBOMDiff()} style={ }>SBOM Diff |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 829 | sbom | Btn | void exportCBOMFile()} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 832 | sbom | Btn | void openCBOMDiff()} style={ }>View Diff |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 916 | sbom | Btn | }>Add Offline Advisory |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1008 | sbom | Btn | setAdvisoryModalOpen(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1009 | sbom | Btn | void saveOfflineAdvisory()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1021 | sbom | Btn | void removeOfflineAdvisory(String(item?.id \|\| ""))} disabled= > |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1050 | sbom | Btn | setDiffOpen(false)}>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1084 | sbom | Btn | setSBOMDiffOpen(false)}>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1117 | sbom | Btn | }>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1147 | sbom | Btn | }>Close |  |
| web/dashboard/src/components/v3/tabs/ThreatExposureTab.tsx | 16 | threat_exposure | button | (icon or dynamic label) | disabled ? undefined : onClick} disabled={disabled |
| web/dashboard/src/components/v3/tabs/ThreatExposureTab.tsx | 96 | threat_exposure | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/ThreatExposureTab.tsx | 102 | threat_exposure | button | setSubView(v)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, f... |  |
| web/dashboard/src/components/v3/tabs/ThreatExposureTab.tsx | 128 | threat_exposure | Btn | Bind | handleBind |
| web/dashboard/src/components/v3/tabs/ThreatExposureTab.tsx | 129 | threat_exposure | Btn | setBindFor(null)}> Cancel |  |
| web/dashboard/src/components/v3/tabs/ThreatExposureTab.tsx | 145 | threat_exposure | button | setSourceFilter(v)} style={{ padding: "6px 14px", borderRadius: 6, fontSize:... |  |
| web/dashboard/src/components/v3/tabs/ThreatExposureTab.tsx | 193 | threat_exposure | Btn | handleResolve(f)}> |  |
| web/dashboard/src/components/v3/tabs/ThreatExposureTab.tsx | 197 | threat_exposure | Btn | }> Bind to key |  |
| web/dashboard/src/components/v3/tabs/ThreatProtectionTab.tsx | 16 | - | button | (icon or dynamic label) | disabled ? undefined : onClick} disabled={disabled |
| web/dashboard/src/components/v3/tabs/ThreatProtectionTab.tsx | 81 | - | Btn | setShowCanaryForm(!showCanaryForm)} small> Add Canary |  |
| web/dashboard/src/components/v3/tabs/ThreatProtectionTab.tsx | 82 | - | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/ThreatProtectionTab.tsx | 108 | - | button | setView(v)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, font... |  |
| web/dashboard/src/components/v3/tabs/ThreatProtectionTab.tsx | 133 | - | Btn | handleAck(s.id)}> Acknowledge |  |
| web/dashboard/src/components/v3/tabs/ThreatProtectionTab.tsx | 154 | - | Btn | (icon or dynamic label) | handleCreateCanary} disabled={saving \|\| !canaryForm.label |
| web/dashboard/src/components/v3/tabs/ThreatProtectionTab.tsx | 155 | - | Btn | setShowCanaryForm(false)} variant="ghost">Cancel |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 446 | - | button | setOp(name)} style={{ background:op===name?C.accent:"transparent", color:op==... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 465 | - | Btn | {if(!session?.token)return;setLoading(true);try{setVaults(await listTokenVaul... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 564 | - | Btn | void submitCurrent()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 580 | - | Btn | setOp("Mask")}>Open Mask Operation |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 588 | - | Btn | setOp("Redact")}>Open Redact Operation |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 764 | - | button | setMode(name)} style={{ background:mode===name?C.accentDim:"transparent", col... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 811 | - | Btn | void submit()} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1183 | - | Btn | void downloadSDK()} disabled= >Download SDK |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1184 | - | Btn | void refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1214 | - | Btn | void submitInit()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1237 | - | Btn | void submitComplete()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1260 | - | Btn | void submitLease()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1276 | - | Btn | void submitReceipt()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1316 | - | Btn | void revokeLease(item)} disabled= >Revoke |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1606 | - | Btn | void loadPolicy(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1607 | - | Btn | (icon or dynamic label) | savePolicy} disabled={saving\|\|loading |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2184 | - | Btn | void loadPolicy(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2185 | - | Btn | (icon or dynamic label) | savePolicy} disabled={saving\|\|loading |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2380 | - | Btn | void refreshVaultRows(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2381 | - | Btn | void downloadVaultSetup()} disabled= >Download Setup Query |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2382 | - | Btn | void createVaultFromPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2439 | - | Btn | void deleteVaultFromPolicy(row)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2714 | - | Btn | void loadPolicy(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2715 | - | Btn | (icon or dynamic label) | savePolicy} disabled={saving\|\|loading |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2928 | - | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3001 | - | Btn | selectSubtab("fieldenc")}>Field Encryption |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3002 | - | Btn | selectSubtab("dataenc-policy")}>Data Encryption Policy |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3003 | - | Btn | selectSubtab("token-policy")}>Token / Mask / Redact Policy |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3004 | - | Btn | selectSubtab("payment-policy")}>Payment Policy |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3005 | - | Btn | selectSubtab("pkcs11")}>PKCS#11 / JCA |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 446 | vault | Btn | (icon or dynamic label) | handleRefresh} disabled={refreshing \|\| busy |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 452 | vault | button | setCategory(cat.id)} style={{ height: 32, padding: "0 12px", borderRadius: 8,... |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 460 | vault | Btn | setModal("create")} style={ }> Store Secret |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 463 | vault | Btn | } style={ }> Generate |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 518 | vault | Btn | } style={ }>+ Folder |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 571 | vault | Btn | setFolderModalOpen(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 572 | vault | Btn | { const folderName = newFolderName.trim().replace(/[^a-zA-Z0-9._/-]/g, "-").r... |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 619 | vault | Btn | } disabled= > Download |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 620 | vault | Btn | } disabled= > Delete |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 639 | vault | Btn | setModal("create")}> Store Your First Secret |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 640 | vault | Btn | }> Generate Key Pair |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 734 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 735 | vault | Btn | void submitCreate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 749 | vault | Btn | copyToClipboard(generatedPublicKey, onToast)}> Copy Public Key |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 752 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 753 | vault | Btn | void submitGenerate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 802 | vault | button | setShowValue(!showValue)} style={ }> {showValue ? <> Hide : <> Reveal } |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 805 | vault | button | copyToClipboard(retrievedValue, onToast)} style={ }> Copy |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 812 | vault | Btn | void fetchFormat()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 813 | vault | Btn | void downloadSecret(selectedSecret)} disabled= > Download |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 854 | vault | Btn | }> Rotate Value |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 857 | vault | Btn | void removeSecret(selectedSecret)} disabled= > Delete |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 858 | vault | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 873 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 874 | vault | Btn | void submitRotate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 154 | webhooks | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 193 | webhooks | button | + Add | addHeader} style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 199 | webhooks | button | removeHeader(i)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 206 | webhooks | button | Cancel | onClose} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 207 | webhooks | button | (icon or dynamic label) | handleSave |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 240 | webhooks | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer" |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 325 | webhooks | button | {wh.enabled ? : } | onToggle} title={wh.enabled ? "Disable" : "Enable" |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 328 | webhooks | button | Test | handleTest} disabled={testing |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 331 | webhooks | button | Edit | onEdit} title="Edit" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 332 | webhooks | button | Delete | onDelete} title="Delete" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 333 | webhooks | button | {logOpen ? : } | onViewLog} title="View log" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 419 | webhooks | button | load(true)} disabled= style={{ background: C.card, border: `1px solid $ `, bo... |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 426 | webhooks | button | } style={ } > Add Webhook |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 270 | - | Btn | load(false)}> |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 309 | - | Btn | (icon or dynamic label) | saveSettings} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 359 | - | Btn | (icon or dynamic label) | saveRegistration} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 379 | - | Btn | setRegistrationDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 380 | - | Btn | { try catch (error) { onToast?.(`Delete failed: $ `); } }}>Delete |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 400 | - | Btn | (icon or dynamic label) | saveFederation} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 415 | - | Btn | setFederationDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 416 | - | Btn | { try catch (error) { onToast?.(`Delete failed: $ `); } }}>Delete |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 449 | - | Btn | (icon or dynamic label) | runIssue} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 479 | - | Btn | (icon or dynamic label) | runExchange} disabled={busy |
| web/dashboard/src/modules/admin/ExposurePanel.tsx | 86 | - | Btn | { setAck( ); setReason(""); }}>Acknowledge |  |
| web/dashboard/src/modules/admin/ExposurePanel.tsx | 98 | - | Btn | setShowClosed((v) => !v)}>{showClosed ? "Hide closed" : `Show $ closed`} |  |
| web/dashboard/src/modules/admin/ExposurePanel.tsx | 108 | - | Btn | setAck(null)}>Cancel |  |
| web/dashboard/src/modules/admin/ExposurePanel.tsx | 109 | - | Btn | void acknowledge()}> |  |
| web/dashboard/src/modules/admin/FipsModePanel.tsx | 103 | - | Btn | void review(m)}> |  |
| web/dashboard/src/modules/admin/FipsModePanel.tsx | 122 | - | Btn | void apply()}> {busy ? "Applying..." : `Switch to $ and restart services`} |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 280 | - | Btn | inputRef.current?.click()} style={{ padding: "8px 14px", borderRadius: 10, bo... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 294 | - | Btn | { onFileChange(null); if (inputRef.current) }} style={ } > Clear |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 839 | - | button | toggleScope(section)} style={{fontSize:11,padding:"4px 10px",borderRadius:6,b... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2224 | - | Btn | void restartAllAllowedServices()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2231 | - | Btn | void loadHealth()}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2260 | - | Btn | void restartSvc(name)} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2278 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2279 | - | Btn | }>Configure TLS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2280 | - | Btn | setFipsConfigModalOpen(true)}>Configure FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2292 | - | Btn | {setSystemState((p)=>( ));onFipsModeChange("enabled");}}>Enable FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2293 | - | Btn | {setSystemState((p)=>( ));onFipsModeChange("disabled");}}>Disable FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2369 | - | Btn | setFipsConfigModalOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2370 | - | Btn | void saveFipsConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2415 | - | Btn | }>Open Interfaces |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2417 | - | Btn | }>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2418 | - | Btn | void saveTLSConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2425 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2426 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2427 | - | Btn | {try catch(e){onToast(`Apply failed: $ `);}}} disabled= >Apply Network Config |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2452 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2453 | - | Btn | void testSnmpSettings()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2454 | - | Btn | void saveSnmpSettings()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2536 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2549 | - | Btn | void loadTags()}>Refresh |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2554 | - | Btn | void addTag()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2569 | - | Btn | void removeTag(name,usageCount)} disabled= >Delete |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2579 | - | Btn | void loadPasswordPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2579 | - | Btn | void savePasswordPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2604 | - | Btn | void saveSecurityPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2623 | - | Btn | void loadAccessHardening()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2624 | - | Btn | void saveAccessHardening()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2655 | - | Btn | void Promise.all([loadAccessHardening(),loadHealth()])} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2656 | - | Btn | openNetIfModal()} disabled= >+ Add Interface |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2687 | - | Btn | void toggleNetIfEnabled(iface)}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2688 | - | Btn | openNetIfModal(iface)}>Edit |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2689 | - | Btn | void deleteNetIf(iface.interface_name)}>Delete |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2766 | - | Btn | }>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2767 | - | Btn | void saveNetIf()}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2773 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2773 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2869 | - | Btn | setPanel("network")}>Open Network |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2870 | - | Btn | setPanel("interfaces")}>Open Interfaces |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2880 | - | Btn | }> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2887 | - | Btn | void openCli()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2900 | - | Btn | { if(!session?.token) return; setHsmSaving(true); try{ const payload= ; const... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2931 | - | Btn | {if(!session?.token) return; const lib=String(hsm.library_path\|\|"").trim(); i... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2934 | - | Btn | setHsm((p)=>( ))}>Use |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2941 | - | Btn | {if(!session?.token) return; setGovSaving(true); try{await updateGovernanceSe... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2947 | - | Btn | {if(!session?.token\|\|!String(smtpTo\|\|"").trim()) setSmtpTesting(true); try ca... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2948 | - | Btn | {if(!session?.token) return; setWebhookTesting((p)=>( )); try catch(error){if... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2949 | - | Btn | {if(!session?.token) return; setWebhookTesting((p)=>( )); try catch(error){if... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2954 | - | Btn | void loadJobs()}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2954 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2979 | - | Btn | { if(!session?.token) return; if(backupScope==="tenant"&&!String(backupTenant... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3003 | - | Btn | dl(sh.file_name,sh.content_base64,sh.content_type)}>Download |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3006 | - | Btn | setBackupCreatedShares([])}>All shares handed out: close |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3034 | - | Btn | backupShareInputRef.current?.click()}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3035 | - | Btn | }>Clear |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3040 | - | Btn | void verifyBackup()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3041 | - | Btn | void restoreBackup()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3055 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDownloading(`$ :artifact`); try ca... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3055 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDownloading(`$ :key`); try catch(e... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3055 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDeleting(id); try catch(error){if(... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3061 | - | Btn | void refreshAlertRules()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3061 | - | Btn | openRuleModal()}>Create Rule |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3078 | - | Btn | {if(!session?.token\|\|!id) return; try{await updateReportingRule(session,id, )... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3081 | - | Btn | openRuleModal(rule)}>Edit |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3082 | - | Btn | {if(!session?.token\|\|!id) return; try catch(error){if(!sessionGuard(error)) o... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3132 | - | Btn | setRuleModalOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3133 | - | Btn | void handleSaveRule()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3140 | - | Btn | void loadGovPolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3141 | - | Btn | openGovPolicyModal()}>+ Create Policy |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3177 | - | button | openGovPolicyModal(policy)} style={{fontSize:10,padding:"3px 8px",borderRadiu... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3178 | - | button | {if(!session?.token) return; try{await updateGovernancePolicy(session,policy.... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3251 | - | Btn | }>Select All |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3252 | - | Btn | setGpTriggers([])}>Clear All |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3295 | - | Btn | setGovPolicyModal(false)}>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3296 | - | Btn | void saveGovPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3304 | - | Btn | void loadFDEStatus()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3340 | - | Btn | void doFDEIntegrityCheck()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3345 | - | Btn | void doFDERotateKey()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3366 | - | Btn | void doFDETestRecovery()} disabled= style={ }> |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 427 | - | button | setActiveTab(t)} style={{ background: activeTab === t ? C.accentDim : "transp... |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 457 | - | Btn | void loadTenants()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 458 | - | Btn | setCreateOpen(true)}>+ Create Tenant |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 624 | - | Btn | void loadPolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 625 | - | Btn | void savePolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 693 | - | Btn | setHsmConfig((c) => ( ))}>Select |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 701 | - | Btn | void loadHSM()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 702 | - | Btn | void saveHSM()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 725 | - | Btn | void loadBackups()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 726 | - | Btn | void handleCreateBackup()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 759 | - | Btn | void handleDownloadArtifact(b.id)}>Artifact |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 760 | - | Btn | void handleDownloadKey(b.id)}>Key |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 763 | - | Btn | void handleDeleteBackup(b.id)}>Delete |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 854 | - | Btn | void handleEnable()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 867 | - | Btn | void loadReadiness()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 868 | - | Btn | void handleDisable()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 871 | - | Btn | void handleDelete()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 929 | - | Btn | setCreateOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 930 | - | Btn | void createTenant()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/GroupBindingsSection.tsx | 26 | - | Btn | void model.upsertBinding()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/GroupBindingsSection.tsx | 38 | - | Btn | void model.removeBinding(binding)} disabled= >Delete |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 256 | - | Btn | void model.loadIdpConfig()}>Reload |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 257 | - | Btn | void model.testIdpConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 258 | - | Btn | void model.saveIdpConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 267 | - | Btn | void model.discoverIdpUsers()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 268 | - | Btn | void model.discoverIdpGroups()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 284 | - | Btn | } > Select |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 299 | - | Btn | void model.discoverIdpMembers()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 344 | - | Btn | void model.importIdpUsers()} disabled= > {model.idpImporting ? "Importing..."... |  |
| web/dashboard/src/modules/admin/user-admin/PoliciesSection.tsx | 11 | - | Btn | void model.savePolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/ScimProvisioningSection.tsx | 136 | - | Btn | void rotateToken()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/ScimProvisioningSection.tsx | 139 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 13 | - | Btn | void model.loadUsers()}> |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 55 | - | Btn | } > Reset Password |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 103 | - | Btn | void model.createUser()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 123 | - | Btn | model.setResetMustChange((prev) => !prev)}>Toggle |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 126 | - | Btn | void model.resetPassword()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMActivityPanel.tsx | 40 | - | Btn | void load()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMIntegrationCard.tsx | 75 | - | Btn | void load()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMIntegrationCard.tsx | 95 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMKeyCheckPanel.tsx | 38 | - | Btn | void run()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMPartitionTable.tsx | 48 | - | Btn | void load()} disabled= > |  |
