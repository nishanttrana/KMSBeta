# Generated UI Button Inventory

Generated at `2026-05-10T16:35:18Z` by `scripts/generate_product_map.py`.

This is a static inventory of controls with `onClick` handlers. For exact runtime behavior, combine it with Playwright traces and network logs.

| File | Line | Tabs | Control | Visible label | Handler snippet |
| --- | --- | --- | --- | --- | --- |
| web/dashboard/src/components/AppErrorBoundary.tsx | 81 | - | button | Try again | this.handleReload |
| web/dashboard/src/components/AppErrorBoundary.tsx | 96 | - | button | window.location.reload()} style={ } > Reload page |  |
| web/dashboard/src/components/IdleWarningModal.tsx | 95 | - | Btn | Logout Now | onLogout |
| web/dashboard/src/components/IdleWarningModal.tsx | 98 | - | Btn | Stay Active | onStayActive |
| web/dashboard/src/components/LoginScreen.tsx | 877 | - | button | {loading ? ( <> Authenticating... ) : ( <> Sign In )} | handleLogin |
| web/dashboard/src/components/LoginScreen.tsx | 930 | - | button | handleSSOLogin(sp.provider)} disabled= className="w-full rounded-xl px-4 py-2... |  |
| web/dashboard/src/components/LoginScreen.tsx | 978 | - | button | setShowPolicyHint((v) => !v)} className="text-cyber-accent transition-colors... |  |
| web/dashboard/src/components/LoginScreen.tsx | 1018 | - | button | {savingPassword ? ( <> Applying... ) : ( <> Update Password and Continue )} | handlePasswordChange |
| web/dashboard/src/components/ThemeToggle.tsx | 17 | - | button | {isDark ? : } | toggle |
| web/dashboard/src/components/ThemeToggle.tsx | 31 | - | button | } onMouseLeave={(e) => } > {isDark ? : } | toggle |
| web/dashboard/src/components/ToastStack.tsx | 84 | - | button | dismiss(toast.id)} aria-label="Dismiss notification" style={ } > × |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 734 | - | button | setCollapsed((v) => !v)} title= className="vk-icon-btn" style={{ width: 22, h... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 860 | - | button | Sign out | onLogout |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 908 | - | button | togglePin(tab)} title= style={{ display: "inline-flex", alignItems: "center",... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 931 | - | button | setPaletteOpen(true)} title="Command palette (⌘K)" className="vk-search-btn"... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 979 | - | Btn | selectTab("admin")} style={cliEnabled ? : }> |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 1015 | - | button | } className="vk-icon-btn" style={{ display: "inline-flex", alignItems: "cente... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 1069 | - | Btn | Logout | onLogout |
| web/dashboard/src/components/primitives.tsx | 23 | - | button | (icon or dynamic label) | onClick |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 56 | - | button | Close | onClose} aria-label="Close" style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", pa... |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 164 | - | Btn | (icon or dynamic label) | cancel |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 165 | - | Btn | (icon or dynamic label) | submit |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 537 | - | button | { if (!disabled) }} onFocus= onBlur= onMouseDown= onKeyDown= style={{ backgro... |  |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 650 | - | button | (icon or dynamic label) | onClick} disabled={disabled |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 677 | - | button | onChange(t)} style={{ background: active === t ? C.accentDim : "transparent",... |  |
| web/dashboard/src/components/v3/runtimeUtils.tsx | 66 | - | button | Retry | reset} style={{ border: "1px solid #243656", borderRadius: 6, padding: "4px 10px", background: "transparent", color:... |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 762 | ai_gateway | Btn | Refresh | refreshAll} disabled={loadingModels |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 772 | ai_gateway | button | setErr("")} style={ }>Dismiss |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 786 | ai_gateway | button | { setView(vc.key); if (vc.key === "governance" && accessRules.length === 0) i... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 941 | ai_gateway | Btn | { setView(s.target); if (s.target === "dlp_policies") void loadDlpPolicies();... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 951 | ai_gateway | Btn | }>View All |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 984 | ai_gateway | Btn | setView("models")}> Register Model |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 985 | ai_gateway | Btn | } style={{ background: C.blueDim, border: `1px solid $ 33`, color: C.blue }}>... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 988 | ai_gateway | Btn | setView("scan")} style={{ background: C.purpleDim, border: `1px solid $ 33`,... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 991 | ai_gateway | Btn | setView("realtime")} style={{ background: C.greenDim, border: `1px solid $ 33... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1050 | ai_gateway | Btn | (icon or dynamic label) | doCreateModel} disabled={modelFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1058 | ai_gateway | Btn | (icon or dynamic label) | loadModels} disabled={loadingModels |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1094 | ai_gateway | Btn | doTestModel(m.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1097 | ai_gateway | Btn | doDeleteModel(m.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1129 | ai_gateway | button | { setAccessForm(f => ( )); }} style={{ padding: "3px 8px", fontSize: 10, bord... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1150 | ai_gateway | button | { setAccessForm(f => ( )); }} style={{ padding: "4px 10px", fontSize: 10, bor... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1179 | ai_gateway | Btn | (icon or dynamic label) | doCreateAccessRule} disabled={accessFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1186 | ai_gateway | Btn | (icon or dynamic label) | loadRules} disabled={loadingRules |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1210 | ai_gateway | Btn | doDeleteAccessRule(r.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1272 | ai_gateway | Btn | (icon or dynamic label) | doCreateBudget} disabled={budgetFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1279 | ai_gateway | Btn | (icon or dynamic label) | loadBudgets} disabled={loadingBudgets |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1375 | ai_gateway | Btn | (icon or dynamic label) | doCreateGuardrail} disabled={guardrailFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1390 | ai_gateway | Btn | (icon or dynamic label) | doTestGuardrail} disabled={guardrailTestBusy \|\| !guardrailTestText.trim() |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1413 | ai_gateway | Btn | (icon or dynamic label) | loadGuardrails} disabled={loadingGuardrails |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1443 | ai_gateway | Btn | doDeleteGuardrail(g.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1476 | ai_gateway | button | setDlpPolicyForm(f => ( ))} style={{ background: C.accentDim, border: `1px so... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1480 | ai_gateway | button | setDlpPolicyForm(f => ( ))} style={{ background: "transparent", border: `1px... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1546 | ai_gateway | Btn | (icon or dynamic label) | doCreateDlpPolicy} disabled={dlpPolicyFormBusy |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1556 | ai_gateway | Btn | (icon or dynamic label) | loadDlpPolicies} disabled={loadingDlpPolicies |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1593 | ai_gateway | Btn | doDeleteDlpPolicy(p.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1614 | ai_gateway | button | setScanMode(m)} style={{ padding: "8px 18px", fontSize: 11, fontWeight: scanM... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1639 | ai_gateway | Btn | doScan("scan")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1642 | ai_gateway | Btn | doScan("redact")} disabled= style={{ background: C.purpleDim, border: `1px so... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1645 | ai_gateway | Btn | doScan("evaluate")} disabled= style={{ background: C.amberDim, border: `1px s... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1772 | ai_gateway | Btn | (icon or dynamic label) | doSimulateGateway} disabled={scanning |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1884 | ai_gateway | Btn | (icon or dynamic label) | loadRealtimeFeed |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1932 | ai_gateway | button | setReportPeriod(val)} style={{ padding: "6px 14px", fontSize: 10, borderRadiu... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 1940 | ai_gateway | Btn | Export JSON | exportReportJSON |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2032 | ai_gateway | button | } style={{ padding: "3px 10px", fontSize: 10, borderRadius: 4, cursor: "point... |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2040 | ai_gateway | Btn | Refresh | loadAudit} disabled={loadingAudit |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2041 | ai_gateway | Btn | Export | exportReportJSON |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2093 | ai_gateway | Btn | setAuditPage(p => Math.max(0, p - 1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/AIGatewayTab.tsx | 2095 | ai_gateway | Btn | setAuditPage(p => Math.min(totalAuditPages - 1, p + 1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/AITab.tsx | 347 | ai | Btn | void handleSend()} disabled= > Send |  |
| web/dashboard/src/components/v3/tabs/AITab.tsx | 361 | ai | Btn | void loadConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AITab.tsx | 362 | ai | Btn | void saveConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 418 | alerts | Btn | void refresh(false)}> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 419 | alerts | Btn | void ackAllAlerts()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 429 | alerts | Btn | setActiveFilter(tab.id)} style={{ background:activeFilter===tab.id?(palette[`... |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 466 | alerts | Btn | void ackAlert(item)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 467 | alerts | Btn | void escalateOne(item)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 488 | alerts | Btn | setPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 490 | alerts | Btn | setPageIndex((prev)=>Math.min(totalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 243 | - | Btn | void load(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 244 | - | Btn | void saveSettings()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 271 | - | Btn | void submitSign()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 313 | - | Btn | void saveProfile()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 353 | - | Btn | editProfile(item)}>Edit |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 354 | - | Btn | void removeProfile(item)}>Delete |  |
| web/dashboard/src/components/v3/tabs/ArtifactSigningTab.tsx | 377 | - | Btn | void verifyRecord(item)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 631 | audit | Btn | void exportEventsAsCEF(filteredEvents, signingKeyId ? session : undefined, si... |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 632 | audit | Btn | (icon or dynamic label) | verifyChain} disabled={chainVerifying |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 635 | audit | Btn | load()} disabled= >Refresh |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 722 | audit | Btn | setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 723 | audit | Btn | setOffset(offset + PAGE_SIZE)}>Next |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 917 | audit | Btn | handleAcknowledge(al.id)}>Ack |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 920 | audit | Btn | handleResolve(al.id)}>Resolve |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 951 | audit | Btn | (icon or dynamic label) | loadForensic} disabled={forensicLoading |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 1059 | audit | Btn | }> View Timeline ( ) |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 1064 | audit | Btn | }> View Session ( ) |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 1069 | audit | Btn | }> View Correlation ( ) |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 370 | - | Btn | refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 371 | - | Btn | Save Settings | saveSettings} disabled={busy \|\| loading |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 475 | - | Btn | Save Settings | saveSettings} disabled={busy |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 516 | - | Btn | setTemplateDraft(DEFAULT_TEMPLATE)}>Reset |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 517 | - | Btn | Save Template | saveTemplate} disabled={busy |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 538 | - | Btn | setTemplateDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 544 | - | Btn | removeTemplate(String(item?.id \|\| ""))}>Delete |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 591 | - | Btn | setPolicyDraft(DEFAULT_POLICY)}>Reset |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 592 | - | Btn | Save Service Default | savePolicy} disabled={busy |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 614 | - | Btn | setPolicyDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 620 | - | Btn | removePolicy(String(item?.service_name \|\| ""))}>Delete |  |
| web/dashboard/src/components/v3/tabs/AutokeyTab.tsx | 661 | - | Btn | Submit Request | submitRequest} disabled={busy |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 481 | byok | Btn | setConnectorView("cards")} title="Card view"> |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 482 | byok | Btn | setConnectorView("list")} title="List view"> |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 483 | byok | Btn | void refresh()} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 484 | byok | Btn | }> Region Mappings |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 485 | byok | Btn | setModal("add")}>+ Add Connector |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 511 | byok | button | setExpandedProvider(isExpanded ? null : card.provider)} style={ }> {isExpande... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 529 | byok | Btn | } disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 535 | byok | Btn | { const activeAccount = card.accounts[0]; if (activeAccount) }} disabled= >Im... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 544 | byok | Btn | } disabled= > Inventory |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 547 | byok | Btn | void deleteConnector(card.provider, card.accounts[0])} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 570 | byok | button | setConnectorMenu(menuOpen ? "" : String(card.provider))} style={{ border: `1p... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 574 | byok | button | } disabled= style={ }>Sync Now |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 575 | byok | button | } disabled= style={ }>Import Keys |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 576 | byok | button | } disabled= style={ }>Browse Inventory |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 577 | byok | button | } disabled= style={ }>Delete Connector |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 627 | byok | button | copyToClipboard(binding.cloud_key_ref \|\| binding.cloud_key_id)} style={ } tit... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 635 | byok | Btn | void rotateBindingAction(binding)} disabled= > {rotatingBinding === binding.i... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 695 | byok | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 696 | byok | Btn | void submitAddConnector()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 738 | byok | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 739 | byok | Btn | void submitImport()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 790 | byok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 791 | byok | Btn | void submitRegionMapping()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 826 | byok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 119 | backup | button | Refresh | load} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 123 | backup | button | setShowCreate(true)} style={ }> New Policy |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 141 | backup | button | setSection(s.id as any)} style={{ padding: "8px 16px", border: "none", backgr... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 189 | backup | button | handleTrigger(p.id)} disabled= style={{ padding: "4px 8px", borderRadius: 4,... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 192 | backup | button | deletePolicy(session, p.id).then(load)} style={{ padding: "4px 6px", borderRa... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 271 | backup | button | handleRestore(p.id)} disabled= style={{ padding: "4px 10px", borderRadius: 4,... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 329 | backup | button | setShowCreate(false)} style={{ padding: "7px 16px", borderRadius: 6, border:... |  |
| web/dashboard/src/components/v3/tabs/BackupTab.tsx | 330 | backup | button | (icon or dynamic label) | handleCreate} disabled={creating \|\| !form.name |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 206 | ct_monitor | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 207 | ct_monitor | Btn | (icon or dynamic label) | submit} disabled={busy |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 315 | ct_monitor | button | setErrorMsg("")} style={ }> |  |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 332 | ct_monitor | Btn | void load(false)}> |  |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 333 | ct_monitor | Btn | setAddOpen(true)}>+ Add Domain |  |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 382 | ct_monitor | Btn | void handleToggle(d.id, d.enabled)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 385 | ct_monitor | Btn | void handleDelete(d.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 467 | ct_monitor | Btn | void load(false)}> Refresh |  |
| web/dashboard/src/components/v3/tabs/CTMonitorTab.tsx | 498 | ct_monitor | Btn | void handleAck(a.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 67 | canary | button | (icon or dynamic label) | disabled ? undefined : onClick} style={{ ...base, ...styles[variant] |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 225 | canary | Btn | setView(v)}> {v === "create" ? <> Deploy : v === "canaries" ? <> Keys : <> Ov... |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 231 | canary | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 320 | canary | Btn | setView("create")}> Deploy New |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 332 | canary | button | toggleRow(c.id)} style={ }> {expandedRows.has(c.id) ? : } |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 348 | canary | Btn | toggleRow(c.id)}> Trips |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 349 | canary | Btn | handleTestTrip(c.id)} disabled= > Test |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 350 | canary | Btn | handleDeactivate(c.id)} disabled= > Deactivate |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 415 | canary | Btn | (icon or dynamic label) | handleCreate} disabled={creating |
| web/dashboard/src/components/v3/tabs/CanaryKeysTab.tsx | 418 | canary | Btn | setView("overview")}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1425 | certs | button | toggleCA(caID)} style={ }> {open? : } : |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1439 | certs | Btn | void actCRL(ca)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1440 | certs | Btn | void actDeleteCA(ca)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1446 | certs | button | toggleIssued(caID)} style={ }> {issuedOpen? : } Issued Certificates ( ) |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1672 | certs | Btn | openProtocolModal(meta.name)}> Configure |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1673 | certs | Btn | void runProtocolTest(meta.name)} > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1681 | certs | Btn | setModal("acme-wizard")}> ACME Wizard |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1682 | certs | Btn | setModal("acme-star")}> STAR |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1683 | certs | Btn | setModal("est-wizard")}> EST Enroll |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1684 | certs | Btn | setModal("scep-wizard")}> SCEP Enroll |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1685 | certs | Btn | setModal("cmpv2-wizard")}> CMPv2 Request |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1701 | certs | Btn | setCAStatusView("all")} style={ }>{`All $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1702 | certs | Btn | setCAStatusView("active")} style={ }>{`Active $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1703 | certs | Btn | setCAStatusView("revoked")} style={ }>{`Revoked $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1704 | certs | Btn | void refreshCAs()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1705 | certs | Btn | setModal("create-ca")}> Create CA |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1797 | certs | Btn | void refreshRenewalIntel()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1823 | certs | Btn | void refreshSTARIntel()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1824 | certs | Btn | setModal("acme-star")}>New |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1852 | certs | Btn | void actRefreshSTARSubscription(item,true)} disabled={rowActionBusy===`star-r... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1853 | certs | Btn | void actDeleteSTARSubscription(item)} disabled={rowActionBusy===`star-delete-... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1880 | certs | Btn | setModal("issue")} style={ }> Issue Certificate |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1881 | certs | Btn | setModal("sign-csr")} style={ }> Sign CSR |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1882 | certs | Btn | setModal("issue-pqc")} style={ }> PQC Issue |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1883 | certs | Btn | setModal("upload-3p")} style={ }> Upload 3rd-Party |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1884 | certs | Btn | setModal("cert-alert-policy")} style={ }> Alert Policy |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1892 | certs | Btn | { setCTBuilding(true); try{ const res=await buildCertMerkleEpoch(session,500)... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1906 | certs | Btn | }>Refresh |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1940 | certs | Btn | { const id=ctProofCertId.trim(); if(!id) try{ const proof=await getCertMerkle... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1999 | certs | Btn | setCertStatusView("all")} style={ }> {`All ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2002 | certs | Btn | setCertStatusView("active")} style={ }> {`Active ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2005 | certs | Btn | setCertStatusView("revoked")} style={ }> {`Revoked ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2009 | certs | Btn | void refreshCerts()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2040 | certs | button | openCertActionMenu(e,certID)} aria-label="Certificate actions" style={{ backg... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2072 | certs | button | } onMouseEnter={(e)=> } onMouseLeave={(e)=> } style={ } > Download |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2086 | certs | button | } disabled={busy===`renew-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } st... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2099 | certs | button | } disabled={busy===`revoke-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } s... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2112 | certs | button | } disabled={busy===`ocsp-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } sty... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2127 | certs | button | } disabled={busy===`delete-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } s... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2163 | certs | Btn | setCertPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2165 | certs | Btn | setCertPageIndex((prev)=>Math.min(certTotalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2222 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2223 | certs | Btn | void submitCreateCA()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2305 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2306 | certs | Btn | void submitIssueCert(modal==="issue-pqc")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2368 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2369 | certs | Btn | void submitSignCSR()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2398 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2399 | certs | Btn | void submitDownloadCert()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2423 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2424 | certs | Btn | void submitUpload()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2443 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2444 | certs | Btn | void saveAlertPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2470 | certs | Btn | setProtocolConfigText(JSON.stringify(protocolDefaultConfigs[String(protocolNa... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2472 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2473 | certs | Btn | void saveProtocol()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2547 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2548 | certs | Btn | void submitCreateSTARSubscription()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2591 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2592 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const email=String... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2657 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2658 | certs | Btn | { if(!session)return; try{ const attrs=await estCSRAttributes(session); onToa... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2665 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const cn=String((d... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2717 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2718 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const msgType=Stri... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2780 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2781 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const msgType=Stri... |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 30 | cloudctl | Btn | selectSubtab("byok")}>BYOK |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 31 | cloudctl | Btn | selectSubtab("hyok")}>HYOK |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 32 | cloudctl | Btn | selectSubtab("google-cse")}>Google CSE |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 33 | cloudctl | Btn | selectSubtab("azure")}>Azure EKM |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 118 | - | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 254 | - | Btn | setAddNodeModalOpen(true)}>Add Instance |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 255 | - | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 316 | - | Btn | void updateNodeRoleAction(node)} > |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 321 | - | Btn | void removeNodeAction(node)}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 332 | - | Btn | setAddNodeModalOpen(true)}>Add First Instance |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 370 | - | Btn | setAddNodeModalOpen(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 371 | - | Btn | void addExistingNode()}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 440 | - | Btn | void saveProfile()}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 458 | - | Btn | void removeProfile(profile)}>Delete |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 489 | - | Btn | void refreshSyncEvents()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 579 | - | Btn | void refreshClusterLogs()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 592 | - | Btn | void refreshClusterLogs()}>Apply |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 755 | compliance | Btn | setView("assessment")} style={ }>Assessment |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 756 | compliance | Btn | setView("reporting")} style={ }>Reporting |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 757 | compliance | Btn | setView("inventory")} style={ }>Crypto Inventory |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 760 | compliance | Btn | void loadInventory()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 887 | compliance | Btn | setView("assessment")} style={ }>Assessment |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 888 | compliance | Btn | setView("reporting")} style={ }>Reporting |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 889 | compliance | Btn | setView("inventory")} style={ }>Crypto Inventory |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 892 | compliance | Btn | void loadReporting()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1025 | compliance | Btn | void triggerReportNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1053 | compliance | Btn | void createScheduleReport()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1073 | compliance | Btn | void downloadJob(job)} disabled= >Download |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1074 | compliance | Btn | void deleteJob(job)}>Delete |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1108 | compliance | Btn | setView("assessment")} style={ }>Assessment |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1109 | compliance | Btn | setView("reporting")} style={ }>Reporting |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1110 | compliance | Btn | setView("inventory")} style={ }>Crypto Inventory |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1121 | compliance | Btn | void createTemplate()} disabled= >+ Template |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1122 | compliance | Btn | void saveTemplate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1123 | compliance | Btn | void removeTemplate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1124 | compliance | Btn | void loadAssessment( )} disabled= >Refresh |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1125 | compliance | Btn | void exportEvidencePack("pdf")} disabled= >Evidence Pack |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1126 | compliance | Btn | void runNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1132 | compliance | Btn | void saveSchedule()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1150 | compliance | Btn | void runNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1985 | compliance | Btn | { setEvidenceBusy(true); try { await downloadEvidenceReport(session, ); onToa... |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 291 | - | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 321 | - | Btn | void refresh(false)}>Reload |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 322 | - | Btn | void savePolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 428 | - | Btn | void runEvaluation()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 601 | - | Btn | void refresh(false)}>Refresh History |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 205 | crypto_agility | button | Cancel | onClose} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 206 | crypto_agility | button | (icon or dynamic label) | handleSave |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 287 | crypto_agility | button | load(true)} disabled= style={{ background: C.card, border: `1px solid $ `, bo... |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 295 | crypto_agility | button | setShowModal(true)} style={ } > Create Migration Plan |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 711 | crypto | button | selectAlgorithmFromRail(String(name),fipsApproved)} disabled= style={{ displa... |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 745 | crypto | button | { if(tabAllowed) }} disabled= style={{ background:op===item.id?C.accent:"tran... |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 868 | crypto | button | {busy?`Execute $ ...`:`Execute $ `} | runOperation |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 896 | crypto | Btn | Hex | renderResultAsHex |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 897 | crypto | Btn | Base64 | renderResultAsBase64 |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 898 | crypto | Btn | Download | downloadResult |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 162 | dr_drill | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 261 | dr_drill | button | setShowCreate(true)} style={ }> Create Schedule |  |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 262 | dr_drill | button | (icon or dynamic label) | load} style={{ ...btnSecondary, padding: "9px 10px" |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 279 | dr_drill | button | setSection(t.key)} style={{ background: "none", border: "none", borderBottom:... |  |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 316 | dr_drill | button | handleRunNow(s.id, s.drill_type)} style={ }> Run Now |  |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 317 | dr_drill | button | handleDelete(s.id)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 401 | dr_drill | button | setSection("schedules")} style= >View Schedules |  |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 435 | dr_drill | button | setShowCreate(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/DRDrillTab.tsx | 436 | dr_drill | button | (icon or dynamic label) | handleCreate} disabled={saving \|\| !form.name.trim() \|\| !form.cron_expr.trim() |
| web/dashboard/src/components/v3/tabs/DSPMTab.tsx | 268 | dspm | Btn | void load()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/DSPMTab.tsx | 272 | dspm | Btn | void handleScan()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/DSPMTab.tsx | 298 | dspm | button | setView(t.id as any)} style={{ padding: "9px 18px", border: "none", backgroun... |  |
| web/dashboard/src/components/v3/tabs/DSPMTab.tsx | 432 | dspm | Btn | void handleScan()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/DSPMTab.tsx | 660 | dspm | Btn | void handleScan()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 228 | - | Btn | onNavigate?.("certs")}>View Certificates → |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 255 | - | button | onUnpinTab?.(tabId)} title={`Unpin $ `} style={ } > |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 265 | - | button | onNavigate?.(tabId)} style={{ display: "inline-flex", alignItems: "center", g... |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 431 | - | Btn | void submitHomeApprovalVote(item, "approved")} disabled={approvalVoteBusy ===... |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 432 | - | Btn | void submitHomeApprovalVote(item, "denied")} disabled={approvalVoteBusy === `... |  |
| web/dashboard/src/components/v3/tabs/DataActivityTab.tsx | 217 | data_activity | Btn | void load()} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/DataActivityTab.tsx | 240 | data_activity | button | setView(key as View)} style={{ padding: "8px 16px", border: "none", backgroun... |  |
| web/dashboard/src/components/v3/tabs/DataActivityTab.tsx | 526 | data_activity | Btn | (icon or dynamic label) | doIngest} disabled={ingestBusy |
| web/dashboard/src/components/v3/tabs/DataActivityTab.tsx | 529 | data_activity | Btn | { setIngestForm( ); setIngestErr(""); setIngestSuccess(false); }}> Reset |  |
| web/dashboard/src/components/v3/tabs/DevSecOpsTab.tsx | 51 | devsecops | button | {copied ? : } | handleCopy |
| web/dashboard/src/components/v3/tabs/DevSecOpsTab.tsx | 642 | devsecops | button | setView(id)} style={{ padding: "9px 18px", border: "none", background: "trans... |  |
| web/dashboard/src/components/v3/tabs/DevSecOpsTab.tsx | 807 | devsecops | button | setApiGroupFilter(g)} style={{ padding: "4px 10px", borderRadius: 5, border:... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 734 | ekm | Btn | setDbView(dbView==="cards"?"list":"cards")} style={ }>{dbView==="cards"? : } |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 735 | ekm | Btn | Deploy Agent | openDeploy |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 736 | ekm | Btn | Register Database | openDbRegister |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 737 | ekm | Btn | setModal("setup-guide")}>Setup Guide |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 738 | ekm | Btn | refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 799 | ekm | Btn | runRotate(agent)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 800 | ekm | Btn | openLogs(agent)} style={ }>Logs |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 801 | ekm | Btn | openHealthDetail(agent)} style={ }>Health |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 828 | ekm | Btn | } disabled= style={ }>Rotate |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 829 | ekm | Btn | } style={ }>Logs |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 867 | ekm | Btn | openHealthDetail(agent)} style={ }>Full Health |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 868 | ekm | Btn | runDelete(agent)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 898 | ekm | Btn | setExpandedTdeGuide(prev=>( ))} style={ }>Guide |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 899 | ekm | Btn | runRevokeTDE(db)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 918 | ekm | Btn | loadAgentKeyAccessLogs(expandedAgent)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 956 | ekm | Btn | setBitLockerView(bitLockerView==="cards"?"list":"cards")} style={ }>{bitLocke... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 957 | ekm | Btn | Register Client | openBitLockerDeploy |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 958 | ekm | Btn | Network Scan | openBitLockerScan |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 959 | ekm | Btn | refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 983 | ekm | Btn | runBitLockerOperation(client,op)} disabled={bitLockerOpClientID===`$ :$ `} st... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 984 | ekm | Btn | openBitLockerActivity(client)} style={ }>Activity |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 985 | ekm | Btn | openBitLockerDelete(client)} style={ }>Delete |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1006 | ekm | Btn | openBitLockerActivity(client)} style={ }>Activity |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1007 | ekm | Btn | openBitLockerOptions(client)} style={ }>Ops |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1008 | ekm | Btn | openBitLockerDelete(client)} style={ }>Del |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1035 | ekm | Btn | setModal("azure-add-config")}>+ Add Azure Vault |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1036 | ekm | Btn | setModal("azure-add-mapping")}>+ Add Key Mapping |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1037 | ekm | Btn | refresh(true)} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1058 | ekm | Btn | { setAzureTestResults(prev=>({...prev,[cfg.id]: })); try{ const res=await tes... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1066 | ekm | Btn | { setAzureSyncing(cfg.id); try{ const res=await syncAzureKeys(session,cfg.id)... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1074 | ekm | Btn | { if(!confirm("Delete this Azure vault configuration?")) return; try catch(e)... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1109 | ekm | Btn | { setAzureOpLoading(`import-$ `); try{const res=await importKeyToAzure(sessio... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1113 | ekm | Btn | { setAzureOpLoading(`rotate-$ `); try{const res=await rotateAzureKey(session,... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1117 | ekm | Btn | {setModal("azure-wrap");setAzureMappingForm(prev=>( ));}} style={ }>Wrap |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1118 | ekm | Btn | {setModal("azure-unwrap");setAzureMappingForm(prev=>( ));}} style={ }>Unwrap |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1119 | ekm | Btn | { if(!confirm("Delete this key mapping?")) return; try catch(e){onToast?.(`De... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1157 | ekm | Btn | { setGoogleCSELoading(true); try{ const domains=googleCSEConfigForm.allowed_d... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1188 | ekm | Btn | { if(!confirm("Delete this Google CSE config?")) return; try catch(e){onToast... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1217 | ekm | Btn | { setGoogleCSELoading(true); try{ await createGoogleCSEKey(session, ); onToas... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1245 | ekm | Btn | { if(!confirm("Delete this CSE key?")) return; try catch(e){onToast?.(`Delete... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1279 | ekm | Btn | setGuideEngine(eng)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1362 | ekm | Btn | (icon or dynamic label) | submitDbRegister} disabled={dbRegistering |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1363 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1393 | ekm | Btn | (icon or dynamic label) | submitDeploy} disabled={deploying |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1394 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1409 | ekm | Btn | downloadText(file.path,file.content)} style={ }>Download |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1424 | ekm | Btn | { const agentId=String(deployPackage?.agent_id\|\|"").trim(); if(!agentId) setV... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1478 | ekm | Btn | (icon or dynamic label) | submitBitLockerDeploy} disabled={bitLockerDeploying |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1479 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1486 | ekm | Btn | downloadText(file.path,file.content)} style={ }>Download |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1504 | ekm | Btn | (icon or dynamic label) | submitBitLockerDelete} disabled={bitLockerDeleteSubmitting\|\|!bitLockerDeleteConfirmBackup |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1505 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1522 | ekm | Btn | (icon or dynamic label) | runBitLockerScan} disabled={bitLockerScanRunning |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1538 | ekm | Btn | (icon or dynamic label) | onboardScannedBitLocker} disabled={bitLockerOnboarding |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1539 | ekm | Btn | {const all= ;bitLockerScanCandidates.forEach(r=> );setBitLockerScanSelected(a... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1581 | ekm | Btn | } disabled={bitLockerOpClientID===`$ :$ `} style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1612 | ekm | Btn | { setAzureLoading(true); try{ await createAzureEKMConfig(session,azureConfigF... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1622 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1641 | ekm | Btn | { setAzureLoading(true); try{ await createAzureKeyMapping(session,azureMappin... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1651 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1659 | ekm | Btn | { setAzureLoading(true); try{ const res=await wrapAzureKey(session,azureMappi... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1667 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1679 | ekm | Btn | { setAzureLoading(true); try{ const res=await unwrapAzureKey(session,azureMap... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 1687 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 106 | envelope_enc | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 206 | envelope_enc | button | setShowRewrap(true)} style={ }> Start Rewrap |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 207 | envelope_enc | button | setShowCreateKEK(true)} style={ }> Create KEK |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 208 | envelope_enc | button | (icon or dynamic label) | load} style={{ ...btnSecondary, padding: "9px 10px" |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 225 | envelope_enc | button | setSection(t.key)} style={{ background: "none", border: "none", borderBottom:... |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 247 | envelope_enc | button | } style={ }> Rotate KEK |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 248 | envelope_enc | button | } style={ }> Rewrap |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 352 | envelope_enc | button | setShowCreateKEK(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 353 | envelope_enc | button | (icon or dynamic label) | handleCreateKEK} disabled={saving \|\| !newKEKName.trim() |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 382 | envelope_enc | button | setShowRewrap(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EnvelopeEncTab.tsx | 383 | envelope_enc | button | (icon or dynamic label) | handleStartRewrap} disabled={saving \|\| !rewrapOld \|\| !rewrapNew \|\| rewrapOld === rewrapNew |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 68 | escrow | button | (icon or dynamic label) | disabled ? undefined : onClick} style={{ ...base, ...styles[variant] |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 86 | escrow | button | (icon or dynamic label) | onClick} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: "no... |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 126 | escrow | button | ✕ | handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 186 | escrow | button | setLegalHold(v => !v)} style={ }> {legalHold ? : } |  |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 192 | escrow | Btn | Cancel | handleClose |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 193 | escrow | Btn | (icon or dynamic label) | handleSubmit} disabled={busy \|\| !name.trim() \|\| !keyFilter.trim() \|\| selectedGuardians.length === 0 |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 244 | escrow | button | ✕ | handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 281 | escrow | Btn | Cancel | handleClose |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 282 | escrow | Btn | (icon or dynamic label) | handleSubmit} disabled={busy \|\| !selectedKey \|\| !selectedPolicy |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 316 | escrow | button | ✕ | handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 345 | escrow | Btn | Cancel | handleClose |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 346 | escrow | Btn | (icon or dynamic label) | handleSubmit} disabled={busy \|\| !escrowId \|\| !reason.trim() \|\| !requestor.trim() \|\| activeKeys.length === 0 |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 378 | escrow | button | ✕ | handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 385 | escrow | Btn | Cancel | handleClose |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 386 | escrow | Btn | (icon or dynamic label) | handleSubmit} disabled={busy \|\| !name.trim() \|\| !email.trim() \|\| !org.trim() |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 534 | escrow | Btn | Refresh | load |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 550 | escrow | button | } style={ }>✕ |  |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 577 | escrow | Btn | setPolicyModal(true)}> Create Policy |  |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 623 | escrow | Btn | setRecoveryModal(true)}> Recovery Request |  |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 624 | escrow | Btn | setEscrowKeyModal(true)}> Escrow a Key |  |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 668 | escrow | Btn | setRecoveryModal(true)}> New Request |  |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 703 | escrow | Btn | handleApprove(rr.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 704 | escrow | Btn | handleDeny(rr.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/EscrowTab.tsx | 726 | escrow | Btn | setGuardianModal(true)}> Add Guardian |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 317 | approvals | Btn | openPolicyModal()}>Create Policy |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 318 | approvals | Btn | Configure | openSettingsModal |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 319 | approvals | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 385 | approvals | Btn | void doVote(r, "approved")}> {voteBusy === `$ :approved` ? "..." : "Approve"} |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 388 | approvals | Btn | void doVote(r, "denied")}> {voteBusy === `$ :denied` ? "..." : "Deny"} |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 435 | approvals | Btn | openPolicyModal()}>Create Policy |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 453 | approvals | Btn | openPolicyModal(p)}>Edit |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 465 | approvals | Btn | Configure | openSettingsModal |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 543 | approvals | Btn | setPolicyModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 544 | approvals | Btn | (icon or dynamic label) | savePolicy} disabled={policySaving \|\| !policyName.trim() |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 591 | approvals | Btn | { try catch (e: any) { onToast?.(`SMTP test failed: $ `); } }}>Test SMTP |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 600 | approvals | Btn | { try catch (e: any) { onToast?.(`Slack test failed: $ `); } }}>Test |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 610 | approvals | Btn | { try catch (e: any) { onToast?.(`Teams test failed: $ `); } }}>Test |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 618 | approvals | Btn | setSettingsModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 619 | approvals | Btn | (icon or dynamic label) | saveSettings} disabled={settingsSaving |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 269 | hsm | Btn | void refreshCLIHints()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 310 | hsm | Btn | void openSSHSession()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 346 | hsm | Btn | void loadProviderConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 372 | hsm | Btn | void autoFetchPartitions()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 373 | hsm | Btn | void persistProviderConfig( , )} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 374 | hsm | Btn | setModal("gen")} disabled= >Generate Key in HSM |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 547 | hsm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 548 | hsm | Btn | { onToast?.(`HSM key generation requested: $ label="$ " partition="$ " [extra... |  |
| web/dashboard/src/components/v3/tabs/HYOKLiveTestPane.tsx | 166 | - | Btn | void executeTest()} disabled= style={ }> {executing ? "Executing..." : `Execu... |  |
| web/dashboard/src/components/v3/tabs/HYOKLiveTestPane.tsx | 173 | - | button | copyToClipboard(testOutput)} style={ } title="Copy output"> |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 400 | hyok | Btn | void refresh(false)} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 401 | hyok | Btn | }> Endpoint URLs |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 402 | hyok | Btn | }> Setup Guide |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 439 | hyok | Btn | openConfig(protocol)}>Configure |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 440 | hyok | Btn | }>URLs |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 441 | hyok | Btn | }>Guide |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 442 | hyok | Btn | void runDelete(protocol)}>Reset |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 580 | hyok | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 581 | hyok | Btn | void submitConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 606 | hyok | button | copyToClipboard(url.path)} style={ } title="Copy URL path"> |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 613 | hyok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 655 | hyok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 557 | - | Btn | setCapsExpanded(p=>!p)}> |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 635 | - | Btn | downloadText(`$ .crt.pem`,issuedBundle.cert)}>Download Cert |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 636 | - | Btn | downloadText(`$ .key.pem`,issuedBundle.key)}>Download Key |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 637 | - | Btn | setIssuedBundle(null)}>Dismiss |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 646 | - | Btn | void refresh()}> |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 647 | - | Btn | setModal("profile")}>+ Add Profile |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 664 | - | Btn | void removeProfile(p)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 677 | - | Btn | void refresh(true)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 678 | - | Btn | setModal("client")}>+ Add Client |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 696 | - | Btn | void removeClient(c)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 710 | - | Btn | void refresh(true)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 711 | - | Btn | setModal("interop-target")}>+ Add Target |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 735 | - | Btn | void runInteropValidation(target)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 738 | - | Btn | void removeInteropTarget(target)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 826 | - | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 827 | - | Btn | void saveProfile()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 912 | - | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 913 | - | Btn | void saveClient()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 965 | - | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KMIPTab.tsx | 966 | - | Btn | void saveInteropTarget()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 173 | - | Btn | void load(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 174 | - | Btn | void saveSettings()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 249 | - | Btn | void saveRule()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 287 | - | Btn | editRule(item)}>Edit |  |
| web/dashboard/src/components/v3/tabs/KeyAccessTab.tsx | 288 | - | Btn | void removeRule(item)}>Delete |  |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 224 | ceremony | Btn | Create Ceremony | openCeremonyModal |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 227 | ceremony | Btn | Add Guardian | openGuardianModal |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 229 | ceremony | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 282 | ceremony | Btn | void doAbort(c)}> |  |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 297 | ceremony | Btn | Add Guardian | openGuardianModal |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 401 | ceremony | Btn | setCeremonyModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 402 | ceremony | Btn | (icon or dynamic label) | saveCeremony} disabled={cSaving \|\| !cName.trim() |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 427 | ceremony | Btn | setGuardianModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeyCeremonyTab.tsx | 428 | ceremony | Btn | (icon or dynamic label) | saveGuardian} disabled={gSaving \|\| !gName.trim() \|\| !gEmail.trim() |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1773 | keys | Btn | void refreshKeyInventory()} style={{height:40,padding:"0 16px",borderRadius:1... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1776 | keys | Btn | setModal("create")} primary style={ } > Create Key |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1783 | keys | Btn | setModal("form-key")} style={{height:40,padding:"0 20px",borderRadius:10,font... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1786 | keys | Btn | } style={{height:40,padding:"0 20px",borderRadius:10,fontSize:12,fontWeight:7... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1789 | keys | Btn | setModal("generate-pqc")} style={{height:40,padding:"0 20px",borderRadius:10,... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1799 | keys | button | { e.stopPropagation(); const next=!showColumnMenu; if(next) setShowColumnMenu... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1927 | keys | button | { e.stopPropagation(); const isOpen=openActionMenuId===k.id; if(isOpen) const... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1969 | keys | button | } style={ } > Edit Key Policy |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1978 | keys | button | } style={ } > Rotate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1991 | keys | button | } disabled= style={ } > Deactivate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2001 | keys | button | } disabled= style={ } > Activate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2011 | keys | button | } disabled= style={ } > Disable |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2021 | keys | button | } style={ } > Export |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2034 | keys | button | } style={ } > Delete |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2067 | keys | Btn | setPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2069 | keys | Btn | setPageIndex((prev)=>Math.min(totalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2174 | keys | button | setCreateTags((prev)=>prev.filter((t)=>t!==tag))} style={ } > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2184 | keys | Btn | setShowCreateTagPicker(!showCreateTagPicker)}>Add More Tags |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2202 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2203 | keys | Btn | (icon or dynamic label) | addCustomerKey} disabled={creating |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2324 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2325 | keys | Btn | (icon or dynamic label) | submitFormKey} disabled={forming |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2431 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2432 | keys | Btn | (icon or dynamic label) | submitImportKey} disabled={importing |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2489 | keys | Btn | updateKeyStatus(comp,"deactivated")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2490 | keys | Btn | updateKeyStatus(comp,"active")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2491 | keys | Btn | updateKeyStatus(comp,"disabled")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2512 | keys | Btn | }> Rotate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2513 | keys | Btn | }> Export |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2514 | keys | Btn | openPolicyEditor(selectedKey)}>Edit Key Policy |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2515 | keys | Btn | updateKeyStatus(selectedKey,"deactivated")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2516 | keys | Btn | updateKeyStatus(selectedKey,"active")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2517 | keys | Btn | updateKeyStatus(selectedKey,"disabled")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2518 | keys | Btn | }> Delete |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2584 | keys | Btn | Add Assignment | addPolicyGrant |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2606 | keys | Btn | removePolicyGrant(subjectType,subjectID)}>Remove |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2628 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2629 | keys | Btn | (icon or dynamic label) | saveKeyPolicy} disabled={policySaving |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2654 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2654 | keys | Btn | (icon or dynamic label) | rotateSelectedKey} disabled={rotating |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2684 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2685 | keys | Btn | (icon or dynamic label) | exportSelectedKey} disabled={exporting |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2710 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2711 | keys | Btn | (icon or dynamic label) | destroySelectedKey} disabled={!destroyReady |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2738 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2738 | keys | Btn | (icon or dynamic label) | generatePQCKey} disabled={pqcGenerating |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 215 | leak_scanner | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 216 | leak_scanner | Btn | (icon or dynamic label) | submit} disabled={busy |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 336 | leak_scanner | button | setError("")} style={ }> |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 353 | leak_scanner | Btn | void load(false)}> |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 354 | leak_scanner | Btn | setAddOpen(true)}>+ Add Target |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 404 | leak_scanner | Btn | void handleScan(t.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 407 | leak_scanner | Btn | void handleDelete(t.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 500 | leak_scanner | Btn | void handleResolve(f.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/LeakScannerTab.tsx | 523 | leak_scanner | Btn | void load(false)}> Refresh |  |
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
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 473 | mpc | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 549 | mpc | Btn | setModal("dkg")}> Generate Key (DKG) |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 579 | mpc | Btn | }> Revoke |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 580 | mpc | Btn | }> Group |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 605 | mpc | Btn | setModal("dkg")}>New DKG |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 606 | mpc | Btn | setModal("sign")} disabled= >New Sign |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 607 | mpc | Btn | setModal("decrypt")} disabled= >New Decrypt |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 649 | mpc | Btn | }> Create Policy |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 662 | mpc | Btn | openEditPolicy(p)}> Edit |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 663 | mpc | Btn | void removePolicy(p.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 676 | mpc | Btn | }> Register |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 689 | mpc | Btn | openEditParticipant(p)}> |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 690 | mpc | Btn | void toggleParticipantStatus(p)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 693 | mpc | Btn | void removeParticipant(p.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 715 | mpc | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 716 | mpc | Btn | void submitDKG()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 733 | mpc | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 734 | mpc | Btn | void submitSign()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 751 | mpc | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 752 | mpc | Btn | void submitDecrypt()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 762 | mpc | Btn | }>Cancel |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 763 | mpc | Btn | void submitParticipant()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 778 | mpc | Btn | Add Rule | addPolicyRule |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 792 | mpc | Btn | removePolicyRule(i)}> |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 812 | mpc | Btn | }>Cancel |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 813 | mpc | Btn | void submitPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 823 | mpc | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 824 | mpc | Btn | void submitRevoke()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 833 | mpc | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/MPCTab.tsx | 834 | mpc | Btn | void submitGroup()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 82 | mtls_mesh | button | (icon or dynamic label) | disabled ? undefined : onClick} style={{ ...base, ...styles[variant] |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 100 | mtls_mesh | button | (icon or dynamic label) | onClick} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: "no... |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 126 | mtls_mesh | button | ✕ | handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 134 | mtls_mesh | button | setAutoRenew(v => !v)} style={ }> {autoRenew ? : } |  |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 140 | mtls_mesh | Btn | Cancel | handleClose |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 141 | mtls_mesh | Btn | (icon or dynamic label) | handleSubmit} disabled={busy \|\| !name.trim() \|\| !namespace.trim() \|\| !endpoint.trim() |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 162 | mtls_mesh | button | ✕ | handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 171 | mtls_mesh | Btn | Cancel | handleClose |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 262 | mtls_mesh | Btn | Refresh | load |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 295 | mtls_mesh | Btn | setRegModal(true)} small> Register Service |  |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 334 | mtls_mesh | Btn | handleRenew(svc.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/MTLSMeshTab.tsx | 396 | mtls_mesh | Btn | setAnchorModal(true)}> Add Trust Anchor |  |
| web/dashboard/src/components/v3/tabs/OpsMetricsTab.tsx | 91 | ops_metrics | button | setTimeWindow(w)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/OpsMetricsTab.tsx | 98 | ops_metrics | button | Refresh | load} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/OpsMetricsTab.tsx | 120 | ops_metrics | button | setSection(s.id as any)} style={{ padding: "8px 16px", border: "none", backgr... |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 198 | pkcs11 | Btn | void createSDKJWT()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 201 | pkcs11 | Btn | void loadOverview()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 208 | pkcs11 | Btn | setShowJWT((v)=>!v)}> |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 209 | pkcs11 | Btn | void copySDKJWT()}>Copy JWT |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 259 | pkcs11 | Btn | void downloadArtifact("pkcs11",pkcsTarget as any)} disabled={downloading===`p... |  |
| web/dashboard/src/components/v3/tabs/PKCS11Tab.tsx | 286 | pkcs11 | Btn | void downloadArtifact("jca",jcaTarget as any)} disabled={downloading===`jca:$... |  |
| web/dashboard/src/components/v3/tabs/PaymentPolicyTab.tsx | 452 | - | Btn | void loadAll(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PaymentPolicyTab.tsx | 453 | - | Btn | (icon or dynamic label) | saveAll} disabled={loading \|\| saving |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 822 | payment | Btn | void refreshAP2Profile()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 823 | payment | Btn | void saveAP2Profile()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 915 | payment | Btn | void refreshInjectionData()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 929 | payment | Btn | void registerTerminal()} disabled= >Register Terminal |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 942 | payment | Btn | void issueChallenge()} disabled= >Issue Challenge |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 943 | payment | Btn | void verifyChallenge()} disabled= >Verify Challenge |  |
| web/dashboard/src/components/v3/tabs/PaymentTab.tsx | 965 | payment | Btn | { if(op==="Payment Key Injection") if(op==="AP2 Agent Payments") void runPaym... |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 85 | playbooks | button | (icon or dynamic label) | disabled ? undefined : onClick} style={{ ...base, ...styles[variant] |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 486 | playbooks | Btn | { if (v === "create") setView(v); }}> {v === "create" ? <> New : v === "playb... |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 492 | playbooks | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 588 | playbooks | Btn | }> New Playbook |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 600 | playbooks | button | toggleRow(pb.id)} style={ }> {expandedRows.has(pb.id) ? : } |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 609 | playbooks | button | handleToggleEnabled(pb)} style={ }> {pb.enabled ? : } |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 617 | playbooks | Btn | handleEdit(pb)}> Edit |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 618 | playbooks | Btn | handleRun(pb.id)} disabled= > Run |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 619 | playbooks | Btn | handleDelete(pb.id)}> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 692 | playbooks | button | removeAction(i)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 708 | playbooks | Btn | Add Action | addAction |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 710 | playbooks | Btn | (icon or dynamic label) | handleCreate} disabled={creating |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 713 | playbooks | Btn | }>Cancel |  |
| web/dashboard/src/components/v3/tabs/PostQuantumTab.tsx | 132 | - | Btn | void refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostQuantumTab.tsx | 133 | - | Btn | void scanNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostQuantumTab.tsx | 134 | - | Btn | void savePolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 537 | posture | Btn | load(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 538 | posture | Btn | (icon or dynamic label) | runScan} disabled={running |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 947 | posture | Btn | setFindingEngine("")} style={ }>Clear engine filter |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1183 | posture | Btn | patchFinding(selectedFinding, "acknowledged")} disabled= >Acknowledge |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1184 | posture | Btn | patchFinding(selectedFinding, "resolved")} disabled= >Resolve |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1185 | posture | Btn | patchFinding(selectedFinding, "reopened")}>Reopen |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1186 | posture | Btn | setSelectedFinding(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1275 | posture | Btn | executeAction(selectedAction)}> Execute |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1277 | posture | Btn | setSelectedAction(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 438 | qkd | Btn | void loadData(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 442 | qkd | Btn | Configure | openConfig |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 547 | qkd | Btn | setModal("inject")} disabled= > Inject to KeyCore |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 551 | qkd | Btn | setModal("keys")} disabled= > View Key Pool |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 610 | qkd | Btn | Register SAE | openRegisterSAE |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 614 | qkd | Btn | openDistribute()} disabled= > Distribute Keys |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 618 | qkd | Btn | setModal("distributions")}> Distributions |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 622 | qkd | button | setShowSAEPanel((v) => !v)} style={ } > {showSAEPanel ? : } |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 641 | qkd | Btn | Register First SAE | openRegisterSAE |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 712 | qkd | button | openDistribute(sae.id)} title="Distribute keys" style={{ background: C.accent... |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 726 | qkd | button | openEditSAE(sae)} title="Edit SAE" style={{ background: C.blueDim, border: `1... |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 740 | qkd | button | handleDeleteSAE(sae)} title="Delete SAE" style={{ background: C.redDim, borde... |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 769 | qkd | Btn | void loadData(true)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 772 | qkd | button | setShowLogsPanel((v) => !v)} style={ } > {showLogsPanel ? : } |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 932 | qkd | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 933 | qkd | Btn | void saveConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1046 | qkd | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1047 | qkd | Btn | void handleSaveSAE()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1101 | qkd | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1102 | qkd | Btn | void handleDistribute()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1171 | qkd | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1204 | qkd | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1205 | qkd | Btn | void injectSelected()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1265 | qkd | Btn | void runSelfTest()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/QKDTab.tsx | 1325 | qkd | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/QRNGTab.tsx | 140 | qrng | Btn | Retry | load} style={{ marginLeft: 16 |
| web/dashboard/src/components/v3/tabs/QRNGTab.tsx | 170 | qrng | Btn | Refresh | load} style={{ marginLeft: "auto" |
| web/dashboard/src/components/v3/tabs/QRNGTab.tsx | 194 | qrng | Btn | }>+ Register Source |  |
| web/dashboard/src/components/v3/tabs/QRNGTab.tsx | 219 | qrng | Btn | openEdit(src)}> |  |
| web/dashboard/src/components/v3/tabs/QRNGTab.tsx | 220 | qrng | Btn | handleDelete(src.id)}> |  |
| web/dashboard/src/components/v3/tabs/QRNGTab.tsx | 254 | qrng | Btn | setHealthOpen(!healthOpen)}> |  |
| web/dashboard/src/components/v3/tabs/QRNGTab.tsx | 310 | qrng | Btn | (icon or dynamic label) | modal === "register" ? handleRegister : handleUpdate |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 477 | restapi | Btn | (icon or dynamic label) | executeRequest} disabled={running |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 508 | restapi | Btn | void loadClientSecurity(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 515 | restapi | button | setSelectedClientID(String(item?.id\|\|""))} style={{ textAlign:"left", border:... |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 611 | restapi | Btn | setClientDraft(selectedClient? :null)}>Reset |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 612 | restapi | Btn | (icon or dynamic label) | saveClientSecurity} disabled={clientSaving |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 733 | restapi | Btn | Refresh cURL | buildPreview |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 734 | restapi | Btn | (icon or dynamic label) | executeRequest} disabled={running |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 238 | rotation | Btn | Create Policy | openCreateModal |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 240 | rotation | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 295 | rotation | Btn | void doTrigger(p.id, p.name)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 298 | rotation | Btn | openEditModal(p)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 301 | rotation | Btn | void doDelete(p)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 359 | rotation | Btn | void doTrigger(u.policy_id, u.policy_name)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 462 | rotation | Btn | setPolicyModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 463 | rotation | Btn | (icon or dynamic label) | savePolicy} disabled={pSaving \|\| !pName.trim() |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 631 | sbom | Btn | { void loadData( ).then(() => loadVulnerabilities( )); }} disabled= > |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 740 | sbom | Btn | void exportSBOMFile("cyclonedx")} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 743 | sbom | Btn | void exportSBOMFile("spdx")} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 747 | sbom | Btn | setExportMenuOpen((prev) => !prev)} disabled= style={ }>Export |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 749 | sbom | Btn | } disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 752 | sbom | Btn | } disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 757 | sbom | Btn | void openSBOMDiff()} style={ }>SBOM Diff |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 826 | sbom | Btn | void exportCBOMFile()} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 829 | sbom | Btn | void openCBOMDiff()} style={ }>View Diff |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 913 | sbom | Btn | }>Add Offline Advisory |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1005 | sbom | Btn | setAdvisoryModalOpen(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1006 | sbom | Btn | void saveOfflineAdvisory()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1018 | sbom | Btn | void removeOfflineAdvisory(String(item?.id \|\| ""))} disabled= > |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1047 | sbom | Btn | setDiffOpen(false)}>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1081 | sbom | Btn | setSBOMDiffOpen(false)}>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1114 | sbom | Btn | }>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 1144 | sbom | Btn | }>Close |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 230 | tfe | Btn | setView("register")}> Register Agent / Policy |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 234 | tfe | Btn | (icon or dynamic label) | load} disabled={loading |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 260 | tfe | button | setView(t.id as any)} style={{ padding: "9px 18px", border: "none", backgroun... |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 401 | tfe | Btn | setView("register")}> Register New Agent |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 484 | tfe | Btn | setView("register")}> Create Policy |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 540 | tfe | Btn | doDeletePolicy(p.id)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 609 | tfe | Btn | } disabled= > |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 613 | tfe | Btn | setAgentForm( )}>Reset |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 719 | tfe | Btn | (icon or dynamic label) | doCreatePolicy} disabled={policyFormBusy |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 723 | tfe | Btn | { setPolicyForm( ); setPolicyFormErr(""); }}>Reset |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 777 | tfe | Btn | { setDlLoading(true); setDlPackage(null); try { const res = await getFileEncr... |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 816 | tfe | Btn | { const blob = new Blob([f.content], ); const url = URL.createObjectURL(blob)... |  |
| web/dashboard/src/components/v3/tabs/TFETab.tsx | 822 | tfe | Btn | { navigator.clipboard?.writeText(f.content).then(() => onToast?.(`Copied $ `)... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 445 | - | button | setOp(name)} style={{ background:op===name?C.accent:"transparent", color:op==... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 464 | - | Btn | {if(!session?.token)return;setLoading(true);try{setVaults(await listTokenVaul... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 563 | - | Btn | void submitCurrent()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 579 | - | Btn | setOp("Mask")}>Open Mask Operation |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 587 | - | Btn | setOp("Redact")}>Open Redact Operation |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 762 | - | button | setMode(name)} style={{ background:mode===name?C.accentDim:"transparent", col... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 809 | - | Btn | void submit()} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1188 | - | Btn | void downloadSDK()} disabled= >Download SDK |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1189 | - | Btn | void refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1219 | - | Btn | void submitInit()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1242 | - | Btn | void submitComplete()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1265 | - | Btn | void submitLease()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1281 | - | Btn | void submitReceipt()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1321 | - | Btn | void revokeLease(item)} disabled= >Revoke |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1610 | - | Btn | void loadPolicy(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1611 | - | Btn | (icon or dynamic label) | savePolicy} disabled={saving\|\|loading |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2186 | - | Btn | void loadPolicy(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2187 | - | Btn | (icon or dynamic label) | savePolicy} disabled={saving\|\|loading |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2382 | - | Btn | void refreshVaultRows(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2383 | - | Btn | void downloadVaultSetup()} disabled= >Download Setup Query |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2384 | - | Btn | void createVaultFromPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2441 | - | Btn | void deleteVaultFromPolicy(row)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2715 | - | Btn | void loadPolicy(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2716 | - | Btn | (icon or dynamic label) | savePolicy} disabled={saving\|\|loading |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2928 | - | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3000 | - | Btn | selectSubtab("fieldenc")}>Field Encryption |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3001 | - | Btn | selectSubtab("dataenc-policy")}>Data Encryption Policy |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3002 | - | Btn | selectSubtab("token-policy")}>Token / Mask / Redact Policy |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3003 | - | Btn | selectSubtab("payment-policy")}>Payment Policy |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 3004 | - | Btn | selectSubtab("pkcs11")}>PKCS#11 / JCA |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 451 | vault | Btn | (icon or dynamic label) | handleRefresh} disabled={refreshing \|\| busy |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 457 | vault | button | setCategory(cat.id)} style={{ height: 32, padding: "0 12px", borderRadius: 8,... |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 465 | vault | Btn | setModal("create")} style={ }> Store Secret |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 468 | vault | Btn | } style={ }> Generate |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 523 | vault | Btn | } style={ }>+ Folder |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 576 | vault | Btn | setFolderModalOpen(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 577 | vault | Btn | { const folderName = newFolderName.trim().replace(/[^a-zA-Z0-9._/-]/g, "-").r... |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 624 | vault | Btn | } disabled= > Download |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 625 | vault | Btn | } disabled= > Delete |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 644 | vault | Btn | setModal("create")}> Store Your First Secret |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 645 | vault | Btn | }> Generate Key Pair |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 739 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 740 | vault | Btn | void submitCreate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 754 | vault | Btn | copyToClipboard(generatedPublicKey, onToast)}> Copy Public Key |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 757 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 758 | vault | Btn | void submitGenerate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 807 | vault | button | setShowValue(!showValue)} style={ }> {showValue ? <> Hide : <> Reveal } |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 810 | vault | button | copyToClipboard(retrievedValue, onToast)} style={ }> Copy |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 817 | vault | Btn | void fetchFormat()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 818 | vault | Btn | void downloadSecret(selectedSecret)} disabled= > Download |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 859 | vault | Btn | }> Rotate Value |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 862 | vault | Btn | void removeSecret(selectedSecret)} disabled= > Delete |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 863 | vault | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 878 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 879 | vault | Btn | void submitRotate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 154 | webhooks | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 193 | webhooks | button | + Add | addHeader} style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 199 | webhooks | button | removeHeader(i)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 206 | webhooks | button | Cancel | onClose} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 207 | webhooks | button | (icon or dynamic label) | handleSave |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 239 | webhooks | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer" |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 324 | webhooks | button | {wh.enabled ? : } | onToggle} title={wh.enabled ? "Disable" : "Enable" |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 327 | webhooks | button | Test | handleTest} disabled={testing |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 330 | webhooks | button | Edit | onEdit} title="Edit" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 331 | webhooks | button | Delete | onDelete} title="Delete" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 332 | webhooks | button | {logOpen ? : } | onViewLog} title="View log" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 417 | webhooks | button | load(true)} disabled= style={{ background: C.card, border: `1px solid $ `, bo... |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 424 | webhooks | button | } style={ } > Add Webhook |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 269 | - | Btn | load(false)}> |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 308 | - | Btn | (icon or dynamic label) | saveSettings} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 358 | - | Btn | (icon or dynamic label) | saveRegistration} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 378 | - | Btn | setRegistrationDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 379 | - | Btn | { try catch (error) { onToast?.(`Delete failed: $ `); } }}>Delete |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 399 | - | Btn | (icon or dynamic label) | saveFederation} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 414 | - | Btn | setFederationDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 415 | - | Btn | { try catch (error) { onToast?.(`Delete failed: $ `); } }}>Delete |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 448 | - | Btn | (icon or dynamic label) | runIssue} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 478 | - | Btn | (icon or dynamic label) | runExchange} disabled={busy |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 272 | - | Btn | inputRef.current?.click()} style={{ padding: "8px 14px", borderRadius: 10, bo... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 286 | - | Btn | { onFileChange(null); if (inputRef.current) }} style={ } > Clear |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 823 | - | button | toggleScope(section)} style={{fontSize:11,padding:"4px 10px",borderRadius:6,b... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2179 | - | Btn | void restartAllAllowedServices()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2186 | - | Btn | void loadHealth()}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2215 | - | Btn | void restartSvc(name)} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2233 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2234 | - | Btn | }>Configure TLS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2235 | - | Btn | setFipsConfigModalOpen(true)}>Configure FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2247 | - | Btn | {setSystemState((p)=>( ));onFipsModeChange("enabled");}}>Enable FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2248 | - | Btn | {setSystemState((p)=>( ));onFipsModeChange("disabled");}}>Disable FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2322 | - | Btn | setFipsConfigModalOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2323 | - | Btn | void saveFipsConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2370 | - | Btn | }>Open Interfaces |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2372 | - | Btn | }>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2373 | - | Btn | void saveTLSConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2380 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2381 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2382 | - | Btn | {try catch(e){onToast(`Apply failed: $ `);}}} disabled= >Apply Network Config |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2407 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2408 | - | Btn | void testSnmpSettings()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2409 | - | Btn | void saveSnmpSettings()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2491 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2504 | - | Btn | void loadTags()}>Refresh |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2509 | - | Btn | void addTag()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2524 | - | Btn | void removeTag(name,usageCount)} disabled= >Delete |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2534 | - | Btn | void loadPasswordPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2534 | - | Btn | void savePasswordPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2559 | - | Btn | void saveSecurityPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2578 | - | Btn | void loadAccessHardening()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2579 | - | Btn | void saveAccessHardening()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2610 | - | Btn | void Promise.all([loadAccessHardening(),loadHealth()])} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2611 | - | Btn | openNetIfModal()} disabled= >+ Add Interface |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2642 | - | Btn | void toggleNetIfEnabled(iface)}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2643 | - | Btn | openNetIfModal(iface)}>Edit |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2644 | - | Btn | void deleteNetIf(iface.interface_name)}>Delete |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2721 | - | Btn | }>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2722 | - | Btn | void saveNetIf()}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2728 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2728 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2823 | - | Btn | setPanel("network")}>Open Network |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2824 | - | Btn | setPanel("interfaces")}>Open Interfaces |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2834 | - | Btn | }> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2841 | - | Btn | void openCli()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2854 | - | Btn | { if(!session?.token) return; setHsmSaving(true); try{ const payload= ; const... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2885 | - | Btn | {if(!session?.token) return; const lib=String(hsm.library_path\|\|"").trim(); i... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2888 | - | Btn | setHsm((p)=>( ))}>Use |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2895 | - | Btn | {if(!session?.token) return; setGovSaving(true); try{await updateGovernanceSe... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2901 | - | Btn | {if(!session?.token\|\|!String(smtpTo\|\|"").trim()) setSmtpTesting(true); try ca... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2902 | - | Btn | {if(!session?.token) return; setWebhookTesting((p)=>( )); try catch(error){if... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2903 | - | Btn | {if(!session?.token) return; setWebhookTesting((p)=>( )); try catch(error){if... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2908 | - | Btn | void loadJobs()}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2908 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2925 | - | Btn | {if(!session?.token) return; if(backupScope==="tenant"&&!String(backupTenant\|... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2951 | - | Btn | void restoreBackup()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2956 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDownloading(`$ :artifact`); try ca... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2956 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDownloading(`$ :key`); try catch(e... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2956 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDeleting(id); try catch(error){if(... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2962 | - | Btn | void refreshAlertRules()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2962 | - | Btn | openRuleModal()}>Create Rule |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2979 | - | Btn | {if(!session?.token\|\|!id) return; try{await updateReportingRule(session,id, )... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2982 | - | Btn | openRuleModal(rule)}>Edit |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 2983 | - | Btn | {if(!session?.token\|\|!id) return; try catch(error){if(!sessionGuard(error)) o... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3033 | - | Btn | setRuleModalOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3034 | - | Btn | void handleSaveRule()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3041 | - | Btn | void loadGovPolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3042 | - | Btn | openGovPolicyModal()}>+ Create Policy |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3078 | - | button | openGovPolicyModal(policy)} style={{fontSize:10,padding:"3px 8px",borderRadiu... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3079 | - | button | {if(!session?.token) return; try{await updateGovernancePolicy(session,policy.... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3152 | - | Btn | }>Select All |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3153 | - | Btn | setGpTriggers([])}>Clear All |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3196 | - | Btn | setGovPolicyModal(false)}>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3197 | - | Btn | void saveGovPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3205 | - | Btn | void loadFDEStatus()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3241 | - | Btn | void doFDEIntegrityCheck()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3246 | - | Btn | void doFDERotateKey()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 3267 | - | Btn | void doFDETestRecovery()} disabled= style={ }> |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 422 | - | button | setActiveTab(t)} style={{ background: activeTab === t ? C.accentDim : "transp... |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 452 | - | Btn | void loadTenants()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 453 | - | Btn | setCreateOpen(true)}>+ Create Tenant |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 618 | - | Btn | void loadPolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 619 | - | Btn | void savePolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 687 | - | Btn | setHsmConfig((c) => ( ))}>Select |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 695 | - | Btn | void loadHSM()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 696 | - | Btn | void saveHSM()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 719 | - | Btn | void loadBackups()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 720 | - | Btn | void handleCreateBackup()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 753 | - | Btn | void handleDownloadArtifact(b.id)}>Artifact |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 754 | - | Btn | void handleDownloadKey(b.id)}>Key |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 757 | - | Btn | void handleDeleteBackup(b.id)}>Delete |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 848 | - | Btn | void handleEnable()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 861 | - | Btn | void loadReadiness()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 862 | - | Btn | void handleDisable()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 865 | - | Btn | void handleDelete()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 923 | - | Btn | setCreateOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 924 | - | Btn | void createTenant()} disabled= > |  |
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
