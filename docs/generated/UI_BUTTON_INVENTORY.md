# Generated UI Button Inventory

Generated at `2026-10-23T17:56:36Z` by `scripts/generate_product_map.py`.

This is a static inventory of controls with `onClick` handlers. For exact runtime behavior, combine it with Playwright traces and network logs.

| File | Line | Tabs | Control | Visible label | Handler snippet |
| --- | --- | --- | --- | --- | --- |
| web/dashboard/src/components/AppErrorBoundary.tsx | 81 | - | button | Try again | this.handleReload |
| web/dashboard/src/components/AppErrorBoundary.tsx | 96 | - | button | window.location.reload()} style={ } > Reload page |  |
| web/dashboard/src/components/IdleWarningModal.tsx | 95 | - | Btn | Logout Now | onLogout |
| web/dashboard/src/components/IdleWarningModal.tsx | 98 | - | Btn | Stay Active | onStayActive |
| web/dashboard/src/components/LoginScreen.tsx | 325 | - | button | {loading ? ( <> Authenticating… ) : ( <> Sign In )} | handleLogin |
| web/dashboard/src/components/LoginScreen.tsx | 355 | - | button | handleSSOLogin(sp.provider)} disabled= className="w-full rounded-lg border bo... |  |
| web/dashboard/src/components/LoginScreen.tsx | 391 | - | button | setShowPolicyHint((v) => !v)} className="text-cyber-accent transition-colors... |  |
| web/dashboard/src/components/LoginScreen.tsx | 423 | - | button | {savingPassword ? ( <> Applying… ) : ( <> Update Password and Continue )} | handlePasswordChange |
| web/dashboard/src/components/ThemeToggle.tsx | 17 | - | button | {isDark ? : } | toggle |
| web/dashboard/src/components/ThemeToggle.tsx | 31 | - | button | } onMouseLeave={(e) => } > {isDark ? : } | toggle |
| web/dashboard/src/components/ToastStack.tsx | 84 | - | button | dismiss(toast.id)} aria-label="Dismiss notification" style={ } > × |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 478 | - | button | setCollapsed((v) => !v)} title= aria-label= className="vk-icon-btn" style={{... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 731 | - | button | Sign out | onLogout |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 783 | - | button | togglePin(tab)} title= style={{ display: "inline-flex", alignItems: "center",... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 817 | - | Btn | selectTab("admin/cli")} style={cliEnabled ? : }> |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 854 | - | button | } className="vk-icon-btn" aria-label="About this KMS build" aria-expanded= ti... |  |
| web/dashboard/src/components/VectaDashboardV3Shell.tsx | 889 | - | button | } className="vk-icon-btn" style={{ display: "inline-flex", alignItems: "cente... |  |
| web/dashboard/src/components/v3/SidebarSearch.tsx | 60 | - | button | onOpen(src.tab, h.label)} title= style={ }> |  |
| web/dashboard/src/components/v3/SidebarSubNav.tsx | 153 | - | button | onSelect(item.id)} style={ } > |  |
| web/dashboard/src/components/v3/chartDrill.tsx | 133 | - | Btn | Clear | onClear |
| web/dashboard/src/components/v3/chartDrill.tsx | 141 | - | Btn | (icon or dynamic label) | onMore} disabled={loading |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 56 | - | button | Close | onClose} aria-label="Close" style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", pa... |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 164 | - | Btn | (icon or dynamic label) | cancel |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 165 | - | Btn | (icon or dynamic label) | submit |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 537 | - | button | { if (!disabled) }} onFocus= onBlur= onMouseDown= onKeyDown= style={{ backgro... |  |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 650 | - | button | (icon or dynamic label) | onClick} disabled={disabled |
| web/dashboard/src/components/v3/legacyPrimitives.tsx | 677 | - | button | onChange(t)} style={{ background: "transparent", color: active === t ? C.text... |  |
| web/dashboard/src/components/v3/runtimeUtils.tsx | 66 | - | button | Retry | reset} style={{ border: "1px solid #243656", borderRadius: 3, padding: "4px 10px", background: "transparent", color:... |
| web/dashboard/src/components/v3/tabs/AlertAnalyticsPanel.tsx | 99 | - | Btn | void load()}>Retry |  |
| web/dashboard/src/components/v3/tabs/AlertAnalyticsPanel.tsx | 107 | - | Btn | void load()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 272 | alerts | Btn | void ackAlert(item)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 273 | alerts | Btn | void escalateOne(item)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 299 | alerts | Btn | void refresh(false)}> |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 300 | alerts | Btn | void ackAllAlerts()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 310 | alerts | Btn | setActiveFilter(tab.id)} style={{ background:activeFilter===tab.id?(palette[`... |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 339 | alerts | Btn | setPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/AlertsTab.tsx | 341 | alerts | Btn | setPageIndex((prev)=>Math.min(totalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/AnchorSettings.tsx | 63 | - | Btn | void save(true)}>Use this authority |  |
| web/dashboard/src/components/v3/tabs/AnchorSettings.tsx | 64 | - | Btn | void save(false)}>Turn off |  |
| web/dashboard/src/components/v3/tabs/AnchorSettings.tsx | 66 | - | Btn | void save(true)}> |  |
| web/dashboard/src/components/v3/tabs/ApprovalPoliciesPanel.tsx | 108 | - | Btn | openPolicyModal()}>Create Policy |  |
| web/dashboard/src/components/v3/tabs/ApprovalPoliciesPanel.tsx | 127 | - | Btn | openPolicyModal(p)}>Edit |  |
| web/dashboard/src/components/v3/tabs/ApprovalPoliciesPanel.tsx | 128 | - | Btn | { const next = p.status === "active" ? "inactive" : "active"; // The server r... |  |
| web/dashboard/src/components/v3/tabs/ApprovalPoliciesPanel.tsx | 212 | - | Btn | setPolicyModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/ApprovalPoliciesPanel.tsx | 213 | - | Btn | (icon or dynamic label) | savePolicy} disabled={policySaving \|\| !policyName.trim() |
| web/dashboard/src/components/v3/tabs/AuditAnalyticsPanel.tsx | 72 | - | Btn | void load()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AuditEventDetail.tsx | 87 | - | Btn | { onClose(); onInvestigate( ); }}> |  |
| web/dashboard/src/components/v3/tabs/AuditInvestigate.tsx | 86 | - | Btn | Investigate | add} disabled={!text.trim() |
| web/dashboard/src/components/v3/tabs/AuditInvestigate.tsx | 88 | - | Btn | void load()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/AuditInvestigate.tsx | 96 | - | button | drop(d)} style={ }>× |  |
| web/dashboard/src/components/v3/tabs/AuditInvestigate.tsx | 100 | - | Btn | onPivotsChange( )}>Clear all |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 354 | audit | Btn | void exportEventsAsCEF(filteredEvents, signingKeyId ? session : undefined, si... |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 355 | audit | Btn | (icon or dynamic label) | verifyChain} disabled={chainVerifying |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 358 | audit | Btn | load()} disabled= >Refresh |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 449 | audit | Btn | setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous |  |
| web/dashboard/src/components/v3/tabs/AuditLogTab.tsx | 450 | audit | Btn | setOffset(offset + PAGE_SIZE)}>Next |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 317 | byok | Btn | setConnectorView("cards")} title="Card view"> |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 318 | byok | Btn | setConnectorView("list")} title="List view"> |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 319 | byok | Btn | void refresh()} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 320 | byok | Btn | }> Region Mappings |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 321 | byok | Btn | setModal("add")}>+ Add Connector |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 347 | byok | button | setExpandedProvider(isExpanded ? null : card.provider)} style={ }> {isExpande... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 365 | byok | Btn | } disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 371 | byok | Btn | } disabled= > Inventory |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 374 | byok | Btn | void deleteConnector(card.provider, card.accounts[0])} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 397 | byok | button | setConnectorMenu(menuOpen ? "" : String(card.provider))} style={{ border: `1p... |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 401 | byok | button | } disabled= style={ }>Sync Now |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 402 | byok | button | } disabled= style={ }>Browse Inventory |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 403 | byok | button | } disabled= style={ }>Delete Connector |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 462 | byok | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 463 | byok | Btn | void submitAddConnector()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 513 | byok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 514 | byok | Btn | void submitRegionMapping()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/BYOKTab.tsx | 549 | byok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/BindingPoliciesPanel.tsx | 95 | - | Btn | setEditing( )}>New binding |  |
| web/dashboard/src/components/v3/tabs/BindingPoliciesPanel.tsx | 108 | - | Btn | setEditing( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/BindingPoliciesPanel.tsx | 109 | - | Btn | void remove(p)}>Delete |  |
| web/dashboard/src/components/v3/tabs/BindingPoliciesPanel.tsx | 146 | - | Btn | Cancel | onCancel |
| web/dashboard/src/components/v3/tabs/BindingPoliciesPanel.tsx | 147 | - | Btn | Save binding | onSave |
| web/dashboard/src/components/v3/tabs/BindingPoliciesPanel.tsx | 177 | - | Btn | void run()}>Check |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysPanel.tsx | 85 | - | Btn | Create canary | create} disabled={busy \|\| !name.trim() |
| web/dashboard/src/components/v3/tabs/CanaryKeysPanel.tsx | 105 | - | Btn | showTrips(k)}>Trips |  |
| web/dashboard/src/components/v3/tabs/CanaryKeysPanel.tsx | 106 | - | Btn | deactivate(k)}>Deactivate |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1452 | certs | button | toggleCA(caID)} style={ }> {open? : } : |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1466 | certs | Btn | void actCRL(ca)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1467 | certs | Btn | void actDeleteCA(ca)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1473 | certs | button | toggleIssued(caID)} style={ }> {issuedOpen? : } Issued Certificates ( ) |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1616 | certs | Btn | openProtocolModal(meta.name)}> Configure |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1617 | certs | Btn | void runProtocolTest(meta.name)} > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1625 | certs | Btn | setModal("acme-wizard")}> ACME Wizard |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1626 | certs | Btn | setModal("acme-star")}> STAR |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1627 | certs | Btn | setModal("est-wizard")}> EST Enroll |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1628 | certs | Btn | setModal("scep-wizard")}> SCEP Enroll |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1629 | certs | Btn | setModal("cmpv2-wizard")}> CMPv2 Request |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1645 | certs | Btn | setCAStatusView("all")} style={ }>{`All $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1646 | certs | Btn | setCAStatusView("active")} style={ }>{`Active $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1647 | certs | Btn | setCAStatusView("revoked")} style={ }>{`Revoked $ `} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1648 | certs | Btn | void refreshCAs()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1649 | certs | Btn | setModal("create-ca")}> Create CA |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1741 | certs | Btn | void refreshRenewalIntel()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1767 | certs | Btn | void refreshSTARIntel()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1768 | certs | Btn | setModal("acme-star")}>New |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1796 | certs | Btn | void actRefreshSTARSubscription(item,true)} disabled={rowActionBusy===`star-r... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1797 | certs | Btn | void actDeleteSTARSubscription(item)} disabled={rowActionBusy===`star-delete-... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1824 | certs | Btn | setModal("issue")} style={ }> Issue Certificate |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1825 | certs | Btn | setModal("sign-csr")} style={ }> Sign CSR |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1826 | certs | Btn | setModal("upload-3p")} style={ }> Upload 3rd-Party |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1827 | certs | Btn | setModal("cert-alert-policy")} style={ }> Alert Policy |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1828 | certs | Btn | setModal("cert-clm-policy")} style={ }> Lifetime policy |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1843 | certs | Btn | setCertStatusView("all")} style={ }> {`All ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1846 | certs | Btn | setCertStatusView("active")} style={ }> {`Active ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1849 | certs | Btn | setCertStatusView("revoked")} style={ }> {`Revoked ($ )`} |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1853 | certs | Btn | void refreshCerts()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1884 | certs | button | openCertActionMenu(e,certID)} aria-label="Certificate actions" style={{ backg... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1916 | certs | button | } onMouseEnter={(e)=> } onMouseLeave={(e)=> } style={ } > Download |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1930 | certs | button | } disabled={busy===`renew-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } st... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1943 | certs | button | } disabled={busy===`revoke-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } s... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1956 | certs | button | } disabled={busy===`ocsp-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } sty... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 1971 | certs | button | } disabled={busy===`delete-$ `} onMouseEnter={(e)=> } onMouseLeave={(e)=> } s... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2007 | certs | Btn | setCertPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2009 | certs | Btn | setCertPageIndex((prev)=>Math.min(certTotalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2054 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2055 | certs | Btn | void submitCreateCA()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2130 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2131 | certs | Btn | void submitIssueCert()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2191 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2192 | certs | Btn | void submitSignCSR()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2221 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2222 | certs | Btn | void submitDownloadCert()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2246 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2247 | certs | Btn | void submitUpload()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2266 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2267 | certs | Btn | void saveAlertPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2287 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2288 | certs | Btn | void saveCLMPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2314 | certs | Btn | setProtocolConfigText(JSON.stringify(protocolDefaultConfigs[String(protocolNa... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2316 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2317 | certs | Btn | void saveProtocol()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2391 | certs | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2392 | certs | Btn | void submitCreateSTARSubscription()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2428 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2429 | certs | Btn | { const email=String((document.getElementById("acme-wiz-email") as any)?.valu... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2487 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2488 | certs | Btn | { if(!session)return; try{ const attrs=await estCSRAttributes(session); onToa... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2495 | certs | Btn | { const cn=String((document.getElementById("est-wiz-cn") as any)?.value\|\|"").... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2548 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2549 | certs | Btn | { if(!session\|\|!activeCA)return; setSubmitting(true); try{ const msgType=scep... |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2611 | certs | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/CertsTab.tsx | 2612 | certs | Btn | { const msgType=cmpMsgType as "ir"\|"cr"\|"kur"\|"rr",cn=String((document.getEle... |  |
| web/dashboard/src/components/v3/tabs/ClientSDKTab.tsx | 53 | pkcs11 | Btn | void download()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 31 | cloudctl | Btn | selectSubtab("byok")}>BYOK |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 32 | cloudctl | Btn | selectSubtab("hyok")}>HYOK |  |
| web/dashboard/src/components/v3/tabs/CloudKeyControlTab.tsx | 33 | cloudctl | Btn | selectSubtab("google-cse")}>Google CSE |  |
| web/dashboard/src/components/v3/tabs/ClusterFailoverPanel.tsx | 74 | - | Btn | void load()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterFailoverPanel.tsx | 99 | - | Btn | void promote(false)}> |  |
| web/dashboard/src/components/v3/tabs/ClusterJoinPanel.tsx | 53 | - | Btn | setMode("issue")}>On this primary: add a node |  |
| web/dashboard/src/components/v3/tabs/ClusterJoinPanel.tsx | 54 | - | Btn | setMode("join")}>On a new node: join a cluster |  |
| web/dashboard/src/components/v3/tabs/ClusterJoinPanel.tsx | 65 | - | Btn | void issue()}> |  |
| web/dashboard/src/components/v3/tabs/ClusterJoinPanel.tsx | 79 | - | Btn | void join()}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTab.tsx | 363 | cluster | Btn | void refresh(false)} disabled= >Retry |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 117 | - | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 267 | - | Btn | setAddNodeModalOpen(true)}>Add Instance |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 268 | - | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 323 | - | Btn | void removeNodeAction(node)}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 334 | - | Btn | setAddNodeModalOpen(true)}>Add First Instance |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 409 | - | Btn | void saveProfile()}> |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 427 | - | Btn | void removeProfile(profile)}>Delete |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 458 | - | Btn | void refreshSyncEvents()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 548 | - | Btn | void refreshClusterLogs()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ClusterTabView.tsx | 561 | - | Btn | void refreshClusterLogs()}>Apply |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 168 | home | button | setOpen((v) => !v)} aria-expanded= style={ } > |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 181 | home | button | onNavigate(r.action.tab)} style={ } > |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 188 | home | button | setOpen((v) => !v)} aria-label="Details" style={ }> |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 203 | home | button | onSnooze(r.id)} style={{ marginTop: 10, fontSize: 12, color: C.muted, backgro... |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 297 | home | button | void refresh()} disabled= style={{ display: "inline-flex", alignItems: "cente... |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 338 | home | button | onNavigate("home/recommendations")} style={ }>View all → |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 353 | home | button | onNavigate("ops")} style={ }> Operations dashboard |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 383 | home | button | void refresh()} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 388 | home | button | setSev("all")}>All ( ) |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 390 | home | button | setSev(s)}> ( ) |  |
| web/dashboard/src/components/v3/tabs/CommandCenterTab.tsx | 397 | home | button | Show snoozed | unsnoozeAll |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 520 | compliance | Btn | setView("assessment")} style={ }>Assessment |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 521 | compliance | Btn | setView("reporting")} style={ }>Reports |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 524 | compliance | Btn | void loadReporting()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 544 | compliance | Btn | void triggerReportNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 570 | compliance | Btn | void createScheduleReport()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 590 | compliance | Btn | void downloadJob(job)} disabled= >Download |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 591 | compliance | Btn | void deleteJob(job)}>Delete |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 625 | compliance | Btn | setView("assessment")} style={ }>Assessment |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 626 | compliance | Btn | setView("reporting")} style={ }>Reports |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 637 | compliance | Btn | void createTemplate()} disabled= >+ Template |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 638 | compliance | Btn | void saveTemplate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 639 | compliance | Btn | void removeTemplate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 640 | compliance | Btn | void loadAssessment( )} disabled= >Refresh |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 641 | compliance | Btn | void exportEvidencePack("pdf")} disabled= >Evidence Pack |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 642 | compliance | Btn | void runNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 648 | compliance | Btn | void saveSchedule()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 666 | compliance | Btn | void runNow()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ComplianceTab.tsx | 1145 | compliance | Btn | { setEvidenceBusy(true); try { await downloadEvidenceReport(session, ); onToa... |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 291 | confidential | Btn | void refresh(false)}>Refresh |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 324 | confidential | Btn | void refresh(false)}>Reload |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 325 | confidential | Btn | void savePolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 431 | confidential | Btn | void runEvaluation()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ConfidentialComputeTab.tsx | 601 | confidential | Btn | void refresh(false)}>Refresh History |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 97 | crypto_agility | button | Retry | onRetry} style={{ marginTop: 14, background: C.card, border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 313 | crypto_agility | button | load(true)} disabled= style={{ background: C.card, border: `1px solid $ `, bo... |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 316 | crypto_agility | button | setRuleModal( )} disabled= style={{ background: C.card, border: `1px solid $... |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 324 | crypto_agility | button | setView(id)} style={{ background: "transparent", border: "none", borderBottom... |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 397 | crypto_agility | button | setRuleModal( )} style= > |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 398 | crypto_agility | button | handleDeleteRule(r)} style= > |  |
| web/dashboard/src/components/v3/tabs/CryptoAgilityTab.tsx | 500 | crypto_agility | button | setView("execution")} style={ }>Readiness &amp; execution |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 714 | crypto | button | selectAlgorithmFromRail(String(name),fipsApproved)} disabled= style={{ displa... |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 748 | crypto | button | { if(tabAllowed) }} disabled= style={{ background:op===item.id?C.accent:"tran... |  |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 870 | crypto | button | {busy?`Execute $ ...`:`Execute $ `} | runOperation |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 898 | crypto | Btn | Hex | renderResultAsHex |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 899 | crypto | Btn | Base64 | renderResultAsBase64 |
| web/dashboard/src/components/v3/tabs/CryptoTab.tsx | 900 | crypto | Btn | Download | downloadResult |
| web/dashboard/src/components/v3/tabs/CryptoperiodPanel.tsx | 51 | - | Btn | void run(r.category, () => setCryptoperiod(session, r.category, Number(draft[... |  |
| web/dashboard/src/components/v3/tabs/CryptoperiodPanel.tsx | 52 | - | Btn | void run(r.category, () => resetCryptoperiod(session, r.category))}>Reset |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 221 | - | Btn | onNavigate?.("certs")}>View Certificates → |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 248 | - | button | onUnpinTab?.(tabId)} title={`Unpin $ `} style={ } > |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 258 | - | button | onNavigate?.(tabId)} style={{ display: "inline-flex", alignItems: "center", g... |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 387 | - | Btn | void submitHomeApprovalVote(item, "approved")} disabled={approvalVoteBusy ===... |  |
| web/dashboard/src/components/v3/tabs/DashboardTabView.tsx | 388 | - | Btn | void submitHomeApprovalVote(item, "denied")} disabled={approvalVoteBusy === `... |  |
| web/dashboard/src/components/v3/tabs/DiscoveryTab.tsx | 213 | discovery | Btn | void load()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/DiscoveryTab.tsx | 214 | discovery | Btn | setScheduleOpen(true)} title={schedule?.paused_reason \|\| (schedule?.enabled ?... |  |
| web/dashboard/src/components/v3/tabs/DiscoveryTab.tsx | 218 | discovery | Btn | void runScan(scanAllTypes)} disabled= title={scanAllTypes.length ? `Scan $ `... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 449 | ekm | Btn | Register Database | openDbRegister} disabled={!agents.length |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 450 | ekm | Btn | setModal("setup-guide")}>Setup Guide |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 470 | ekm | Btn | setExpandedTdeGuide(prev=>( ))} style={ }>Guide |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 471 | ekm | Btn | runRevokeTDE(db)} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 502 | ekm | Btn | setBitLockerView(bitLockerView==="cards"?"list":"cards")} style={ }>{bitLocke... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 503 | ekm | Btn | Register Client | openBitLockerDeploy |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 504 | ekm | Btn | Network Scan | openBitLockerScan |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 505 | ekm | Btn | refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 529 | ekm | Btn | runBitLockerOperation(client,op)} disabled={bitLockerOpClientID===`$ :$ `} st... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 530 | ekm | Btn | openBitLockerActivity(client)} style={ }>Activity |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 531 | ekm | Btn | openBitLockerDelete(client)} style={ }>Delete |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 552 | ekm | Btn | openBitLockerActivity(client)} style={ }>Activity |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 553 | ekm | Btn | openBitLockerOptions(client)} style={ }>Ops |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 554 | ekm | Btn | openBitLockerDelete(client)} style={ }>Del |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 586 | ekm | Btn | { setGoogleCSELoading(true); try{ const domains=googleCSEConfigForm.allowed_d... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 618 | ekm | Btn | { const v=await promptDialog.prompt( ); if(v===null) return; try{await update... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 623 | ekm | Btn | { if(!confirm("Delete this Google CSE config?")) return; try catch(e){onToast... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 652 | ekm | Btn | { setGoogleCSELoading(true); try{ await createGoogleCSEKey(session, ); onToas... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 680 | ekm | Btn | { if(!confirm("Delete this CSE key?")) return; try catch(e){onToast?.(`Delete... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 716 | ekm | Btn | setGuideEngine(eng)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 759 | ekm | Btn | (icon or dynamic label) | submitDbRegister} disabled={dbRegistering |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 760 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 777 | ekm | Btn | (icon or dynamic label) | submitBitLockerDeploy} disabled={bitLockerDeploying |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 778 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 785 | ekm | Btn | downloadText(file.path,file.content)} style={ }>Download |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 803 | ekm | Btn | (icon or dynamic label) | submitBitLockerDelete} disabled={bitLockerDeleteSubmitting\|\|!bitLockerDeleteConfirmBackup |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 804 | ekm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 821 | ekm | Btn | (icon or dynamic label) | runBitLockerScan} disabled={bitLockerScanRunning |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 837 | ekm | Btn | (icon or dynamic label) | onboardScannedBitLocker} disabled={bitLockerOnboarding |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 838 | ekm | Btn | {const all= ;bitLockerScanCandidates.forEach(r=> );setBitLockerScanSelected(a... |  |
| web/dashboard/src/components/v3/tabs/EKMTab.tsx | 880 | ekm | Btn | } disabled={bitLockerOpClientID===`$ :$ `} style={ }> |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 254 | approvals | Btn | Configure | openSettingsModal |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 255 | approvals | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 320 | approvals | Btn | void doVote(r, "approved")}> {voteBusy === `$ :approved` ? "..." : "Approve"} |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 323 | approvals | Btn | void doVote(r, "denied")}> {voteBusy === `$ :denied` ? "..." : "Deny"} |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 373 | approvals | Btn | Configure | openSettingsModal |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 430 | approvals | Btn | { if (!smtpTestTo.trim()) try catch (e: any) { onToast?.(`SMTP test failed: $... |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 445 | approvals | Btn | { try { await testGovernanceWebhook(session, ch); onToast?.(`$ test sent thro... |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 454 | approvals | Btn | setSettingsModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/GovernanceTab.tsx | 455 | approvals | Btn | (icon or dynamic label) | saveSettings} disabled={settingsSaving |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 272 | hsm | Btn | void refreshCLIHints()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 316 | hsm | Btn | void openSSHSession()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 352 | hsm | Btn | void loadProviderConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 378 | hsm | Btn | void autoFetchPartitions()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 379 | hsm | Btn | void persistProviderConfig( , )} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 380 | hsm | Btn | setModal("gen")} disabled= >Generate Key in HSM |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 553 | hsm | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/HSMTab.tsx | 554 | hsm | Btn | { onToast?.(`HSM key generation requested: $ label="$ " partition="$ " [extra... |  |
| web/dashboard/src/components/v3/tabs/HYOKAzureConfig.tsx | 116 | - | button | setRows((cur) => cur.filter((_, j) => j !== i))} style={ }> |  |
| web/dashboard/src/components/v3/tabs/HYOKAzureConfig.tsx | 119 | - | Btn | setRows((cur) => [...cur, ])}> Add key |  |
| web/dashboard/src/components/v3/tabs/HYOKAzureConfig.tsx | 134 | - | button | { try catch }} style={ }> |  |
| web/dashboard/src/components/v3/tabs/HYOKAzureConfig.tsx | 139 | - | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/HYOKAzureConfig.tsx | 140 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HYOKLiveTestPane.tsx | 166 | - | Btn | void executeTest()} disabled= style={ }> {executing ? "Executing..." : `Execu... |  |
| web/dashboard/src/components/v3/tabs/HYOKLiveTestPane.tsx | 173 | - | button | copyToClipboard(testOutput)} style={ } title="Copy output"> |  |
| web/dashboard/src/components/v3/tabs/HYOKOCIConfig.tsx | 132 | - | button | set( )} style={ }> |  |
| web/dashboard/src/components/v3/tabs/HYOKOCIConfig.tsx | 135 | - | Btn | set({ rows: [...m.rows, ] })}> Add key |  |
| web/dashboard/src/components/v3/tabs/HYOKOCIConfig.tsx | 150 | - | button | { try catch }} style={ }> |  |
| web/dashboard/src/components/v3/tabs/HYOKOCIConfig.tsx | 155 | - | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/HYOKOCIConfig.tsx | 156 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 294 | hyok | Btn | void refresh(false)} disabled= > Refresh |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 295 | hyok | Btn | }> Endpoint URLs |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 296 | hyok | Btn | }> Setup Guide |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 335 | hyok | Btn | openConfig(protocol)}>Configure |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 336 | hyok | Btn | }>URLs |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 337 | hyok | Btn | }>Guide |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 338 | hyok | Btn | void runDelete(protocol)}>Reset |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 479 | hyok | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 480 | hyok | Btn | void submitConfig()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 508 | hyok | button | copyToClipboard(url.path)} style={ } title="Copy URL path"> |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 515 | hyok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/HYOKTab.tsx | 557 | hyok | Btn | setModal(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/HYOKXKSConfig.tsx | 116 | - | button | setRows((cur) => cur.filter((_, j) => j !== i))} style={ }> |  |
| web/dashboard/src/components/v3/tabs/HYOKXKSConfig.tsx | 119 | - | Btn | setRows((cur) => [...cur, ])}> Add key |  |
| web/dashboard/src/components/v3/tabs/HYOKXKSConfig.tsx | 134 | - | button | { try catch }} style={ }> |  |
| web/dashboard/src/components/v3/tabs/HYOKXKSConfig.tsx | 139 | - | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/HYOKXKSConfig.tsx | 140 | - | Btn | void save()} disabled= > |  |
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
| web/dashboard/src/components/v3/tabs/KeyCreateMenu.tsx | 22 | - | Btn | Create Key | onCreate} style={{ ...btnStyle, padding: "0 20px", minWidth: 130 |
| web/dashboard/src/components/v3/tabs/KeyCreateMenu.tsx | 25 | - | Btn | setOpen((v) => !v)} aria-haspopup="menu" aria-expanded= style={{ ...btnStyle,... |  |
| web/dashboard/src/components/v3/tabs/KeyCreateMenu.tsx | 31 | - | button | } className="vk-nav-item" style={ }> |  |
| web/dashboard/src/components/v3/tabs/KeyDerivationPanel.tsx | 53 | - | Btn | void load()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/KeyDerivationPanel.tsx | 77 | - | Btn | void run(k.key_id, "start migration", () => kdfTransition(session, k.key_id,... |  |
| web/dashboard/src/components/v3/tabs/KeyDerivationPanel.tsx | 81 | - | Btn | void run(k.key_id, "re-protect vault tokens", () => kdfReprotectVault(session... |  |
| web/dashboard/src/components/v3/tabs/KeyDerivationPanel.tsx | 83 | - | Btn | void run(k.key_id, "abort", () => kdfTransition(session, k.key_id, "abort"))}... |  |
| web/dashboard/src/components/v3/tabs/KeyInventoryPanel.tsx | 16 | - | button | (icon or dynamic label) | onClick} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", bor... |
| web/dashboard/src/components/v3/tabs/KeyInventoryPanel.tsx | 60 | - | Btn | Export JSON | handleExport |
| web/dashboard/src/components/v3/tabs/KeyInventoryPanel.tsx | 61 | - | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 17 | - | button | (icon or dynamic label) | disabled ? undefined : onClick} disabled={disabled |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 84 | - | Btn | setShowForm(!showForm)} small> New Job |  |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 85 | - | Btn | (icon or dynamic label) | load |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 111 | - | Btn | (icon or dynamic label) | handleCreate} disabled={saving \|\| !form.key_id |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 112 | - | Btn | setShowForm(false)} variant="ghost">Cancel |  |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 131 | - | Btn | handleToggle(j)}>{j.enabled ? : } |  |
| web/dashboard/src/components/v3/tabs/KeySchedulingTab.tsx | 134 | - | Btn | handleDelete(j.id)}> |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1746 | keys | Btn | void refreshKeyInventory()} style={{height:40,padding:"0 16px",borderRadius:4... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1749 | keys | Btn | setModal("metadata-profiles")} style={{height:40,padding:"0 16px",borderRadiu... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1750 | keys | Btn | setModal("binding-policies")} style={{height:40,padding:"0 16px",borderRadius... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1759 | keys | button | { e.stopPropagation(); const next=!showColumnMenu; if(next) setShowColumnMenu... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1887 | keys | button | { e.stopPropagation(); const isOpen=openActionMenuId===k.id; if(isOpen) const... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1929 | keys | button | } style={ } > Edit Key Policy |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1938 | keys | button | } style={ } > Rotate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1951 | keys | button | } style={ } > Verify Integrity |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1957 | keys | button | } style={ } > Attest |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1963 | keys | button | } disabled= style={ } > Deactivate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1973 | keys | button | } disabled= style={ } > Activate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1983 | keys | button | } disabled= style={ } > Disable |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 1993 | keys | button | } style={ } > Export |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2004 | keys | button | } style={ } > Delete |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2023 | keys | Btn | }>Create your first key |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2039 | keys | Btn | setPageIndex((prev)=>Math.max(0,prev-1))} disabled= >Prev |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2041 | keys | Btn | setPageIndex((prev)=>Math.min(totalPages-1,prev+1))} disabled= >Next |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2143 | keys | button | setCreateTags((prev)=>prev.filter((t)=>t!==tag))} style={ } > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2153 | keys | Btn | setShowCreateTagPicker(!showCreateTagPicker)}>Add More Tags |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2170 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2171 | keys | Btn | (icon or dynamic label) | addCustomerKey} disabled={creating |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2292 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2293 | keys | Btn | (icon or dynamic label) | submitFormKey} disabled={forming |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2399 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2400 | keys | Btn | (icon or dynamic label) | submitImportKey} disabled={importing |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2459 | keys | Btn | updateKeyStatus(comp,"deactivated")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2460 | keys | Btn | updateKeyStatus(comp,"active")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2461 | keys | Btn | updateKeyStatus(comp,"disabled")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2483 | keys | Btn | }> Rotate |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2484 | keys | Btn | setModal("export")}> Export |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2485 | keys | Btn | Public key (PEM) | downloadSelectedPublicKey |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2486 | keys | Btn | openPolicyEditor(selectedKey)}>Edit Key Policy |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2487 | keys | Btn | updateKeyStatus(selectedKey,"deactivated")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2488 | keys | Btn | updateKeyStatus(selectedKey,"active")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2489 | keys | Btn | updateKeyStatus(selectedKey,"disabled")} disabled= > |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2490 | keys | Btn | }> Delete |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2547 | keys | Btn | Add Assignment | addPolicyGrant |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2567 | keys | Btn | removePolicyGrant(subjectType,subjectID)}>Remove |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2589 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2590 | keys | Btn | (icon or dynamic label) | saveKeyPolicy} disabled={policySaving |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2611 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2611 | keys | Btn | (icon or dynamic label) | rotateSelectedKey} disabled={rotating |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2638 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2639 | keys | Btn | (icon or dynamic label) | destroySelectedKey} disabled={!destroyReady |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2667 | keys | Btn | setModal(null)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2667 | keys | Btn | (icon or dynamic label) | generatePQCKey} disabled={pqcGenerating |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2673 | keys | Btn | setAttestResult(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2680 | keys | Btn | {const b=new Blob([JSON.stringify(attestResult,null,2)], );const a=document.c... |  |
| web/dashboard/src/components/v3/tabs/KeysTab.tsx | 2681 | keys | Btn | navigator.clipboard?.writeText(JSON.stringify(attestResult,null,2))}>Copy |  |
| web/dashboard/src/components/v3/tabs/MetadataProfilesPanel.tsx | 77 | - | Btn | setEditing( )}>New profile |  |
| web/dashboard/src/components/v3/tabs/MetadataProfilesPanel.tsx | 90 | - | Btn | void check(p)}>Check keys |  |
| web/dashboard/src/components/v3/tabs/MetadataProfilesPanel.tsx | 91 | - | Btn | setEditing( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/MetadataProfilesPanel.tsx | 92 | - | Btn | void remove(p)}>Delete |  |
| web/dashboard/src/components/v3/tabs/MetadataProfilesPanel.tsx | 142 | - | Btn | set( )}>Remove |  |
| web/dashboard/src/components/v3/tabs/MetadataProfilesPanel.tsx | 146 | - | Btn | set({ labels: [...value.labels, ] })}>Add label |  |
| web/dashboard/src/components/v3/tabs/MetadataProfilesPanel.tsx | 148 | - | Btn | Cancel | onCancel |
| web/dashboard/src/components/v3/tabs/MetadataProfilesPanel.tsx | 149 | - | Btn | Save profile | onSave |
| web/dashboard/src/components/v3/tabs/OpsMetricsPanel.tsx | 97 | - | button | setTimeWindow(w)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/OpsMetricsPanel.tsx | 104 | - | button | Refresh | load} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/OpsMetricsPanel.tsx | 144 | - | button | setSection(s.id as any)} style={{ padding: "8px 16px", border: "none", backgr... |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 76 | playbooks | button | (icon or dynamic label) | disabled ? undefined : onClick} style={{ ...base, ...styles[variant] |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 177 | playbooks | button | onChange(filters.filter((_: any, idx: number) => idx !== i))} style={ }> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 181 | playbooks | Btn | onChange([...filters, ])}> Add filter |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 374 | playbooks | button | setOpenRun(open ? "" : r.id)} style={ }>{open ? : } |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 384 | playbooks | Btn | handleCancel(r)}> Cancel |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 385 | playbooks | Btn | handleRetry(r)}> Retry |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 422 | playbooks | Btn | openEditor()}> New |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 423 | playbooks | Btn | }> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 476 | playbooks | button | setDryRun(null)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 507 | playbooks | button | handleToggle(pb)} style={ }>{pb.enabled ? : } |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 513 | playbooks | Btn | openEditor(pb)}> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 514 | playbooks | Btn | handleDryRun(pb)}> Dry run |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 515 | playbooks | Btn | handleRun(pb)}> Run |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 516 | playbooks | Btn | handleDelete(pb)}> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 558 | playbooks | button | { setRunFilter( ); setView("runs"); }} style={ }> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 619 | playbooks | button | setForm((p: any) => ( ))} style={ }> |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 651 | playbooks | Btn | setForm((p: any) => ({ ...p, actions: [...p.actions, ] }))}> Add action |  |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 653 | playbooks | Btn | (icon or dynamic label) | handleSave} disabled={saving \|\| !form.name |
| web/dashboard/src/components/v3/tabs/PlaybooksTab.tsx | 654 | playbooks | Btn | }>Cancel |  |
| web/dashboard/src/components/v3/tabs/PostureHeaderParts.tsx | 25 | - | button | onChange(m)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 546 | posture | Btn | load(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 547 | posture | Btn | (icon or dynamic label) | runScan} disabled={running |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 970 | posture | Btn | setFindingEngine("")} style={ }>Clear engine filter |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1223 | posture | Btn | patchFinding(selectedFinding, "acknowledged")} disabled= >Acknowledge |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1224 | posture | Btn | patchFinding(selectedFinding, "resolved")} disabled= >Resolve |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1225 | posture | Btn | patchFinding(selectedFinding, "reopened")}>Reopen |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1226 | posture | Btn | setSelectedFinding(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1317 | posture | Btn | executeAction(selectedAction)}> Execute |  |
| web/dashboard/src/components/v3/tabs/PostureTab.tsx | 1319 | posture | Btn | setSelectedAction(null)}>Close |  |
| web/dashboard/src/components/v3/tabs/PrivateEndpoints.tsx | 81 | - | Btn | void approve()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/PrivateEndpoints.tsx | 95 | - | button | void withdraw(e)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 446 | restapi | Btn | (icon or dynamic label) | executeRequest} disabled={running |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 477 | restapi | Btn | void loadClientSecurity(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 485 | restapi | button | setSelectedClientID(String(item?.id\|\|""))} style={{ textAlign:"left", border:... |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 582 | restapi | Btn | setClientDraft(selectedClient? :null)}>Reset |  |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 583 | restapi | Btn | (icon or dynamic label) | saveClientSecurity} disabled={clientSaving |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 705 | restapi | Btn | Refresh cURL | buildPreview |
| web/dashboard/src/components/v3/tabs/RestAPITab.tsx | 706 | restapi | Btn | (icon or dynamic label) | executeRequest} disabled={running |
| web/dashboard/src/components/v3/tabs/RestClientLifecycle.tsx | 24 | - | Btn | }> |  |
| web/dashboard/src/components/v3/tabs/RestClientLifecycle.tsx | 25 | - | Btn | I stored it | onDismiss |
| web/dashboard/src/components/v3/tabs/RestClientLifecycle.tsx | 49 | - | Btn | (icon or dynamic label) | submit} disabled={busy \|\| !name.trim() |
| web/dashboard/src/components/v3/tabs/RestClientLifecycle.tsx | 103 | - | Btn | void approve()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/RestClientLifecycle.tsx | 105 | - | Btn | (icon or dynamic label) | rotate} disabled={Boolean(busy) |
| web/dashboard/src/components/v3/tabs/RestClientLifecycle.tsx | 106 | - | Btn | (icon or dynamic label) | revoke} disabled={Boolean(busy) |
| web/dashboard/src/components/v3/tabs/RestClientRole.tsx | 50 | - | Btn | void save()}>Save role |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 204 | - | Btn | void refresh()}> Retry |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 243 | - | Btn | Create Policy | openCreateModal |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 245 | - | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 298 | - | Btn | void doTrigger(p.id, p.name)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 301 | - | Btn | openEditModal(p)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 304 | - | Btn | void doDelete(p)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 360 | - | Btn | void doTrigger(u.policy_id, u.policy_name)}> |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 453 | - | Btn | setPolicyModal(false)}>Cancel |  |
| web/dashboard/src/components/v3/tabs/RotationSchedulerTab.tsx | 454 | - | Btn | (icon or dynamic label) | savePolicy} disabled={pSaving \|\| !pName.trim() \|\| !pFilter.trim() |
| web/dashboard/src/components/v3/tabs/RotationSchedulingTab.tsx | 22 | rotation | button | setView(id)} style={{ display: "inline-flex", alignItems: "center", gap: 6, p... |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 400 | sbom | Btn | void loadData( )} disabled= > |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 487 | sbom | Btn | void exportSBOMFile("cyclonedx")} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 490 | sbom | Btn | void exportSBOMFile("spdx")} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 494 | sbom | Btn | setExportMenuOpen((prev) => !prev)} disabled= style={ }>Export |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 496 | sbom | Btn | } disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 499 | sbom | Btn | } disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 504 | sbom | Btn | void openSBOMDiff()} style={ }>SBOM Diff |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 563 | sbom | Btn | void exportCBOMFile()} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 566 | sbom | Btn | void openCBOMDiff()} style={ }>View Diff |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 658 | sbom | Btn | setDiffOpen(false)}>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 692 | sbom | Btn | setSBOMDiffOpen(false)}>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 720 | sbom | Btn | }>Close |  |
| web/dashboard/src/components/v3/tabs/SBOMTab.tsx | 750 | sbom | Btn | }>Close |  |
| web/dashboard/src/components/v3/tabs/SSHCADetail.tsx | 86 | - | Btn | void editPrincipals()}>Edit principals |  |
| web/dashboard/src/components/v3/tabs/SSHCADetail.tsx | 87 | - | Btn | void downloadSSHKRL(session, ca).catch((e) => onToast?.(errMsg(e)))}>Download... |  |
| web/dashboard/src/components/v3/tabs/SSHCADetail.tsx | 88 | - | Btn | void setStatus("disabled")}>Disable |  |
| web/dashboard/src/components/v3/tabs/SSHCADetail.tsx | 88 | - | Btn | void setStatus("active")}>Enable |  |
| web/dashboard/src/components/v3/tabs/SSHCADetail.tsx | 124 | - | Btn | void revoke(c)}>Revoke |  |
| web/dashboard/src/components/v3/tabs/SSHCADetail.tsx | 141 | - | Btn | copy(value, onToast)}>Copy |  |
| web/dashboard/src/components/v3/tabs/SSHCADetail.tsx | 219 | - | Btn | void submit()}> |  |
| web/dashboard/src/components/v3/tabs/SSHCADetail.tsx | 224 | - | Btn | copy(issued, onToast)}>Copy |  |
| web/dashboard/src/components/v3/tabs/SSHCertificatesPanel.tsx | 35 | - | Btn | setCreating(!creating)}> |  |
| web/dashboard/src/components/v3/tabs/SSHCertificatesPanel.tsx | 135 | - | Btn | void submit()}> |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 194 | - | Btn | void run(i.identity, () => setInternalMTLSPolicy(session, i.identity, i.kind... |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 198 | - | Btn | void run(i.identity, () => rotateInternalMTLS(session, i.identity, "graceful"... |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 204 | - | Btn | { setConfirmForce(""); void run(i.identity, () => rotateInternalMTLS(session,... |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 209 | - | Btn | setConfirmForce(i.identity)}>Force |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 254 | - | Btn | void run("edge", async () => , "Edge key exchange saved; Envoy and KMIP apply... |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 304 | - | Btn | void run(`$ -cert`, async () => { await setEdgeCertificateSource(session, );... |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 315 | - | Btn | void run(`$ -csr`, async () => { const out = await createEdgeCSR(session, );... |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 324 | - | Btn | void run(`$ -install`, async () => { await installEdgeCertificate(session, li... |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 340 | - | button | setView(v.id)} style={{ display: "inline-flex", gap: 6, alignItems: "center",... |  |
| web/dashboard/src/components/v3/tabs/ServiceMTLSPanel.tsx | 362 | - | Btn | void run("rotate-all", async () => { const out = await rotateAllInternalMTLS(... |  |
| web/dashboard/src/components/v3/tabs/SetupChecklist.tsx | 51 | - | button | onNavigate(s.action.tab)} style={ }> → |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 445 | - | button | setOp(name)} style={{ background:op===name?C.accent:"transparent", color:op==... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 464 | - | Btn | {if(!session?.token)return;setLoading(true);try{setVaults(await listTokenVaul... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 555 | - | Btn | void submitCurrent()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 571 | - | Btn | setOp("Mask")}>Open Mask Operation |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 579 | - | Btn | setOp("Redact")}>Open Redact Operation |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 758 | - | button | } style={{ background:mode===name?C.accentDim:"transparent", color:mode===nam... |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 805 | - | Btn | void submit()} disabled= style={ }> |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1177 | - | Btn | void downloadSDK()} disabled= >Download SDK |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1178 | - | Btn | void refresh(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1208 | - | Btn | void submitInit()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1231 | - | Btn | void submitComplete()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1254 | - | Btn | void submitLease()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1270 | - | Btn | void submitReceipt()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1310 | - | Btn | void revokeLease(item)} disabled= >Revoke |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1600 | - | Btn | void loadPolicy(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 1601 | - | Btn | (icon or dynamic label) | savePolicy} disabled={saving\|\|loading |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2099 | - | Btn | void loadPolicy(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2100 | - | Btn | (icon or dynamic label) | savePolicy} disabled={saving\|\|loading |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2295 | - | Btn | void refreshVaultRows(false)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2296 | - | Btn | void createVaultFromPolicy()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2324 | - | Btn | void deleteVaultFromPolicy(row)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2371 | - | Btn | void refresh()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2444 | - | Btn | selectSubtab("fieldenc")}>Field Encryption |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2445 | - | Btn | selectSubtab("dataenc-policy")}>Data Encryption Policy |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2446 | - | Btn | selectSubtab("token-policy")}>Token / Mask / Redact Policy |  |
| web/dashboard/src/components/v3/tabs/TokenizeTab.tsx | 2447 | - | Btn | selectSubtab("pkcs11")}>Java SDK |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 243 | vault | Btn | void loadAll()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 244 | vault | Btn | Generate key pair | openGenerate |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 245 | vault | Btn | Store secret | openCreate |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 280 | vault | button | setCategory(cat.id)} style= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 310 | vault | button | setCurrentPath(path)} title= style={{ display: "inline-flex", alignItems: "ce... |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 341 | vault | button | } style={ }> |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 342 | vault | button | } style={ }> |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 349 | vault | Btn | setShown((n) => n + PAGE)}>Show more ( left) |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 357 | vault | Btn | Store a secret | openCreate |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 358 | vault | Btn | Generate key pair | openGenerate |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 399 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 400 | vault | Btn | void submitCreate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 414 | vault | Btn | copyToClipboard(generatedPublicKey, onToast)}> Copy Public Key |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 417 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 418 | vault | Btn | void submitGenerate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 432 | vault | Btn | setModal(null)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/VaultTab.tsx | 433 | vault | Btn | void submitRotate()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 132 | - | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 166 | - | button | Add | addCustom} disabled={!custom.trim() |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 171 | - | button | toggleEvent(e)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 180 | - | button | Cancel | onClose} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 181 | - | button | (icon or dynamic label) | handleSave |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 215 | - | button | (icon or dynamic label) | onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer" |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 307 | - | button | {wh.enabled ? : } | onToggle} title={wh.enabled ? "Disable" : "Enable" |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 310 | - | button | Test | handleTest} disabled={testing |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 313 | - | button | Edit | onEdit} title="Edit" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 314 | - | button | Delete | onDelete} title="Delete" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 315 | - | button | {logOpen ? : } | onViewLog} title="View log" style={{ background: "none", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 406 | - | button | load(true)} disabled= style={{ background: C.card, border: `1px solid $ `, bo... |  |
| web/dashboard/src/components/v3/tabs/WebhooksTab.tsx | 413 | - | button | } style={ } > New stream |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 304 | workload | Btn | load(false)}> |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 343 | workload | Btn | Rotate Signing Keys | rotateSigningKeys} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 344 | workload | Btn | (icon or dynamic label) | saveSettings} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 395 | workload | Btn | (icon or dynamic label) | saveRegistration} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 415 | workload | Btn | setRegistrationDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 416 | workload | Btn | { try catch (error) { onToast?.(`Delete failed: $ `); } }}>Delete |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 436 | workload | Btn | (icon or dynamic label) | saveFederation} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 451 | workload | Btn | setFederationDraft( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 452 | workload | Btn | { try catch (error) { onToast?.(`Delete failed: $ `); } }}>Delete |  |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 485 | workload | Btn | (icon or dynamic label) | runIssue} disabled={busy |
| web/dashboard/src/components/v3/tabs/WorkloadIdentityTab.tsx | 525 | workload | Btn | (icon or dynamic label) | runExchange} disabled={busy |
| web/dashboard/src/components/v3/tabs/agility/CarafPanel.tsx | 362 | - | button | setThreatModal( )}> Add threat |  |
| web/dashboard/src/components/v3/tabs/agility/CarafPanel.tsx | 376 | - | button | setThreatModal( )}> |  |
| web/dashboard/src/components/v3/tabs/agility/CarafPanel.tsx | 377 | - | button | void remove("threat", t.id, t.name)}> |  |
| web/dashboard/src/components/v3/tabs/agility/CarafPanel.tsx | 387 | - | button | setAssetModal( )}> Add asset |  |
| web/dashboard/src/components/v3/tabs/agility/CarafPanel.tsx | 418 | - | button | setDecisionFor(x)}> Decide |  |
| web/dashboard/src/components/v3/tabs/agility/CarafPanel.tsx | 419 | - | button | setAssetModal( )}> |  |
| web/dashboard/src/components/v3/tabs/agility/CarafPanel.tsx | 420 | - | button | void remove("asset", x.asset.id, x.asset.name)}> |  |
| web/dashboard/src/components/v3/tabs/agility/DrillPanel.tsx | 56 | - | button | void run()}> |  |
| web/dashboard/src/components/v3/tabs/agility/PqcExecutionPanel.tsx | 99 | - | button | void act("scan", async () => { const s = await runPQCScan(session); return `S... |  |
| web/dashboard/src/components/v3/tabs/agility/PqcExecutionPanel.tsx | 102 | - | button | setShowPlan(true)}> Build execution plan |  |
| web/dashboard/src/components/v3/tabs/agility/PqcExecutionPanel.tsx | 149 | - | button | setOpen(expanded ? null : p.id)}> {expanded ? : } |  |
| web/dashboard/src/components/v3/tabs/agility/PqcExecutionPanel.tsx | 160 | - | button | void act(`dry-$ `, async () => { await executePQCPlan(session, p.id, true); r... |  |
| web/dashboard/src/components/v3/tabs/agility/PqcExecutionPanel.tsx | 163 | - | button | { if (!window.confirm(`Execute "$ "? Each key step creates a new key of its t... |  |
| web/dashboard/src/components/v3/tabs/agility/PqcExecutionPanel.tsx | 169 | - | button | { if (!window.confirm(`Roll back "$ "? The successor keys it created are deac... |  |
| web/dashboard/src/components/v3/tabs/agility/ui.tsx | 72 | - | button | Cancel | onClose} style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/agility/ui.tsx | 73 | - | button | (icon or dynamic label) | onSave |
| web/dashboard/src/components/v3/tabs/byok/Automation.tsx | 68 | - | Btn | void save()}> |  |
| web/dashboard/src/components/v3/tabs/byok/Automation.tsx | 78 | - | Btn | { createAutomationPlaybook(session, p.trigger).then(() => { onToast?.(`Playbo... |  |
| web/dashboard/src/components/v3/tabs/byok/CloudConsole.tsx | 95 | - | Btn | void run()}>{con.busy ? "Running…" : `Run $ `} |  |
| web/dashboard/src/components/v3/tabs/byok/CloudConsole.tsx | 98 | - | Btn | Export as script | exportScript |
| web/dashboard/src/components/v3/tabs/byok/Console.tsx | 86 | - | Btn | void load()}>Refresh |  |
| web/dashboard/src/components/v3/tabs/byok/Console.tsx | 87 | - | Btn | setConsoleOpen(true)}>Cloud console |  |
| web/dashboard/src/components/v3/tabs/byok/Console.tsx | 88 | - | Btn | setCreating(true)}> Bring your own key |  |
| web/dashboard/src/components/v3/tabs/byok/Console.tsx | 129 | - | Btn | download("vecta-byok-cloud-calls.sh", runsToScript(runs))}> Export as script |  |
| web/dashboard/src/components/v3/tabs/byok/Console.tsx | 136 | - | button | setOpenRun(openRun === r.id ? "" : r.id)} style={ }> · {k ? `$ $ ` : r.byok_i... |  |
| web/dashboard/src/components/v3/tabs/byok/CreateWizard.tsx | 156 | - | Btn | (icon or dynamic label) | onClose |
| web/dashboard/src/components/v3/tabs/byok/CreateWizard.tsx | 157 | - | Btn | void submit()}> |  |
| web/dashboard/src/components/v3/tabs/byok/KeyDetail.tsx | 90 | - | Btn | void act(op)}>{busy === op ? `$ …` : label} |  |
| web/dashboard/src/components/v3/tabs/byok/KeyDetail.tsx | 109 | - | Btn | setView(v)}>{ [v]} |  |
| web/dashboard/src/components/v3/tabs/byok/KeyDetail.tsx | 156 | - | button | setOpen(open === r.id ? "" : r.id)} style={ }> · steps · |  |
| web/dashboard/src/components/v3/tabs/byok/KeyPages.tsx | 71 | - | Btn | void act(op, params, confirm)}>{con.busy === op ? `$ …` : label} |  |
| web/dashboard/src/components/v3/tabs/byok/KeyPages.tsx | 83 | - | Btn | { setTab(t.id); setForm( ); }}> |  |
| web/dashboard/src/components/v3/tabs/byok/RunSteps.tsx | 37 | - | button | copy(s.cli \|\| "")} title="Copy the CLI equivalent" style={ }> |  |
| web/dashboard/src/components/v3/tabs/discovery/AssetDetail.tsx | 178 | - | button | setStatus(s)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/discovery/AssetDetail.tsx | 186 | - | Btn | void save()} disabled= >Save |  |
| web/dashboard/src/components/v3/tabs/discovery/AssetDetail.tsx | 193 | - | Btn | (confirmRemove ? void remove() : setConfirmRemove(true))} disabled= > |  |
| web/dashboard/src/components/v3/tabs/discovery/Buckets.tsx | 125 | - | button | setDeep((d) => !d)} title="Also read objects whose names say nothing: up to 2... |  |
| web/dashboard/src/components/v3/tabs/discovery/Buckets.tsx | 130 | - | Btn | void add()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/discovery/Buckets.tsx | 134 | - | button | onNavigate?.("playbooks")} style={ }>New storage connection |  |
| web/dashboard/src/components/v3/tabs/discovery/Buckets.tsx | 153 | - | Btn | void test(b)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/discovery/Buckets.tsx | 154 | - | button | void remove(b)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/discovery/Charts.tsx | 39 | - | button | (icon or dynamic label) | onClick} title={title |
| web/dashboard/src/components/v3/tabs/discovery/DistrustedCAs.tsx | 79 | - | Btn | setAdding((v) => !v)}> |  |
| web/dashboard/src/components/v3/tabs/discovery/DistrustedCAs.tsx | 94 | - | Btn | void add()}>Distrust |  |
| web/dashboard/src/components/v3/tabs/discovery/DistrustedCAs.tsx | 109 | - | Btn | void removeDistrustedCA(session, c.spki_sha256).then(load, (e) => onToast?.(e... |  |
| web/dashboard/src/components/v3/tabs/discovery/Inventory.tsx | 88 | - | button | set( )} title="Assets the last scan of their source didn't observe" style={{... |  |
| web/dashboard/src/components/v3/tabs/discovery/Inventory.tsx | 96 | - | button | setFilters(NO_FILTERS)} style={ }>Clear filters |  |
| web/dashboard/src/components/v3/tabs/discovery/Inventory.tsx | 154 | - | button | (icon or dynamic label) | onClick |
| web/dashboard/src/components/v3/tabs/discovery/Repositories.tsx | 91 | - | Btn | void add()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/discovery/Repositories.tsx | 95 | - | button | onNavigate?.("playbooks")} style={ }>New Git connection |  |
| web/dashboard/src/components/v3/tabs/discovery/Repositories.tsx | 113 | - | Btn | void test(r)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/discovery/Repositories.tsx | 114 | - | button | void remove(r)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/discovery/Schedule.tsx | 69 | - | button | setEnabled(false)}>Off |  |
| web/dashboard/src/components/v3/tabs/discovery/Schedule.tsx | 70 | - | button | setEnabled(true)}>On |  |
| web/dashboard/src/components/v3/tabs/discovery/Schedule.tsx | 75 | - | button | setHours(h)}> |  |
| web/dashboard/src/components/v3/tabs/discovery/Schedule.tsx | 84 | - | button | setPicked(on ? picked.filter((p) => p !== id) : [...picked, id])}> |  |
| web/dashboard/src/components/v3/tabs/discovery/Schedule.tsx | 99 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/discovery/Sources.tsx | 96 | - | Btn | (icon or dynamic label) | a.run} disabled={isUpload && uploading |
| web/dashboard/src/components/v3/tabs/discovery/Sources.tsx | 98 | - | Btn | onScan([s.id])} disabled= title={s.configured ? `Scan $ ` : "Set this source... |  |
| web/dashboard/src/components/v3/tabs/discovery/Sources.tsx | 161 | - | button | pick(p)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/discovery/Sources.tsx | 171 | - | Btn | void add()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/discovery/Sources.tsx | 185 | - | button | void remove(t)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 31 | - | Btn | void copy()}>{done ? : } |  |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 153 | - | Btn | void issue(client)} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 168 | - | Btn | setOS(o)}> |  |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 188 | - | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 188 | - | Btn | void create()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 189 | - | Btn | Finish later | onClose |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 189 | - | Btn | setStep(3)} disabled= >I've copied it |  |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 190 | - | Btn | Finish later | onClose |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 191 | - | Btn | Add another | again |
| web/dashboard/src/components/v3/tabs/ekm/AddClientWizard.tsx | 191 | - | Btn | Done | onClose |
| web/dashboard/src/components/v3/tabs/ekm/CheckInStrip.tsx | 29 | - | button | setPicked(picked === b.entry.at ? null : b.entry.at)} title={`$ · $ after the... |  |
| web/dashboard/src/components/v3/tabs/ekm/CheckInStrip.tsx | 53 | - | button | setList(!list)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/ekm/ClientDrawer.tsx | 114 | - | button | Close | onClose} aria-label="Close" style={{ background: "transparent", border: `1px solid ${C.border |
| web/dashboard/src/components/v3/tabs/ekm/ClientDrawer.tsx | 183 | - | Btn | act("Key requests", async () => setLogs(await listEKMAgentLogs(session, c.id,... |  |
| web/dashboard/src/components/v3/tabs/ekm/ClientDrawer.tsx | 199 | - | Btn | Rotate key | rotate} disabled={!detail?.key \|\| busy !== "" |
| web/dashboard/src/components/v3/tabs/ekm/ClientDrawer.tsx | 200 | - | Btn | onReenrol(c)} disabled= >New registration token |  |
| web/dashboard/src/components/v3/tabs/ekm/ClientDrawer.tsx | 201 | - | Btn | Remove | remove} disabled={busy !== "" |
| web/dashboard/src/components/v3/tabs/ekm/Clients.tsx | 84 | - | Btn | void load(false)} disabled= aria-label="Refresh"> |  |
| web/dashboard/src/components/v3/tabs/ekm/Clients.tsx | 85 | - | Btn | setWizard( )}> Add client |  |
| web/dashboard/src/components/v3/tabs/ekm/Clients.tsx | 109 | - | button | setDrill(null)} data-testid="ekm-drill" style={ }> · |  |
| web/dashboard/src/components/v3/tabs/ekm/Clients.tsx | 117 | - | Btn | setWizard( )}> Add client |  |
| web/dashboard/src/components/v3/tabs/ekm/Clients.tsx | 139 | - | Btn | }>{c.registration === "registered" ? <>Health : "Continue setup"} |  |
| web/dashboard/src/components/v3/tabs/ekm/EdgeDevices.tsx | 68 | - | Btn | setAdding(!adding)}> |  |
| web/dashboard/src/components/v3/tabs/ekm/EdgeDevices.tsx | 77 | - | Btn | setToken(null)}>Done |  |
| web/dashboard/src/components/v3/tabs/ekm/EdgeDevices.tsx | 89 | - | Btn | void issue(d)}> |  |
| web/dashboard/src/components/v3/tabs/ekm/EdgeDevices.tsx | 90 | - | Btn | void revoke(d)}>Revoke |  |
| web/dashboard/src/components/v3/tabs/ekm/EdgeDevices.tsx | 130 | - | Btn | void submit()}> |  |
| web/dashboard/src/components/v3/tabs/ekm/EdgeDevices.tsx | 166 | - | Btn | void revoke(l)}>Revoke |  |
| web/dashboard/src/components/v3/tabs/ekm/Kubernetes.tsx | 23 | - | button | { try catch }} style={ }> |  |
| web/dashboard/src/components/v3/tabs/playbooks/CredentialDetail.tsx | 75 | - | Btn | Delete | onDelete |
| web/dashboard/src/components/v3/tabs/playbooks/CredentialDetail.tsx | 76 | - | Btn | Edit | onEdit |
| web/dashboard/src/components/v3/tabs/playbooks/CredentialDetail.tsx | 77 | - | Btn | (icon or dynamic label) | onTest |
| web/dashboard/src/components/v3/tabs/playbooks/CredentialForm.tsx | 94 | - | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/playbooks/CredentialForm.tsx | 95 | - | Btn | (icon or dynamic label) | save |
| web/dashboard/src/components/v3/tabs/playbooks/Credentials.tsx | 125 | - | Btn | void test(c)}> |  |
| web/dashboard/src/components/v3/tabs/playbooks/Credentials.tsx | 135 | - | Btn | void load()}> |  |
| web/dashboard/src/components/v3/tabs/playbooks/Credentials.tsx | 136 | - | Btn | setForm( )}> Add credential |  |
| web/dashboard/src/components/v3/tabs/vault/Access.tsx | 40 | - | button | Delete rule | onDelete} style={{ background: "none", border: "none", color: C.redFg, cursor: "pointer", padding: 2 |
| web/dashboard/src/components/v3/tabs/vault/Access.tsx | 110 | - | Btn | void save()}> |  |
| web/dashboard/src/components/v3/tabs/vault/Access.tsx | 160 | - | Btn | void setCap()}> Set cap |  |
| web/dashboard/src/components/v3/tabs/vault/Access.tsx | 172 | - | button | void act("Version cap removed.", () => deleteVersionCap(session, c.id))} styl... |  |
| web/dashboard/src/components/v3/tabs/vault/Access.tsx | 234 | - | Btn | setOpen(true)}> Add rule |  |
| web/dashboard/src/components/v3/tabs/vault/Access.tsx | 274 | - | Btn | setOpen(false)} disabled= >Cancel |  |
| web/dashboard/src/components/v3/tabs/vault/Access.tsx | 275 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 69 | - | Btn | Cancel | onClose |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 70 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 124 | - | Btn | setDialog( )} disabled= >New role |  |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 134 | - | Btn | void (async () => { setBusy("issue-" + role.name); try { const out = await is... |  |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 146 | - | Btn | setDialog( )}>Edit |  |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 165 | - | Btn | void act("renew-" + l.id, () => renewDBLease(session, l.id), "Lease renewed."... |  |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 166 | - | Btn | void act("revoke-" + l.id, () => revokeDBLease(session, l.id), "Login dropped... |  |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 181 | - | Btn | { try catch }}> |  |
| web/dashboard/src/components/v3/tabs/vault/DatabaseCredentials.tsx | 186 | - | Btn | setIssued(null)}>Done |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 142 | - | Btn | setVisible((v) => !v)}>{visible ? <> Hide : <> Show } |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 143 | - | Btn | void reveal()} disabled= title= >{busy ? "Reading..." : <> Reveal } |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 144 | - | Btn | void navigator.clipboard.writeText(shown.value).then(() => onToast?.("Copied... |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 145 | - | Btn | Download | onDownload} disabled={busy \|\| !can("value") |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 165 | - | button | void reveal(v.version)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 166 | - | button | void rollback(v.version)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 167 | - | button | void destroyVersion(v.version)} style={ }> |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 187 | - | Btn | void run("Secret restored.", () => restoreSecret(session, secret.id), "close"... |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 188 | - | Btn | Rotate value | onRotate |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 191 | - | Btn | void destroy()}> Destroy |  |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 192 | - | Btn | Delete | onDelete |
| web/dashboard/src/components/v3/tabs/vault/Detail.tsx | 193 | - | Btn | Close | onClose |
| web/dashboard/src/modules/admin/ExposurePanel.tsx | 89 | - | Btn | { setAck( ); setReason(""); }}>Acknowledge |  |
| web/dashboard/src/modules/admin/ExposurePanel.tsx | 101 | - | Btn | setShowClosed((v) => !v)}>{showClosed ? "Hide closed" : `Show $ closed`} |  |
| web/dashboard/src/modules/admin/ExposurePanel.tsx | 111 | - | Btn | setAck(null)}>Cancel |  |
| web/dashboard/src/modules/admin/ExposurePanel.tsx | 112 | - | Btn | void acknowledge()}> |  |
| web/dashboard/src/modules/admin/FipsModePanel.tsx | 103 | - | Btn | void review(m)}> |  |
| web/dashboard/src/modules/admin/FipsModePanel.tsx | 122 | - | Btn | void apply()}> {busy ? "Applying..." : `Switch to $ and restart services`} |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 886 | - | Btn | void loadHealth()}> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 969 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 970 | - | Btn | setFipsConfigModalOpen(true)}>Configure FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 982 | - | Btn | {setSystemState((p)=>( ));onFipsModeChange("enabled");}}>Enable FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 983 | - | Btn | {setSystemState((p)=>( ));onFipsModeChange("disabled");}}>Disable FIPS |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1038 | - | Btn | setFipsConfigModalOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1039 | - | Btn | void saveFipsConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1046 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1047 | - | Btn | void testSnmpSettings()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1048 | - | Btn | void saveSnmpSettings()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1130 | - | Btn | void loadTags()}>Refresh |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1135 | - | Btn | void addTag()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1150 | - | Btn | void removeTag(name,usageCount)} disabled= >Delete |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1160 | - | Btn | void loadPasswordPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1160 | - | Btn | void savePasswordPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1184 | - | Btn | void saveSecurityPolicy()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1202 | - | Btn | void loadAccessHardening()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1203 | - | Btn | void saveAccessHardening()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1233 | - | Btn | void loadSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1233 | - | Btn | void saveSystemState()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1306 | - | Btn | }> |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1313 | - | Btn | void openCli()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1326 | - | Btn | { if(!session?.token) return; setHsmSaving(true); try{ const payload= ; const... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1357 | - | Btn | {if(!session?.token) return; const lib=String(hsm.library_path\|\|"").trim(); i... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1360 | - | Btn | setHsm((p)=>( ))}>Use |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1367 | - | Btn | {if(!session?.token) return; setGovSaving(true); try{await updateGovernanceSe... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1372 | - | Btn | {if(!session?.token\|\|!String(smtpTo\|\|"").trim()) setSmtpTesting(true); try ca... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1380 | - | Btn | {if(!session?.token) return; setWebhookTesting((p)=>( )); try{await testGover... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1387 | - | Btn | void refreshAlertRules()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1387 | - | Btn | openRuleModal()}>Create Rule |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1404 | - | Btn | {if(!session?.token\|\|!id) return; try{await updateReportingRule(session,id, )... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1407 | - | Btn | openRuleModal(rule)}>Edit |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1408 | - | Btn | {if(!session?.token\|\|!id) return; try catch(error){if(!sessionGuard(error)) o... |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1463 | - | Btn | void handleTestRule()} disabled= > |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1476 | - | Btn | setRuleModalOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/SystemAdminTab.tsx | 1477 | - | Btn | void handleSaveRule()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 358 | - | button | setActiveTab(t)} style={{ background: activeTab === t ? C.accentDim : "transp... |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 388 | - | Btn | void loadTenants()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 389 | - | Btn | setCreateOpen(true)}>+ Create Tenant |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 555 | - | Btn | void loadPolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 556 | - | Btn | void savePolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 576 | - | Btn | void loadBackups()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 577 | - | Btn | void handleCreateBackup()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 610 | - | Btn | void handleDownloadArtifact(b.id)}>Artifact |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 611 | - | Btn | void handleDownloadKey(b.id)}>Key |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 614 | - | Btn | void handleDeleteBackup(b.id)}>Delete |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 706 | - | Btn | void handleEnable()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 724 | - | Btn | void loadReadiness()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 725 | - | Btn | void handleDisable()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 728 | - | Btn | void handleDelete()} disabled= > |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 782 | - | Btn | setCreateOpen(false)}>Cancel |  |
| web/dashboard/src/modules/admin/TenantAdminTab.tsx | 783 | - | Btn | void createTenant()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/GroupBindingsSection.tsx | 24 | - | Btn | void model.upsertBinding()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/GroupBindingsSection.tsx | 36 | - | Btn | void model.removeBinding(binding)} disabled= >Delete |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 252 | - | Btn | void model.loadIdpConfig()}>Reload |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 253 | - | Btn | void model.testIdpConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 254 | - | Btn | void model.saveIdpConfig()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 263 | - | Btn | void model.discoverIdpUsers()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 264 | - | Btn | void model.discoverIdpGroups()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 280 | - | Btn | } > Select |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 295 | - | Btn | void model.discoverIdpMembers()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/IdentityProvidersSection.tsx | 336 | - | Btn | void model.importIdpUsers()} disabled= > {model.idpImporting ? "Importing..."... |  |
| web/dashboard/src/modules/admin/user-admin/PoliciesSection.tsx | 11 | - | Btn | void model.savePolicies()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/ScimProvisioningSection.tsx | 139 | - | Btn | void rotateToken()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/ScimProvisioningSection.tsx | 142 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 14 | - | Btn | void model.loadUsers()}> |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 56 | - | Btn | } > Reset Password |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 100 | - | Btn | void model.createUser()} disabled= > |  |
| web/dashboard/src/modules/admin/user-admin/UserManagementSection.tsx | 120 | - | Btn | void model.resetPassword()} disabled= > |  |
| web/dashboard/src/modules/backup/BackupSchedulesPanel.tsx | 71 | - | Btn | void load()}>Refresh |  |
| web/dashboard/src/modules/backup/BackupSchedulesPanel.tsx | 72 | - | Btn | { setEditing(""); setForm( ); }}>New schedule |  |
| web/dashboard/src/modules/backup/BackupSchedulesPanel.tsx | 118 | - | Btn | setForm(null)}>Cancel |  |
| web/dashboard/src/modules/backup/BackupSchedulesPanel.tsx | 119 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/modules/backup/BackupSchedulesPanel.tsx | 144 | - | Btn | void act(`run:$ `, () => runBackupSchedule(session!, s.id), "Backup taken.")}... |  |
| web/dashboard/src/modules/backup/BackupSchedulesPanel.tsx | 145 | - | Btn | }> |  |
| web/dashboard/src/modules/backup/BackupSchedulesPanel.tsx | 146 | - | Btn | void act(`toggle:$ `, () => saveBackupSchedule(session!, s.id, ), s.enabled ?... |  |
| web/dashboard/src/modules/backup/BackupSchedulesPanel.tsx | 147 | - | Btn | void act(`del:$ `, () => deleteBackupSchedule(session!, s.id), "Schedule dele... |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 116 | - | Btn | inputRef.current?.click()} style={{ padding: "8px 14px", borderRadius: 4, box... |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 130 | - | Btn | { onFileChange(null); if (inputRef.current) }} style={ } > Clear |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 303 | - | Btn | void loadJobs()}> |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 316 | - | Btn | { if(!session?.token) return; if(backupScope==="tenant"&&!String(backupTenant... |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 340 | - | Btn | dl(sh.file_name,sh.content_base64,sh.content_type)}>Download |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 343 | - | Btn | setBackupCreatedShares([])}>All shares handed out: close |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 380 | - | Btn | backupShareInputRef.current?.click()}> |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 381 | - | Btn | }>Clear |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 386 | - | Btn | void verifyBackup()} disabled= > |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 387 | - | Btn | void restoreBackup()} disabled= > |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 401 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDownloading(`$ :artifact`); try ca... |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 401 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDownloading(`$ :key`); try catch(e... |  |
| web/dashboard/src/modules/backup/EncryptedBackupsPanel.tsx | 401 | - | Btn | {if(!session?.token\|\|!id) return; setBackupDeleting(id); try catch(error){if(... |  |
| web/dashboard/src/modules/hsm/HSMActivityPanel.tsx | 40 | - | Btn | void load()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMIntegrationCard.tsx | 75 | - | Btn | void load()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMIntegrationCard.tsx | 95 | - | Btn | void save()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMKeyCheckPanel.tsx | 38 | - | Btn | void run()} disabled= > |  |
| web/dashboard/src/modules/hsm/HSMPartitionTable.tsx | 48 | - | Btn | void load()} disabled= > |  |
| web/dashboard/src/modules/keys/ExportKeyDialog.tsx | 102 | - | Btn | Cancel | onClose |
| web/dashboard/src/modules/keys/ExportKeyDialog.tsx | 103 | - | Btn | void run()} disabled= > |  |
| web/dashboard/src/modules/keys/KeyDescription.tsx | 45 | - | Btn | void save()}> |  |
| web/dashboard/src/modules/keys/KeyHistoryPanel.tsx | 76 | - | Btn | void verify()} disabled= > |  |
