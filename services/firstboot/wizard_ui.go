package main

const wizardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vecta KMS First-Boot Wizard</title>
  <style>
    :root{
      --bg:#0b1220;
      --panel:#111a2d;
      --panel-2:#0f172a;
      --text:#e5edf7;
      --muted:#93a8c4;
      --line:#2b3b57;
      --ok:#22c55e;
      --ok-text:#052e16;
      --warn:#f59e0b;
    }
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--text);font-family:Segoe UI,Arial,sans-serif}
    .wrap{max-width:1180px;margin:0 auto;padding:24px}
    h1{margin:0 0 8px}
    .sub{margin:0 0 20px;color:var(--muted)}
    .layout{display:grid;grid-template-columns:280px 1fr;gap:16px}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}
    .stepper{list-style:none;padding:0;margin:0}
    .stepper li{padding:10px 12px;border:1px solid var(--line);border-radius:8px;margin:8px 0;color:var(--muted)}
    .stepper li.active{color:var(--text);border-color:#3f5f90;background:#16213a}
    .step{display:none}
    .step.active{display:block}
    h2{margin:0 0 12px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
    label{display:block;font-size:13px;color:var(--muted);margin-bottom:4px}
    input,select,textarea{width:100%;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;color:var(--text);padding:9px}
    textarea{min-height:90px}
    .checks{display:grid;grid-template-columns:1fr 1fr;gap:8px}
    .check{display:flex;align-items:center;gap:8px;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--panel-2)}
    .check input{width:auto}
    .radio{display:flex;gap:14px;flex-wrap:wrap}
    .radio label{display:flex;align-items:center;gap:8px;margin:0;color:var(--text)}
    .radio input{width:auto}
    .actions{display:flex;gap:10px;margin-top:16px}
    button{padding:10px 14px;border:0;border-radius:8px;cursor:pointer;font-weight:700}
    .btn{background:#334155;color:#dbe6f8}
    .btn-ok{background:var(--ok);color:var(--ok-text)}
    .panel-title{font-weight:700;margin:12px 0 8px}
    pre{white-space:pre-wrap;overflow:auto;max-height:380px;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;padding:10px}
    .status{color:var(--warn);font-weight:700}
    .note{font-size:12px;color:var(--muted)}
    @media (max-width:980px){
      .layout{grid-template-columns:1fr}
      .grid,.grid-3,.checks{grid-template-columns:1fr}
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Vecta KMS First-Boot Wizard</h1>
    <p class="sub">FDE -> Network -> FIPS -> Features -> HSM -> License/Admin -> Apply</p>
    <div class="layout">
      <aside class="card">
        <ol class="stepper" id="stepper">
          <li class="active">0. Full Disk Encryption</li>
          <li>1. Network Configuration</li>
          <li>2. FIPS Mode</li>
          <li>3. Feature Selector</li>
          <li>4. HSM Mode</li>
          <li>5. License and Admin</li>
          <li>6. Review and Apply</li>
        </ol>
      </aside>
      <main class="card">
        <section class="step active">
          <h2>Step 0: Full Disk Encryption</h2>
          <div class="grid">
            <div>
              <label>Appliance ID</label>
              <input id="appliance_id" value="kms-prod-01">
            </div>
            <div>
              <label>LUKS Device</label>
              <input id="fde_luks_device" value="/dev/sda3">
            </div>
            <div>
              <label>LUKS2 Passphrase</label>
              <input id="fde_passphrase" type="password" value="ChangeMeStrongPassphrase!">
            </div>
            <div>
              <label>Recovery Passphrase (optional)</label>
              <input id="fde_recovery_passphrase" type="password" value="">
            </div>
            <div>
              <label>Recovery Shares (N)</label>
              <input id="fde_recovery_shares" type="number" min="2" max="10" value="5">
            </div>
            <div>
              <label>Recovery Threshold (M)</label>
              <input id="fde_recovery_threshold" type="number" min="2" max="10" value="3">
            </div>
          </div>
          <div class="panel-title">Unlock Method</div>
          <div class="radio">
            <label><input type="radio" name="unlock_method" value="console"> Console</label>
            <label><input type="radio" name="unlock_method" value="usb"> USB</label>
            <label><input type="radio" name="unlock_method" value="tang"> Tang</label>
            <label><input type="radio" name="unlock_method" value="rest_api" checked> REST API</label>
          </div>
          <div class="grid">
            <div>
              <label>Operator Public Key (optional PEM)</label>
              <textarea id="fde_operator_public_key" placeholder="-----BEGIN PUBLIC KEY-----"></textarea>
            </div>
            <div>
              <label>Tang Server (for tang mode)</label>
              <input id="fde_tang_server" value="">
            </div>
          </div>
          <div class="check" style="margin-top:12px">
            <input id="fde_enabled" type="checkbox" checked>
            <label for="fde_enabled" style="margin:0">Enable FDE (LUKS2 AES-256-XTS)</label>
          </div>
        </section>

        <section class="step">
          <h2>Step 1: Network Configuration</h2>
          <div class="panel-title">Management (eth0)</div>
          <div class="grid-3">
            <div>
              <label>Interface</label>
              <input id="mgmt_interface" value="eth0">
            </div>
            <div>
              <label>Mode</label>
              <select id="mgmt_mode">
                <option value="static" selected>static</option>
                <option value="dhcp">dhcp</option>
              </select>
            </div>
            <div>
              <label>IPv4 Address/CIDR</label>
              <input id="mgmt_address" value="10.0.1.100/24">
            </div>
            <div>
              <label>Gateway</label>
              <input id="mgmt_gateway" value="10.0.1.1">
            </div>
            <div>
              <label>DNS (comma-separated)</label>
              <input id="mgmt_dns" value="10.0.1.2,8.8.8.8">
            </div>
            <div>
              <label>Hostname</label>
              <input id="mgmt_hostname" value="vecta-kms-prod-01">
            </div>
            <div>
              <label>Domain</label>
              <input id="mgmt_domain" value="internal.bank.com">
            </div>
            <div>
              <label>IPv6 Enabled</label>
              <select id="mgmt_ipv6_enabled">
                <option value="false" selected>false</option>
                <option value="true">true</option>
              </select>
            </div>
            <div>
              <label>IPv6 Address</label>
              <input id="mgmt_ipv6_address" value="">
            </div>
          </div>
          <div class="panel-title">Cluster (eth1)</div>
          <div class="grid-3">
            <div class="check">
              <input id="cluster_enabled" type="checkbox" checked>
              <label for="cluster_enabled" style="margin:0">Enable cluster interface</label>
            </div>
            <div>
              <label>Interface</label>
              <input id="cluster_interface" value="eth1">
            </div>
            <div>
              <label>IPv4 Address/CIDR</label>
              <input id="cluster_address" value="172.16.0.100/24">
            </div>
            <div>
              <label>MTU</label>
              <input id="cluster_mtu" type="number" value="9000">
            </div>
          </div>
          <div class="panel-title">TLS, NTP, Syslog</div>
          <div class="grid">
            <div>
              <label>TLS Mode</label>
              <select id="tls_mode">
                <option value="custom" selected>custom</option>
                <option value="self-signed">self-signed</option>
                <option value="acme">acme</option>
              </select>
            </div>
            <div>
              <label>NTP Servers (comma-separated)</label>
              <input id="ntp_servers" value="pool.ntp.org">
            </div>
            <div>
              <label>TLS Cert Path</label>
              <input id="tls_cert_path" value="/etc/vecta/tls/server.crt">
            </div>
            <div>
              <label>TLS Key Path</label>
              <input id="tls_key_path" value="/etc/vecta/tls/server.key">
            </div>
            <div>
              <label>TLS CA Path</label>
              <input id="tls_ca_path" value="/etc/vecta/tls/ca.crt">
            </div>
            <div>
              <label>Syslog Server</label>
              <input id="syslog_server" value="syslog.bank.com:514">
            </div>
            <div>
              <label>Syslog Protocol</label>
              <select id="syslog_protocol">
                <option value="tcp+tls" selected>tcp+tls</option>
                <option value="udp">udp</option>
              </select>
            </div>
            <div class="check">
              <input id="syslog_enabled" type="checkbox" checked>
              <label for="syslog_enabled" style="margin:0">Enable syslog export</label>
            </div>
          </div>
        </section>

        <section class="step">
          <h2>Step 2: FIPS Mode</h2>
          <div class="radio">
            <label><input type="radio" name="fips_mode" value="strict" checked> Strict FIPS 140-3</label>
            <label><input type="radio" name="fips_mode" value="standard"> Standard Mode</label>
          </div>
          <p class="note">Strict blocks non-FIPS algorithms system-wide. Standard allows full catalog with warnings/policy controls.</p>
        </section>

        <section class="step">
          <h2>Step 3: Feature Selector</h2>
          <div class="checks">
            <label class="check"><input id="f_secrets" type="checkbox" checked> secrets</label>
            <label class="check"><input id="f_certs" type="checkbox" checked> certs</label>
            <label class="check"><input id="f_governance" type="checkbox" checked> governance</label>
            <label class="check"><input id="f_cloud_byok" type="checkbox"> cloud_byok</label>
            <label class="check"><input id="f_hyok_proxy" type="checkbox"> hyok_proxy</label>
            <label class="check"><input id="f_kmip_server" type="checkbox" checked> kmip_server</label>
            <label class="check"><input id="f_qkd_interface" type="checkbox"> qkd_interface</label>
            <label class="check"><input id="f_ekm_database" type="checkbox"> ekm_database</label>
            <label class="check"><input id="f_payment_crypto" type="checkbox" checked> payment_crypto</label>
            <label class="check"><input id="f_compliance_dashboard" type="checkbox" checked> compliance_dashboard</label>
            <label class="check"><input id="f_sbom_cbom" type="checkbox" checked> sbom_cbom</label>
            <label class="check"><input id="f_reporting_alerting" type="checkbox" checked> reporting_alerting</label>
            <label class="check"><input id="f_ai_llm" type="checkbox"> ai_llm</label>
            <label class="check"><input id="f_pqc_migration" type="checkbox" checked> pqc_migration</label>
            <label class="check"><input id="f_crypto_discovery" type="checkbox"> crypto_discovery</label>
            <label class="check"><input id="f_mpc_engine" type="checkbox"> mpc_engine</label>
            <label class="check"><input id="f_data_protection" type="checkbox" checked> data_protection</label>
            <label class="check"><input id="f_clustering" type="checkbox"> clustering</label>
          </div>
        </section>

        <section class="step">
          <h2>Step 4: HSM Mode and HSM Network</h2>
          <div class="radio">
            <label><input type="radio" name="hsm_mode" value="software" checked> software</label>
            <label><input type="radio" name="hsm_mode" value="hardware"> hardware</label>
            <label><input type="radio" name="hsm_mode" value="auto"> auto</label>
          </div>
          <div class="grid-3" style="margin-top:12px">
            <div class="check">
              <input id="hsm_enabled" type="checkbox">
              <label for="hsm_enabled" style="margin:0">Enable dedicated HSM interface</label>
            </div>
            <div>
              <label>HSM Interface</label>
              <input id="hsm_interface" value="eth2">
            </div>
            <div>
              <label>HSM IPv4 Address/CIDR</label>
              <input id="hsm_address" value="">
            </div>
          </div>
        </section>

        <section class="step">
          <h2>Step 5: License Activation and Admin</h2>
          <div class="grid">
            <div>
              <label>License Key</label>
              <input id="license_key" value="SEC-KMS-ENT-2026-XXXX">
            </div>
            <div>
              <label>Max Keys</label>
              <input id="license_max_keys" type="number" value="5000000">
            </div>
            <div>
              <label>Max Tenants</label>
              <input id="license_max_tenants" type="number" value="50">
            </div>
            <div>
              <label>Licensed Features (comma-separated or *)</label>
              <input id="license_features_allowed" value="*">
            </div>
          </div>
          <div class="panel-title">Admin Bootstrap</div>
          <div class="grid">
            <div>
              <label>Admin Username</label>
              <input id="admin_username" value="admin">
            </div>
            <div>
              <label>Admin Email</label>
              <input id="admin_email" value="admin@vecta.local">
            </div>
            <div>
              <label>Admin Password</label>
              <input id="admin_password" type="password" value="VectaAdmin@2026">
            </div>
            <div class="check">
              <input id="admin_force_password_change" type="checkbox" checked>
              <label for="admin_force_password_change" style="margin:0">Force password change on first login</label>
            </div>
            <div class="check">
              <input id="require_reboot" type="checkbox" checked>
              <label for="require_reboot" style="margin:0">Require reboot after apply</label>
            </div>
          </div>
        </section>

        <section class="step">
          <h2>Step 6: Review and Apply</h2>
          <p class="note">Preview checks input and renders generated files. Apply writes config files and validates deployment.yaml against the schema before write.</p>
          <pre id="payload_preview"></pre>
          <div class="actions">
            <button type="button" class="btn" id="preview_btn">Preview</button>
            <button type="button" class="btn-ok" id="apply_btn">Apply</button>
            <span class="status" id="status"></span>
          </div>
          <pre id="out"></pre>
        </section>

        <div class="actions">
          <button type="button" class="btn" id="back_btn">Back</button>
          <button type="button" class="btn-ok" id="next_btn">Next</button>
        </div>
      </main>
    </div>
  </div>
  <script>
    const stepEls = Array.from(document.querySelectorAll(".step"));
    const stepLabels = Array.from(document.querySelectorAll("#stepper li"));
    const backBtn = document.getElementById("back_btn");
    const nextBtn = document.getElementById("next_btn");
    const previewBtn = document.getElementById("preview_btn");
    const applyBtn = document.getElementById("apply_btn");
    const payloadPreview = document.getElementById("payload_preview");
    const out = document.getElementById("out");
    const statusEl = document.getElementById("status");
    let currentStep = 0;

    function val(id) {
      return document.getElementById(id).value.trim();
    }
    function isChecked(id) {
      return document.getElementById(id).checked;
    }
    function intVal(id, fallback) {
      const n = parseInt(val(id), 10);
      return Number.isFinite(n) ? n : fallback;
    }
    function boolFromSelect(id) {
      return val(id) === "true";
    }
    function selectedRadio(name) {
      const found = document.querySelector('input[name="' + name + '"]:checked');
      return found ? found.value : "";
    }
    function csvList(raw) {
      return raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    }

    function buildPayload() {
      const featuresAllowed = csvList(val("license_features_allowed"));
      return {
        metadata: {
          appliance_id: val("appliance_id")
        },
        spec: {
          hsm_mode: selectedRadio("hsm_mode"),
          fde: {
            enabled: isChecked("fde_enabled"),
            luks_device: val("fde_luks_device"),
            passphrase: val("fde_passphrase"),
            unlock_method: selectedRadio("unlock_method"),
            recovery_shares: intVal("fde_recovery_shares", 5),
            recovery_threshold: intVal("fde_recovery_threshold", 3),
            operator_public_key: val("fde_operator_public_key"),
            tang_server: val("fde_tang_server"),
            recovery_passphrase: val("fde_recovery_passphrase")
          },
          fips: {
            mode: selectedRadio("fips_mode")
          },
          network: {
            management: {
              interface: val("mgmt_interface"),
              mode: val("mgmt_mode"),
              ipv4: {
                address: val("mgmt_address"),
                gateway: val("mgmt_gateway"),
                dns: csvList(val("mgmt_dns"))
              },
              ipv6: {
                enabled: boolFromSelect("mgmt_ipv6_enabled"),
                address: val("mgmt_ipv6_address")
              },
              hostname: val("mgmt_hostname"),
              domain: val("mgmt_domain")
            },
            cluster: {
              enabled: isChecked("cluster_enabled"),
              interface: val("cluster_interface"),
              ipv4: {
                address: val("cluster_address")
              },
              mtu: intVal("cluster_mtu", 9000)
            },
            hsm: {
              enabled: isChecked("hsm_enabled"),
              interface: val("hsm_interface"),
              ipv4: {
                address: val("hsm_address")
              }
            },
            tls: {
              mode: val("tls_mode"),
              cert_path: val("tls_cert_path"),
              key_path: val("tls_key_path"),
              ca_path: val("tls_ca_path")
            },
            ntp: {
              servers: csvList(val("ntp_servers"))
            },
            syslog: {
              enabled: isChecked("syslog_enabled"),
              server: val("syslog_server"),
              protocol: val("syslog_protocol")
            },
            firewall: {
              enabled: true,
              allowed_ports: {
                management: [443, 5696, 9443],
                cluster: [2379, 2380, 5432, 4222, 8160],
                hsm: [2300, 2310]
              }
            }
          },
          features: {
            secrets: isChecked("f_secrets"),
            certs: isChecked("f_certs"),
            governance: isChecked("f_governance"),
            cloud_byok: isChecked("f_cloud_byok"),
            hyok_proxy: isChecked("f_hyok_proxy"),
            kmip_server: isChecked("f_kmip_server"),
            qkd_interface: isChecked("f_qkd_interface"),
            ekm_database: isChecked("f_ekm_database"),
            payment_crypto: isChecked("f_payment_crypto"),
            compliance_dashboard: isChecked("f_compliance_dashboard"),
            sbom_cbom: isChecked("f_sbom_cbom"),
            reporting_alerting: isChecked("f_reporting_alerting"),
            ai_llm: isChecked("f_ai_llm"),
            pqc_migration: isChecked("f_pqc_migration"),
            crypto_discovery: isChecked("f_crypto_discovery"),
            mpc_engine: isChecked("f_mpc_engine"),
            data_protection: isChecked("f_data_protection"),
            clustering: isChecked("f_clustering")
          },
          license: {
            key: val("license_key"),
            max_keys: intVal("license_max_keys", 5000000),
            max_tenants: intVal("license_max_tenants", 50),
            features_allowed: featuresAllowed.length > 0 ? featuresAllowed : ["*"]
          },
          admin: {
            username: val("admin_username"),
            password: val("admin_password"),
            email: val("admin_email"),
            force_password_change: isChecked("admin_force_password_change")
          },
          timing: {
            require_reboot: isChecked("require_reboot")
          }
        }
      };
    }

    function setStep(next) {
      if (next < 0 || next >= stepEls.length) return;
      currentStep = next;
      stepEls.forEach((el, i) => el.classList.toggle("active", i === currentStep));
      stepLabels.forEach((el, i) => el.classList.toggle("active", i === currentStep));
      backBtn.disabled = currentStep === 0;
      nextBtn.style.display = currentStep === stepEls.length - 1 ? "none" : "inline-block";
      renderPayloadPreview();
    }

    function renderPayloadPreview() {
      payloadPreview.textContent = JSON.stringify(buildPayload(), null, 2);
    }

    async function submit(path) {
      statusEl.textContent = "working...";
      out.textContent = "";
      try {
        const payload = buildPayload();
        const res = await fetch(path, {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        out.textContent = JSON.stringify(data, null, 2);
        statusEl.textContent = res.ok ? "done" : "failed";
      } catch (err) {
        out.textContent = String(err);
        statusEl.textContent = "failed";
      }
    }

    backBtn.addEventListener("click", () => setStep(currentStep - 1));
    nextBtn.addEventListener("click", () => setStep(currentStep + 1));
    previewBtn.addEventListener("click", () => submit("/api/v1/firstboot/preview"));
    applyBtn.addEventListener("click", () => submit("/api/v1/firstboot/apply"));
    document.querySelectorAll("input,select,textarea").forEach((el) => {
      el.addEventListener("input", renderPayloadPreview);
      el.addEventListener("change", renderPayloadPreview);
    });
    setStep(0);
  </script>
</body>
</html>`
