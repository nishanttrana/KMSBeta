// @ts-nocheck
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Bot, Send, Settings, Shield, Sparkles, Loader2, AlertTriangle } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import {
  getAIConfig,
  updateAIConfig,
  queryAI,
  analyzeIncident,
  recommendPosture,
  explainPolicy,
  checkAIServiceHealth,
  type AIConfig,
  type AIResponse,
} from "../../../lib/ai";
import { logUIAuditEvent } from "../../../lib/auditLogger";
import { B, Btn, Card, Chk, FG, Inp, Section, Sel, Tabs } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  warnings?: string[];
  redactions?: number;
  action?: string;
};

const SUGGESTED_PROMPTS = [
  { label: "Security Posture", prompt: "What is my current security posture and what should I improve?", action: "posture" },
  { label: "Key Inventory", prompt: "Summarize my key inventory and highlight any keys needing rotation", action: "query" },
  { label: "Recent Alerts", prompt: "Analyze recent unresolved alerts and recommend actions", action: "query" },
  { label: "Compliance Gaps", prompt: "What compliance gaps exist and how should I remediate them?", action: "query" },
  { label: "Incident Analysis", prompt: "Help me analyze the most recent security incident", action: "incident" },
  { label: "Policy Review", prompt: "Review my active policies and suggest improvements", action: "query" },
];

const LLM_BACKENDS = [
  { v: "claude", l: "Anthropic Claude" },
  { v: "openai", l: "OpenAI" },
  { v: "azure-openai", l: "Azure OpenAI" },
  { v: "ollama", l: "Ollama (Local)" },
  { v: "vllm", l: "vLLM" },
  { v: "llamacpp", l: "llama.cpp" },
];

type AITabProps = {
  session: AuthSession | null;
  onToast?: (message: string) => void;
};

export const AITab = ({ session, onToast }: AITabProps) => {
  const [subTab, setSubTab] = useState("Chat");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [config, setConfig] = useState<AIConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(false);
  const [configSaving, setConfigSaving] = useState(false);
  const [serviceAvailable, setServiceAvailable] = useState<boolean | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Config form state
  const [cfgBackend, setCfgBackend] = useState("openai");
  const [cfgEndpoint, setCfgEndpoint] = useState("");
  const [cfgModel, setCfgModel] = useState("");
  const [cfgApiKey, setCfgApiKey] = useState("");
  const [cfgMaxTokens, setCfgMaxTokens] = useState(4096);
  const [cfgTemp, setCfgTemp] = useState(0.7);
  const [cfgCtxKeys, setCfgCtxKeys] = useState(true);
  const [cfgCtxPolicies, setCfgCtxPolicies] = useState(true);
  const [cfgCtxAudit, setCfgCtxAudit] = useState(true);
  const [cfgCtxPosture, setCfgCtxPosture] = useState(true);
  const [cfgCtxAlerts, setCfgCtxAlerts] = useState(true);
  const [cfgRedactionFields, setCfgRedactionFields] = useState("encrypted_material,wrapped_dek,pwd_hash");

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => { scrollToBottom(); }, [messages]);

  // Health check
  useEffect(() => {
    if (!session?.token) { setServiceAvailable(null); return; }
    let cancelled = false;
    const check = async () => {
      const ok = await checkAIServiceHealth(session);
      if (!cancelled) setServiceAvailable(ok);
    };
    void check();
    const interval = setInterval(check, 30000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [session]);

  // Load config
  const loadConfig = useCallback(async () => {
    if (!session?.token) return;
    setConfigLoading(true);
    try {
      const cfg = await getAIConfig(session);
      setConfig(cfg);
      setCfgBackend(cfg.backend || "openai");
      setCfgEndpoint(cfg.endpoint || "");
      setCfgModel(cfg.model || "");
      setCfgApiKey(cfg.api_key_secret || "");
      setCfgMaxTokens(cfg.max_context_tokens || 4096);
      setCfgTemp(cfg.temperature || 0.7);
      setCfgCtxKeys(cfg.context_sources?.keys?.enabled ?? true);
      setCfgCtxPolicies(cfg.context_sources?.policies?.enabled ?? true);
      setCfgCtxAudit(cfg.context_sources?.audit?.enabled ?? true);
      setCfgCtxPosture(cfg.context_sources?.posture?.enabled ?? true);
      setCfgCtxAlerts(cfg.context_sources?.alerts?.enabled ?? true);
      setCfgRedactionFields((cfg.redaction_fields || []).join(","));
    } catch (err) {
      onToast?.(`AI config load failed: ${errMsg(err)}`);
    } finally {
      setConfigLoading(false);
    }
  }, [onToast, session]);

  useEffect(() => {
    if (subTab === "Configuration") void loadConfig();
  }, [subTab, loadConfig]);

  const saveConfig = useCallback(async () => {
    if (!session?.token) return;
    setConfigSaving(true);
    try {
      const updated = await updateAIConfig(session, {
        backend: cfgBackend,
        endpoint: cfgEndpoint,
        model: cfgModel,
        api_key_secret: cfgApiKey,
        max_context_tokens: cfgMaxTokens,
        temperature: cfgTemp,
        context_sources: {
          keys: { enabled: cfgCtxKeys, limit: 100, fields: ["id", "name", "algorithm", "state", "created_at"] },
          policies: { enabled: cfgCtxPolicies, all: true, limit: 50 },
          audit: { enabled: cfgCtxAudit, last_hours: 24, limit: 200 },
          posture: { enabled: cfgCtxPosture, current: true },
          alerts: { enabled: cfgCtxAlerts, unresolved: true, limit: 50 },
        },
        redaction_fields: cfgRedactionFields.split(",").map((f) => f.trim()).filter(Boolean),
      });
      setConfig(updated);
      onToast?.("AI configuration saved.");
      void logUIAuditEvent(session, { action: "ai.config.updated", target_type: "ai_service", target_id: "config" });
    } catch (err) {
      onToast?.(`AI config save failed: ${errMsg(err)}`);
    } finally {
      setConfigSaving(false);
    }
  }, [cfgApiKey, cfgBackend, cfgCtxAlerts, cfgCtxAudit, cfgCtxKeys, cfgCtxPolicies, cfgCtxPosture, cfgEndpoint, cfgMaxTokens, cfgModel, cfgRedactionFields, cfgTemp, onToast, session]);

  const handleSend = useCallback(async (text?: string, action?: string) => {
    const q = (text || input).trim();
    if (!q || !session?.token) return;
    setLoading(true);
    setInput("");
    const userMsg: ChatMessage = { role: "user", content: q, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMsg]);
    try {
      void logUIAuditEvent(session, { action: "ai.query.submitted", target_type: "ai_service", target_id: "chat", details: { query_length: q.length } });
      let result: AIResponse;
      if (action === "incident") {
        result = await analyzeIncident(session, { title: "Dashboard Query", description: q });
      } else if (action === "posture") {
        result = await recommendPosture(session, q);
      } else {
        result = await queryAI(session, q, false);
      }
      const assistantMsg: ChatMessage = {
        role: "assistant",
        content: result.answer || "No response from AI service.",
        timestamp: result.generated_at || new Date().toISOString(),
        warnings: result.warnings,
        redactions: result.redactions_applied,
        action: result.action,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      const errorMsg: ChatMessage = {
        role: "assistant",
        content: `Error: ${errMsg(err)}`,
        timestamp: new Date().toISOString(),
        warnings: ["AI service request failed"],
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  }, [input, session]);

  const statusDot = serviceAvailable === true ? C.green : serviceAvailable === false ? C.red : C.dim;
  const statusText = serviceAvailable === true ? "AI Service Available" : serviceAvailable === false ? "AI Service Unavailable" : "Checking...";

  return (
    <div>
      {/* Header bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: statusDot }} />
            <span style={{ fontSize: 10, color: C.dim }}>{statusText}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 6, background: `${C.green}18`, border: `1px solid ${C.green}33` }}>
            <Shield size={12} color={C.green} />
            <span style={{ fontSize: 10, color: C.green, fontWeight: 600 }}>Governance Enforced</span>
          </div>
        </div>
        <Tabs tabs={["Chat", "Configuration"]} active={subTab} set={setSubTab} />
      </div>

      {subTab === "Chat" && (
        <div>
          {/* Suggested prompts */}
          {messages.length === 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 8 }}>Suggested prompts</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(200px,1fr))", gap: 8 }}>
                {SUGGESTED_PROMPTS.map((sp) => (
                  <Card
                    key={sp.label}
                    style={{ padding: "10px 14px", cursor: "pointer", transition: "border-color .15s" }}
                    onClick={() => void handleSend(sp.prompt, sp.action)}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                      <Sparkles size={12} color={C.accent} />
                      <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{sp.label}</span>
                    </div>
                    <div style={{ fontSize: 10, color: C.dim }}>{sp.prompt}</div>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {/* Chat messages */}
          <div style={{ maxHeight: 480, overflowY: "auto", marginBottom: 12, display: "flex", flexDirection: "column", gap: 8 }}>
            {messages.map((msg, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                }}
              >
                <div
                  style={{
                    maxWidth: "80%",
                    padding: "10px 14px",
                    borderRadius: 10,
                    background: msg.role === "user" ? `${C.accent}22` : C.surface,
                    border: `1px solid ${msg.role === "user" ? C.accent + "44" : C.border}`,
                  }}
                >
                  <div style={{ fontSize: 9, color: C.muted, marginBottom: 4 }}>
                    {msg.role === "user" ? "You" : "AI Assistant"} · {new Date(msg.timestamp).toLocaleTimeString()}
                  </div>
                  <div style={{ fontSize: 12, color: C.text, lineHeight: 1.5, whiteSpace: "pre-wrap" }}>
                    {msg.content}
                  </div>
                  {msg.warnings && msg.warnings.length > 0 && (
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 6 }}>
                      {msg.warnings.map((w, wi) => (
                        <div key={wi} style={{ display: "flex", alignItems: "center", gap: 4, padding: "2px 6px", borderRadius: 4, background: `${C.amber}18`, fontSize: 9, color: C.amber }}>
                          <AlertTriangle size={10} /> {w}
                        </div>
                      ))}
                    </div>
                  )}
                  {msg.redactions != null && msg.redactions > 0 && (
                    <div style={{ fontSize: 9, color: C.muted, marginTop: 4 }}>
                      {msg.redactions} field{msg.redactions > 1 ? "s" : ""} redacted for security
                    </div>
                  )}
                </div>
              </div>
            ))}
            {loading && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: 10 }}>
                <Loader2 size={14} className="vecta-spin" color={C.accent} />
                <span style={{ fontSize: 11, color: C.dim }}>AI is thinking...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input area */}
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <div style={{ flex: 1, position: "relative" }}>
              <input
                style={{
                  width: "100%",
                  padding: "10px 14px",
                  paddingRight: 40,
                  borderRadius: 8,
                  border: `1px solid ${C.border}`,
                  background: C.surface,
                  color: C.text,
                  fontSize: 12,
                  outline: "none",
                }}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void handleSend(); } }}
                placeholder="Ask about your KMS configuration, keys, policies..."
                disabled={loading || !session?.token}
              />
            </div>
            <Btn small primary onClick={() => void handleSend()} disabled={loading || !input.trim() || !session?.token}>
              <Send size={14} /> Send
            </Btn>
          </div>

          {/* Governance notice */}
          <div style={{ fontSize: 9, color: C.muted, marginTop: 8, textAlign: "center" }}>
            AI respects KMS governance rules — cannot bypass approval policies, quorum requirements, or RBAC rules. Sensitive fields are automatically redacted before sending to the LLM provider.
          </div>
        </div>
      )}

      {subTab === "Configuration" && (
        <Section title="AI Service Configuration" actions={<div style={{ display: "flex", gap: 8 }}>
          <Btn small onClick={() => void loadConfig()} disabled={configLoading}>{configLoading ? "Loading..." : "Refresh"}</Btn>
          <Btn small primary onClick={() => void saveConfig()} disabled={configSaving}>{configSaving ? "Saving..." : "Save"}</Btn>
        </div>}>
          <Card style={{ padding: 10, borderRadius: 8, marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>LLM Provider</div>
            <Row2>
              <FG label="Backend">
                <Sel value={cfgBackend} onChange={(e: any) => setCfgBackend(e.target.value)}>
                  {LLM_BACKENDS.map((b) => <option key={b.v} value={b.v}>{b.l}</option>)}
                </Sel>
              </FG>
              <FG label="Model"><Inp value={cfgModel} onChange={(e: any) => setCfgModel(e.target.value)} placeholder="gpt-4, claude-3-opus, etc." /></FG>
            </Row2>
            <Row2>
              <FG label="Endpoint URL"><Inp value={cfgEndpoint} onChange={(e: any) => setCfgEndpoint(e.target.value)} placeholder="https://api.openai.com/v1" /></FG>
              <FG label="API Key / Secret Reference"><Inp type="password" value={cfgApiKey} onChange={(e: any) => setCfgApiKey(e.target.value)} placeholder="sk-... or vault secret ID" /></FG>
            </Row2>
            <Row2>
              <FG label="Max Context Tokens"><Inp type="number" value={String(cfgMaxTokens)} onChange={(e: any) => setCfgMaxTokens(Number(e.target.value || 4096))} /></FG>
              <FG label={`Temperature (${cfgTemp})`}>
                <input
                  type="range"
                  min="0"
                  max="2"
                  step="0.1"
                  value={cfgTemp}
                  onChange={(e) => setCfgTemp(Number(e.target.value))}
                  style={{ width: "100%" }}
                />
              </FG>
            </Row2>
          </Card>

          <Card style={{ padding: 10, borderRadius: 8, marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>Context Sources</div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>Select which KMS data the AI can access when answering queries.</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(160px,1fr))", gap: 8 }}>
              <Chk label="Key Inventory" checked={cfgCtxKeys} onChange={() => setCfgCtxKeys(!cfgCtxKeys)} />
              <Chk label="Governance Policies" checked={cfgCtxPolicies} onChange={() => setCfgCtxPolicies(!cfgCtxPolicies)} />
              <Chk label="Audit Events" checked={cfgCtxAudit} onChange={() => setCfgCtxAudit(!cfgCtxAudit)} />
              <Chk label="Security Posture" checked={cfgCtxPosture} onChange={() => setCfgCtxPosture(!cfgCtxPosture)} />
              <Chk label="Active Alerts" checked={cfgCtxAlerts} onChange={() => setCfgCtxAlerts(!cfgCtxAlerts)} />
            </div>
          </Card>

          <Card style={{ padding: 10, borderRadius: 8, marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>Security & Redaction</div>
            <FG label="Redaction Fields (comma-separated)">
              <Inp value={cfgRedactionFields} onChange={(e: any) => setCfgRedactionFields(e.target.value)} placeholder="encrypted_material,wrapped_dek,pwd_hash" />
            </FG>
            <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>These fields will be stripped from any data sent to the LLM backend. Key material and secrets are always redacted regardless of this setting.</div>
          </Card>

          <Card style={{ padding: 8, borderRadius: 8, background: `${C.green}11`, border: `1px solid ${C.green}33` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <Shield size={14} color={C.green} />
              <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>Governance Enforcement Active</span>
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>
              All AI operations are subject to KMS governance rules. The AI service cannot bypass approval policies, quorum requirements, or RBAC controls. Every query generates an audit trail.
              Customers can integrate their own LLM by selecting the appropriate backend and providing their endpoint URL and credentials.
            </div>
          </Card>
        </Section>
      )}
    </div>
  );
};
