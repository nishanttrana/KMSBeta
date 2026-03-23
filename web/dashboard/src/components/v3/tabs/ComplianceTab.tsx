// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import {
  B,
  Btn,
  Card,
  Chk,
  FG,
  Inp,
  Row2,
  Section,
  Sel,
  Stat,
  usePromptDialog
} from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  AreaChart,
  Area,
  BarChart,
  Bar as RBar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  RadialBarChart,
  RadialBar,
  PieChart,
  Pie,
  Cell,
  Legend
} from "recharts";
import {
  deleteComplianceTemplate,
  getComplianceAssessment,
  getComplianceAssessmentDelta,
  getComplianceAssessmentSchedule,
  getCompliancePostureBreakdown,
  getComplianceKeyHygiene,
  getComplianceFrameworkGaps,
  getComplianceAuditAnomalies,
  listComplianceAssessmentHistory,
  listComplianceFrameworkCatalog,
  listComplianceTemplates,
  runComplianceAssessment,
  updateComplianceAssessmentSchedule,
  upsertComplianceTemplate
} from "../../../lib/compliance";
import {
  createReportingScheduledReport,
  deleteReportingReportJob,
  downloadReportingReport,
  generateReportingReport,
  getReportingAlertStats,
  getReportingMTTD,
  getReportingMTTR,
  getReportingReportJob,
  getReportingTopSources,
  listReportingReportJobs,
  listReportingReportTemplates,
  listReportingScheduledReports
} from "../../../lib/reporting";
import { getAuthRESTClientSecuritySummary, getAuthSCIMSummary } from "../../../lib/authAdmin";
import { getAutokeySummary } from "../../../lib/autokey";
import { getCertRenewalSummary } from "../../../lib/certs";
import { getKeyAccessSummary } from "../../../lib/keyaccess";
import { getMPCOverview } from "../../../lib/mpc";
import { getPQCInventory } from "../../../lib/pqc";
import { getSigningSummary } from "../../../lib/signing";
import { getWorkloadIdentitySummary } from "../../../lib/workloadIdentity";

/* ── Shared chart tooltip ── */
const ChartTip = ({ children, style }: any) => (
  <div style={{ background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "8px 12px", fontSize: 10, color: C.text, boxShadow: "0 4px 20px rgba(0,0,0,.5)", ...style }}>
    {children}
  </div>
);

function shortDate(value: any) {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return `${dt.getMonth() + 1}/${dt.getDate()}`;
}

function isRealAssessment(item: any) {
  return Boolean(item && typeof item === "object" && String(item?.id || "").trim() && !/^auto$/i.test(String(item?.trigger || "").trim()));
}

export const ComplianceTab = ({ session, onToast }: any) => {
  const promptDialog = usePromptDialog();
  const [assessment, setAssessment] = useState<any>(null);
  const [assessmentDelta, setAssessmentDelta] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [schedule, setSchedule] = useState<any>({ enabled: false, frequency: "daily" });
  const [templates, setTemplates] = useState<any[]>([]);
  const [frameworkCatalog, setFrameworkCatalog] = useState<any[]>([]);
  const [selectedTemplateID, setSelectedTemplateID] = useState("default");
  const [templateDraft, setTemplateDraft] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [savingTemplate, setSavingTemplate] = useState(false);
  const [deletingTemplate, setDeletingTemplate] = useState(false);
  const [view, setView] = useState("assessment");

  /* ── NEW: compliance functional state ── */
  const [postureBreakdown, setPostureBreakdown] = useState<any>(null);
  const [keyHygiene, setKeyHygiene] = useState<any>(null);
  const [frameworkGaps, setFrameworkGaps] = useState<any[]>([]);
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [pqcInventory, setPqcInventory] = useState<any>(null);
  const [autokeySummary, setAutokeySummary] = useState<any>(null);
  const [workloadSummary, setWorkloadSummary] = useState<any>(null);
  const [scimSummary, setScimSummary] = useState<any>(null);
  const [restClientSecurity, setRestClientSecurity] = useState<any>(null);
  const [certRenewalSummary, setCertRenewalSummary] = useState<any>(null);
  const [keyAccessSummary, setKeyAccessSummary] = useState<any>(null);
  const [signingSummary, setSigningSummary] = useState<any>(null);
  const [mpcOverview, setMpcOverview] = useState<any>(null);

  /* ── Reporting state ── */
  const [reportTemplates, setReportTemplates] = useState<any[]>([]);
  const [reportJobs, setReportJobs] = useState<any[]>([]);
  const [scheduledReports, setScheduledReports] = useState<any[]>([]);
  const [reportForm, setReportForm] = useState<any>({ template_id: "", format: "pdf" });
  const [scheduleForm, setScheduleForm] = useState<any>({ name: "weekly-compliance", template_id: "", format: "pdf", schedule: "weekly", recipients: "" });
  const [reportBusy, setReportBusy] = useState(false);

  /* ── NEW: alert stats state ── */
  const [alertStats, setAlertStats] = useState<any>(null);
  const [mttd, setMttd] = useState<any>(null);
  const [mttr, setMttr] = useState<any>(null);
  const [topSources, setTopSources] = useState<any>(null);

  /* ── Crypto Inventory (KeyInsight) state ── */
  const [inventoryKeys, setInventoryKeys] = useState<any[]>([]);
  const [inventoryCerts, setInventoryCerts] = useState<any[]>([]);
  const [inventoryLoading, setInventoryLoading] = useState(false);
  const [inventorySearch, setInventorySearch] = useState("");
  const [inventoryFilter, setInventoryFilter] = useState("all");

  /* ── Template seed logic (unchanged) ── */
  const frameworkSeed = useMemo(() => {
    const list = Array.isArray(frameworkCatalog) ? frameworkCatalog : [];
    return list
      .map((fw: any) => ({
        framework_id: String(fw?.id || "").trim(),
        label: String(`${String(fw?.name || fw?.id || "").trim()} ${String(fw?.version || "").trim()}`).trim(),
        enabled: true,
        weight: 1,
        controls: (Array.isArray(fw?.controls) ? fw.controls : [])
          .map((ctrl: any) => ({
            id: String(ctrl?.id || "").trim(),
            title: String(ctrl?.title || "").trim(),
            category: String(ctrl?.category || "").trim(),
            requirement: String(ctrl?.requirement || "").trim(),
            enabled: true,
            weight: 1,
            threshold: 80
          }))
          .filter((ctrl: any) => Boolean(ctrl.id))
      }))
      .filter((fw: any) => Boolean(fw.framework_id));
  }, [frameworkCatalog]);

  const buildTemplateDraft = (input: any = {}) => {
    const numOr = (value: any, fallback: number) => { const n = Number(value); return Number.isFinite(n) ? n : fallback; };
    const sourceFrameworks = Array.isArray(input?.frameworks) ? input.frameworks : [];
    const sourceByID: any = {};
    sourceFrameworks.forEach((fw: any) => { const id = String(fw?.framework_id || "").trim(); if (id) sourceByID[id] = fw; });
    const mergedFrameworks = frameworkSeed.map((base: any) => {
      const incoming = sourceByID[base.framework_id] || {};
      const controlByID: any = {};
      (Array.isArray(incoming?.controls) ? incoming.controls : []).forEach((ctrl: any) => { const id = String(ctrl?.id || "").trim(); if (id) controlByID[id] = ctrl; });
      const mergedControls = (Array.isArray(base?.controls) ? base.controls : []).map((ctrl: any) => {
        const incomingCtrl = controlByID[ctrl.id] || {};
        return { ...ctrl, ...incomingCtrl, id: ctrl.id, title: String(incomingCtrl?.title || ctrl.title || ""), category: String(incomingCtrl?.category || ctrl.category || ""), requirement: String(incomingCtrl?.requirement || ctrl.requirement || ""), enabled: incomingCtrl?.enabled === undefined ? Boolean(ctrl.enabled) : Boolean(incomingCtrl.enabled), weight: Math.max(0.1, numOr(incomingCtrl?.weight, ctrl.weight || 1)), threshold: Math.max(1, Math.min(100, Math.round(numOr(incomingCtrl?.threshold, ctrl.threshold || 80)))) };
      });
      return { ...base, ...incoming, framework_id: base.framework_id, label: String(incoming?.label || base.label || base.framework_id), enabled: incoming?.enabled === undefined ? Boolean(base.enabled) : Boolean(incoming.enabled), weight: Math.max(0.1, numOr(incoming?.weight, base.weight || 1)), controls: mergedControls };
    });
    return { id: String(input?.id || ""), tenant_id: String(input?.tenant_id || session?.tenantId || ""), name: String(input?.name || "Custom Compliance Template"), description: String(input?.description || ""), enabled: input?.enabled === undefined ? true : Boolean(input.enabled), frameworks: mergedFrameworks };
  };

  /* ── Data loaders ── */
  const loadTemplates = async () => {
    if (!session?.token) { setTemplates([]); setFrameworkCatalog([]); return { templates: [], frameworks: [] }; }
    try {
      const [tplOut, catalogOut] = await Promise.all([listComplianceTemplates(session), listComplianceFrameworkCatalog(session)]);
      const nextTemplates = Array.isArray(tplOut) ? tplOut : [];
      const nextCatalog = Array.isArray(catalogOut) ? catalogOut : [];
      setTemplates(nextTemplates);
      setFrameworkCatalog(nextCatalog);
      return { templates: nextTemplates, frameworks: nextCatalog };
    } catch (error) { onToast?.(`Compliance templates load failed: ${errMsg(error)}`); return { templates: [], frameworks: [] }; }
  };

  const loadAssessment = async (opts: any = {}) => {
    if (!session?.token) { setAssessment(null); setAssessmentDelta(null); setHistory([]); setSchedule({ enabled: false, frequency: "daily" }); setPostureBreakdown(null); setKeyHygiene(null); setFrameworkGaps([]); setAnomalies([]); setPqcInventory(null); setAutokeySummary(null); setWorkloadSummary(null); setScimSummary(null); setRestClientSecurity(null); setCertRenewalSummary(null); setKeyAccessSummary(null); setSigningSummary(null); setMpcOverview(null); setMttr(null); setMttd(null); return; }
    if (!opts?.silent) setLoading(true);
    try {
      const payload = await loadTemplates();
      const candidateTemplateID = String((opts?.templateId ?? selectedTemplateID) || "default");
      const hasTemplate = candidateTemplateID === "default" || payload.templates.some((item: any) => String(item?.id || "") === candidateTemplateID);
      const effectiveTemplateID = hasTemplate ? candidateTemplateID : "default";
      if (effectiveTemplateID !== selectedTemplateID) setSelectedTemplateID(effectiveTemplateID);

      const [assessOut, scheduleOut, historyOut, autokeySummaryOut, workloadSummaryOut, scimSummaryOut, restClientSecurityOut, certRenewalSummaryOut, keyAccessSummaryOut, signingSummaryOut, mpcOverviewOut] = await Promise.all([
        getComplianceAssessment(session, effectiveTemplateID),
        getComplianceAssessmentSchedule(session),
        listComplianceAssessmentHistory(session, 20, effectiveTemplateID),
        getAutokeySummary(session).catch(() => null),
        getWorkloadIdentitySummary(session).catch(() => null),
        getAuthSCIMSummary(session).catch(() => null),
        getAuthRESTClientSecuritySummary(session).catch(() => null),
        getCertRenewalSummary(session).catch(() => null),
        getKeyAccessSummary(session).catch(() => null),
        getSigningSummary(session).catch(() => null),
        getMPCOverview(session).catch(() => null)
      ]);

      const visibleHistory = (Array.isArray(historyOut) ? historyOut : []).filter((item: any) => isRealAssessment(item));
      const visibleAssessment = isRealAssessment(assessOut) ? assessOut : (visibleHistory[0] || null);
      setAssessment(visibleAssessment);
      setSchedule(scheduleOut || { enabled: false, frequency: "daily" });
      setHistory(visibleHistory);
      setAutokeySummary(autokeySummaryOut || null);
      setWorkloadSummary(workloadSummaryOut || null);
      setScimSummary(scimSummaryOut || null);
      setRestClientSecurity(restClientSecurityOut || null);
      setCertRenewalSummary(certRenewalSummaryOut || null);
      setKeyAccessSummary(keyAccessSummaryOut || null);
      setSigningSummary(signingSummaryOut || null);
      setMpcOverview(mpcOverviewOut || null);
      const hasAssessment = Boolean(visibleAssessment) || visibleHistory.length > 0;
      if (hasAssessment) {
        const [breakdownOut, hygieneOut, anomalyOut, deltaOut, pqcInventoryOut, mttrOut, mttdOut] = await Promise.all([
          getCompliancePostureBreakdown(session).catch(() => null),
          getComplianceKeyHygiene(session).catch(() => null),
          getComplianceAuditAnomalies(session).catch(() => []),
          getComplianceAssessmentDelta(session, effectiveTemplateID).catch(() => null),
          getPQCInventory(session).catch(() => null),
          getReportingMTTR(session).catch(() => null),
          getReportingMTTD(session).catch(() => null)
        ]);
        setPostureBreakdown(breakdownOut || null);
        setKeyHygiene(hygieneOut || null);
        setAnomalies(Array.isArray(anomalyOut) ? anomalyOut : []);
        setAssessmentDelta(deltaOut || null);
        setPqcInventory(pqcInventoryOut || null);
        setMttr(mttrOut || null);
        setMttd(mttdOut || null);

        /* load gaps for first framework with a score */
        const fwScores = assessOut?.framework_scores || {};
        const firstFW = Object.keys(fwScores)[0];
        if (firstFW) {
          const gaps = await getComplianceFrameworkGaps(session, firstFW).catch(() => []);
          setFrameworkGaps(Array.isArray(gaps) ? gaps : []);
        } else {
          setFrameworkGaps([]);
        }
      } else {
        setPostureBreakdown(null);
        setKeyHygiene(null);
        setFrameworkGaps([]);
        setAnomalies([]);
        setAssessmentDelta(null);
        setPqcInventory(null);
        setAutokeySummary(autokeySummaryOut || null);
        setWorkloadSummary(workloadSummaryOut || null);
        setRestClientSecurity(restClientSecurityOut || null);
        setCertRenewalSummary(certRenewalSummaryOut || null);
        setKeyAccessSummary(keyAccessSummaryOut || null);
        setSigningSummary(signingSummaryOut || null);
        setMpcOverview(mpcOverviewOut || null);
        setMttr(null);
        setMttd(null);
      }

      if (effectiveTemplateID === "default") { setTemplateDraft(null); }
      else {
        const selected = payload.templates.find((item: any) => String(item?.id || "") === effectiveTemplateID);
        setTemplateDraft(selected ? buildTemplateDraft(selected) : null);
      }
    } catch (error) { onToast?.(`Compliance assessment load failed: ${errMsg(error)}`); }
    finally { if (!opts?.silent) setLoading(false); }
  };

  const loadReporting = async () => {
    if (!session?.token) { setReportTemplates([]); setReportJobs([]); setScheduledReports([]); setAlertStats(null); setMttr(null); setMttd(null); setTopSources(null); return; }
    try {
      const [templatesOut, jobsOut, scheduledOut, statsOut, mttrOut, mttdOut, topOut] = await Promise.all([
        listReportingReportTemplates(session),
        listReportingReportJobs(session, 40, 0),
        listReportingScheduledReports(session),
        getReportingAlertStats(session).catch(() => null),
        getReportingMTTR(session).catch(() => null),
        getReportingMTTD(session).catch(() => null),
        getReportingTopSources(session).catch(() => null)
      ]);
      const tpls = Array.isArray(templatesOut) ? templatesOut : [];
      setReportTemplates(tpls);
      setReportJobs(Array.isArray(jobsOut) ? jobsOut : []);
      setScheduledReports(Array.isArray(scheduledOut) ? scheduledOut : []);
      setAlertStats(statsOut || null);
      setMttr(mttrOut || null);
      setMttd(mttdOut || null);
      setTopSources(topOut || null);
      if (!reportForm.template_id && tpls.length) setReportForm((prev: any) => ({ ...prev, template_id: String(tpls[0]?.id || "") }));
      if (!scheduleForm.template_id && tpls.length) setScheduleForm((prev: any) => ({ ...prev, template_id: String(tpls[0]?.id || "") }));
    } catch (error) { onToast?.(`Reporting load failed: ${errMsg(error)}`); }
  };

  const loadInventory = async () => {
    if (!session?.token) { setInventoryKeys([]); setInventoryCerts([]); return; }
    setInventoryLoading(true);
    try {
      const base = String(session?.baseUrl || "").replace(/\/+$/, "");
      const headers: any = { Authorization: `Bearer ${session.token}`, "X-Tenant-Id": String(session.tenantId || "root") };
      const [keysRes, certsRes] = await Promise.all([
        fetch(`${base}/svc/v1/keys?limit=500`, { headers }).then((r) => r.json()).catch(() => []),
        fetch(`${base}/svc/certs/certificates?limit=500`, { headers }).then((r) => r.json()).catch(() => [])
      ]);
      setInventoryKeys(Array.isArray(keysRes) ? keysRes : Array.isArray(keysRes?.keys) ? keysRes.keys : []);
      setInventoryCerts(Array.isArray(certsRes) ? certsRes : Array.isArray(certsRes?.certificates) ? certsRes.certificates : []);
    } catch (error) { onToast?.(`Inventory load failed: ${errMsg(error)}`); }
    finally { setInventoryLoading(false); }
  };

  useEffect(() => { void loadAssessment({ templateId: "default" }); }, [session?.token, session?.tenantId]);
  useEffect(() => { if (view === "reporting") void loadReporting(); }, [view, session?.token, session?.tenantId]);
  useEffect(() => { if (view === "inventory") void loadInventory(); }, [view, session?.token, session?.tenantId]);

  /* ── Actions (unchanged) ── */
  const runNow = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    setRunning(true);
    try {
      await runComplianceAssessment(session, { templateId: selectedTemplateID, recompute: true });
      await loadAssessment({ silent: true, templateId: selectedTemplateID });
      onToast?.("Compliance assessment completed.");
    } catch (error) { onToast?.(`Assessment run failed: ${errMsg(error)}`); }
    finally { setRunning(false); }
  };

  const saveSchedule = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    setSavingSchedule(true);
    try {
      const out = await updateComplianceAssessmentSchedule(session, { enabled: Boolean(schedule?.enabled), frequency: String(schedule?.frequency || "daily") as any });
      setSchedule(out || schedule);
      onToast?.("Assessment schedule updated.");
    } catch (error) { onToast?.(`Schedule update failed: ${errMsg(error)}`); }
    finally { setSavingSchedule(false); }
  };

  const createTemplate = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    const nameInput = await promptDialog.prompt({ title: "Create Compliance Template", message: "Provide a name for the custom compliance template.", placeholder: "Template name", confirmLabel: "Create", cancelLabel: "Cancel", validate: (value: string) => (String(value || "").trim() ? "" : "Template name is required.") });
    const name = String(nameInput || "").trim();
    if (!name) return;
    setSavingTemplate(true);
    try {
      const out = await upsertComplianceTemplate(session, { name, description: "", enabled: true, frameworks: Array.isArray(templateDraft?.frameworks) && templateDraft.frameworks.length ? templateDraft.frameworks : frameworkSeed } as any);
      const nextID = String(out?.id || "").trim();
      if (nextID) setSelectedTemplateID(nextID);
      await loadAssessment({ silent: true, templateId: nextID || "default" });
      onToast?.("Compliance template created.");
    } catch (error) { onToast?.(`Template create failed: ${errMsg(error)}`); }
    finally { setSavingTemplate(false); }
  };

  const saveTemplate = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    if (selectedTemplateID === "default") { onToast?.("Built-in template is read-only. Create a custom template first."); return; }
    if (!templateDraft) { onToast?.("No template selected."); return; }
    setSavingTemplate(true);
    try {
      const out = await upsertComplianceTemplate(session, { id: selectedTemplateID, name: String(templateDraft?.name || "").trim(), description: String(templateDraft?.description || "").trim(), enabled: Boolean(templateDraft?.enabled), frameworks: Array.isArray(templateDraft?.frameworks) ? templateDraft.frameworks : [] } as any);
      setTemplateDraft(buildTemplateDraft(out || templateDraft));
      await loadAssessment({ silent: true, templateId: selectedTemplateID });
      onToast?.("Compliance template saved.");
    } catch (error) { onToast?.(`Template save failed: ${errMsg(error)}`); }
    finally { setSavingTemplate(false); }
  };

  const removeTemplate = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    if (selectedTemplateID === "default") { onToast?.("Built-in template cannot be deleted."); return; }
    const ok = await promptDialog.confirm({ title: "Delete Template", message: "Delete selected compliance template?", confirmLabel: "Delete", cancelLabel: "Cancel", danger: true });
    if (!ok) return;
    setDeletingTemplate(true);
    try {
      await deleteComplianceTemplate(session, selectedTemplateID);
      setSelectedTemplateID("default");
      setTemplateDraft(null);
      await loadAssessment({ silent: true, templateId: "default" });
      onToast?.("Compliance template deleted.");
    } catch (error) { onToast?.(`Template delete failed: ${errMsg(error)}`); }
    finally { setDeletingTemplate(false); }
  };

  const patchFramework = (frameworkID: string, patch: any) => {
    setTemplateDraft((prev: any) => {
      if (!prev) return prev;
      const frameworks = (Array.isArray(prev?.frameworks) ? prev.frameworks : []).map((fw: any) => String(fw?.framework_id || "") !== frameworkID ? fw : { ...fw, ...patch });
      return { ...prev, frameworks };
    });
  };

  const patchControl = (frameworkID: string, controlID: string, patch: any) => {
    setTemplateDraft((prev: any) => {
      if (!prev) return prev;
      const frameworks = (Array.isArray(prev?.frameworks) ? prev.frameworks : []).map((fw: any) => {
        if (String(fw?.framework_id || "") !== frameworkID) return fw;
        const controls = (Array.isArray(fw?.controls) ? fw.controls : []).map((ctrl: any) => String(ctrl?.id || "") !== controlID ? ctrl : { ...ctrl, ...patch });
        return { ...fw, controls };
      });
      return { ...prev, frameworks };
    });
  };

  const triggerReportNow = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    if (!String(reportForm?.template_id || "").trim()) { onToast?.("Select a report template."); return; }
    setReportBusy(true);
    try {
      const created = await generateReportingReport(session, { template_id: String(reportForm.template_id || "").trim(), format: String(reportForm.format || "pdf").trim().toLowerCase(), requested_by: String(session?.username || "dashboard") });
      const stable = await getReportingReportJob(session, String(created?.id || ""));
      onToast?.(`Report queued: ${String(stable?.id || created?.id || "").slice(0, 12)}...`);
      await loadReporting();
    } catch (error) { onToast?.(`Report generation failed: ${errMsg(error)}`); }
    finally { setReportBusy(false); }
  };

  const exportEvidencePack = async (format = "pdf") => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    setReportBusy(true);
    try {
      const created = await generateReportingReport(session, {
        template_id: "evidence_pack",
        format,
        requested_by: String(session?.username || "dashboard")
      });
      const stable = await getReportingReportJob(session, String(created?.id || ""));
      onToast?.(`Evidence pack queued: ${String(stable?.id || created?.id || "").slice(0, 12)}...`);
      await loadReporting();
    } catch (error) {
      onToast?.(`Evidence pack export failed: ${errMsg(error)}`);
    } finally {
      setReportBusy(false);
    }
  };

  const downloadJob = async (job: any) => {
    if (!session?.token) return;
    try {
      const out = await downloadReportingReport(session, String(job?.id || ""));
      const raw = String(out?.content || "");
      const binary = atob(raw);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      const blob = new Blob([bytes], { type: String(out?.content_type || "application/octet-stream") });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${String(job?.template_id || "report")}-${String(job?.id || "job")}.${String(job?.format || "bin").toLowerCase()}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (error) { onToast?.(`Download failed: ${errMsg(error)}`); }
  };

  const deleteJob = async (job: any) => {
    if (!session?.token) return;
    const ok = await promptDialog.confirm({ title: "Delete Report", message: `Delete report job ${String(job?.id || "").slice(0, 16)}?`, confirmLabel: "Delete", cancelLabel: "Cancel", danger: true });
    if (!ok) return;
    try { await deleteReportingReportJob(session, String(job?.id || "")); onToast?.("Report deleted."); await loadReporting(); }
    catch (error) { onToast?.(`Delete report failed: ${errMsg(error)}`); }
  };

  const createScheduleReport = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    if (!String(scheduleForm?.template_id || "").trim()) { onToast?.("Select a template for schedule."); return; }
    setReportBusy(true);
    try {
      await createReportingScheduledReport(session, { name: String(scheduleForm?.name || "weekly-compliance").trim() || "weekly-compliance", template_id: String(scheduleForm?.template_id || "").trim(), format: String(scheduleForm?.format || "pdf").trim().toLowerCase(), schedule: String(scheduleForm?.schedule || "weekly").trim().toLowerCase() as any, recipients: String(scheduleForm?.recipients || "").split(",").map((v) => String(v || "").trim()).filter(Boolean) });
      onToast?.("Scheduled report created.");
      await loadReporting();
    } catch (error) { onToast?.(`Create schedule failed: ${errMsg(error)}`); }
    finally { setReportBusy(false); }
  };

  /* ── Computed data ── */
  const templateOptions = [{ id: "default", name: "Built-in Baseline" }, ...(Array.isArray(templates) ? templates : []).map((item: any) => ({ id: String(item?.id || ""), name: String(item?.name || item?.id || "Custom Template") }))];

  const frameworkScores = assessment?.framework_scores || {};
  const labelByID: any = {};
  (Array.isArray(frameworkCatalog) ? frameworkCatalog : []).forEach((fw: any) => { const id = String(fw?.id || "").trim(); if (id) labelByID[id] = String(`${String(fw?.name || id).trim()} ${String(fw?.version || "").trim()}`).trim(); });
  (Array.isArray(templateDraft?.frameworks) ? templateDraft.frameworks : []).forEach((fw: any) => { const id = String(fw?.framework_id || "").trim(); if (id && String(fw?.label || "").trim()) labelByID[id] = String(fw.label); });

  const frameworkIDs = Array.from(new Set([...Object.keys(frameworkScores || {}), ...(Array.isArray(templateDraft?.frameworks) ? templateDraft.frameworks.map((fw: any) => String(fw?.framework_id || "")).filter(Boolean) : [])]));
  const palette = [C.green, C.blue, C.amber, C.accent];
  const frameworkRows = frameworkIDs.map((id, idx) => {
    const score = Math.max(0, Math.min(100, Number(frameworkScores?.[id] || 0)));
    return { id, label: labelByID[id] || id, score, color: palette[idx % palette.length] };
  });

  const pqc = assessment?.pqc || {};
  const pqcReady = Math.max(0, Math.min(100, Number(pqc?.ready_percent || assessment?.posture?.pqc_readiness || 0)));
  const findings = Array.isArray(assessment?.findings) ? assessment.findings : [];
  const score = Math.max(0, Math.min(100, Number(assessment?.overall_score || assessment?.posture?.overall_score || 0)));
  const scoreColor = score >= 85 ? C.green : score >= 65 ? C.blue : C.amber;

  const toneForFinding = (severity: string) => {
    const s = String(severity || "").toLowerCase();
    if (s === "critical") return "red";
    if (s === "high" || s === "warning" || s === "medium") return "amber";
    return "blue";
  };

  /* ── Chart data ── */
  const radarData = useMemo(() => frameworkRows.map((r) => ({ framework: r.label.split(" ")[0], score: r.score })), [frameworkRows]);

  const trendData = useMemo(() => {
    const items = Array.isArray(history) ? [...history] : [];
    items.sort((a: any, b: any) => new Date(String(a?.created_at || 0)).getTime() - new Date(String(b?.created_at || 0)).getTime());
    return items.slice(-20).map((item: any) => ({
      name: shortDate(item?.created_at),
      score: Math.max(0, Math.min(100, Number(item?.overall_score || 0)))
    }));
  }, [history]);

  const gaugeData = useMemo(() => [{ name: "Score", value: score, fill: scoreColor }], [score, scoreColor]);

  const pqcDonut = useMemo(() => {
    const migrated = Number(pqc?.ml_kem_migrated || 0) + Number(pqc?.ml_dsa_migrated || 0);
    const pending = Number(pqc?.pending || 0);
    const data = [];
    if (migrated > 0) data.push({ name: "Migrated", value: migrated, fill: C.green });
    if (pending > 0) data.push({ name: "Pending", value: pending, fill: C.amber });
    if (!data.length) data.push({ name: "No Data", value: 1, fill: C.border });
    return data;
  }, [pqc]);

  const findingSeverityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, warning: 0, info: 0 };
    findings.forEach((f: any) => {
      const s = String(f?.severity || "").toLowerCase();
      if (s === "critical") counts.critical++;
      else if (s === "high") counts.high++;
      else if (s === "warning" || s === "medium") counts.warning++;
      else counts.info++;
    });
    return counts;
  }, [findings]);
  const findingTotal = findingSeverityCounts.critical + findingSeverityCounts.high + findingSeverityCounts.warning + findingSeverityCounts.info;

  /* posture breakdown bar data */
  const breakdownBars = useMemo(() => {
    if (!postureBreakdown) return [];
    return [
      { name: "Key Hygiene", value: Math.round(Number(postureBreakdown.key_hygiene || 0)), fill: C.blue },
      { name: "Policy", value: Math.round(Number(postureBreakdown.policy_compliance || 0)), fill: C.green },
      { name: "Access", value: Math.round(Number(postureBreakdown.access_security || 0)), fill: C.amber },
      { name: "Crypto", value: Math.round(Number(postureBreakdown.crypto_posture || 0)), fill: C.accent },
      { name: "PQC", value: Math.round(Number(postureBreakdown.pqc_readiness || 0)), fill: C.purple }
    ];
  }, [postureBreakdown]);

  /* key hygiene algorithm distribution */
  const algoDistribution = useMemo(() => {
    if (!keyHygiene?.algorithm_distribution) return [];
    return Object.entries(keyHygiene.algorithm_distribution)
      .map(([name, count]) => ({ name, count: Number(count || 0) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [keyHygiene]);

  /* ── Alert stats chart data ── */
  const severityDonut = useMemo(() => {
    if (!alertStats?.by_severity) return [];
    const map: any = alertStats.by_severity;
    return [
      { name: "Critical", value: Number(map.critical || 0), fill: C.red },
      { name: "High", value: Number(map.high || 0), fill: C.amber },
      { name: "Warning", value: Number(map.warning || 0), fill: C.amber },
      { name: "Info", value: Number(map.info || 0), fill: C.blue }
    ].filter((d) => d.value > 0);
  }, [alertStats]);

  const dailyTrend = useMemo(() => {
    if (!alertStats?.daily_trend) return [];
    return Object.entries(alertStats.daily_trend)
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-14)
      .map(([date, count]) => ({ name: shortDate(date), alerts: Number(count || 0) }));
  }, [alertStats]);

  const statusBar = useMemo(() => {
    if (!alertStats?.by_status) return null;
    const map: any = alertStats.by_status;
    const total = Object.values(map).reduce((s: number, v: any) => s + Number(v || 0), 0) as number;
    if (!total) return null;
    return {
      new: Number(map.new || 0),
      acknowledged: Number(map.acknowledged || 0),
      resolved: Number(map.resolved || 0),
      false_positive: Number(map.false_positive || 0),
      total
    };
  }, [alertStats]);

  const mttrBars = useMemo(() => {
    if (!mttr) return [];
    return ["critical", "high", "warning", "info"]
      .filter((k) => Number(mttr[k] || 0) > 0)
      .map((k) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), minutes: Math.round(Number(mttr[k] || 0)), fill: k === "critical" ? C.red : k === "high" ? C.amber : k === "warning" ? C.amber : C.blue }));
  }, [mttr]);

  const mttdBars = useMemo(() => {
    if (!mttd) return [];
    return ["critical", "high", "warning", "info"]
      .filter((k) => Number(mttd[k] || 0) > 0)
      .map((k) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), minutes: Math.round(Number(mttd[k] || 0)), fill: k === "critical" ? C.red : k === "high" ? C.amber : k === "warning" ? C.amber : C.blue }));
  }, [mttd]);

  const topActors = useMemo(() => Array.isArray(topSources?.top_actors) ? topSources.top_actors.slice(0, 5) : [], [topSources]);
  const topIPs = useMemo(() => Array.isArray(topSources?.top_ips) ? topSources.top_ips.slice(0, 5) : [], [topSources]);
  const topServices = useMemo(() => Array.isArray(topSources?.top_services) ? topSources.top_services.slice(0, 5) : [], [topSources]);

  /* ══════════════════════════ INVENTORY (KeyInsight) VIEW ══════════════════════════ */
  const invAlgoDistribution = useMemo(() => {
    const map: Record<string, number> = {};
    inventoryKeys.forEach((k: any) => { const algo = String(k?.algorithm || "unknown"); map[algo] = (map[algo] || 0) + 1; });
    return Object.entries(map).sort(([, a], [, b]) => b - a).map(([name, count]) => ({ name, count }));
  }, [inventoryKeys]);

  const invAgeDistribution = useMemo(() => {
    const buckets = { "<30d": 0, "30-90d": 0, "90-180d": 0, "180-365d": 0, ">1yr": 0 };
    const now = Date.now();
    inventoryKeys.forEach((k: any) => {
      const created = new Date(String(k?.created_at || "")).getTime();
      if (Number.isNaN(created)) return;
      const days = Math.floor((now - created) / 86400000);
      if (days < 30) buckets["<30d"]++;
      else if (days < 90) buckets["30-90d"]++;
      else if (days < 180) buckets["90-180d"]++;
      else if (days < 365) buckets["180-365d"]++;
      else buckets[">1yr"]++;
    });
    return Object.entries(buckets).map(([name, count]) => ({ name, count }));
  }, [inventoryKeys]);

  const invRiskItems = useMemo(() => {
    const risks: any[] = [];
    inventoryKeys.forEach((k: any) => {
      const algo = String(k?.algorithm || "").toLowerCase();
      const exportAllowed = Boolean(k?.export_allowed);
      const status = String(k?.status || "").toLowerCase();
      const hsmNonExportable = String(k?.labels?.hsm_non_exportable || "false") === "true";
      if (algo.includes("rsa-1024") || algo.includes("des") || algo.includes("3des") || algo.includes("rc4"))
        risks.push({ id: k?.id, name: k?.name || k?.id, risk: "critical", reason: `Weak algorithm: ${algo}`, type: "key" });
      if (exportAllowed && !hsmNonExportable)
        risks.push({ id: k?.id, name: k?.name || k?.id, risk: "warning", reason: "Key is exportable — consider restricting", type: "key" });
      if (status === "compromised" || status === "destroyed")
        risks.push({ id: k?.id, name: k?.name || k?.id, risk: "critical", reason: `Key status: ${status}`, type: "key" });
      const created = new Date(String(k?.created_at || "")).getTime();
      if (!Number.isNaN(created) && (Date.now() - created) > 365 * 86400000)
        risks.push({ id: k?.id, name: k?.name || k?.id, risk: "high", reason: "Key older than 1 year — consider rotation", type: "key" });
    });
    inventoryCerts.forEach((c: any) => {
      const notAfter = new Date(String(c?.not_after || "")).getTime();
      if (!Number.isNaN(notAfter)) {
        const daysLeft = Math.floor((notAfter - Date.now()) / 86400000);
        if (daysLeft < 0) risks.push({ id: c?.id, name: c?.subject_cn || c?.id, risk: "critical", reason: "Certificate expired", type: "cert" });
        else if (daysLeft < 30) risks.push({ id: c?.id, name: c?.subject_cn || c?.id, risk: "high", reason: `Certificate expires in ${daysLeft} days`, type: "cert" });
        else if (daysLeft < 90) risks.push({ id: c?.id, name: c?.subject_cn || c?.id, risk: "warning", reason: `Certificate expires in ${daysLeft} days`, type: "cert" });
      }
      const algo = String(c?.algorithm || "").toLowerCase();
      if (algo.includes("sha1") || algo.includes("md5"))
        risks.push({ id: c?.id, name: c?.subject_cn || c?.id, risk: "critical", reason: `Weak signing: ${algo}`, type: "cert" });
    });
    return risks.sort((a, b) => (a.risk === "critical" ? 0 : a.risk === "high" ? 1 : 2) - (b.risk === "critical" ? 0 : b.risk === "high" ? 1 : 2));
  }, [inventoryKeys, inventoryCerts]);

  const invCertExpiryTimeline = useMemo(() => {
    const buckets = { "Expired": 0, "<30d": 0, "30-90d": 0, "90-180d": 0, ">180d": 0 };
    inventoryCerts.forEach((c: any) => {
      const notAfter = new Date(String(c?.not_after || "")).getTime();
      if (Number.isNaN(notAfter)) return;
      const days = Math.floor((notAfter - Date.now()) / 86400000);
      if (days < 0) buckets["Expired"]++;
      else if (days < 30) buckets["<30d"]++;
      else if (days < 90) buckets["30-90d"]++;
      else if (days < 180) buckets["90-180d"]++;
      else buckets[">180d"]++;
    });
    return Object.entries(buckets).map(([name, count]) => ({ name, count }));
  }, [inventoryCerts]);

  const invPqcReadiness = useMemo(() => {
    let pqcReady = 0, hybrid = 0, classical = 0;
    inventoryKeys.forEach((k: any) => {
      const algo = String(k?.algorithm || "").toLowerCase();
      if (algo.includes("ml-") || algo.includes("slh-") || algo.includes("dilithium") || algo.includes("kyber")) pqcReady++;
      else if (algo.includes("hybrid")) hybrid++;
      else classical++;
    });
    return [
      { name: "PQC Native", count: pqcReady, fill: C.green },
      { name: "Hybrid", count: hybrid, fill: C.blue },
      { name: "Classical", count: classical, fill: C.amber }
    ];
  }, [inventoryKeys]);

  const invHsmKeys = useMemo(() => inventoryKeys.filter((k: any) => k?.labels?.hsm_provider || k?.labels?.hsm_key_label), [inventoryKeys]);
  const invExportableKeys = useMemo(() => inventoryKeys.filter((k: any) => Boolean(k?.export_allowed)), [inventoryKeys]);
  const invFilteredRisks = useMemo(() => {
    let items = invRiskItems;
    if (inventoryFilter !== "all") items = items.filter((r) => r.risk === inventoryFilter);
    if (inventorySearch) { const q = inventorySearch.toLowerCase(); items = items.filter((r) => String(r.name || "").toLowerCase().includes(q) || String(r.reason || "").toLowerCase().includes(q)); }
    return items;
  }, [invRiskItems, inventoryFilter, inventorySearch]);

  const invScore = useMemo(() => {
    if (!inventoryKeys.length && !inventoryCerts.length) return 100;
    const criticals = invRiskItems.filter((r) => r.risk === "critical").length;
    const highs = invRiskItems.filter((r) => r.risk === "high").length;
    const warnings = invRiskItems.filter((r) => r.risk === "warning").length;
    const total = inventoryKeys.length + inventoryCerts.length;
    return Math.max(0, Math.round(100 - (criticals * 15 + highs * 8 + warnings * 3) / Math.max(1, total) * 10));
  }, [invRiskItems, inventoryKeys.length, inventoryCerts.length]);

  if (view === "inventory") {
    const scoreTone = invScore >= 80 ? C.green : invScore >= 60 ? C.amber : C.red;
    return (
      <div>
        <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
          <Btn small onClick={() => setView("assessment")} style={{ background: "transparent", borderColor: C.border, color: C.text, height: 28 }}>Assessment</Btn>
          <Btn small onClick={() => setView("reporting")} style={{ background: "transparent", borderColor: C.border, color: C.text, height: 28 }}>Reporting</Btn>
          <Btn small onClick={() => setView("inventory")} style={{ background: C.accentDim, borderColor: C.accent, color: C.accent, height: 28 }}>Crypto Inventory</Btn>
        </div>

        <Section title="Cryptographic Inventory" actions={<Btn small onClick={() => void loadInventory()} disabled={inventoryLoading}>{inventoryLoading ? "Scanning..." : "Refresh Inventory"}</Btn>}>

          {/* KPI Row */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(150px,1fr))", gap: 10, marginBottom: 14 }}>
            <Card style={{ padding: "10px 12px" }}>
              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Inventory Score</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: scoreTone, marginTop: 4 }}>{invScore}</div>
              <div style={{ fontSize: 10, color: C.dim }}>{invScore >= 80 ? "Healthy" : invScore >= 60 ? "Needs attention" : "At risk"}</div>
            </Card>
            <Card style={{ padding: "10px 12px" }}>
              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Total Keys</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: C.accent, marginTop: 4 }}>{inventoryKeys.length}</div>
              <div style={{ fontSize: 10, color: C.dim }}>{invAlgoDistribution.length} algorithms</div>
            </Card>
            <Card style={{ padding: "10px 12px" }}>
              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Certificates</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: C.blue, marginTop: 4 }}>{inventoryCerts.length}</div>
              <div style={{ fontSize: 10, color: C.dim }}>{invCertExpiryTimeline.find((b) => b.name === "Expired")?.count || 0} expired</div>
            </Card>
            <Card style={{ padding: "10px 12px" }}>
              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>HSM Backed</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: C.purple, marginTop: 4 }}>{invHsmKeys.length}</div>
              <div style={{ fontSize: 10, color: C.dim }}>{invExportableKeys.length} exportable</div>
            </Card>
            <Card style={{ padding: "10px 12px" }}>
              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Risk Findings</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: C.red, marginTop: 4 }}>{invRiskItems.length}</div>
              <div style={{ fontSize: 10, color: C.dim }}>{invRiskItems.filter((r) => r.risk === "critical").length} critical</div>
            </Card>
          </div>

          {/* Charts Row */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
            {/* Algorithm Distribution */}
            <Card>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>Algorithm Distribution</div>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={invAlgoDistribution.slice(0, 8)} layout="vertical">
                  <XAxis type="number" tick={{ fontSize: 9, fill: C.dim }} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: C.dim }} width={90} />
                  <Tooltip content={({ payload }: any) => payload?.[0] ? <ChartTip>{`${payload[0].payload.name}: ${payload[0].value}`}</ChartTip> : null} />
                  <RBar dataKey="count" fill={C.accent} radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Card>

            {/* Key Age Distribution */}
            <Card>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>Key Age Distribution</div>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={invAgeDistribution}>
                  <XAxis dataKey="name" tick={{ fontSize: 9, fill: C.dim }} />
                  <YAxis tick={{ fontSize: 9, fill: C.dim }} />
                  <Tooltip content={({ payload }: any) => payload?.[0] ? <ChartTip>{`${payload[0].payload.name}: ${payload[0].value} keys`}</ChartTip> : null} />
                  <RBar dataKey="count" fill={C.blue} radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Card>

            {/* PQC Readiness */}
            <Card>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>PQC Readiness</div>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={invPqcReadiness} dataKey="count" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={65} paddingAngle={2}>
                    {invPqcReadiness.map((entry: any, i: number) => <Cell key={i} fill={entry.fill} />)}
                  </Pie>
                  <Legend iconSize={8} wrapperStyle={{ fontSize: 9 }} />
                  <Tooltip content={({ payload }: any) => payload?.[0] ? <ChartTip>{`${payload[0].name}: ${payload[0].value}`}</ChartTip> : null} />
                </PieChart>
              </ResponsiveContainer>
            </Card>
          </div>

          {/* Certificate Expiry Timeline */}
          <Card style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>Certificate Expiry Timeline</div>
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={invCertExpiryTimeline}>
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: C.dim }} />
                <YAxis tick={{ fontSize: 9, fill: C.dim }} />
                <Tooltip content={({ payload }: any) => payload?.[0] ? <ChartTip>{`${payload[0].payload.name}: ${payload[0].value} certs`}</ChartTip> : null} />
                <RBar dataKey="count" radius={[4, 4, 0, 0]}>
                  {invCertExpiryTimeline.map((entry: any, i: number) => <Cell key={i} fill={entry.name === "Expired" ? C.red : entry.name === "<30d" ? C.amber : C.green} />)}
                </RBar>
              </BarChart>
            </ResponsiveContainer>
          </Card>

          {/* Risk Findings Table */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Risk Findings ({invFilteredRisks.length})</div>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <Inp value={inventorySearch} onChange={(e: any) => setInventorySearch(e.target.value)} placeholder="Search..." style={{ width: 160, height: 28, fontSize: 10 }} />
                <Sel w={100} value={inventoryFilter} onChange={(e: any) => setInventoryFilter(e.target.value)} style={{ height: 28, fontSize: 10 }}>
                  <option value="all">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="warning">Warning</option>
                </Sel>
              </div>
            </div>
            <div style={{ display: "grid", gap: 4, maxHeight: 340, overflowY: "auto" }}>
              {invFilteredRisks.slice(0, 50).map((r: any, i: number) => (
                <div key={`${r.id}-${i}`} style={{ display: "grid", gridTemplateColumns: "70px 60px 1fr", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.border}`, alignItems: "center" }}>
                  <B c={r.risk === "critical" ? "red" : r.risk === "high" ? "amber" : "blue"}>{String(r.risk).toUpperCase()}</B>
                  <B c={r.type === "key" ? "accent" : "purple"}>{r.type === "key" ? "KEY" : "CERT"}</B>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 11, color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(r.name || r.id)}</div>
                    <div style={{ fontSize: 9, color: C.dim }}>{r.reason}</div>
                  </div>
                </div>
              ))}
              {!invFilteredRisks.length && <div style={{ fontSize: 10, color: C.muted, padding: 12, textAlign: "center" }}>No risk findings detected. Your crypto inventory looks healthy.</div>}
            </div>
          </Card>
        </Section>
      </div>
    );
  }

  /* ══════════════════════════ REPORTING VIEW ══════════════════════════ */
  if (view === "reporting") {
    return (
      <div>
        <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
          <Btn small onClick={() => setView("assessment")} style={{ background: "transparent", borderColor: C.border, color: C.text, height: 28 }}>Assessment</Btn>
          <Btn small onClick={() => setView("reporting")} style={{ background: C.accentDim, borderColor: C.accent, color: C.accent, height: 28 }}>Reporting</Btn>
          <Btn small onClick={() => setView("inventory")} style={{ background: "transparent", borderColor: C.border, color: C.text, height: 28 }}>Crypto Inventory</Btn>
        </div>

        <Section title="Compliance Reporting" actions={<Btn small onClick={() => void loadReporting()} disabled={reportBusy}>{reportBusy ? "Working..." : "Refresh"}</Btn>}>

          {/* ═══ Alert Analytics Dashboard ═══ */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 10 }}>
            {/* Severity Donut */}
            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Alert Severity</span>
                <B c="accent">{alertStats?.total || 0} total</B>
              </div>
              {severityDonut.length > 0 ? (
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={severityDonut} cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3} dataKey="value" strokeWidth={0}>
                      {severityDonut.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
                    </Pie>
                    <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTip><span style={{ color: payload[0]?.payload?.fill, fontWeight: 700 }}>{payload[0]?.name}</span>: {payload[0]?.value}</ChartTip> : null} />
                    <Legend verticalAlign="bottom" height={24} iconType="circle" iconSize={8} formatter={(v) => <span style={{ color: C.dim, fontSize: 9 }}>{v}</span>} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No alert data</span></div>
              )}
            </Card>

            {/* Daily Alert Trend */}
            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Daily Trend</span>
                <B c="blue">{dailyTrend.length} days</B>
              </div>
              {dailyTrend.length > 0 ? (
                <ResponsiveContainer width="100%" height={160}>
                  <AreaChart data={dailyTrend}>
                    <defs>
                      <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={C.accent} stopOpacity={0.25} />
                        <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 8 }} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
                    <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={25} allowDecimals={false} />
                    <Tooltip content={({ active, payload, label }) => active && payload?.length ? <ChartTip><div style={{ fontWeight: 700, color: C.accent, marginBottom: 2 }}>{label}</div>Alerts: <span style={{ fontWeight: 700 }}>{payload[0]?.value}</span></ChartTip> : null} cursor={{ stroke: C.borderHi, strokeDasharray: "3 3" }} />
                    <Area type="monotone" dataKey="alerts" stroke={C.accent} strokeWidth={2} fill="url(#alertGrad)" dot={{ fill: C.accent, r: 2, strokeWidth: 0 }} activeDot={{ fill: C.accent, r: 4, stroke: C.bg, strokeWidth: 2 }} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No daily trend data</span></div>
              )}
            </Card>

            {/* MTTR by Severity */}
            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Mean Time to Resolve</span>
                <B c="green">MTTR</B>
              </div>
              {mttrBars.length > 0 ? (
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={mttrBars} layout="vertical">
                    <XAxis type="number" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} unit="m" />
                    <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} axisLine={false} tickLine={false} width={55} />
                    <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTip><span style={{ fontWeight: 700, color: payload[0]?.payload?.fill }}>{payload[0]?.payload?.name}</span>: {payload[0]?.value} min</ChartTip> : null} cursor={{ fill: C.accentDim }} />
                    <RBar dataKey="minutes" radius={[0, 4, 4, 0]}>
                      {mttrBars.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
                    </RBar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No MTTR data</span></div>
              )}
            </Card>
          </div>

          {/* ═══ Alert Status Progress Bar ═══ */}
          {statusBar && (
            <Card style={{ marginBottom: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Alert Resolution Status</span>
                <span style={{ fontSize: 9, color: C.muted }}>{statusBar.total} total</span>
              </div>
              <div style={{ display: "flex", height: 14, borderRadius: 7, overflow: "hidden", border: `1px solid ${C.border}` }}>
                {statusBar.resolved > 0 && <div style={{ width: `${(statusBar.resolved / statusBar.total) * 100}%`, background: C.green }} title={`Resolved: ${statusBar.resolved}`} />}
                {statusBar.acknowledged > 0 && <div style={{ width: `${(statusBar.acknowledged / statusBar.total) * 100}%`, background: C.blue }} title={`Acknowledged: ${statusBar.acknowledged}`} />}
                {statusBar.new > 0 && <div style={{ width: `${(statusBar.new / statusBar.total) * 100}%`, background: C.amber }} title={`New: ${statusBar.new}`} />}
                {statusBar.false_positive > 0 && <div style={{ width: `${(statusBar.false_positive / statusBar.total) * 100}%`, background: C.muted }} title={`False Positive: ${statusBar.false_positive}`} />}
              </div>
              <div style={{ display: "flex", gap: 14, marginTop: 6, flexWrap: "wrap" }}>
                {[["Resolved", statusBar.resolved, C.green], ["Acknowledged", statusBar.acknowledged, C.blue], ["New", statusBar.new, C.amber], ["False Positive", statusBar.false_positive, C.muted]].map(([label, count, color]) => (
                  <div key={String(label)} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.dim }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: color as string }} />
                    {label} ({count})
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* ═══ Top Sources ═══ */}
          {(topActors.length > 0 || topIPs.length > 0 || topServices.length > 0) && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 10 }}>
              {[["Top Actors", topActors, C.accent], ["Top Source IPs", topIPs, C.blue], ["Top Services", topServices, C.green]].map(([title, items, color]) => (
                <Card key={String(title)}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 6, display: "block" }}>{title as string}</span>
                  {(items as any[]).length > 0 ? (items as any[]).map((item: any, idx: number) => (
                    <div key={idx} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0", borderBottom: `1px solid ${C.border}` }}>
                      <span style={{ fontSize: 10, color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "70%" }}>{String(item?.key || "-")}</span>
                      <span style={{ fontSize: 10, fontWeight: 700, color: color as string }}>{Number(item?.count || 0)}</span>
                    </div>
                  )) : <span style={{ fontSize: 10, color: C.muted }}>No data</span>}
                </Card>
              ))}
            </div>
          )}

          {/* ═══ Report Generation + Schedule (existing, kept) ═══ */}
          <Row2>
            <Card>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>Generate Report</div>
              <div style={{ display: "grid", gap: 8 }}>
                <FG label="Template">
                  <Sel value={String(reportForm?.template_id || "")} onChange={(e) => setReportForm((prev: any) => ({ ...prev, template_id: e.target.value }))}>
                    <option value="">Select template</option>
                    {(Array.isArray(reportTemplates) ? reportTemplates : []).map((t: any) => <option key={String(t?.id || "")} value={String(t?.id || "")}>{String(t?.name || t?.id || "template")}</option>)}
                  </Sel>
                </FG>
                <FG label="Format">
                  <Sel value={String(reportForm?.format || "pdf")} onChange={(e) => setReportForm((prev: any) => ({ ...prev, format: e.target.value }))}>
                    <option value="pdf">PDF</option>
                    <option value="json">JSON</option>
                    <option value="csv">CSV</option>
                  </Sel>
                </FG>
                <div><Btn small primary onClick={() => void triggerReportNow()} disabled={reportBusy}>{reportBusy ? "Generating..." : "Run Report"}</Btn></div>
              </div>
            </Card>
            <Card>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>Create Schedule</div>
              <div style={{ display: "grid", gap: 8 }}>
                <FG label="Name"><Inp value={String(scheduleForm?.name || "")} onChange={(e) => setScheduleForm((prev: any) => ({ ...prev, name: e.target.value }))} /></FG>
                <FG label="Template">
                  <Sel value={String(scheduleForm?.template_id || "")} onChange={(e) => setScheduleForm((prev: any) => ({ ...prev, template_id: e.target.value }))}>
                    <option value="">Select template</option>
                    {(Array.isArray(reportTemplates) ? reportTemplates : []).map((t: any) => <option key={String(t?.id || "")} value={String(t?.id || "")}>{String(t?.name || t?.id || "template")}</option>)}
                  </Sel>
                </FG>
                <Row2>
                  <FG label="Format">
                    <Sel value={String(scheduleForm?.format || "pdf")} onChange={(e) => setScheduleForm((prev: any) => ({ ...prev, format: e.target.value }))}>
                      <option value="pdf">PDF</option><option value="json">JSON</option><option value="csv">CSV</option>
                    </Sel>
                  </FG>
                  <FG label="Schedule">
                    <Sel value={String(scheduleForm?.schedule || "weekly")} onChange={(e) => setScheduleForm((prev: any) => ({ ...prev, schedule: e.target.value }))}>
                      <option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option>
                    </Sel>
                  </FG>
                </Row2>
                <FG label="Recipients (comma separated)">
                  <Inp value={String(scheduleForm?.recipients || "")} onChange={(e) => setScheduleForm((prev: any) => ({ ...prev, recipients: e.target.value }))} placeholder="admin@org.com,security@org.com" />
                </FG>
                <div><Btn small onClick={() => void createScheduleReport()} disabled={reportBusy}>{reportBusy ? "Saving..." : "Create Schedule"}</Btn></div>
              </div>
            </Card>
          </Row2>

          <div style={{ height: 10 }} />
          <Row2>
            <Card>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>Recent Reports</div>
              <div style={{ display: "grid", gap: 6, maxHeight: 240, overflowY: "auto" }}>
                {(Array.isArray(reportJobs) ? reportJobs : []).map((job: any) => {
                  const status = String(job?.status || "pending").toLowerCase();
                  const tone = status === "completed" ? "green" : status === "failed" ? "red" : "blue";
                  return (
                    <div key={String(job?.id || Math.random())} style={{ display: "grid", gridTemplateColumns: "1fr auto auto auto", alignItems: "center", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
                      <div>
                        <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{String(job?.template_id || "report")}</div>
                        <div style={{ fontSize: 9, color: C.dim }}>{String(job?.format || "").toUpperCase()} • {job?.created_at ? new Date(String(job.created_at)).toLocaleString() : "-"}</div>
                      </div>
                      <B c={tone}>{status}</B>
                      <Btn small onClick={() => void downloadJob(job)} disabled={status !== "completed"}>Download</Btn>
                      <Btn small danger onClick={() => void deleteJob(job)}>Delete</Btn>
                    </div>
                  );
                })}
                {!Array.isArray(reportJobs) || !reportJobs.length ? <div style={{ fontSize: 10, color: C.muted }}>No reports generated yet.</div> : null}
              </div>
            </Card>
            <Card>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>Scheduled Reports</div>
              <div style={{ display: "grid", gap: 6, maxHeight: 240, overflowY: "auto" }}>
                {(Array.isArray(scheduledReports) ? scheduledReports : []).map((item: any) => (
                  <div key={String(item?.id || Math.random())} style={{ padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                      <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{String(item?.name || item?.id || "-")}</div>
                      <B c={Boolean(item?.enabled) ? "green" : "red"}>{Boolean(item?.enabled) ? "Enabled" : "Disabled"}</B>
                    </div>
                    <div style={{ fontSize: 9, color: C.dim, marginTop: 2 }}>{`${String(item?.template_id || "-")} • ${String(item?.format || "").toUpperCase()} • ${String(item?.schedule || "").toUpperCase()}`}</div>
                    <div style={{ fontSize: 9, color: C.muted, marginTop: 2 }}>{`Next run: ${item?.next_run_at ? new Date(String(item.next_run_at)).toLocaleString() : "-"}`}</div>
                  </div>
                ))}
                {!Array.isArray(scheduledReports) || !scheduledReports.length ? <div style={{ fontSize: 10, color: C.muted }}>No scheduled reports configured.</div> : null}
              </div>
            </Card>
          </Row2>
        </Section>
        {promptDialog.ui}
      </div>
    );
  }

  /* ══════════════════════════ ASSESSMENT VIEW ══════════════════════════ */
  return (
    <div>
      <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
        <Btn small onClick={() => setView("assessment")} style={{ background: C.accentDim, borderColor: C.accent, color: C.accent, height: 28 }}>Assessment</Btn>
        <Btn small onClick={() => setView("reporting")} style={{ background: "transparent", borderColor: C.border, color: C.text, height: 28 }}>Reporting</Btn>
        <Btn small onClick={() => setView("inventory")} style={{ background: "transparent", borderColor: C.border, color: C.text, height: 28 }}>Crypto Inventory</Btn>
      </div>
      <Section
        title="Compliance Posture"
        actions={
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <FG label="Template">
              <Sel w={220} value={selectedTemplateID} onChange={(e) => void loadAssessment({ templateId: e.target.value })}>
                {templateOptions.map((item: any) => <option key={String(item?.id || "default")} value={String(item?.id || "default")}>{String(item?.name || item?.id || "Template")}</option>)}
              </Sel>
            </FG>
            <Btn small onClick={() => void createTemplate()} disabled={savingTemplate}>+ Template</Btn>
            <Btn small onClick={() => void saveTemplate()} disabled={savingTemplate || selectedTemplateID === "default"}>{savingTemplate ? "Saving..." : "Save Template"}</Btn>
            <Btn small onClick={() => void removeTemplate()} disabled={deletingTemplate || selectedTemplateID === "default"}>{deletingTemplate ? "Deleting..." : "Delete Template"}</Btn>
            <Btn small onClick={() => void loadAssessment({ templateId: selectedTemplateID })} disabled={loading}>Refresh</Btn>
            <Btn small onClick={() => void exportEvidencePack("pdf")} disabled={reportBusy}>Evidence Pack</Btn>
            <Btn small primary onClick={() => void runNow()} disabled={running}>{running ? "Running..." : "Run Assessment"}</Btn>
            <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "2px 8px", border: `1px solid ${C.border}`, borderRadius: 8 }}>
              <Chk label="Scheduled" checked={Boolean(schedule?.enabled)} onChange={() => setSchedule((prev: any) => ({ ...prev, enabled: !prev?.enabled }))} />
              <Sel w={96} value={String(schedule?.frequency || "daily")} onChange={(e) => setSchedule((prev: any) => ({ ...prev, frequency: e.target.value }))}>
                <option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option>
              </Sel>
              <Btn small onClick={() => void saveSchedule()} disabled={savingSchedule}>{savingSchedule ? "Saving..." : "Save"}</Btn>
            </div>
          </div>
        }
      >
        <div style={{ fontSize: 10, color: C.muted, marginBottom: 8 }}>
          Assessment is calculated from real key/certificate posture and scored against the selected template ({selectedTemplateID === "default" ? "Built-in Baseline" : "Custom Template"}).
        </div>

        {!assessment ? (
          <Card style={{ borderColor: C.amber, background: C.amberDim, marginBottom: 10 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
              <div>
                <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 4 }}>No compliance scan has been run yet</div>
                <div style={{ fontSize: 10, color: C.dim }}>
                  The score stays at 0 until the first assessment completes. Run a scan to generate posture, framework coverage, and findings.
                </div>
              </div>
              <Btn small primary onClick={() => void runNow()} disabled={running}>{running ? "Running..." : "Run First Scan"}</Btn>
            </div>
          </Card>
        ) : null}

        {/* ═══ Template Configuration (unchanged) ═══ */}
        {selectedTemplateID !== "default" && templateDraft ? (
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>Template Configuration</div>
              <B c={Boolean(templateDraft?.enabled) ? "green" : "red"}>{Boolean(templateDraft?.enabled) ? "Enabled" : "Disabled"}</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 8, alignItems: "end" }}>
              <FG label="Template Name"><Inp value={String(templateDraft?.name || "")} onChange={(e) => setTemplateDraft((prev: any) => ({ ...prev, name: e.target.value }))} /></FG>
              <FG label="Description"><Inp value={String(templateDraft?.description || "")} onChange={(e) => setTemplateDraft((prev: any) => ({ ...prev, description: e.target.value }))} /></FG>
              <Chk label="Enabled" checked={Boolean(templateDraft?.enabled)} onChange={() => setTemplateDraft((prev: any) => ({ ...prev, enabled: !prev?.enabled }))} />
            </div>
            <div style={{ height: 8 }} />
            <div style={{ display: "grid", gap: 8, maxHeight: 280, overflowY: "auto", paddingRight: 4 }}>
              {(Array.isArray(templateDraft?.frameworks) ? templateDraft.frameworks : []).map((fw: any) => (
                <Card key={String(fw?.framework_id || Math.random())}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 110px", gap: 8, alignItems: "center", marginBottom: 6 }}>
                    <Chk label={String(fw?.label || fw?.framework_id || "Framework")} checked={Boolean(fw?.enabled)} onChange={() => patchFramework(String(fw?.framework_id || ""), { enabled: !fw?.enabled })} />
                    <FG label="Weight"><Inp type="number" value={String(fw?.weight ?? 1)} onChange={(e) => patchFramework(String(fw?.framework_id || ""), { weight: Math.max(0.1, Number(e.target.value) || 1) })} /></FG>
                  </div>
                  <div style={{ display: "grid", gap: 6 }}>
                    {(Array.isArray(fw?.controls) ? fw.controls : []).map((ctrl: any) => (
                      <div key={String(ctrl?.id || Math.random())} style={{ display: "grid", gridTemplateColumns: "1fr 90px 90px", gap: 8, alignItems: "center", padding: "6px 0", borderTop: `1px solid ${C.border}` }}>
                        <div>
                          <Chk label={String(ctrl?.title || ctrl?.id || "Control")} checked={Boolean(ctrl?.enabled)} onChange={() => patchControl(String(fw?.framework_id || ""), String(ctrl?.id || ""), { enabled: !ctrl?.enabled })} />
                          <div style={{ fontSize: 9, color: C.dim, marginTop: 2 }}>{String(ctrl?.requirement || ctrl?.category || "")}</div>
                        </div>
                        <FG label="Weight"><Inp type="number" value={String(ctrl?.weight ?? 1)} onChange={(e) => patchControl(String(fw?.framework_id || ""), String(ctrl?.id || ""), { weight: Math.max(0.1, Number(e.target.value) || 1) })} /></FG>
                        <FG label="Threshold"><Inp type="number" value={String(ctrl?.threshold ?? 80)} onChange={(e) => patchControl(String(fw?.framework_id || ""), String(ctrl?.id || ""), { threshold: Math.max(1, Math.min(100, Number(e.target.value) || 80)) })} /></FG>
                      </div>
                    ))}
                  </div>
                </Card>
              ))}
            </div>
          </Card>
        ) : null}
        {selectedTemplateID === "default" ? <Card><div style={{ fontSize: 10, color: C.muted }}>Built-in Baseline is read-only. Create a custom template to configure framework/control weights, thresholds, and enabled controls.</div></Card> : null}

        <div style={{ height: 10 }} />

        {assessmentDelta && (
          <>
            <Card style={{ marginBottom: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>What Changed Since Last Scan</span>
                <B c={Number(assessmentDelta?.score_delta || 0) > 0 ? "green" : Number(assessmentDelta?.score_delta || 0) < 0 ? "red" : "blue"}>
                  {Number(assessmentDelta?.score_delta || 0) >= 0 ? "+" : ""}{Number(assessmentDelta?.score_delta || 0)} score delta
                </B>
              </div>
              <div style={{ fontSize: 10, color: C.dim, marginBottom: 10 }}>{String(assessmentDelta?.summary || "No prior comparison available.")}</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div>
                  <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Added Findings</div>
                  <div style={{ display: "grid", gap: 6 }}>
                    {(Array.isArray(assessmentDelta?.added_findings) ? assessmentDelta.added_findings : []).slice(0, 4).map((item: any, idx: number) => (
                      <div key={`added-${idx}`} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                          <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{String(item?.title || "-")}</div>
                          <B c="red">+{Number(item?.delta || 0)}</B>
                        </div>
                        <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>{String(item?.severity || "").toUpperCase()} • {Number(item?.current_count || 0)} current</div>
                      </div>
                    ))}
                    {(!assessmentDelta?.added_findings || !assessmentDelta.added_findings.length) && <div style={{ fontSize: 10, color: C.muted }}>No new findings.</div>}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Resolved Findings</div>
                  <div style={{ display: "grid", gap: 6 }}>
                    {(Array.isArray(assessmentDelta?.resolved_findings) ? assessmentDelta.resolved_findings : []).slice(0, 4).map((item: any, idx: number) => (
                      <div key={`resolved-${idx}`} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                          <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{String(item?.title || "-")}</div>
                          <B c="green">{Number(item?.delta || 0)}</B>
                        </div>
                        <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>{String(item?.severity || "").toUpperCase()} • {Number(item?.previous_count || 0)} previous</div>
                      </div>
                    ))}
                    {(!assessmentDelta?.resolved_findings || !assessmentDelta.resolved_findings.length) && <div style={{ fontSize: 10, color: C.muted }}>No resolved findings.</div>}
                  </div>
                </div>
              </div>

              <div style={{ height: 10 }} />
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div>
                  <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Recovered Domains</div>
                  <div style={{ display: "grid", gap: 6 }}>
                    {(Array.isArray(assessmentDelta?.recovered_domains) ? assessmentDelta.recovered_domains : []).slice(0, 4).map((item: any, idx: number) => (
                      <div key={`recovered-${idx}`} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                          <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{String(item?.label || item?.domain || "-")}</div>
                          <B c="green">+{Number(item?.delta || 0)}</B>
                        </div>
                        <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>{Number(item?.previous_score || 0)} → {Number(item?.current_score || 0)} • {String(item?.status || "")}</div>
                      </div>
                    ))}
                    {(!assessmentDelta?.recovered_domains || !assessmentDelta.recovered_domains.length) && <div style={{ fontSize: 10, color: C.muted }}>No recovered domains.</div>}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>New Failing Connectors</div>
                  <div style={{ display: "grid", gap: 6 }}>
                    {(Array.isArray(assessmentDelta?.new_failing_connectors) ? assessmentDelta.new_failing_connectors : []).slice(0, 4).map((item: any, idx: number) => (
                      <div key={`connector-${idx}`} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                          <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{String(item?.label || item?.connector || "-")}</div>
                          <B c="red">+{Number(item?.delta || 0)}</B>
                        </div>
                        <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>{Number(item?.previous_fails || 0)} → {Number(item?.current_fails || 0)} failures</div>
                      </div>
                    ))}
                    {(!assessmentDelta?.new_failing_connectors || !assessmentDelta.new_failing_connectors.length) && <div style={{ fontSize: 10, color: C.muted }}>No newly failing connectors.</div>}
                  </div>
                </div>
              </div>
            </Card>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
              <Card>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Mean Time to Detect</span>
                  <B c="blue">MTTD</B>
                </div>
                {mttdBars.length > 0 ? (
                  <ResponsiveContainer width="100%" height={150}>
                    <BarChart data={mttdBars} layout="vertical">
                      <XAxis type="number" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} unit="m" />
                      <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} axisLine={false} tickLine={false} width={55} />
                      <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTip><span style={{ fontWeight: 700, color: payload[0]?.payload?.fill }}>{payload[0]?.payload?.name}</span>: {payload[0]?.value} min</ChartTip> : null} cursor={{ fill: C.accentDim }} />
                      <RBar dataKey="minutes" radius={[0, 4, 4, 0]}>
                        {mttdBars.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
                      </RBar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height: 150, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No MTTD data yet.</span></div>
                )}
              </Card>

              <Card>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Mean Time to Resolve</span>
                  <B c="green">MTTR</B>
                </div>
                {mttrBars.length > 0 ? (
                  <ResponsiveContainer width="100%" height={150}>
                    <BarChart data={mttrBars} layout="vertical">
                      <XAxis type="number" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} unit="m" />
                      <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} axisLine={false} tickLine={false} width={55} />
                      <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTip><span style={{ fontWeight: 700, color: payload[0]?.payload?.fill }}>{payload[0]?.payload?.name}</span>: {payload[0]?.value} min</ChartTip> : null} cursor={{ fill: C.accentDim }} />
                      <RBar dataKey="minutes" radius={[0, 4, 4, 0]}>
                        {mttrBars.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
                      </RBar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height: 150, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No MTTR data yet.</span></div>
                )}
              </Card>
            </div>
          </>
        )}

        {/* ═══ ROW 1: Score Gauge + Framework Radar + PQC Donut ═══ */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
          {/* Overall Score Gauge */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Overall Score</span>
              <B c={score >= 85 ? "green" : score >= 65 ? "blue" : "amber"}>{score}/100</B>
            </div>
            <ResponsiveContainer width="100%" height={150}>
              <RadialBarChart cx="50%" cy="50%" innerRadius="50%" outerRadius="90%" startAngle={210} endAngle={-30} data={gaugeData} barSize={14}>
                <RadialBar dataKey="value" cornerRadius={7} background={{ fill: C.border }} />
              </RadialBarChart>
            </ResponsiveContainer>
            <div style={{ textAlign: "center", fontSize: 28, fontWeight: 800, color: scoreColor, marginTop: -8 }}>{score}</div>
            <div style={{ textAlign: "center", fontSize: 9, color: C.muted }}>Compliance Score</div>
          </Card>

          {/* Framework Radar */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Framework Coverage</span>
              <B c="accent">{frameworkRows.length} frameworks</B>
            </div>
            {radarData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="65%">
                  <PolarGrid stroke={C.border} />
                  <PolarAngleAxis dataKey="framework" tick={{ fill: C.dim, fontSize: 9 }} />
                  <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fill: C.muted, fontSize: 8 }} tickCount={4} />
                  <Radar dataKey="score" stroke={C.accent} fill={C.accent} fillOpacity={0.2} strokeWidth={2} />
                </RadarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 180, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No framework data</span></div>
            )}
          </Card>

          {/* PQC Readiness Donut */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Post-Quantum Readiness</span>
              <B c="green">{Math.round(pqcReady)}%</B>
            </div>
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={pqcDonut} cx="50%" cy="50%" innerRadius={35} outerRadius={50} paddingAngle={3} dataKey="value" strokeWidth={0}>
                  {pqcDonut.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
                </Pie>
                <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTip><span style={{ color: payload[0]?.payload?.fill, fontWeight: 700 }}>{payload[0]?.name}</span>: {payload[0]?.value}</ChartTip> : null} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 4, marginTop: 2 }}>
              {[["ML-KEM", Number(pqc?.ml_kem_migrated || 0)], ["ML-DSA", Number(pqc?.ml_dsa_migrated || 0)], ["Pending", Number(pqc?.pending || 0)]].map(([k, v]) => (
                <div key={String(k)} style={{ textAlign: "center" }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{Number(v).toLocaleString()}</div>
                  <div style={{ fontSize: 8, color: C.muted }}>{k}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>PQC Migration Gaps</span>
            <B c={Number(pqcInventory?.classical_usage?.length || 0) > 0 || Number(pqcInventory?.non_migrated_interfaces?.length || 0) > 0 || Number(pqcInventory?.non_migrated_certificates?.length || 0) > 0 ? "amber" : "green"}>
              {`${Number(pqcInventory?.readiness_score || 0)}/100`}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="RSA / ECC Active" v={String(Number(pqcInventory?.classical_usage?.length || 0))} c={Number(pqcInventory?.classical_usage?.length || 0) > 0 ? "amber" : "green"} />
            <Stat l="Interfaces Pending" v={String(Number(pqcInventory?.non_migrated_interfaces?.length || 0))} c={Number(pqcInventory?.non_migrated_interfaces?.length || 0) > 0 ? "amber" : "green"} />
            <Stat l="Certificates Pending" v={String(Number(pqcInventory?.non_migrated_certificates?.length || 0))} c={Number(pqcInventory?.non_migrated_certificates?.length || 0) > 0 ? "amber" : "green"} />
            <Stat l="Tenant PQC Policy" v={String(pqcInventory?.policy?.profile_id || "balanced_hybrid").replaceAll("_", " ")} c="accent" />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Non-Migrated Interfaces</div>
              {(pqcInventory?.non_migrated_interfaces || []).slice(0, 4).map((item: any) => (
                <div key={`${item.interface_name}-${item.port}`} style={{ padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <span style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{item.interface_name}</span>
                    <span style={{ fontSize: 10, color: C.red }}>{item.effective_pqc_mode}</span>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim }}>{`${item.protocol.toUpperCase()} ${item.bind_address}:${item.port}`}</div>
                </div>
              ))}
              {!(pqcInventory?.non_migrated_interfaces || []).length && <div style={{ fontSize: 10, color: C.muted }}>No interface migration gaps.</div>}
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Non-Migrated Certificates</div>
              {(pqcInventory?.non_migrated_certificates || []).slice(0, 4).map((item: any) => (
                <div key={item.cert_id} style={{ padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <span style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{item.subject_cn}</span>
                    <span style={{ fontSize: 10, color: C.red }}>{item.algorithm}</span>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim }}>{item.status || "active"}</div>
                </div>
              ))}
              {!(pqcInventory?.non_migrated_certificates || []).length && <div style={{ fontSize: 10, color: C.muted }}>No certificate migration gaps.</div>}
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Autokey Controls</span>
            <B c={!autokeySummary?.enabled ? "amber" : Number(autokeySummary?.failed_count || 0) > 0 ? "red" : Number(autokeySummary?.pending_approvals || 0) > 0 || Number(autokeySummary?.policy_mismatch_count || 0) > 0 ? "amber" : "green"}>
              {!autokeySummary?.enabled ? "Disabled" : Number(autokeySummary?.failed_count || 0) > 0 ? "Failures" : Number(autokeySummary?.pending_approvals || 0) > 0 || Number(autokeySummary?.policy_mismatch_count || 0) > 0 ? "Needs review" : "Aligned"}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="Templates" v={String(Number(autokeySummary?.template_count || 0))} c="blue" />
            <Stat l="Service Defaults" v={String(Number(autokeySummary?.service_policy_count || 0))} c="blue" />
            <Stat l="Pending Approvals" v={String(Number(autokeySummary?.pending_approvals || 0))} c={Number(autokeySummary?.pending_approvals || 0) > 0 ? "amber" : "green"} />
            <Stat l="Policy Mismatches" v={String(Number(autokeySummary?.policy_mismatch_count || 0))} c={Number(autokeySummary?.policy_mismatch_count || 0) > 0 ? "amber" : "green"} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Policy Alignment</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>
                  {Number(autokeySummary?.policy_mismatch_count || 0) > 0 ? "Generated requests diverged from org policy" : "Generated requests matched org policy"}
                </div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  {Number(autokeySummary?.policy_matched_count || 0)} matched • {Number(autokeySummary?.denied_count || 0)} denied • {Number(autokeySummary?.failed_count || 0)} failed
                </div>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Compliance Actions</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>Autokey request governance</div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  Review approval backlog, keep default service policies enforced, and use tenant templates so generated handles stay aligned with org cryptography standards.
                </div>
              </div>
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Workload Identity Controls</span>
            <B c={!workloadSummary?.enabled ? "amber" : Number(workloadSummary?.expired_svid_count || 0) > 0 || Number(workloadSummary?.over_privileged_count || 0) > 0 ? "red" : "green"}>
              {!workloadSummary?.enabled ? "Disabled" : Number(workloadSummary?.expired_svid_count || 0) > 0 || Number(workloadSummary?.over_privileged_count || 0) > 0 ? "Needs review" : "Aligned"}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="Trust Domain" v={String(workloadSummary?.trust_domain || "-")} c="accent" />
            <Stat l="Expired SVIDs" v={String(Number(workloadSummary?.expired_svid_count || 0))} c={Number(workloadSummary?.expired_svid_count || 0) > 0 ? "red" : "green"} />
            <Stat l="Over-Privileged" v={String(Number(workloadSummary?.over_privileged_count || 0))} c={Number(workloadSummary?.over_privileged_count || 0) > 0 ? "amber" : "green"} />
            <Stat l="Static API Keys" v={Boolean(workloadSummary?.disable_static_api_keys) ? "Disabled" : "Allowed"} c={Boolean(workloadSummary?.disable_static_api_keys) ? "green" : "amber"} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Rotation & Usage</div>
              <div style={{ display: "grid", gap: 6 }}>
                <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{Boolean(workloadSummary?.rotation_healthy) ? "Rotation healthy" : "Rotation attention needed"}</div>
                  <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                    {Number(workloadSummary?.expiring_svid_count || 0)} expiring • {Number(workloadSummary?.token_exchange_count_24h || 0)} token exchanges • {Number(workloadSummary?.unique_workloads_using_keys_24h || 0)} workloads used keys in the last 24h
                  </div>
                </div>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Compliance Actions</div>
              <div style={{ display: "grid", gap: 6 }}>
                <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>Identity hardening</div>
                  <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                    Review registrations with wildcard access, rotate expiring SVIDs, and disable static API keys so workload callers use SPIFFE/SVID exchange instead of long-lived bearer secrets.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>SCIM Provisioning Controls</span>
            <B c={!scimSummary?.enabled ? "amber" : !scimSummary?.token_configured ? "amber" : Number(scimSummary?.disabled_users || 0) > 0 ? "amber" : "green"}>
              {!scimSummary?.enabled ? "Disabled" : !scimSummary?.token_configured ? "Token missing" : Number(scimSummary?.disabled_users || 0) > 0 ? "Needs review" : "Aligned"}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="Managed Users" v={String(Number(scimSummary?.managed_users || 0))} c="blue" />
            <Stat l="Managed Groups" v={String(Number(scimSummary?.managed_groups || 0))} c="green" />
            <Stat l="Disabled Users" v={String(Number(scimSummary?.disabled_users || 0))} c={Number(scimSummary?.disabled_users || 0) > 0 ? "amber" : "green"} />
            <Stat l="Role-Mapped Groups" v={String(Number(scimSummary?.role_mapped_groups || 0))} c="blue" />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Provisioning State</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>
                  {Boolean(scimSummary?.enabled) && Boolean(scimSummary?.token_configured) ? "Tenant can accept SCIM pushes" : "Provisioning handshake is incomplete"}
                </div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  {Boolean(scimSummary?.token_configured) ? `Token prefix ${String(scimSummary?.token_prefix || "").trim() || "configured"} is registered for the tenant.` : "Rotate the SCIM bearer token and configure the IdP connector before enabling production provisioning."}
                </div>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Compliance Actions</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>Identity lifecycle hygiene</div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  Keep group-to-role mappings reviewed, disable orphaned identities on deprovision, and audit tenants where SCIM is enabled but token rotation or role mappings are incomplete.
                </div>
              </div>
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Certificate Renewal Controls</span>
            <B c={Number(certRenewalSummary?.emergency_rotation_count || 0) > 0 ? "red" : Number(certRenewalSummary?.missed_window_count || 0) > 0 || Number(certRenewalSummary?.mass_renewal_risks?.length || 0) > 0 ? "amber" : "green"}>
              {Number(certRenewalSummary?.emergency_rotation_count || 0) > 0 ? "Emergency rotation" : Number(certRenewalSummary?.missed_window_count || 0) > 0 || Number(certRenewalSummary?.mass_renewal_risks?.length || 0) > 0 ? "Needs review" : "Aligned"}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="ARI Mode" v={Boolean(certRenewalSummary?.ari_enabled) ? "Enabled" : "Local"} c={Boolean(certRenewalSummary?.ari_enabled) ? "green" : "amber"} />
            <Stat l="Missed Windows" v={String(Number(certRenewalSummary?.missed_window_count || 0))} c={Number(certRenewalSummary?.missed_window_count || 0) > 0 ? "amber" : "green"} />
            <Stat l="Emergency Rotations" v={String(Number(certRenewalSummary?.emergency_rotation_count || 0))} c={Number(certRenewalSummary?.emergency_rotation_count || 0) > 0 ? "red" : "green"} />
            <Stat l="Mass-Renewal Risks" v={String(Number(certRenewalSummary?.mass_renewal_risks?.length || 0))} c={Number(certRenewalSummary?.mass_renewal_risks?.length || 0) > 0 ? "amber" : "green"} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Window Discipline</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>
                  {Number(certRenewalSummary?.missed_window_count || 0) > 0 ? "Renewal windows were missed" : "Coordinated renewal windows are being met"}
                </div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  {Number(certRenewalSummary?.due_soon_count || 0)} certificates are due soon. Poll every {Number(certRenewalSummary?.recommended_poll_hours || 24)} hours and keep clients renewing inside the CA-directed window.
                </div>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Risk Hotspots</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>
                  {Number(certRenewalSummary?.mass_renewal_risks?.length || 0) > 0 ? "Mass-renewal concentration detected" : "No mass-renewal hotspot detected"}
                </div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  {Number(certRenewalSummary?.mass_renewal_risks?.length || 0) > 0 ? "Distribute certificate cohorts across more renewal days or widen the ARI bias window to avoid one-day rotation spikes." : "Renewal schedule is distributed across CA buckets without triggering the current hotspot threshold."}
                </div>
              </div>
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>REST Client Authentication Controls</span>
            <B c={Number(restClientSecurity?.total_clients || 0) === 0 ? "blue" : Number(restClientSecurity?.replay_violations || 0) > 0 || Number(restClientSecurity?.signature_failures || 0) > 0 ? "red" : Number(restClientSecurity?.non_compliant_clients || 0) > 0 || Number(restClientSecurity?.unsigned_rejects || 0) > 0 ? "amber" : "green"}>
              {Number(restClientSecurity?.total_clients || 0) === 0 ? "No REST clients" : Number(restClientSecurity?.replay_violations || 0) > 0 || Number(restClientSecurity?.signature_failures || 0) > 0 ? "Control failures" : Number(restClientSecurity?.non_compliant_clients || 0) > 0 || Number(restClientSecurity?.unsigned_rejects || 0) > 0 ? "Migration pending" : "Aligned"}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="Sender-Constrained" v={`${Number(restClientSecurity?.sender_constrained_clients || 0)}/${Number(restClientSecurity?.total_clients || 0)}`} c={Number(restClientSecurity?.non_compliant_clients || 0) > 0 ? "amber" : "green"} />
            <Stat l="Replay Violations" v={String(Number(restClientSecurity?.replay_violations || 0))} c={Number(restClientSecurity?.replay_violations || 0) > 0 ? "red" : "green"} />
            <Stat l="Signature Failures" v={String(Number(restClientSecurity?.signature_failures || 0))} c={Number(restClientSecurity?.signature_failures || 0) > 0 ? "red" : "green"} />
            <Stat l="Unsigned Rejects" v={String(Number(restClientSecurity?.unsigned_rejects || 0))} c={Number(restClientSecurity?.unsigned_rejects || 0) > 0 ? "amber" : "green"} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Current Control State</div>
              <div style={{ display: "grid", gap: 6 }}>
                <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>Signed vs unsigned REST traffic</div>
                  <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                    {Number(restClientSecurity?.unsigned_rejects || 0)} unsigned requests were blocked. {Number(restClientSecurity?.verified_requests || 0)} signed or bound requests were accepted through the hardened path.
                  </div>
                </div>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Compliance Actions</div>
              <div style={{ display: "grid", gap: 6 }}>
                <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>Sender-constrained migration</div>
                  <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                    Move legacy bearer clients to OAuth mTLS, DPoP, or HTTP Message Signatures and investigate any replay or signature failures before treating REST control posture as compliant.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Key Access Justification Controls</span>
            <B c={!keyAccessSummary?.enabled ? "amber" : Number(keyAccessSummary?.bypass_count_24h || 0) > 0 ? "red" : Number(keyAccessSummary?.unjustified_count_24h || 0) > 0 || Number(keyAccessSummary?.approval_count_24h || 0) > 0 ? "amber" : "green"}>
              {!keyAccessSummary?.enabled ? "Disabled" : Number(keyAccessSummary?.bypass_count_24h || 0) > 0 ? "Bypass detected" : Number(keyAccessSummary?.unjustified_count_24h || 0) > 0 || Number(keyAccessSummary?.approval_count_24h || 0) > 0 ? "Needs review" : "Aligned"}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="Rules" v={String(Number(keyAccessSummary?.rule_count || 0))} c="blue" />
            <Stat l="Requests 24h" v={String(Number(keyAccessSummary?.total_requests_24h || 0))} c="accent" />
            <Stat l="Unjustified" v={String(Number(keyAccessSummary?.unjustified_count_24h || 0))} c={Number(keyAccessSummary?.unjustified_count_24h || 0) > 0 ? "amber" : "green"} />
            <Stat l="Bypass Signals" v={String(Number(keyAccessSummary?.bypass_count_24h || 0))} c={Number(keyAccessSummary?.bypass_count_24h || 0) > 0 ? "red" : "green"} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Policy Outcome</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>
                  {Number(keyAccessSummary?.unjustified_count_24h || 0) > 0 ? "Some external key requests lacked valid justification" : "External key requests matched declared reason-code policy"}
                </div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  {Number(keyAccessSummary?.allow_count_24h || 0)} allowed • {Number(keyAccessSummary?.deny_count_24h || 0)} denied • {Number(keyAccessSummary?.approval_count_24h || 0)} held for approval
                </div>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Compliance Actions</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>Usage justification enforcement</div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  Require valid reason codes for HYOK, EKM, and external decrypt/sign calls and investigate any bypass or policy-scope mismatch before accepting the external-access control posture.
                </div>
              </div>
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Artifact Signing Controls</span>
            <B c={!signingSummary?.enabled ? "amber" : Number(signingSummary?.verification_failures_24h || 0) > 0 ? "red" : Number(signingSummary?.transparency_logged_24h || 0) < Number(signingSummary?.record_count_24h || 0) ? "amber" : "green"}>
              {!signingSummary?.enabled ? "Disabled" : Number(signingSummary?.verification_failures_24h || 0) > 0 ? "Verification failures" : Number(signingSummary?.transparency_logged_24h || 0) < Number(signingSummary?.record_count_24h || 0) ? "Transparency gaps" : "Aligned"}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="Profiles" v={String(Number(signingSummary?.profile_count || 0))} c="blue" />
            <Stat l="Signed 24h" v={String(Number(signingSummary?.record_count_24h || 0))} c="accent" />
            <Stat l="Transparency Logged" v={String(Number(signingSummary?.transparency_logged_24h || 0))} c={Number(signingSummary?.transparency_logged_24h || 0) < Number(signingSummary?.record_count_24h || 0) ? "amber" : "green"} />
            <Stat l="Verify Failures" v={String(Number(signingSummary?.verification_failures_24h || 0))} c={Number(signingSummary?.verification_failures_24h || 0) > 0 ? "red" : "green"} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Provenance State</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>
                  {Number(signingSummary?.transparency_logged_24h || 0) < Number(signingSummary?.record_count_24h || 0) ? "Some signatures were not logged with transparency metadata" : "Recent signatures were logged with transparency metadata"}
                </div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  {Number(signingSummary?.workload_signed_24h || 0)} workload-signed • {Number(signingSummary?.oidc_signed_24h || 0)} OIDC-signed • {Array.isArray(signingSummary?.artifact_counts) ? signingSummary.artifact_counts.length : 0} artifact classes active
                </div>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Compliance Actions</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>Supply-chain signing hygiene</div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  Enforce trust constraints on workload or OIDC identities, require transparency logging for release profiles, and investigate verification failures before treating build provenance as compliant.
                </div>
              </div>
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Threshold Signing / FROST Controls</span>
            <B c={Number(mpcOverview?.stats?.failed_ceremonies || 0) > 0 ? "red" : Number(mpcOverview?.stats?.pending_ceremonies || 0) > 0 ? "amber" : Number(mpcOverview?.stats?.active_keys || 0) > 0 ? "green" : "amber"}>
              {Number(mpcOverview?.stats?.failed_ceremonies || 0) > 0 ? "Failures" : Number(mpcOverview?.stats?.pending_ceremonies || 0) > 0 ? "Pending ceremony" : Number(mpcOverview?.stats?.active_keys || 0) > 0 ? "Aligned" : "No active keys"}
            </B>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
            <Stat l="Active Keys" v={String(Number(mpcOverview?.stats?.active_keys || 0))} c="green" />
            <Stat l="Pending Ceremonies" v={String(Number(mpcOverview?.stats?.pending_ceremonies || 0))} c={Number(mpcOverview?.stats?.pending_ceremonies || 0) > 0 ? "amber" : "green"} />
            <Stat l="Failed Ceremonies" v={String(Number(mpcOverview?.stats?.failed_ceremonies || 0))} c={Number(mpcOverview?.stats?.failed_ceremonies || 0) > 0 ? "red" : "green"} />
            <Stat l="Participants" v={String(Number(mpcOverview?.stats?.total_participants || 0))} c="blue" />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Ceremony State</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>
                  {Number(mpcOverview?.stats?.pending_ceremonies || 0) > 0 ? "Quorum-backed ceremonies are waiting on contributors" : "No pending threshold ceremonies"}
                </div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  {Number(mpcOverview?.stats?.completed_ceremonies || 0)} completed • {Number(mpcOverview?.stats?.active_policies || 0)} active policies • {Number(mpcOverview?.stats?.total_keys || 0)} total quorum-backed keys
                </div>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Compliance Actions</div>
              <div style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>Quorum ceremony discipline</div>
                <div style={{ fontSize: 8, color: C.dim, marginTop: 4 }}>
                  Keep participant roster and threshold policy current, investigate failed ceremonies, and review stalled approvals so high-assurance signing does not fall back to single-holder controls.
                </div>
              </div>
            </div>
          </div>
        </Card>

        <div style={{ height: 10 }} />

        {/* ═══ ROW 2: Posture Breakdown + Key Hygiene ═══ */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          {/* Posture Category Breakdown */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Posture Breakdown</span>
              <B c="accent">{postureBreakdown ? `${Number(postureBreakdown.gap_count || 0)} gaps` : "-"}</B>
            </div>
            {breakdownBars.length > 0 ? (
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={breakdownBars} layout="vertical">
                  <XAxis type="number" domain={[0, 100]} tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} axisLine={false} tickLine={false} width={55} />
                  <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTip><span style={{ fontWeight: 700, color: payload[0]?.payload?.fill }}>{payload[0]?.payload?.name}</span>: {payload[0]?.value}/100</ChartTip> : null} cursor={{ fill: C.accentDim }} />
                  <RBar dataKey="value" radius={[0, 4, 4, 0]}>
                    {breakdownBars.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
                  </RBar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>Run an assessment to populate posture breakdown.</span></div>
            )}
          </Card>

          {/* Key Hygiene / Algorithm Distribution */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Key Hygiene</span>
              <B c="blue">{keyHygiene ? `${Number(keyHygiene.total_keys || 0)} keys` : "-"}</B>
            </div>
            {algoDistribution.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={110}>
                  <BarChart data={algoDistribution}>
                    <XAxis dataKey="name" tick={{ fill: C.dim, fontSize: 8 }} axisLine={{ stroke: C.border }} tickLine={false} />
                    <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={25} allowDecimals={false} />
                    <Tooltip content={({ active, payload, label }) => active && payload?.length ? <ChartTip><span style={{ fontWeight: 700, color: C.accent }}>{label}</span>: {payload[0]?.value} keys</ChartTip> : null} cursor={{ fill: C.accentDim }} />
                    <RBar dataKey="count" fill={C.accent} radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6, marginTop: 8 }}>
                  {[
                    ["Rotation", `${Math.round(Number(keyHygiene?.rotation_coverage_percent || 0))}%`, C.green],
                    ["Orphaned", Number(keyHygiene?.orphaned_count || 0), C.amber],
                    ["Expired", Number(keyHygiene?.expiring_count || 0), C.red]
                  ].map(([label, value, color]) => (
                    <div key={String(label)} style={{ textAlign: "center", padding: "6px 0", border: `1px solid ${C.border}`, borderRadius: 8 }}>
                      <div style={{ fontSize: 14, fontWeight: 700, color: color as string }}>{value}</div>
                      <div style={{ fontSize: 8, color: C.muted }}>{label}</div>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No key hygiene data</span></div>
            )}
          </Card>
        </div>

        <div style={{ height: 10 }} />

        {/* ═══ Score Trendline (AreaChart) ═══ */}
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Score Trendline</span>
            <B c="blue">{trendData.length ? `${trendData[trendData.length - 1]?.score || 0} latest` : "No history"}</B>
          </div>
          {trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={C.accent} stopOpacity={0.25} />
                    <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 8 }} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
                <YAxis domain={[0, 100]} tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={30} />
                <Tooltip content={({ active, payload, label }) => active && payload?.length ? <ChartTip><div style={{ fontWeight: 700, color: C.accent, marginBottom: 2 }}>{label}</div>Score: <span style={{ fontWeight: 700 }}>{payload[0]?.value}</span></ChartTip> : null} cursor={{ stroke: C.borderHi, strokeDasharray: "3 3" }} />
                <Area type="monotone" dataKey="score" stroke={C.accent} strokeWidth={2} fill="url(#scoreGrad)" dot={{ fill: C.accent, r: 2, strokeWidth: 0 }} activeDot={{ fill: C.accent, r: 4, stroke: C.bg, strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          ) : <div style={{ fontSize: 10, color: C.muted }}>Run more assessments to populate trendline.</div>}
        </Card>

        <div style={{ height: 10 }} />

        {/* ═══ Findings severity bar + list ═══ */}
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Findings</span>
            <B c={findings.length ? "amber" : "green"}>{findings.length ? `${findings.length} open` : "No open findings"}</B>
          </div>
          {/* Severity distribution bar */}
          {findingTotal > 0 && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ display: "flex", height: 12, borderRadius: 6, overflow: "hidden", border: `1px solid ${C.border}` }}>
                {findingSeverityCounts.critical > 0 && <div style={{ width: `${(findingSeverityCounts.critical / findingTotal) * 100}%`, background: C.red }} title={`Critical: ${findingSeverityCounts.critical}`} />}
                {findingSeverityCounts.high > 0 && <div style={{ width: `${(findingSeverityCounts.high / findingTotal) * 100}%`, background: C.amber }} title={`High: ${findingSeverityCounts.high}`} />}
                {findingSeverityCounts.warning > 0 && <div style={{ width: `${(findingSeverityCounts.warning / findingTotal) * 100}%`, background: C.amber }} title={`Warning: ${findingSeverityCounts.warning}`} />}
                {findingSeverityCounts.info > 0 && <div style={{ width: `${(findingSeverityCounts.info / findingTotal) * 100}%`, background: C.blue }} title={`Info: ${findingSeverityCounts.info}`} />}
              </div>
              <div style={{ display: "flex", gap: 12, marginTop: 4 }}>
                {[["Critical", findingSeverityCounts.critical, C.red], ["High", findingSeverityCounts.high, C.amber], ["Warning", findingSeverityCounts.warning, C.amber], ["Info", findingSeverityCounts.info, C.blue]].filter(([,c]) => (c as number) > 0).map(([label, count, color]) => (
                  <div key={String(label)} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.dim }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: color as string }} />
                    {label} ({count})
                  </div>
                ))}
              </div>
            </div>
          )}
          <div style={{ display: "grid", gap: 8 }}>
            {findings.map((finding: any, index: number) => (
              <Card key={String(finding?.id || finding?.title || index)} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
                <div>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{String(finding?.title || "")}</div>
                  <div style={{ fontSize: 10, color: C.dim, marginTop: 3 }}>{String(finding?.fix || "")}</div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ fontSize: 10, color: C.muted }}>{`${Number(finding?.count || 0)} item(s)`}</div>
                  <B c={toneForFinding(String(finding?.severity || ""))}>{String(finding?.severity || "open").toUpperCase()}</B>
                </div>
              </Card>
            ))}
            {!findings.length && !loading ? <Card><div style={{ fontSize: 10, color: C.muted }}>No active findings from current key/certificate state.</div></Card> : null}
          </div>
        </Card>

        <div style={{ height: 10 }} />

        {/* ═══ Compliance Gaps ═══ */}
        {frameworkGaps.length > 0 && (
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Compliance Gaps</span>
              <B c="red">{frameworkGaps.length} gaps</B>
            </div>
            <div style={{ maxHeight: 220, overflow: "auto", border: `1px solid ${C.border}`, borderRadius: 8 }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Title</th>
                    <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Severity</th>
                    <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Status</th>
                    <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {frameworkGaps.map((gap: any, idx: number) => (
                    <tr key={String(gap?.id || idx)} style={{ borderBottom: `1px solid ${C.border}` }}>
                      <td style={{ padding: "8px 10px", fontSize: 11, color: C.text }}>
                        <div style={{ fontWeight: 600 }}>{String(gap?.title || "-")}</div>
                        <div style={{ fontSize: 9, color: C.muted }}>{String(gap?.description || "").slice(0, 100)}</div>
                      </td>
                      <td style={{ padding: "8px 10px", fontSize: 10 }}>
                        <B c={toneForFinding(String(gap?.severity || ""))}>{String(gap?.severity || "-")}</B>
                      </td>
                      <td style={{ padding: "8px 10px", fontSize: 10, color: C.dim }}>{String(gap?.status || "-")}</td>
                      <td style={{ padding: "8px 10px", fontSize: 10, color: C.muted }}>{gap?.detected_at ? new Date(String(gap.detected_at)).toLocaleDateString() : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* ═══ Anomalies ═══ */}
        {anomalies.length > 0 && (
          <Card style={{ marginTop: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Security Anomalies</span>
              <B c="red">{anomalies.length} detected</B>
            </div>
            <div style={{ display: "grid", gap: 6 }}>
              {anomalies.slice(0, 10).map((a: any, idx: number) => (
                <div key={String(a?.id || idx)} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
                  <div>
                    <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{String(a?.type || "-")}</div>
                    <div style={{ fontSize: 9, color: C.dim }}>{String(a?.description || "")}</div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ fontSize: 9, color: C.muted }}>{a?.detected_at ? new Date(String(a.detected_at)).toLocaleDateString() : "-"}</span>
                    <B c={toneForFinding(String(a?.severity || ""))}>{String(a?.severity || "info")}</B>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        <div style={{ height: 10 }} />

        {/* ═══ Assessment History ═══ */}
        <Card>
          <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>Assessment History</div>
          <div style={{ display: "grid", gap: 6 }}>
            {(Array.isArray(history) ? history : []).slice(0, 10).map((item: any) => (
              <div key={String(item?.id || "")} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 10, padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <B c="blue">{String(item?.trigger || "manual").toUpperCase()}</B>
                  <span style={{ color: C.muted }}>{new Date(item?.created_at || Date.now()).toLocaleString()}</span>
                  <span style={{ color: C.dim }}>{String(item?.template_name || "Built-in Baseline")}</span>
                </div>
                <span style={{ color: C.text, fontWeight: 700 }}>{`${Number(item?.overall_score || 0)} / 100`}</span>
              </div>
            ))}
            {!history.length && !loading ? <div style={{ fontSize: 10, color: C.muted }}>No assessment history yet.</div> : null}
          </div>
        </Card>
      </Section>
      {promptDialog.ui}
    </div>
  );
};
