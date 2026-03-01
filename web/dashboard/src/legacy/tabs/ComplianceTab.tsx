// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import {
  B,
  Bar,
  Btn,
  Card,
  Chk,
  FG,
  Inp,
  Row2,
  Section,
  Sel,
  usePromptDialog
} from "../../components/v3/legacyPrimitives";
import { C } from "../../components/v3/theme";
import { errMsg } from "../../components/v3/runtimeUtils";
import {
  deleteComplianceTemplate,
  getComplianceAssessment,
  getComplianceAssessmentSchedule,
  listComplianceAssessmentHistory,
  listComplianceFrameworkCatalog,
  listComplianceTemplates,
  runComplianceAssessment,
  updateComplianceAssessmentSchedule,
  upsertComplianceTemplate
} from "../../lib/compliance";
import {
  createReportingScheduledReport,
  deleteReportingReportJob,
  downloadReportingReport,
  generateReportingReport,
  getReportingReportJob,
  listReportingReportJobs,
  listReportingReportTemplates,
  listReportingScheduledReports
} from "../../lib/reporting";

export const ComplianceTab = ({ session, onToast }: any) => {
  const promptDialog = usePromptDialog();
  const [assessment, setAssessment] = useState<any>(null);
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
  const [reportTemplates, setReportTemplates] = useState<any[]>([]);
  const [reportJobs, setReportJobs] = useState<any[]>([]);
  const [scheduledReports, setScheduledReports] = useState<any[]>([]);
  const [reportForm, setReportForm] = useState<any>({
    template_id: "",
    format: "pdf"
  });
  const [scheduleForm, setScheduleForm] = useState<any>({
    name: "weekly-compliance",
    template_id: "",
    format: "pdf",
    schedule: "weekly",
    recipients: ""
  });
  const [reportBusy, setReportBusy] = useState(false);

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
    const numOr = (value: any, fallback: number) => {
      const n = Number(value);
      return Number.isFinite(n) ? n : fallback;
    };

    const sourceFrameworks = Array.isArray(input?.frameworks) ? input.frameworks : [];
    const sourceByID: any = {};
    sourceFrameworks.forEach((fw: any) => {
      const id = String(fw?.framework_id || "").trim();
      if (id) sourceByID[id] = fw;
    });

    const mergedFrameworks = frameworkSeed.map((base: any) => {
      const incoming = sourceByID[base.framework_id] || {};
      const controlByID: any = {};
      (Array.isArray(incoming?.controls) ? incoming.controls : []).forEach((ctrl: any) => {
        const id = String(ctrl?.id || "").trim();
        if (id) controlByID[id] = ctrl;
      });

      const mergedControls = (Array.isArray(base?.controls) ? base.controls : []).map((ctrl: any) => {
        const incomingCtrl = controlByID[ctrl.id] || {};
        return {
          ...ctrl,
          ...incomingCtrl,
          id: ctrl.id,
          title: String(incomingCtrl?.title || ctrl.title || ""),
          category: String(incomingCtrl?.category || ctrl.category || ""),
          requirement: String(incomingCtrl?.requirement || ctrl.requirement || ""),
          enabled: incomingCtrl?.enabled === undefined ? Boolean(ctrl.enabled) : Boolean(incomingCtrl.enabled),
          weight: Math.max(0.1, numOr(incomingCtrl?.weight, ctrl.weight || 1)),
          threshold: Math.max(1, Math.min(100, Math.round(numOr(incomingCtrl?.threshold, ctrl.threshold || 80))))
        };
      });

      return {
        ...base,
        ...incoming,
        framework_id: base.framework_id,
        label: String(incoming?.label || base.label || base.framework_id),
        enabled: incoming?.enabled === undefined ? Boolean(base.enabled) : Boolean(incoming.enabled),
        weight: Math.max(0.1, numOr(incoming?.weight, base.weight || 1)),
        controls: mergedControls
      };
    });

    return {
      id: String(input?.id || ""),
      tenant_id: String(input?.tenant_id || session?.tenantId || ""),
      name: String(input?.name || "Custom Compliance Template"),
      description: String(input?.description || ""),
      enabled: input?.enabled === undefined ? true : Boolean(input.enabled),
      frameworks: mergedFrameworks
    };
  };

  const loadTemplates = async () => {
    if (!session?.token) {
      setTemplates([]);
      setFrameworkCatalog([]);
      return { templates: [], frameworks: [] };
    }

    try {
      const [tplOut, catalogOut] = await Promise.all([
        listComplianceTemplates(session),
        listComplianceFrameworkCatalog(session)
      ]);
      const nextTemplates = Array.isArray(tplOut) ? tplOut : [];
      const nextCatalog = Array.isArray(catalogOut) ? catalogOut : [];
      setTemplates(nextTemplates);
      setFrameworkCatalog(nextCatalog);
      return { templates: nextTemplates, frameworks: nextCatalog };
    } catch (error) {
      onToast?.(`Compliance templates load failed: ${errMsg(error)}`);
      return { templates: [], frameworks: [] };
    }
  };

  const loadAssessment = async (opts: any = {}) => {
    if (!session?.token) {
      setAssessment(null);
      setHistory([]);
      setSchedule({ enabled: false, frequency: "daily" });
      return;
    }

    if (!opts?.silent) setLoading(true);
    try {
      const payload = await loadTemplates();
      const candidateTemplateID = String((opts?.templateId ?? selectedTemplateID) || "default");
      const hasTemplate = candidateTemplateID === "default" || payload.templates.some((item: any) => String(item?.id || "") === candidateTemplateID);
      const effectiveTemplateID = hasTemplate ? candidateTemplateID : "default";
      if (effectiveTemplateID !== selectedTemplateID) setSelectedTemplateID(effectiveTemplateID);

      const [assessOut, scheduleOut, historyOut] = await Promise.all([
        getComplianceAssessment(session, effectiveTemplateID),
        getComplianceAssessmentSchedule(session),
        listComplianceAssessmentHistory(session, 20, effectiveTemplateID)
      ]);

      setAssessment(assessOut || null);
      setSchedule(scheduleOut || { enabled: false, frequency: "daily" });
      setHistory(Array.isArray(historyOut) ? historyOut : []);

      if (effectiveTemplateID === "default") {
        setTemplateDraft(null);
      } else {
        const selected = payload.templates.find((item: any) => String(item?.id || "") === effectiveTemplateID);
        setTemplateDraft(selected ? buildTemplateDraft(selected) : null);
      }
    } catch (error) {
      onToast?.(`Compliance assessment load failed: ${errMsg(error)}`);
    } finally {
      if (!opts?.silent) setLoading(false);
    }
  };

  const loadReporting = async () => {
    if (!session?.token) {
      setReportTemplates([]);
      setReportJobs([]);
      setScheduledReports([]);
      return;
    }
    try {
      const [templatesOut, jobsOut, scheduledOut] = await Promise.all([
        listReportingReportTemplates(session),
        listReportingReportJobs(session, 40, 0),
        listReportingScheduledReports(session)
      ]);
      const templates = Array.isArray(templatesOut) ? templatesOut : [];
      const jobs = Array.isArray(jobsOut) ? jobsOut : [];
      const scheduled = Array.isArray(scheduledOut) ? scheduledOut : [];
      setReportTemplates(templates);
      setReportJobs(jobs);
      setScheduledReports(scheduled);
      if (!reportForm.template_id && templates.length) {
        setReportForm((prev: any) => ({ ...prev, template_id: String(templates[0]?.id || "") }));
      }
      if (!scheduleForm.template_id && templates.length) {
        setScheduleForm((prev: any) => ({ ...prev, template_id: String(templates[0]?.id || "") }));
      }
    } catch (error) {
      onToast?.(`Reporting load failed: ${errMsg(error)}`);
    }
  };

  useEffect(() => {
    void loadAssessment({ templateId: "default" });
  }, [session?.token, session?.tenantId]);

  useEffect(() => {
    if (view === "reporting") {
      void loadReporting();
    }
  }, [view, session?.token, session?.tenantId]);

  const runNow = async () => {
    if (!session?.token) {
      onToast?.("Login is required.");
      return;
    }
    setRunning(true);
    try {
      const out = await runComplianceAssessment(session, { templateId: selectedTemplateID, recompute: true });
      setAssessment(out || null);
      const hist = await listComplianceAssessmentHistory(session, 20, selectedTemplateID);
      setHistory(Array.isArray(hist) ? hist : []);
      onToast?.("Compliance assessment completed.");
    } catch (error) {
      onToast?.(`Assessment run failed: ${errMsg(error)}`);
    } finally {
      setRunning(false);
    }
  };

  const saveSchedule = async () => {
    if (!session?.token) {
      onToast?.("Login is required.");
      return;
    }
    setSavingSchedule(true);
    try {
      const out = await updateComplianceAssessmentSchedule(session, {
        enabled: Boolean(schedule?.enabled),
        frequency: String(schedule?.frequency || "daily") as any
      });
      setSchedule(out || schedule);
      onToast?.("Assessment schedule updated.");
    } catch (error) {
      onToast?.(`Schedule update failed: ${errMsg(error)}`);
    } finally {
      setSavingSchedule(false);
    }
  };

  const createTemplate = async () => {
    if (!session?.token) {
      onToast?.("Login is required.");
      return;
    }

    const nameInput = await promptDialog.prompt({
      title: "Create Compliance Template",
      message: "Provide a name for the custom compliance template.",
      placeholder: "Template name",
      confirmLabel: "Create",
      cancelLabel: "Cancel",
      validate: (value: string) => (String(value || "").trim() ? "" : "Template name is required.")
    });

    const name = String(nameInput || "").trim();
    if (!name) return;

    setSavingTemplate(true);
    try {
      const out = await upsertComplianceTemplate(session, {
        name,
        description: "",
        enabled: true,
        frameworks: Array.isArray(templateDraft?.frameworks) && templateDraft.frameworks.length ? templateDraft.frameworks : frameworkSeed
      } as any);
      const nextID = String(out?.id || "").trim();
      if (nextID) setSelectedTemplateID(nextID);
      await loadAssessment({ silent: true, templateId: nextID || "default" });
      onToast?.("Compliance template created.");
    } catch (error) {
      onToast?.(`Template create failed: ${errMsg(error)}`);
    } finally {
      setSavingTemplate(false);
    }
  };

  const saveTemplate = async () => {
    if (!session?.token) {
      onToast?.("Login is required.");
      return;
    }
    if (selectedTemplateID === "default") {
      onToast?.("Built-in template is read-only. Create a custom template first.");
      return;
    }
    if (!templateDraft) {
      onToast?.("No template selected.");
      return;
    }

    setSavingTemplate(true);
    try {
      const out = await upsertComplianceTemplate(session, {
        id: selectedTemplateID,
        name: String(templateDraft?.name || "").trim(),
        description: String(templateDraft?.description || "").trim(),
        enabled: Boolean(templateDraft?.enabled),
        frameworks: Array.isArray(templateDraft?.frameworks) ? templateDraft.frameworks : []
      } as any);
      setTemplateDraft(buildTemplateDraft(out || templateDraft));
      await loadAssessment({ silent: true, templateId: selectedTemplateID });
      onToast?.("Compliance template saved.");
    } catch (error) {
      onToast?.(`Template save failed: ${errMsg(error)}`);
    } finally {
      setSavingTemplate(false);
    }
  };

  const removeTemplate = async () => {
    if (!session?.token) {
      onToast?.("Login is required.");
      return;
    }
    if (selectedTemplateID === "default") {
      onToast?.("Built-in template cannot be deleted.");
      return;
    }

    const ok = await promptDialog.confirm({
      title: "Delete Template",
      message: "Delete selected compliance template?",
      confirmLabel: "Delete",
      cancelLabel: "Cancel",
      danger: true
    });
    if (!ok) return;

    setDeletingTemplate(true);
    try {
      await deleteComplianceTemplate(session, selectedTemplateID);
      setSelectedTemplateID("default");
      setTemplateDraft(null);
      await loadAssessment({ silent: true, templateId: "default" });
      onToast?.("Compliance template deleted.");
    } catch (error) {
      onToast?.(`Template delete failed: ${errMsg(error)}`);
    } finally {
      setDeletingTemplate(false);
    }
  };

  const patchFramework = (frameworkID: string, patch: any) => {
    setTemplateDraft((prev: any) => {
      if (!prev) return prev;
      const frameworks = (Array.isArray(prev?.frameworks) ? prev.frameworks : []).map((fw: any) => {
        if (String(fw?.framework_id || "") !== frameworkID) return fw;
        return { ...fw, ...patch };
      });
      return { ...prev, frameworks };
    });
  };

  const patchControl = (frameworkID: string, controlID: string, patch: any) => {
    setTemplateDraft((prev: any) => {
      if (!prev) return prev;
      const frameworks = (Array.isArray(prev?.frameworks) ? prev.frameworks : []).map((fw: any) => {
        if (String(fw?.framework_id || "") !== frameworkID) return fw;
        const controls = (Array.isArray(fw?.controls) ? fw.controls : []).map((ctrl: any) => {
          if (String(ctrl?.id || "") !== controlID) return ctrl;
          return { ...ctrl, ...patch };
        });
        return { ...fw, controls };
      });
      return { ...prev, frameworks };
    });
  };

  const templateOptions = [
    { id: "default", name: "Built-in Baseline" },
    ...(Array.isArray(templates) ? templates : []).map((item: any) => ({ id: String(item?.id || ""), name: String(item?.name || item?.id || "Custom Template") }))
  ];

  const frameworkScores = assessment?.framework_scores || {};
  const labelByID: any = {};
  (Array.isArray(frameworkCatalog) ? frameworkCatalog : []).forEach((fw: any) => {
    const id = String(fw?.id || "").trim();
    if (id) labelByID[id] = String(`${String(fw?.name || id).trim()} ${String(fw?.version || "").trim()}`).trim();
  });
  (Array.isArray(templateDraft?.frameworks) ? templateDraft.frameworks : []).forEach((fw: any) => {
    const id = String(fw?.framework_id || "").trim();
    if (id && String(fw?.label || "").trim()) labelByID[id] = String(fw.label);
  });

  const frameworkIDs = Array.from(new Set([
    ...Object.keys(frameworkScores || {}),
    ...(Array.isArray(templateDraft?.frameworks) ? templateDraft.frameworks.map((fw: any) => String(fw?.framework_id || "")).filter(Boolean) : [])
  ]));

  const palette = [C.green, C.blue, C.amber, C.accent];
  const frameworkRows = frameworkIDs.map((id, idx) => {
    const score = Math.max(0, Math.min(100, Number(frameworkScores?.[id] || 0)));
    return { id, label: labelByID[id] || id, score, color: palette[idx % palette.length] };
  });

  const pqc = assessment?.pqc || {};
  const pqcReady = Math.max(0, Math.min(100, Number(pqc?.ready_percent || assessment?.posture?.pqc_readiness || 0)));
  const findings = Array.isArray(assessment?.findings) ? assessment.findings : [];
  const score = Math.max(0, Math.min(100, Number(assessment?.overall_score || assessment?.posture?.overall_score || 0)));

  const toneForFinding = (severity: string) => {
    const s = String(severity || "").toLowerCase();
    if (s === "critical") return "red";
    if (s === "high") return "amber";
    if (s === "warning" || s === "medium") return "amber";
    return "blue";
  };

  const trendData = useMemo(() => {
    const items = Array.isArray(history) ? [...history] : [];
    items.sort((a: any, b: any) => new Date(String(a?.created_at || 0)).getTime() - new Date(String(b?.created_at || 0)).getTime());
    return items.slice(-12).map((item: any) => ({
      id: String(item?.id || ""),
      score: Math.max(0, Math.min(100, Number(item?.overall_score || 0))),
      at: String(item?.created_at || "")
    }));
  }, [history]);

  const trendPoints = trendData.map((item: any, index: number) => {
    const x = trendData.length === 1 ? 50 : (index / (trendData.length - 1)) * 100;
    const y = 100 - Math.max(0, Math.min(100, Number(item?.score || 0)));
    return {
      ...item,
      x,
      y: Math.max(4, Math.min(96, y)),
      label: new Date(String(item?.at || Date.now())).toLocaleDateString(undefined, { month: "short", day: "numeric" })
    };
  });
  const trendPolyline = trendPoints.map((point: any) => `${point.x},${point.y}`).join(" ");

  const triggerReportNow = async () => {
    if (!session?.token) {
      onToast?.("Login is required.");
      return;
    }
    if (!String(reportForm?.template_id || "").trim()) {
      onToast?.("Select a report template.");
      return;
    }
    setReportBusy(true);
    try {
      const created = await generateReportingReport(session, {
        template_id: String(reportForm.template_id || "").trim(),
        format: String(reportForm.format || "pdf").trim().toLowerCase(),
        requested_by: String(session?.username || "dashboard")
      });
      const stable = await getReportingReportJob(session, String(created?.id || ""));
      onToast?.(`Report queued: ${String(stable?.id || created?.id || "").slice(0, 12)}...`);
      await loadReporting();
    } catch (error) {
      onToast?.(`Report generation failed: ${errMsg(error)}`);
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
      for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: String(out?.content_type || "application/octet-stream") });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const ext = String(job?.format || "bin").toLowerCase();
      a.href = url;
      a.download = `${String(job?.template_id || "report")}-${String(job?.id || "job")}.${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      onToast?.(`Download failed: ${errMsg(error)}`);
    }
  };

  const deleteJob = async (job: any) => {
    if (!session?.token) return;
    const ok = await promptDialog.confirm({
      title: "Delete Report",
      message: `Delete report job ${String(job?.id || "").slice(0, 16)}?`,
      confirmLabel: "Delete",
      cancelLabel: "Cancel",
      danger: true
    });
    if (!ok) return;
    try {
      await deleteReportingReportJob(session, String(job?.id || ""));
      onToast?.("Report deleted.");
      await loadReporting();
    } catch (error) {
      onToast?.(`Delete report failed: ${errMsg(error)}`);
    }
  };

  const createSchedule = async () => {
    if (!session?.token) {
      onToast?.("Login is required.");
      return;
    }
    if (!String(scheduleForm?.template_id || "").trim()) {
      onToast?.("Select a template for schedule.");
      return;
    }
    setReportBusy(true);
    try {
      await createReportingScheduledReport(session, {
        name: String(scheduleForm?.name || "weekly-compliance").trim() || "weekly-compliance",
        template_id: String(scheduleForm?.template_id || "").trim(),
        format: String(scheduleForm?.format || "pdf").trim().toLowerCase(),
        schedule: String(scheduleForm?.schedule || "weekly").trim().toLowerCase() as any,
        recipients: String(scheduleForm?.recipients || "")
          .split(",")
          .map((v) => String(v || "").trim())
          .filter(Boolean)
      });
      onToast?.("Scheduled report created.");
      await loadReporting();
    } catch (error) {
      onToast?.(`Create schedule failed: ${errMsg(error)}`);
    } finally {
      setReportBusy(false);
    }
  };

  if (view === "reporting") {
    return (
      <div>
        <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
          <Btn
            small
            onClick={() => setView("assessment")}
            style={{ background: "transparent", borderColor: C.border, color: C.text, height: 28 }}
          >
            Assessment
          </Btn>
          <Btn
            small
            onClick={() => setView("reporting")}
            style={{ background: C.accentDim, borderColor: C.accent, color: C.accent, height: 28 }}
          >
            Reporting
          </Btn>
        </div>

        <Section
          title="Compliance Reporting"
          actions={<Btn small onClick={() => void loadReporting()} disabled={reportBusy}>{reportBusy ? "Working..." : "Refresh"}</Btn>}
        >
          <Row2>
            <Card>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>Generate Report</div>
              <div style={{ display: "grid", gap: 8 }}>
                <FG label="Template">
                  <Sel value={String(reportForm?.template_id || "")} onChange={(e) => setReportForm((prev: any) => ({ ...prev, template_id: e.target.value }))}>
                    <option value="">Select template</option>
                    {(Array.isArray(reportTemplates) ? reportTemplates : []).map((t: any) => (
                      <option key={String(t?.id || "")} value={String(t?.id || "")}>{String(t?.name || t?.id || "template")}</option>
                    ))}
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
                    {(Array.isArray(reportTemplates) ? reportTemplates : []).map((t: any) => (
                      <option key={String(t?.id || "")} value={String(t?.id || "")}>{String(t?.name || t?.id || "template")}</option>
                    ))}
                  </Sel>
                </FG>
                <Row2>
                  <FG label="Format">
                    <Sel value={String(scheduleForm?.format || "pdf")} onChange={(e) => setScheduleForm((prev: any) => ({ ...prev, format: e.target.value }))}>
                      <option value="pdf">PDF</option>
                      <option value="json">JSON</option>
                      <option value="csv">CSV</option>
                    </Sel>
                  </FG>
                  <FG label="Schedule">
                    <Sel value={String(scheduleForm?.schedule || "weekly")} onChange={(e) => setScheduleForm((prev: any) => ({ ...prev, schedule: e.target.value }))}>
                      <option value="hourly">Hourly</option>
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                    </Sel>
                  </FG>
                </Row2>
                <FG label="Recipients (comma separated)">
                  <Inp value={String(scheduleForm?.recipients || "")} onChange={(e) => setScheduleForm((prev: any) => ({ ...prev, recipients: e.target.value }))} placeholder="admin@org.com,security@org.com" />
                </FG>
                <div><Btn small onClick={() => void createSchedule()} disabled={reportBusy}>{reportBusy ? "Saving..." : "Create Schedule"}</Btn></div>
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

  return (
    <div>
      <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
        <Btn
          small
          onClick={() => setView("assessment")}
          style={{ background: C.accentDim, borderColor: C.accent, color: C.accent, height: 28 }}
        >
          Assessment
        </Btn>
        <Btn
          small
          onClick={() => setView("reporting")}
          style={{ background: "transparent", borderColor: C.border, color: C.text, height: 28 }}
        >
          Reporting
        </Btn>
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
            <Btn small primary onClick={() => void runNow()} disabled={running}>{running ? "Running..." : "Run Assessment"}</Btn>
            <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "2px 8px", border: `1px solid ${C.border}`, borderRadius: 8 }}>
              <Chk label="Scheduled" checked={Boolean(schedule?.enabled)} onChange={() => setSchedule((prev: any) => ({ ...prev, enabled: !prev?.enabled }))} />
              <Sel w={96} value={String(schedule?.frequency || "daily")} onChange={(e) => setSchedule((prev: any) => ({ ...prev, frequency: e.target.value }))}>
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </Sel>
              <Btn small onClick={() => void saveSchedule()} disabled={savingSchedule}>{savingSchedule ? "Saving..." : "Save"}</Btn>
            </div>
          </div>
        }
      >
        <div style={{ fontSize: 10, color: C.muted, marginBottom: 8 }}>
          Assessment is calculated from real key/certificate posture and scored against the selected template ({selectedTemplateID === "default" ? "Built-in Baseline" : "Custom Template"}).
        </div>

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

        <Row2>
          <Card>
            <div style={{ display: "grid", gridTemplateColumns: "126px 1fr", gap: 10 }}>
              <Card style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                <div style={{ fontSize: 48, lineHeight: 1, fontWeight: 800, color: C.accent }}>{score}</div>
                <div style={{ fontSize: 11, color: C.dim }}>/ 100</div>
                <div style={{ width: "100%", marginTop: 8 }}><Bar pct={score} color={score >= 85 ? C.green : score >= 65 ? C.blue : C.amber} /></div>
              </Card>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8 }}>
                {frameworkRows.map((row) => (
                  <Card key={row.id}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, marginBottom: 4 }}>
                      <span style={{ color: C.text, fontWeight: 700 }}>{row.label}</span>
                      <span style={{ color: row.score >= 85 ? C.green : row.score >= 65 ? C.blue : C.amber, fontWeight: 700 }}>{row.score}%</span>
                    </div>
                    <Bar pct={row.score} color={row.color} />
                  </Card>
                ))}
              </div>
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>Post-Quantum Readiness</div>
            <div style={{ fontSize: 54, lineHeight: 1, fontWeight: 800, color: C.green, textAlign: "center", marginTop: 4 }}>{`${Math.round(pqcReady)}%`}</div>
            <div style={{ fontSize: 11, color: C.dim, textAlign: "center", marginTop: 6 }}>PQC-ready keys</div>
            <div style={{ height: 8 }} />
            {[["ML-KEM migrated", Number(pqc?.ml_kem_migrated || 0)], ["ML-DSA migrated", Number(pqc?.ml_dsa_migrated || 0)], ["Pending", Number(pqc?.pending || 0)]].map(([k, v]) => (
              <div key={String(k)} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, padding: "4px 0", borderBottom: `1px solid ${C.border}` }}>
                <span style={{ color: C.muted }}>{k}</span>
                <span style={{ color: C.text, fontWeight: 700 }}>{Number(v).toLocaleString()}</span>
              </div>
            ))}
          </Card>
        </Row2>

        <div style={{ height: 10 }} />
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>Score Trendline (Previous Scans)</div>
            <B c="blue">{trendPoints.length ? `${trendPoints[trendPoints.length - 1]?.score || 0} latest` : "No history"}</B>
          </div>
          {trendPoints.length ? (
            <div>
              <div style={{ height: 140, border: `1px solid ${C.border}`, borderRadius: 10, padding: 8, background: C.card }}>
                <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ width: "100%", height: "100%", display: "block" }}>
                  {[100, 75, 50, 25, 0].map((tick: number) => <line key={tick} x1="0" x2="100" y1={100 - tick} y2={100 - tick} stroke={C.border} strokeWidth="0.6" />)}
                  <polyline fill="none" stroke={C.accent} strokeWidth="2" points={trendPolyline} />
                  {trendPoints.map((point: any, index: number) => <circle key={`${point.id}-${index}`} cx={point.x} cy={point.y} r="2" fill={C.accent} />)}
                </svg>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: C.dim, marginTop: 6 }}>
                <span>{trendPoints[0]?.label || "-"}</span>
                <span>{trendPoints[trendPoints.length - 1]?.label || "-"}</span>
              </div>
            </div>
          ) : <div style={{ fontSize: 10, color: C.muted }}>Run more assessments to populate trendline.</div>}
        </Card>

        <div style={{ height: 10 }} />
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>Findings</div>
            <B c={findings.length ? "amber" : "green"}>{findings.length ? `${findings.length} open` : "No open findings"}</B>
          </div>
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
