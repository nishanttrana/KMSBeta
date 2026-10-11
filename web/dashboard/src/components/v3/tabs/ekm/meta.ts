import type { LucideIcon } from "lucide-react";
import { Clock, Database, Wifi, WifiOff } from "lucide-react";
import type { EKMClient, EKMClientCheckIn, EKMClientHealth, EKMClientThresholds } from "../../../../lib/ekmClients";
import type { Drill } from "../../chartDrill";
import { C } from "../../theme";

export const MONO = "var(--font-mono)";

// Health is the service's verdict (services/ekm/clients.go clientHealth); the
// dashboard only names and colours it.
export const HEALTH: Record<EKMClientHealth, { label: string; tone: "green" | "amber" | "red" | "blue"; fg: string; bg: string; icon: LucideIcon }> = {
  healthy: { label: "Healthy", tone: "green", fg: C.greenFg, bg: C.greenDim, icon: Wifi },
  degraded: { label: "Degraded", tone: "amber", fg: C.amberFg, bg: C.amberDim, icon: WifiOff },
  offline: { label: "Offline", tone: "red", fg: C.redFg, bg: C.redDim, icon: WifiOff },
  pending: { label: "Awaiting registration", tone: "blue", fg: C.blueFg, bg: C.blueDim, icon: Clock },
};

// The engines the service registers a client for (isSupportedTDEEngine).
export const ENGINES = [
  { id: "mssql", label: "SQL Server" },
  { id: "oracle", label: "Oracle" },
  { id: "postgresql", label: "PostgreSQL" },
  { id: "mysql", label: "MySQL" },
  { id: "db2", label: "Db2" },
  { id: "mariadb", label: "MariaDB" },
];
export const engineLabel = (id: string) => ENGINES.find((e) => e.id === id)?.label ?? id;

// The service's own rule, shown before the request is made.
export const CLIENT_NAME = /^[A-Za-z0-9._-]{3,40}$/;

export const span = (sec: number) => (sec % 3600 === 0 && sec >= 7200 ? `${sec / 3600} h` : `${Math.round(sec / 60)} min`);

export function ago(sec: number | undefined): string {
  if (sec === undefined || !Number.isFinite(sec)) return "Never";
  const s = Math.max(0, Math.round(sec));
  if (s < 5) return "Just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ${m % 60} min ago`;
  return `${Math.floor(h / 24)} d ago`;
}

// Age of the last check-in now: what the service measured, plus the time
// since it answered. The viewer's clock is never compared with the server's.
export function ageNow(c: EKMClient, fetchedAt: number, now: number): number | undefined {
  if (c.last_seen_age_sec === undefined) return undefined;
  return c.last_seen_age_sec + Math.max(0, now - fetchedAt) / 1000;
}

export function fmtTime(v?: string): string {
  if (!v) return "-";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return "-";
  return d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" });
}

// Tiles are counted and drilled with the same predicates over the same rows.
// A tile takes a hue only while its count is a state that needs attention.
export type ClientDrill = Drill<EKMClient> & { key: string };
export type ClientTile = ClientDrill & { hint: string; icon: LucideIcon; attention?: "blue" | "amber" | "red" };

export function tiles(th: EKMClientThresholds): ClientTile[] {
  const lo = span(th.healthy_within_sec);
  const hi = span(th.degraded_within_sec);
  return [
    { key: "registered", label: "Registered", hint: "", icon: Database, match: (c) => c.registration === "registered" },
    { key: "pending", label: "Awaiting registration", hint: "", icon: Clock, attention: "blue", match: (c) => c.registration === "pending" },
    { key: "healthy", label: "Healthy", hint: `within ${lo}`, icon: Wifi, match: (c) => c.health === "healthy" },
    { key: "degraded", label: "Degraded", hint: `${lo} to ${hi}`, icon: WifiOff, attention: "amber", match: (c) => c.health === "degraded" },
    { key: "offline", label: "Offline", hint: `over ${hi}`, icon: WifiOff, attention: "red", match: (c) => c.health === "offline" },
  ];
}

// One bar per check-in: how long after the one before it arrived, against
// the interval the agent is configured for. Height carries the same reading
// as the fill, so the strip doesn't depend on colour.
export type BarKind = "ontime" | "late" | "missed";
export const BAR: Record<BarKind, { label: string; fill: string }> = {
  ontime: { label: "On time", fill: "var(--cls-ontime)" },
  late: { label: "Late", fill: "var(--cls-late)" },
  missed: { label: "Check-ins missed before it", fill: "var(--cls-missed)" },
};
export type CheckInBar = { entry: EKMClientCheckIn; gapSec: number; kind: BarKind; heightPct: number };

export function checkInBars(checkIns: EKMClientCheckIn[], intervalSec: number, max = 30): CheckInBar[] {
  const interval = Math.max(1, intervalSec);
  const rows = checkIns.slice(-(max + 1));
  const out: CheckInBar[] = [];
  for (let i = 1; i < rows.length; i++) {
    const gapSec = Math.max(0, (new Date(rows[i]!.at).getTime() - new Date(rows[i - 1]!.at).getTime()) / 1000);
    const ratio = gapSec / interval;
    const kind: BarKind = ratio > 4 ? "missed" : ratio > 1.6 ? "late" : "ontime";
    out.push({ entry: rows[i]!, gapSec, kind, heightPct: Math.max(18, Math.min(100, 100 - (ratio - 1) * 25)) });
  }
  return out;
}

export function gap(sec: number): string {
  const s = Math.round(sec);
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

// Commands for the database host. The token is pasted into a file the agent
// reads and removes; it is never part of a command line.
export type TargetOS = "linux" | "windows";
export function installSteps(os: TargetOS, server: string): { label: string; cmd: string }[] {
  if (os === "windows") {
    const dir = "$env:ProgramData\\Vecta\\EKMAgent";
    return [
      { label: "Paste the token into the file that opens, then save and close it", cmd: `New-Item -ItemType Directory -Force "${dir}" | Out-Null; notepad "${dir}\\registration-token"` },
      { label: "Register this host", cmd: `.\\ekm-agent.exe -enroll -server ${server} -token-file "${dir}\\registration-token"` },
      { label: "Run the agent as a service", cmd: ".\\ekm-agent.exe -service install; .\\ekm-agent.exe -service start" },
    ];
  }
  return [
    { label: "Paste the token, press Enter, then Ctrl-D", cmd: "sudo sh -c 'umask 077; mkdir -p /etc/vecta-ekm; cat > /etc/vecta-ekm/registration-token'" },
    { label: "Register this host", cmd: `sudo ./ekm-agent -enroll -server ${server} -token-file /etc/vecta-ekm/registration-token` },
    { label: "Run the agent as a service", cmd: "sudo ./ekm-agent -service install && sudo ./ekm-agent -service start" },
  ];
}
