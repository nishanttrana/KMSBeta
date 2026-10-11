import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { EKMClient } from "../../src/lib/ekmClients";
import { ENGINES, ageNow, ago, checkInBars, installSteps, span, tiles } from "../../src/components/v3/tabs/ekm/meta";

const ROOT = join(__dirname, "..", "..", "..", "..");
const TH = { healthy_within_sec: 300, degraded_within_sec: 3600 };
const c = (health: EKMClient["health"], age?: number): EKMClient => ({
  id: health, name: health, db_engine: "oracle", host: "", registration: health === "pending" ? "pending" : "registered", health,
  source_ip: "", version: "", tde_state: "unknown", heartbeat_interval_sec: 30, assigned_key_id: "", assigned_key_version: "",
  credential: "", ...(age === undefined ? {} : { last_seen_age_sec: age }),
});
const at = (sec: number) => ({ at: new Date(1_800_000_000_000 + sec * 1000).toISOString(), source_ip: "", version: "", status: "connected" });

describe("EKM clients", () => {
  it("counts each client by the service's verdict, and each tile lists what it counts", () => {
    const rows = [c("healthy", 3), c("healthy", 200), c("degraded", 900), c("offline", 9000), c("pending")];
    const count = (key: string) => rows.filter(tiles(TH).find((t) => t.key === key)!.match).length;
    expect(["registered", "pending", "healthy", "degraded", "offline"].map(count)).toEqual([4, 1, 2, 1, 1]);
    expect(count("registered") + count("pending")).toBe(rows.length);
    // A client whose reported age and verdict disagree is counted by the verdict.
    expect(tiles(TH).find((t) => t.key === "healthy")!.match(c("degraded", 1))).toBe(false);
  });

  // A tile's hue marks a state that needs attention, never the tile itself.
  it("words the tiles from the service's thresholds and colours only what needs attention", () => {
    expect(tiles(TH).map((t) => t.hint)).toEqual(["", "", "within 5 min", "5 min to 60 min", "over 60 min"]);
    expect(tiles(TH).map((t) => t.attention ?? "")).toEqual(["", "blue", "", "amber", "red"]);
    expect(span(7200)).toBe("2 h");
  });

  it("ages the last check-in from the service's measurement, not the viewer's clock", () => {
    expect(ageNow(c("healthy", 10), 1000, 6000)).toBe(15);
    expect(ageNow(c("healthy", 10), 6000, 1000)).toBe(10);
    expect(ageNow(c("pending"), 0, 5000)).toBeUndefined();
    expect([ago(undefined), ago(2), ago(17), ago(1500), ago(11000), ago(200000)]).toEqual(["Never", "Just now", "17s ago", "25 min ago", "3 h 3 min ago", "2 d ago"]);
  });

  it("draws one bar per check-in after the first, shorter the later it came", () => {
    const bars = checkInBars([at(0), at(30), at(80), at(110), at(400)], 30);
    expect(bars.map((b) => b.kind)).toEqual(["ontime", "late", "ontime", "missed"]);
    expect(bars.map((b) => Math.round(b.gapSec))).toEqual([30, 50, 30, 290]);
    expect(bars[0]!.heightPct).toBe(100);
    expect(bars[1]!.heightPct).toBeLessThan(bars[0]!.heightPct);
    expect(bars[3]!.heightPct).toBe(18);
    expect(checkInBars([at(0)], 30)).toEqual([]);
    expect(checkInBars(Array.from({ length: 80 }, (_, i) => at(i * 30)), 30)).toHaveLength(30);
  });

  it("never puts the registration token on a command line", () => {
    for (const os of ["linux", "windows"] as const) {
      const steps = installSteps(os, "https://kms.example.com/svc/ekm");
      expect(steps).toHaveLength(3);
      expect(steps[1]!.cmd).toContain("-enroll -server https://kms.example.com/svc/ekm -token-file ");
      expect(steps.map((s) => s.cmd).join("\n")).not.toMatch(/vekm-reg|<token>|echo /);
    }
  });

  // The engines offered are the ones the service accepts, and the commands
  // use flags the agent defines and the file name its packages ship.
  it("offers what the service and the agent really have", () => {
    const service = readFileSync(join(ROOT, "services/ekm/util.go"), "utf8");
    const supported = (service.match(/func isSupportedTDEEngine[\s\S]*?case ([^\n]+):/) ?? [])[1]!.replace(/"/g, "").split(",").map((s) => s.trim()).sort();
    expect(ENGINES.map((e) => e.id).sort()).toEqual(supported);
    const agent = readFileSync(join(ROOT, "services/ekm-agent/main.go"), "utf8");
    for (const flag of ["enroll", "server", "token-file", "ca", "service"]) expect(agent).toContain(`"${flag}"`);
    expect(readFileSync(join(ROOT, "services/ekm-agent/scripts/package-windows-agent.ps1"), "utf8")).toContain('"ekm-agent.exe"');
    expect(readFileSync(join(ROOT, "services/ekm-agent/scripts/install-ekm-agent.sh"), "utf8")).toContain('AGENT_BIN="./ekm-agent"');
  });

  // Health is the service's verdict. The dashboard holds no threshold of its
  // own and never compares an age with one.
  it("never judges health itself", () => {
    for (const f of ["meta.ts", "Clients.tsx", "ClientDrawer.tsx", "CheckInStrip.tsx", "AddClientWizard.tsx"]) {
      const src = readFileSync(join(ROOT, "web/dashboard/src/components/v3/tabs/ekm", f), "utf8");
      expect(src, f).not.toMatch(/within_sec\s*[<>]|[<>]=?\s*[\w.]*within_sec|\b300\b|health\s*=\s*["'`]/);
    }
  });
});
