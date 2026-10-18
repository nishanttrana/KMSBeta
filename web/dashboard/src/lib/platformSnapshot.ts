// Collects the live state the recommendation engine evaluates. Each source is
// loaded independently (allSettled): a service that is down or not licensed
// yields `undefined`, which the engine reports as "not assessed" rather than
// guessing.
import type { AuthSession } from "./auth";
import { listKeys, getKeyAccessSettings } from "./keycore";
import { getCertSummary, listCertificates } from "./certs";
import { listPolicies as listRotationPolicies } from "./rotationScheduler";
import { listGovernancePolicies, listGovernanceBackups } from "./governance";
import { getPQCReadiness } from "./pqc";
import { getAgilityPosture } from "./cryptoAgility";
import { getPostureRisk, listPostureFindings } from "./posture";
import { getClusterOverview } from "./cluster";
import { listAuthUsers } from "./authAdmin";
import type { KeyAlgorithmFacts, PlatformSnapshot } from "./recommendations";

// True only for a real capture time. The posture service answers a tenant it
// has never scanned with a zero time, which is not a scan.
export function scanOnRecord(capturedAt?: string): boolean {
  return Date.parse(capturedAt || "") > 0;
}

async function opt<T>(p: Promise<T>): Promise<T | undefined> {
  try {
    return await p;
  } catch {
    return undefined;
  }
}

// clustered is false where the clustering feature is not deployed: there is
// no cluster service to ask, and asking drew a 503 on every load.
export async function loadPlatformSnapshot(session: AuthSession, fipsEnabled?: boolean, clustered = true): Promise<PlatformSnapshot> {
  const [keys, keyAlgorithms, certs, certSummary, rotationPolicies, backups, keyAccess, governancePolicies, pqc, postureFindings, postureRisk, cluster, users] =
    await Promise.all([
      opt(listKeys(session, { limit: 5000 })),
      opt(getAgilityPosture(session).then((p) => p.algorithms as KeyAlgorithmFacts[])),
      opt(listCertificates(session, { limit: 500 })),
      opt(getCertSummary(session)),
      opt(listRotationPolicies(session)),
      opt(listGovernanceBackups(session, { limit: 200 })),
      opt(getKeyAccessSettings(session)),
      opt(listGovernancePolicies(session)),
      opt(getPQCReadiness(session).then((r) => r ?? null)),
      opt(listPostureFindings(session, { limit: 500 })),
      opt(getPostureRisk(session)),
      clustered ? opt(getClusterOverview(session).then((c) => c?.summary)) : Promise.resolve(undefined),
      opt(listAuthUsers(session)),
    ]);
  return {
    now: new Date(),
    keys,
    keyAlgorithms,
    certs,
    certSummary,
    rotationPolicies,
    backups: backups && backups.map((b) => ({ status: b.status, ...(b.completed_at ? { completed_at: b.completed_at } : {}), ...(b.created_at ? { created_at: b.created_at } : {}) })),
    keyAccess,
    governancePolicies: governancePolicies as Array<{ status?: string }> | undefined,
    pqc,
    postureFindings,
    // A posture scan stores a risk snapshot; without one, an empty findings
    // list means "never evaluated", not "nothing found".
    postureEvaluated: postureRisk ? scanOnRecord(postureRisk.captured_at) : undefined,
    cluster,
    users,
    fipsEnabled,
  };
}
