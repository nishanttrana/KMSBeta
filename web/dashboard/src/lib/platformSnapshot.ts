// Collects the live state the recommendation engine evaluates. Each source is
// loaded independently (allSettled): a service that is down or not licensed
// yields `undefined`, which the engine reports as "not assessed" rather than
// guessing.
import type { AuthSession } from "./auth";
import { listKeys, getKeyAccessSettings } from "./keycore";
import { listCertificates } from "./certs";
import { listPolicies as listRotationPolicies } from "./rotationScheduler";
import { listGovernancePolicies, listGovernanceBackups } from "./governance";
import { getPQCReadiness } from "./pqc";
import { listPostureFindings } from "./posture";
import { getClusterOverview } from "./cluster";
import { listAuthUsers } from "./authAdmin";
import type { PlatformSnapshot } from "./recommendations";

async function opt<T>(p: Promise<T>): Promise<T | undefined> {
  try {
    return await p;
  } catch {
    return undefined;
  }
}

export async function loadPlatformSnapshot(session: AuthSession, fipsEnabled?: boolean): Promise<PlatformSnapshot> {
  const [keys, certs, rotationPolicies, backups, keyAccess, governancePolicies, pqc, postureFindings, cluster, users] =
    await Promise.all([
      opt(listKeys(session, { limit: 5000 })),
      opt(listCertificates(session, { limit: 500 })),
      opt(listRotationPolicies(session)),
      opt(listGovernanceBackups(session, { limit: 200 })),
      opt(getKeyAccessSettings(session)),
      opt(listGovernancePolicies(session)),
      opt(getPQCReadiness(session).then((r) => r ?? null)),
      opt(listPostureFindings(session, { limit: 500 })),
      opt(getClusterOverview(session).then((c) => c?.summary)),
      opt(listAuthUsers(session)),
    ]);
  return {
    now: new Date(),
    keys,
    certs,
    rotationPolicies,
    backups: backups && backups.map((b) => ({ status: b.status, ...(b.completed_at ? { completed_at: b.completed_at } : {}), ...(b.created_at ? { created_at: b.created_at } : {}) })),
    keyAccess,
    governancePolicies: governancePolicies as Array<{ status?: string }> | undefined,
    pqc,
    postureFindings,
    cluster,
    users,
    fipsEnabled,
  };
}
