import YAML from "yaml";
import type { FeatureKey } from "../config/tabs";
import { trackedFetch } from "./serviceApi";

export type DeploymentConfig = {
  apiVersion?: string;
  kind?: string;
  metadata?: Record<string, unknown> & {
    install_mode?: "fast" | "interactive";
  };
  spec?: {
    hsm_mode?: "hardware" | "software" | "auto";
    features?: Partial<Record<FeatureKey, boolean>>;
  };
};

// The one deployment file (infra/deployment/deployment.yaml) is mounted into
// the dashboard container at /config/deployment.yaml; the image carries no
// copy of its own. A copy baked with every feature on showed the Cluster
// module where cluster-manager was never started (13.28.0-beta). Where the
// file can't be read the feature set is empty, which the shell treats as
// unknown.
const DEPLOYMENT_URL = "/config/deployment.yaml";

export async function loadDeploymentConfig(): Promise<DeploymentConfig> {
  try {
    const response = await trackedFetch(DEPLOYMENT_URL, { cache: "no-store" });
    if (!response.ok) {
      return {};
    }
    const parsed = YAML.parse(await response.text()) as DeploymentConfig;
    return parsed?.spec ? parsed : {};
  } catch {
    return {};
  }
}

export function enabledFeatures(config: DeploymentConfig): Set<FeatureKey> {
  const active = new Set<FeatureKey>();
  if (!config.spec) {
    return active;
  }
  const features = config.spec.features ?? {};
  (Object.keys(features) as FeatureKey[]).forEach((name) => {
    if (features[name]) {
      active.add(name);
    }
  });

  const mode = config.spec?.hsm_mode ?? "software";
  if (mode === "hardware") {
    active.add("hsm_hardware");
  } else if (mode === "software") {
    active.add("hsm_software");
  } else {
    active.add("hsm_hardware");
    active.add("hsm_software");
  }
  return active;
}
