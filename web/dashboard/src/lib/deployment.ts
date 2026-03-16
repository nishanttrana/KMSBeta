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

const defaultDeployment: DeploymentConfig = {
  apiVersion: "kms.vecta.com/v1",
  kind: "DeploymentConfig",
  spec: {
    hsm_mode: "auto",
    features: {
      secrets: true,
      certs: true,
      governance: true,
      cloud_byok: true,
      hyok_proxy: true,
      kmip_server: true,
      qkd_interface: true,
      ekm_database: true,
      payment_crypto: true,
      compliance_dashboard: true,
      sbom_cbom: true,
      reporting_alerting: true,
      ai_llm: true,
      pqc_migration: true,
      crypto_discovery: true,
      mpc_engine: true,
      data_protection: true,
      clustering: true
    }
  }
};

const candidateUrls = [
  "/config/deployment.yaml",
  "/deployment.yaml",
  "/infra/deployment/deployment.yaml"
];

export async function loadDeploymentConfig(): Promise<DeploymentConfig> {
  for (const url of candidateUrls) {
    try {
      const response = await trackedFetch(url, { cache: "no-store" });
      if (!response.ok) {
        continue;
      }
      const body = await response.text();
      const parsed = YAML.parse(body) as DeploymentConfig;
      if (parsed?.spec) {
        return parsed;
      }
    } catch {
      // continue with next source
    }
  }
  return defaultDeployment;
}

export function enabledFeatures(config: DeploymentConfig): Set<FeatureKey> {
  const active = new Set<FeatureKey>();
  const features = config.spec?.features ?? {};
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
