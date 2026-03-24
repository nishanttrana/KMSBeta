import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const runInDocker = process.env.DASHBOARD_IN_DOCKER === "true";

function serviceURL(serviceName: string, port: number): string {
  if (runInDocker) {
    return `http://${serviceName}:${port}`;
  }
  return `http://127.0.0.1:${port}`;
}

export default defineConfig({
  plugins: [react()],

  build: {
    // esbuild minifier (default) — fast and produces smaller output than terser
    minify: "esbuild",
    // No source maps in production bundles — don't ship internal code paths
    sourcemap: false,
    // Warn when any single chunk exceeds 700 kB before compression.
    // tab-restapi includes swagger-ui (~670 kB) but is lazy-loaded on demand.
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        // Split vendor libraries into stable long-lived chunks so they are
        // cached independently from app code that changes on every release.
        manualChunks: (id) => {
          // ── Vendor: stable long-cached chunks ────────────────────────────
          if (id.includes("node_modules/react") || id.includes("node_modules/react-dom")) {
            return "vendor-react";
          }
          if (id.includes("node_modules/recharts") || id.includes("node_modules/d3-") || id.includes("node_modules/victory-")) {
            return "vendor-charts";
          }
          if (id.includes("node_modules/lucide-react")) {
            return "vendor-icons";
          }
          if (id.includes("node_modules/@tanstack")) {
            return "vendor-query";
          }
          if (id.includes("node_modules/zustand")) {
            return "vendor-state";
          }
          if (id.includes("node_modules/swagger-ui-dist")) {
            return "vendor-swagger";
          }
          // ── App: split the heaviest tab sub-components into own chunks ───
          // These are lazy-loaded from WorkbenchTab and only fetched on demand.
          if (id.includes("/tabs/TokenizeTab")) return "tab-tokenize";
          if (id.includes("/tabs/CryptoTab"))   return "tab-crypto";
          if (id.includes("/tabs/RestAPITab"))   return "tab-restapi";
          if (id.includes("/tabs/PaymentTab"))   return "tab-payment";
        }
      }
    }
  },

  server: {
    port: 5173,
    host: true,
    proxy: {
      "/auth": {
        target: serviceURL("auth", 8001),
        changeOrigin: true
      },
      "/svc/keycore": {
        target: serviceURL("keycore", 8010),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/keycore/, "")
      },
      "/svc/secrets": {
        target: serviceURL("secrets", 8020),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/secrets/, "")
      },
      "/svc/certs": {
        target: serviceURL("certs", 8030),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/certs/, "")
      },
      "/svc/policy": {
        target: serviceURL("policy", 8040),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/policy/, "")
      },
      "/svc/governance": {
        target: serviceURL("governance", 8050),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/governance/, "")
      },
      "/svc/pqc": {
        target: serviceURL("pqc", 8060),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/pqc/, "")
      },
      "/svc/audit": {
        target: serviceURL("audit", 8070),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/audit/, "")
      },
      "/svc/cloud": {
        target: serviceURL("cloud", 8080),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/cloud/, "")
      },
      "/svc/compliance": {
        target: serviceURL("compliance", 8110),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/compliance/, "")
      },
      "/svc/hyok": {
        target: serviceURL("hyok", 8120),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/hyok/, "")
      },
      "/svc/ekm": {
        target: serviceURL("ekm", 8130),
        changeOrigin: true,
        rewrite: (path) => {
          const out = path.replace(/^\/svc\/ekm/, "");
          return out === "" ? "/" : out;
        }
      },
      "/svc/kmip": {
        target: serviceURL("kmip", 8160),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/kmip/, "")
      },
      "/svc/reporting": {
        target: serviceURL("reporting", 8140),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/reporting/, "")
      },
      "/svc/posture": {
        target: serviceURL("posture", 8220),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/posture/, "")
      },
      "/svc/qkd": {
        target: serviceURL("qkd", 8150),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/qkd/, "")
      },
      "/svc/qrng": {
        target: serviceURL("qrng", 8230),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/qrng/, "")
      },
      "/svc/payment": {
        target: serviceURL("payment", 8170),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/payment/, "")
      },
      "/svc/confidential": {
        target: serviceURL("confidential", 8240),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/confidential/, "")
      },
      "/svc/sbom": {
        target: serviceURL("sbom", 8180),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/sbom/, "")
      },
      "/svc/dataprotect": {
        target: serviceURL("dataprotect", 8200),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/dataprotect/, "")
      },
      "/svc/mpc": {
        target: serviceURL("mpc", 8190),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/mpc/, "")
      },
      "/svc/cluster": {
        target: serviceURL("cluster-manager", 8210),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/cluster/, "")
      },
      "/svc/software-vault": {
        target: serviceURL("software-vault", 8440),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/software-vault/, "")
      },
      "/svc/auth": {
        target: serviceURL("auth", 8001),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/svc\/auth/, "")
      },
      "/api": {
        target: runInDocker ? "https://envoy:443" : "https://127.0.0.1:443",
        changeOrigin: true,
        secure: false
      }
    }
  }
});
