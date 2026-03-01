import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { getSession } from "./lib/auth";
import { captureFrontendError } from "./lib/telemetry";
import "./index.css";

const queryClient = new QueryClient();

function normalizeDashboardURL(): void {
  const current = new URL(window.location.href);
  let changed = false;

  if (current.pathname.endsWith("/index.html")) {
    const nextPath = current.pathname.slice(0, -"/index.html".length);
    current.pathname = nextPath || "/";
    changed = true;
  }

  if (current.searchParams.has("b")) {
    current.searchParams.delete("b");
    changed = true;
  }

  if (!changed) {
    return;
  }

  const search = current.searchParams.toString();
  const nextURL = `${current.pathname}${search ? `?${search}` : ""}${current.hash || ""}`;
  window.history.replaceState({}, "", nextURL);
}

function installGlobalErrorTelemetry(): void {
  const win = window as Window & { __vectaErrorTelemetryInstalled?: boolean };
  if (win.__vectaErrorTelemetryInstalled) {
    return;
  }
  win.__vectaErrorTelemetryInstalled = true;

  window.addEventListener("error", (event: ErrorEvent) => {
    const error = event.error ?? new Error(event.message || "window error");
    void captureFrontendError(getSession(), error, {
      component: "window.onerror",
      filename: event.filename,
      lineno: event.lineno,
      colno: event.colno
    });
  });

  window.addEventListener("unhandledrejection", (event: PromiseRejectionEvent) => {
    void captureFrontendError(getSession(), event.reason, {
      component: "window.onunhandledrejection"
    });
  });
}

normalizeDashboardURL();
installGlobalErrorTelemetry();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>
);
