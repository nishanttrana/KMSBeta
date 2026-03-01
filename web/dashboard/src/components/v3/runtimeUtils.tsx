import { Component, type ReactNode } from "react";

export function errMsg(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

export function normalizeFipsModeValue(mode: string): "enabled" | "disabled" {
  const raw = String(mode || "").toLowerCase().trim();
  if (raw === "enabled" || raw === "strict" || raw === "fips" || raw === "on" || raw === "true") {
    return "enabled";
  }
  return "disabled";
}

export function isFipsModeEnabled(mode: string): boolean {
  return normalizeFipsModeValue(mode) === "enabled";
}

type TabErrorBoundaryProps = {
  resetKey?: string;
  renderFallback?: ((errorMessage: string, reset: () => void) => JSX.Element) | undefined;
  children: ReactNode;
};

type TabErrorBoundaryState = {
  hasError: boolean;
  errorMessage: string;
};

export class TabErrorBoundary extends Component<TabErrorBoundaryProps, TabErrorBoundaryState> {
  constructor(props: TabErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, errorMessage: "" };
  }

  static getDerivedStateFromError(error: unknown): TabErrorBoundaryState {
    return {
      hasError: true,
      errorMessage: errMsg(error)
    };
  }

  componentDidCatch(error: unknown): void {
    console.error("Tab render failed", error);
  }

  componentDidUpdate(prevProps: TabErrorBoundaryProps): void {
    if (prevProps.resetKey !== this.props.resetKey && this.state.hasError) {
      this.setState({ hasError: false, errorMessage: "" });
    }
  }

  render(): JSX.Element {
    if (this.state.hasError) {
      const reset = () => this.setState({ hasError: false, errorMessage: "" });
      if (typeof this.props.renderFallback === "function") {
        return this.props.renderFallback(this.state.errorMessage || "Unexpected runtime error.", reset);
      }
      return (
        <div style={{ border: "1px solid #ef4444", borderRadius: 10, padding: 12 }}>
          <div style={{ fontSize: 12, color: "#ef4444", fontWeight: 700, marginBottom: 6 }}>This tab failed to render.</div>
          <div style={{ fontSize: 10, color: "#94a3b8", marginBottom: 8 }}>{this.state.errorMessage || "Unexpected runtime error."}</div>
          <button onClick={reset} style={{ border: "1px solid #243656", borderRadius: 6, padding: "4px 10px", background: "transparent", color: "#06d6e0", cursor: "pointer", fontSize: 10 }}>
            Retry
          </button>
        </div>
      );
    }
    return <>{this.props.children}</>;
  }
}
