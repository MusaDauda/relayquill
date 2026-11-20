import { Component, type ErrorInfo, type ReactNode } from "react";
import { StatusBadge } from "../components/StatusBadge.js";

interface ErrorBoundaryProps {
  readonly children: ReactNode;
  readonly onReset?: () => void;
}

interface ErrorBoundaryState {
  readonly hasError: boolean;
  readonly safeMessage: string;
}

export class ConsoleErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = {
    hasError: false,
    safeMessage: ""
  };

  static getDerivedStateFromError(error: unknown): ErrorBoundaryState {
    const safeMessage =
      error instanceof Error ? error.message.slice(0, 240) : "Unexpected rendering error.";
    return { hasError: true, safeMessage };
  }

  override componentDidCatch(_error: Error, _info: ErrorInfo): void {
    // Do not persist or export client crash telemetry containing private workspace state.
  }

  override render(): ReactNode {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <main className="rq-main" role="alert">
        <section className="rq-card">
          <div className="rq-card-header">
            <h1 className="rq-page-title">Console View Interrupted</h1>
            <StatusBadge tone="error" label="Unavailable" />
          </div>
          <p className="rq-page-lead">
            An unexpected display boundary error occurred. No private draft or session material was
            written to browser storage.
          </p>
          <p className="mono">{this.state.safeMessage}</p>
          <div className="rq-row">
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              onClick={() => {
                this.setState({ hasError: false, safeMessage: "" });
                this.props.onReset?.();
              }}
            >
              Reset View
            </button>
          </div>
        </section>
      </main>
    );
  }
}
