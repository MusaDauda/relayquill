import { type JSX } from "react";
import { type HttpApiFailure } from "../api/http-client.js";
import {
  type ResourceViewState,
  resourceStateFromApiError
} from "../features/resource-state/model.js";
import { ResourceStatePanel } from "./ResourceStatePanel.js";
import { StatusBadge } from "./StatusBadge.js";

export type MutationFeedbackState<TDraft = unknown> =
  | { readonly kind: "idle" }
  | { readonly kind: "submitting"; readonly label: string }
  | {
      readonly kind: "succeeded";
      readonly title: string;
      readonly detail: string;
      readonly receiptId?: string | undefined;
    }
  | {
      readonly kind: "failed";
      readonly error: HttpApiFailure;
      readonly preservedDraft?: TDraft | undefined;
      readonly currentServerState?: unknown;
    };

export function MutationFeedback<TDraft = unknown>({
  state,
  resourceLabel,
  onRetry,
  onResolveOriginal,
  onReapplyDraft,
  onDismiss
}: {
  readonly state: MutationFeedbackState<TDraft>;
  readonly resourceLabel: string;
  readonly onRetry?: (() => void) | undefined;
  readonly onResolveOriginal?: (() => void) | undefined;
  readonly onReapplyDraft?: ((draft: TDraft) => void) | undefined;
  readonly onDismiss?: (() => void) | undefined;
}): JSX.Element | null {
  if (state.kind === "idle") {
    return null;
  }

  if (state.kind === "submitting") {
    return (
      <section className="rq-state-panel" data-tone="info" role="status" aria-live="polite">
        <div className="rq-row">
          <StatusBadge status="refreshing" label="Submitting" />
          <span>{state.label}</span>
        </div>
      </section>
    );
  }

  if (state.kind === "succeeded") {
    return (
      <section className="rq-state-panel" data-tone="ok" role="status" aria-live="polite">
        <div className="rq-row-between">
          <div className="rq-row">
            <StatusBadge status="accepted" label={state.title} />
            {state.receiptId !== undefined ? (
              <span className="mono">Receipt: {state.receiptId}</span>
            ) : null}
          </div>
          {onDismiss !== undefined ? (
            <button type="button" className="rq-btn" onClick={onDismiss}>
              Dismiss
            </button>
          ) : null}
        </div>
        <p>{state.detail}</p>
      </section>
    );
  }

  const errView: ResourceViewState<null, TDraft> = resourceStateFromApiError<null, TDraft>({
    status: state.error.status,
    code: state.error.code,
    message: state.error.message,
    acceptance: state.error.acceptance,
    retryable: state.error.retryable,
    retryAfterSeconds: state.error.retryAfterSeconds,
    resourceRef: state.error.resourceRef,
    preservedDraft: state.preservedDraft,
    currentServerState: state.currentServerState,
    unsupportedProtocol: state.error.unsupportedProtocol
  });

  return (
    <ResourceStatePanel
      view={errView}
      resourceLabel={resourceLabel}
      onRetry={onRetry}
      onResolveOriginal={onResolveOriginal}
      onReapplyDraft={onReapplyDraft}
    >
      {() => null}
    </ResourceStatePanel>
  );
}
