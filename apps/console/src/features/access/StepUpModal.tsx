import { type JSX, useState } from "react";
import { startAuthentication } from "@simplewebauthn/browser";
import { useConsoleRuntime } from "../../app/session.js";
import { CopyableId } from "../../components/CopyableId.js";
import { ConsoleIcon } from "../../components/Icons.js";
import { Modal } from "../../components/Modal.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";

export interface StepUpTargetDescriptor {
  readonly action: string;
  readonly actionLabel: string;
  readonly scopeKind: "installation" | "tenant" | "project";
  readonly tenantId: string | null;
  readonly projectId: string | null;
  readonly targetResourceId: string;
  readonly targetVersion: string;
  readonly canonicalCommandSha256: string;
  readonly summary: string;
}

export interface StepUpCompletionProof {
  readonly operationProofId: string;
  readonly canonicalCommandSha256: string;
  readonly targetVersion: string;
}

export function StepUpModal({
  target,
  onCancel,
  onVerified
}: {
  readonly target: StepUpTargetDescriptor | null;
  readonly onCancel: () => void;
  readonly onVerified: (proof: StepUpCompletionProof) => void | Promise<void>;
}): JSX.Element | null {
  const { api } = useConsoleRuntime();
  const [phase, setPhase] = useState<"ready" | "challenging" | "verifying" | "error">("ready");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);

  if (target === null) {
    return null;
  }

  const busy = phase === "challenging" || phase === "verifying";

  const handleAuthenticate = async (): Promise<void> => {
    setPhase("challenging");
    setErrorMessage(null);
    setErrorCode(null);

    const optRes = await api.requestStepUpOptions(
      {
        schema_version: 1,
        action: target.action,
        scope_kind: target.scopeKind,
        tenant_id: target.tenantId,
        project_id: target.projectId,
        target_resource_id: target.targetResourceId,
        target_version: target.targetVersion,
        canonical_command_sha256: target.canonicalCommandSha256
      },
      generateIdempotencyKey("stepup-opt")
    );

    if (!optRes.ok) {
      setPhase("error");
      setErrorCode(optRes.code);
      setErrorMessage(optRes.message);
      return;
    }

    let assertion: unknown;
    try {
      assertion = await startAuthentication({
        optionsJSON: optRes.data.public_key
      });
    } catch (err) {
      setPhase("error");
      setErrorCode("WEBAUTHN_CEREMONY_ABORTED");
      setErrorMessage(
        err instanceof Error
          ? err.message
          : "Passkey verification ceremony was cancelled or failed."
      );
      return;
    }

    setPhase("verifying");
    const completeRes = await api.completeStepUp(
      {
        schema_version: 1,
        auth_challenge_id: optRes.data.auth_challenge_id,
        response: assertion
      },
      generateIdempotencyKey("stepup-done")
    );

    if (!completeRes.ok) {
      setPhase("error");
      setErrorCode(completeRes.code);
      setErrorMessage(completeRes.message);
      return;
    }

    setPhase("ready");
    await onVerified({
      operationProofId: completeRes.data.operation_proof_id,
      canonicalCommandSha256: target.canonicalCommandSha256,
      targetVersion: target.targetVersion
    });
  };

  return (
    <Modal
      open
      title="Operation-Bound Passkey Step-Up"
      description="High-consequence governance and recovery mutations require a single-use cryptographic passkey proof bound to the exact target resource version and canonical command digest."
      preventClose={busy}
      onClose={onCancel}
      footer={
        <>
          <button
            type="button"
            className="rq-btn"
            disabled={busy}
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            type="button"
            className="rq-btn rq-btn-primary"
            disabled={busy}
            onClick={() => {
              void handleAuthenticate();
            }}
          >
            <ConsoleIcon name="key" />
            <span>
              {phase === "challenging"
                ? "Waiting for Passkey..."
                : phase === "verifying"
                  ? "Verifying Operation Proof..."
                  : "Verify with Passkey & Execute"}
            </span>
          </button>
        </>
      }
    >
      <div className="rq-card-inset">
        <div className="rq-row-between">
          <strong className="rq-label">{target.actionLabel}</strong>
          <StatusBadge
            status={phase === "error" ? "forbidden" : busy ? "refreshing" : "awaiting_passkey"}
            label={
              phase === "error"
                ? "Verification Failed"
                : busy
                  ? "Ceremony Active"
                  : "Step-Up Required"
            }
            live="polite"
          />
        </div>
        <p className="rq-meta-text">{target.summary}</p>
        <dl className="rq-kv-grid">
          <dt>Capability Action</dt>
          <dd className="mono">{target.action}</dd>
          <dt>Scope Kind</dt>
          <dd className="mono">{target.scopeKind}</dd>
          <dt>Target Resource ID</dt>
          <dd className="mono">{target.targetResourceId}</dd>
          <dt>Bound Target Version</dt>
          <dd className="mono">{target.targetVersion}</dd>
          <dt>Canonical Command SHA-256</dt>
          <dd>
            <CopyableId value={target.canonicalCommandSha256} compact />
          </dd>
        </dl>
      </div>

      {errorMessage !== null ? (
        <section className="rq-state-panel" data-tone="error" role="alert">
          <div className="rq-row-between">
            <StatusBadge status="forbidden" label="Step-Up Rejected" />
            {errorCode !== null ? <span className="mono">{errorCode}</span> : null}
          </div>
          <p>{errorMessage}</p>
        </section>
      ) : null}
    </Modal>
  );
}
