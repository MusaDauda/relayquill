import { type JSX, useCallback, useEffect, useState } from "react";
import { hashCanonicalJson } from "@relayquill/contracts";
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration
} from "@simplewebauthn/browser";
import {
  type CompletedEnrollmentDto,
  type EnrollmentIntentDto
} from "../../api/dtos.js";
import {
  type AccessSection,
  buildAccessPath,
  buildPlatformPath,
  buildProjectPath,
  useConsoleRouter
} from "../../app/router.js";
import { useConsoleRuntime } from "../../app/session.js";
import { CopyableId } from "../../components/CopyableId.js";
import { FormField } from "../../components/FormField.js";
import { ConsoleIcon } from "../../components/Icons.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";
import { formatCountdown } from "../../utils/format.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { StepUpModal, type StepUpTargetDescriptor } from "./StepUpModal.js";

function BootstrapApprovalHelperCard({
  intent,
  polling,
  onPollNow
}: {
  readonly intent: EnrollmentIntentDto;
  readonly polling: boolean;
  readonly onPollNow: () => void;
}): JSX.Element {
  const [countdownText, setCountdownText] = useState<string>(() =>
    formatCountdown(intent.expires_at)
  );

  useEffect(() => {
    setCountdownText(formatCountdown(intent.expires_at));
    const timer = window.setInterval(() => {
      setCountdownText(formatCountdown(intent.expires_at));
    }, 1000);
    return () => {
      window.clearInterval(timer);
    };
  }, [intent.expires_at]);

  const cliCommand = [
    "npm run start --workspace @relayquill/admin --",
    "--config config/development.bootstrap-operator.json",
    "access approve-enrollment",
    `--intent-id ${intent.intent_id}`,
    `--version ${intent.version}`,
    `--comparison-sha256 ${intent.comparison_sha256}`,
    "--operator-ref local-bootstrap-operator"
  ].join(" ");

  return (
    <section
      className="rq-card-inset"
      aria-label="Bootstrap Approval Helper Card"
      data-testid="bootstrap-approval-helper"
    >
      <div className="rq-row-between">
        <div className="rq-row">
          <strong className="rq-card-title">Bootstrap Approval Helper</strong>
          <StatusBadge status={intent.state} live="polite" />
          {polling ? (
            <StatusBadge status="refreshing" label="Live Polling Active" />
          ) : null}
        </div>
        <button type="button" className="rq-btn" onClick={onPollNow}>
          <ConsoleIcon name="refresh" />
          <span>Check Approval Status</span>
        </button>
      </div>

      <p className="rq-meta-text">
        Compare the out-of-band SHA-256 fingerprint below before approving this enrollment intent
        from the local administrative CLI. No secret token is placed in any URL or browser storage.
      </p>

      <dl className="rq-kv-grid">
        <dt>Enrollment Intent ID</dt>
        <dd>
          <CopyableId label="Intent ID" value={intent.intent_id} />
        </dd>
        <dt>Intent Purpose</dt>
        <dd className="mono">{intent.purpose}</dd>
        <dt>Intent Version</dt>
        <dd className="mono">{intent.version}</dd>
        <dt>Out-of-Band Comparison SHA-256</dt>
        <dd>
          <CopyableId label="Comparison SHA-256" value={intent.comparison_sha256} />
        </dd>
        <dt>Intent Expiry Countdown</dt>
        <dd className="mono" aria-live="polite">
          {countdownText} (<UtcTimestamp value={intent.expires_at} showLocal={false} />)
        </dd>
      </dl>

      <div className="rq-stack-sm">
        <strong className="rq-label">Administrative CLI Approval Command</strong>
        <pre className="rq-json-viewer">
          <code>{cliCommand}</code>
        </pre>
        <div>
          <CopyableId label="Approval CLI Command" value={cliCommand} compact />
        </div>
      </div>
    </section>
  );
}

export function AccessPage({ section }: { readonly section: AccessSection }): JSX.Element {
  const { navigate } = useConsoleRouter();
  const { api, session, refreshSession, logout } = useConsoleRuntime();

  const webAuthnSupported =
    typeof window !== "undefined" ? browserSupportsWebAuthn() : true;

  // Sign-In state
  const [signInFeedback, setSignInFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });

  // Enrollment state
  const [enrollPurpose, setEnrollPurpose] = useState<"first_platform_admin" | "invited_human">(
    "first_platform_admin"
  );
  const [invitedReference, setInvitedReference] = useState("");
  const [authenticatorLabel, setAuthenticatorLabel] = useState("Primary Operator Passkey");
  const [activeIntent, setActiveIntent] = useState<EnrollmentIntentDto | null>(null);
  const [completedEnrollment, setCompletedEnrollment] = useState<CompletedEnrollmentDto | null>(
    null
  );
  const [enrollFeedback, setEnrollFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });

  // Recovery state
  const [recoveryReference, setRecoveryReference] = useState("");
  const [recoveryLabel, setRecoveryLabel] = useState("Recovery Replacement Passkey");
  const [recoveryIntent, setRecoveryIntent] = useState<EnrollmentIntentDto | null>(null);
  const [completedRecovery, setCompletedRecovery] = useState<CompletedEnrollmentDto | null>(null);
  const [recoveryFeedback, setRecoveryFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });

  // Active session step-up state (Revoke Other Sessions)
  const [stepUpTarget, setStepUpTarget] = useState<StepUpTargetDescriptor | null>(null);
  const [sessionFeedback, setSessionFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });

  const pollIntent = useCallback(
    async (intentId: string, isRecovery: boolean): Promise<void> => {
      const res = await api.getEnrollmentIntent(intentId);
      if (res.ok) {
        if (isRecovery) {
          setRecoveryIntent(res.data);
        } else {
          setActiveIntent(res.data);
        }
      }
    },
    [api]
  );

  useEffect(() => {
    if (activeIntent === null || activeIntent.state !== "requested") {
      return;
    }
    const timer = window.setInterval(() => {
      void pollIntent(activeIntent.intent_id, false);
    }, 3000);
    return () => {
      window.clearInterval(timer);
    };
  }, [activeIntent, pollIntent]);

  useEffect(() => {
    if (recoveryIntent === null || recoveryIntent.state !== "requested") {
      return;
    }
    const timer = window.setInterval(() => {
      void pollIntent(recoveryIntent.intent_id, true);
    }, 3000);
    return () => {
      window.clearInterval(timer);
    };
  }, [pollIntent, recoveryIntent]);

  const handlePasskeySignIn = async (): Promise<void> => {
    setSignInFeedback({
      kind: "submitting",
      label: "Requesting discoverable passkey challenge..."
    });

    const optRes = await api.requestSignInOptions(generateIdempotencyKey("signin-opt"));
    if (!optRes.ok) {
      setSignInFeedback({ kind: "failed", error: optRes });
      return;
    }

    let assertion: unknown;
    try {
      assertion = await startAuthentication({
        optionsJSON: optRes.data.public_key
      });
    } catch (err) {
      setSignInFeedback({
        kind: "failed",
        error: {
          ok: false,
          status: 400,
          code: "WEBAUTHN_CEREMONY_CANCELLED",
          message:
            err instanceof Error
              ? err.message
              : "Discoverable passkey sign-in was cancelled or failed.",
          acceptance: "known_rejected",
          retryable: true,
          aborted: false,
          fieldErrors: []
        }
      });
      return;
    }

    setSignInFeedback({
      kind: "submitting",
      label: "Verifying passkey assertion and establishing session..."
    });

    const completeRes = await api.completeSignIn(
      {
        schema_version: 1,
        auth_challenge_id: optRes.data.auth_challenge_id,
        response: assertion
      },
      generateIdempotencyKey("signin-complete")
    );

    if (!completeRes.ok) {
      setSignInFeedback({ kind: "failed", error: completeRes });
      return;
    }

    const loadedSession = await refreshSession();
    setSignInFeedback({
      kind: "succeeded",
      title: "Signed In",
      detail: `Authenticated as ${completeRes.data.display_name} (${completeRes.data.principal_id}).`
    });

    const firstWorkspace = loadedSession?.workspaces[0];
    if (firstWorkspace !== undefined) {
      navigate(
        buildProjectPath(
          firstWorkspace.tenant_id,
          firstWorkspace.project_id,
          "overview"
        )
      );
    } else if ((loadedSession?.platform_roles.length ?? 0) > 0) {
      navigate(buildPlatformPath("tenants"));
    }
  };

  const handleStartEnrollmentIntent = async (): Promise<void> => {
    setCompletedEnrollment(null);
    setEnrollFeedback({
      kind: "submitting",
      label: "Creating browser-bound enrollment intent..."
    });

    const body =
      enrollPurpose === "first_platform_admin"
        ? ({ schema_version: 1, purpose: "first_platform_admin" } as const)
        : ({
            schema_version: 1,
            purpose: "invited_human",
            invited_intent_reference: invitedReference.trim()
          } as const);

    const res = await api.createEnrollmentIntent(
      body,
      generateIdempotencyKey("enroll-intent")
    );

    if (!res.ok) {
      setEnrollFeedback({ kind: "failed", error: res });
      return;
    }

    setActiveIntent(res.data);
    setEnrollFeedback({
      kind: "succeeded",
      title: "Enrollment Intent Created",
      detail:
        res.data.state === "requested"
          ? "Approve the intent via the Bootstrap Approval Helper below, then register your passkey."
          : "Enrollment intent is ready for passkey attestation."
    });
  };

  const handleCompletePasskeyEnrollment = async (
    intent: EnrollmentIntentDto,
    label: string,
    isRecovery: boolean
  ): Promise<void> => {
    const setFeedback = isRecovery ? setRecoveryFeedback : setEnrollFeedback;
    setFeedback({
      kind: "submitting",
      label: "Requesting WebAuthn credential creation options..."
    });

    const optRes = await api.requestEnrollmentPasskeyOptions(
      intent.intent_id,
      {
        schema_version: 1,
        intent_version: intent.version,
        authenticator_label: label.trim() || "Operator Passkey"
      },
      generateIdempotencyKey("enroll-opt")
    );

    if (!optRes.ok) {
      setFeedback({ kind: "failed", error: optRes });
      return;
    }

    let attestation: unknown;
    try {
      attestation = await startRegistration({
        optionsJSON: optRes.data.public_key
      });
    } catch (err) {
      setFeedback({
        kind: "failed",
        error: {
          ok: false,
          status: 400,
          code: "WEBAUTHN_ATTESTATION_CANCELLED",
          message:
            err instanceof Error
              ? err.message
              : "Passkey registration ceremony was cancelled or failed.",
          acceptance: "known_rejected",
          retryable: true,
          aborted: false,
          fieldErrors: []
        }
      });
      return;
    }

    setFeedback({
      kind: "submitting",
      label: "Completing passkey enrollment..."
    });

    const completeRes = await api.completeEnrollmentPasskey(
      intent.intent_id,
      {
        schema_version: 1,
        auth_challenge_id: optRes.data.auth_challenge_id,
        response: attestation
      },
      generateIdempotencyKey("enroll-complete")
    );

    if (!completeRes.ok) {
      setFeedback({ kind: "failed", error: completeRes });
      return;
    }

    if (isRecovery) {
      setCompletedRecovery(completeRes.data);
    } else {
      setCompletedEnrollment(completeRes.data);
    }

    await pollIntent(intent.intent_id, isRecovery);
    setFeedback({
      kind: "succeeded",
      title: "Passkey Enrolled",
      detail: `Passkey ${completeRes.data.passkey_id} bound to principal ${completeRes.data.principal_id} (${completeRes.data.passkey_state}).`
    });
  };

  const handleStartRecoveryIntent = async (): Promise<void> => {
    setCompletedRecovery(null);
    setRecoveryFeedback({
      kind: "submitting",
      label: "Creating restricted factor recovery intent..."
    });

    const res = await api.createEnrollmentIntent(
      {
        schema_version: 1,
        purpose: "restricted_factor_recovery",
        target_recovery_reference: recoveryReference.trim()
      },
      generateIdempotencyKey("recovery-intent")
    );

    if (!res.ok) {
      setRecoveryFeedback({ kind: "failed", error: res });
      return;
    }

    setRecoveryIntent(res.data);
    setRecoveryFeedback({
      kind: "succeeded",
      title: "Recovery Intent Created",
      detail:
        "Verify the comparison SHA-256 out-of-band and approve before registering the replacement passkey."
    });
  };

  const openRevokeOtherSessionsStepUp = (): void => {
    if (session === null) {
      return;
    }
    const canonical = hashCanonicalJson({
      action: "sessions.revoke_others",
      principal_id: session.principal_id,
      current_session_id: session.session_id
    });
    setStepUpTarget({
      action: "sessions.revoke_others",
      actionLabel: "Revoke All Other Active Sessions",
      scopeKind: "installation",
      tenantId: null,
      projectId: null,
      targetResourceId: session.principal_id,
      targetVersion: session.authority_epoch,
      canonicalCommandSha256: canonical.sha256,
      summary:
        "Immediately terminates all other browser sessions for your principal while preserving your current active session."
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Operator Access & Passkey Security</h1>
          <p className="rq-page-lead">
            Phishing-resistant WebAuthn discoverable passkey authentication, browser-bound
            enrollment with out-of-band SHA-256 verification, and operation-bound step-up proofs.
          </p>
        </div>
        <div className="rq-row">
          <StatusBadge
            status={webAuthnSupported ? "verified_supported" : "unavailable"}
            label={webAuthnSupported ? "WebAuthn Ready" : "WebAuthn Unsupported"}
          />
          {session !== null ? (
            <StatusBadge
              status="active"
              label={`Session: ${session.display_name}`}
              live="polite"
            />
          ) : (
            <StatusBadge status="draft" label="Unauthenticated" live="polite" />
          )}
        </div>
      </header>

      <div className="rq-tabs" role="tablist" aria-label="Operator access workflows">
        <button
          type="button"
          role="tab"
          className="rq-tab"
          aria-selected={section === "sign-in"}
          onClick={() => {
            navigate(buildAccessPath("sign-in"));
          }}
        >
          Passkey Sign-In
        </button>
        <button
          type="button"
          role="tab"
          className="rq-tab"
          aria-selected={section === "enroll"}
          onClick={() => {
            navigate(buildAccessPath("enroll"));
          }}
        >
          Passkey Enrollment
        </button>
        <button
          type="button"
          role="tab"
          className="rq-tab"
          aria-selected={section === "recovery"}
          onClick={() => {
            navigate(buildAccessPath("recovery"));
          }}
        >
          Factor Recovery
        </button>
      </div>

      {session !== null ? (
        <section className="rq-card" aria-label="Active session security">
          <div className="rq-card-header">
            <h2 className="rq-section-title">Active Operator Session</h2>
            <StatusBadge status="active" label={session.purpose} />
          </div>
          <dl className="rq-kv-grid">
            <dt>Principal ID</dt>
            <dd>
              <CopyableId value={session.principal_id} />
            </dd>
            <dt>Session ID</dt>
            <dd>
              <CopyableId value={session.session_id} />
            </dd>
            <dt>Display Name</dt>
            <dd>{session.display_name}</dd>
            <dt>Authority Epoch</dt>
            <dd className="mono">{session.authority_epoch}</dd>
            <dt>Platform Roles</dt>
            <dd className="mono">
              {session.platform_roles.length > 0
                ? session.platform_roles.join(", ")
                : "none (workspace-scoped)"}
            </dd>
            <dt>Idle Expiry</dt>
            <dd>
              <UtcTimestamp value={session.idle_expires_at} />
            </dd>
            <dt>Absolute Expiry</dt>
            <dd>
              <UtcTimestamp value={session.absolute_expires_at} />
            </dd>
          </dl>
          <MutationFeedback
            state={sessionFeedback}
            resourceLabel="Session revocation"
            onDismiss={() => {
              setSessionFeedback({ kind: "idle" });
            }}
          />
          <div className="rq-row">
            <button
              type="button"
              className="rq-btn"
              onClick={openRevokeOtherSessionsStepUp}
            >
              <ConsoleIcon name="shield" />
              <span>Revoke Other Sessions (Step-Up)</span>
            </button>
            <button
              type="button"
              className="rq-btn rq-btn-danger"
              onClick={() => {
                void logout();
              }}
            >
              Sign Out
            </button>
          </div>
        </section>
      ) : null}

      {section === "sign-in" ? (
        <section className="rq-card" aria-labelledby="signin-heading">
          <div className="rq-card-header">
            <h2 id="signin-heading" className="rq-section-title">
              Discoverable Passkey Sign-In
            </h2>
            <StatusBadge status="verified_supported" label="User Verification Required" />
          </div>
          <p className="rq-meta-text">
            Sign in using your registered discoverable WebAuthn credential. No username, password,
            or magic link is transmitted; your authenticator resolves your opaque 32-byte credential
            handle directly.
          </p>

          <MutationFeedback
            state={signInFeedback}
            resourceLabel="Passkey sign-in"
            onRetry={() => {
              void handlePasskeySignIn();
            }}
          />

          <div className="rq-row">
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              onClick={() => {
                void handlePasskeySignIn();
              }}
            >
              <ConsoleIcon name="key" />
              <span>Sign In with Discoverable Passkey</span>
            </button>
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                navigate(buildAccessPath("enroll"));
              }}
            >
              Need to Enroll a Passkey?
            </button>
          </div>
        </section>
      ) : null}

      {section === "enroll" ? (
        <section className="rq-card" aria-labelledby="enroll-heading">
          <div className="rq-card-header">
            <h2 id="enroll-heading" className="rq-section-title">
              Browser-Bound Passkey Enrollment
            </h2>
            <StatusBadge
              status={activeIntent?.state ?? "draft"}
              label={activeIntent !== null ? `Intent: ${activeIntent.state}` : "Step 1 of 3"}
            />
          </div>

          <p className="rq-meta-text">
            Enrollment creates an HttpOnly pre-authentication proof cookie bound to this browser,
            yields an out-of-band comparison SHA-256 digest for approval, and registers a resident
            discoverable passkey.
          </p>

          <div className="rq-grid-2">
            <FormField
              label="Enrollment Purpose"
              helpText="Choose First Platform Admin when bootstrapping a fresh installation, or Invited Human when completing an administrator-issued invitation."
            >
              {({ inputId, describedBy }) => (
                <select
                  id={inputId}
                  aria-describedby={describedBy}
                  className="rq-select"
                  value={enrollPurpose}
                  onChange={(e) => {
                    setEnrollPurpose(
                      e.target.value === "invited_human"
                        ? "invited_human"
                        : "first_platform_admin"
                    );
                  }}
                >
                  <option value="first_platform_admin">
                    First Platform Administrator (Bootstrap)
                  </option>
                  <option value="invited_human">Invited Human Operator</option>
                </select>
              )}
            </FormField>

            <FormField
              label="Authenticator Label"
              helpText="Human-readable label recorded in audit logs for this passkey."
              required
            >
              {({ inputId, describedBy }) => (
                <input
                  id={inputId}
                  aria-describedby={describedBy}
                  type="text"
                  className="rq-input"
                  value={authenticatorLabel}
                  onChange={(e) => {
                    setAuthenticatorLabel(e.target.value);
                  }}
                />
              )}
            </FormField>
          </div>

          {enrollPurpose === "invited_human" ? (
            <FormField
              label="Invited Intent Reference"
              helpText="Out-of-band reference identifier provided by your tenant or project administrator."
              required
            >
              {({ inputId, describedBy }) => (
                <input
                  id={inputId}
                  aria-describedby={describedBy}
                  type="text"
                  className="rq-input mono"
                  value={invitedReference}
                  onChange={(e) => {
                    setInvitedReference(e.target.value);
                  }}
                />
              )}
            </FormField>
          ) : null}

          <MutationFeedback
            state={enrollFeedback}
            resourceLabel="Passkey enrollment"
            onDismiss={() => {
              setEnrollFeedback({ kind: "idle" });
            }}
          />

          <div className="rq-row">
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              disabled={
                enrollPurpose === "invited_human" && invitedReference.trim().length === 0
              }
              onClick={() => {
                void handleStartEnrollmentIntent();
              }}
            >
              1. Create Enrollment Intent
            </button>

            {activeIntent !== null ? (
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                onClick={() => {
                  void handleCompletePasskeyEnrollment(
                    activeIntent,
                    authenticatorLabel,
                    false
                  );
                }}
              >
                <ConsoleIcon name="key" />
                <span>2. Register Passkey in Browser</span>
              </button>
            ) : null}

            {completedEnrollment !== null ? (
              <button
                type="button"
                className="rq-btn"
                onClick={() => {
                  navigate(buildAccessPath("sign-in"));
                }}
              >
                3. Proceed to Sign-In
              </button>
            ) : null}
          </div>

          {activeIntent !== null ? (
            <BootstrapApprovalHelperCard
              intent={activeIntent}
              polling={activeIntent.state === "requested"}
              onPollNow={() => {
                void pollIntent(activeIntent.intent_id, false);
              }}
            />
          ) : null}
        </section>
      ) : null}

      {section === "recovery" ? (
        <section className="rq-card" aria-labelledby="recovery-heading">
          <div className="rq-card-header">
            <h2 id="recovery-heading" className="rq-section-title">
              Restricted Factor Recovery
            </h2>
            <StatusBadge
              status={recoveryIntent?.state ?? "awaiting_review"}
              label="Two-Person Reviewed Recovery"
            />
          </div>
          <p className="rq-meta-text">
            Factor recovery never issues an unreviewed bypass session. It creates a browser-bound
            recovery intent verified by out-of-band comparison SHA-256 and distinct-operator review.
          </p>

          <div className="rq-grid-2">
            <FormField
              label="Target Recovery Reference"
              helpText="Recovery incident or principal reference authorized for factor replacement."
              required
            >
              {({ inputId, describedBy }) => (
                <input
                  id={inputId}
                  aria-describedby={describedBy}
                  type="text"
                  className="rq-input mono"
                  value={recoveryReference}
                  onChange={(e) => {
                    setRecoveryReference(e.target.value);
                  }}
                />
              )}
            </FormField>

            <FormField
              label="Replacement Passkey Label"
              helpText="Audit label for the replacement hardware or platform authenticator."
              required
            >
              {({ inputId, describedBy }) => (
                <input
                  id={inputId}
                  aria-describedby={describedBy}
                  type="text"
                  className="rq-input"
                  value={recoveryLabel}
                  onChange={(e) => {
                    setRecoveryLabel(e.target.value);
                  }}
                />
              )}
            </FormField>
          </div>

          <MutationFeedback
            state={recoveryFeedback}
            resourceLabel="Factor recovery"
            onDismiss={() => {
              setRecoveryFeedback({ kind: "idle" });
            }}
          />

          <div className="rq-row">
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              disabled={recoveryReference.trim().length === 0}
              onClick={() => {
                void handleStartRecoveryIntent();
              }}
            >
              1. Create Recovery Enrollment Intent
            </button>

            {recoveryIntent !== null ? (
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                onClick={() => {
                  void handleCompletePasskeyEnrollment(
                    recoveryIntent,
                    recoveryLabel,
                    true
                  );
                }}
              >
                <ConsoleIcon name="key" />
                <span>2. Attest Replacement Passkey</span>
              </button>
            ) : null}
          </div>

          {recoveryIntent !== null ? (
            <BootstrapApprovalHelperCard
              intent={recoveryIntent}
              polling={recoveryIntent.state === "requested"}
              onPollNow={() => {
                void pollIntent(recoveryIntent.intent_id, true);
              }}
            />
          ) : null}

          {completedRecovery !== null ? (
            <section className="rq-card-inset" role="status" aria-live="polite">
              <div className="rq-row-between">
                <strong className="rq-label">Replacement Passkey Recorded</strong>
                <StatusBadge status={completedRecovery.passkey_state} />
              </div>
              <p className="rq-meta-text">
                Next required step: <span className="mono">{completedRecovery.next_action}</span>.
                The replacement credential remains gated until distinct-reviewer recovery approval
                completes.
              </p>
            </section>
          ) : null}
        </section>
      ) : null}

      <StepUpModal
        target={stepUpTarget}
        onCancel={() => {
          setStepUpTarget(null);
        }}
        onVerified={async (proof) => {
          setStepUpTarget(null);
          setSessionFeedback({
            kind: "submitting",
            label: "Revoking all other active sessions..."
          });
          const res = await api.revokeOtherSessions(
            {
              schema_version: 1,
              operation_proof_id: proof.operationProofId,
              canonical_command_sha256: proof.canonicalCommandSha256
            },
            generateIdempotencyKey("revoke-others")
          );
          if (!res.ok) {
            setSessionFeedback({ kind: "failed", error: res });
            return;
          }
          setSessionFeedback({
            kind: "succeeded",
            title: "Other Sessions Revoked",
            detail: "All other sessions for your principal were revoked.",
            receiptId: res.data.receipt?.id
          });
        }}
      />
    </div>
  );
}
