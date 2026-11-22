import { type JSX, useState } from "react";
import { type TotpEnrollResponseDto } from "../../api/dtos.js";
import {
  buildBillingPath,
  buildProjectPath,
  buildSettingsAuditPath,
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
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { consoleTelemetry } from "../../utils/telemetry.js";

export function OnboardingPage(): JSX.Element {
  const { api, session } = useConsoleRuntime();
  const { navigate } = useConsoleRouter();

  const [totpEnroll, setTotpEnroll] = useState<TotpEnrollResponseDto | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpEnrolled, setTotpEnrolled] = useState(false);
  const [totpFeedback, setTotpFeedback] = useState<MutationFeedbackState>({ kind: "idle" });

  const [docKind, setDocKind] = useState<"tos" | "privacy" | "dpa">("privacy");
  const [docVersion, setDocVersion] = useState("2026-11-01");
  const [legalFeedback, setLegalFeedback] = useState<MutationFeedbackState>({ kind: "idle" });

  const primaryWorkspace = session?.workspaces[0] ?? null;

  const handleEnrollTotp = async (): Promise<void> => {
    setTotpFeedback({ kind: "submitting", label: "Generating TOTP MFA secret..." });
    const res = await api.enrollTotp(generateIdempotencyKey("totp-enroll"));
    if (!res.ok) {
      setTotpFeedback({ kind: "failed", error: res });
      return;
    }
    setTotpEnroll(res.data);
    setTotpFeedback({
      kind: "succeeded",
      title: "Secret Generated",
      detail: "Scan or copy the Base32 secret into your authenticator app, then enter a 6-digit verification code."
    });
  };

  const handleVerifyTotp = async (): Promise<void> => {
    setTotpFeedback({ kind: "submitting", label: "Verifying TOTP authenticator code..." });
    const res = await api.verifyTotp(
      { totp_code: totpCode.trim() },
      generateIdempotencyKey("totp-verify")
    );
    if (!res.ok) {
      setTotpFeedback({ kind: "failed", error: res });
      return;
    }
    setTotpEnrolled(res.data.enrolled);
    consoleTelemetry.captureEvent("onboarding.mfa_enrolled", { method: "totp" });
    setTotpFeedback({
      kind: "succeeded",
      title: "MFA Enabled",
      detail: "TOTP multi-factor authentication is active for commercial password logins and GDPR confirmations."
    });
  };

  const handleAcceptLegal = async (): Promise<void> => {
    setLegalFeedback({ kind: "submitting", label: "Recording signed legal acceptance..." });
    const res = await api.acceptLegal(
      { document_kind: docKind, doc_version: docVersion.trim() || "2026-11-01" },
      generateIdempotencyKey("legal-accept")
    );
    if (!res.ok) {
      setLegalFeedback({ kind: "failed", error: res });
      return;
    }
    setLegalFeedback({
      kind: "succeeded",
      title: "Acceptance Recorded",
      detail: `${res.data.document_kind.toUpperCase()} version ${res.data.doc_version} logged in PostgreSQL audit trail.`
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Workspace Onboarding</h1>
          <p className="rq-page-lead">
            Complete multi-factor security, review legal compliance records, configure regional
            billing, and inspect webhook destinations.
          </p>
        </div>
        {session !== null ? (
          <StatusBadge status="active" label={`Operator: ${session.display_name}`} />
        ) : null}
      </header>

      <div className="rq-grid-2">
        <section className="rq-card" aria-label="Step 1 TOTP MFA setup">
          <div className="rq-card-header">
            <h2 className="rq-card-title">1. Authenticator App MFA (TOTP)</h2>
            <StatusBadge status={totpEnrolled ? "active" : "draft"} label={totpEnrolled ? "Verified" : "Optional"} />
          </div>
          <p className="rq-meta-text">
            Enroll an RFC 6238 authenticator factor. Security settings are never paywalled even on
            capped free tiers.
          </p>

          <div className="rq-row">
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              onClick={() => {
                void handleEnrollTotp();
              }}
            >
              <ConsoleIcon name="key" />
              <span>Generate TOTP Secret</span>
            </button>
          </div>

          {totpEnroll !== null ? (
            <div className="rq-card-inset">
              <CopyableId label="Base32 Secret" value={totpEnroll.secret_base32} />
              <p className="rq-meta-text mono">{totpEnroll.otpauth_uri}</p>
              <FormField label="6-Digit Authenticator Code" required>
                {({ inputId, describedBy }) => (
                  <input
                    id={inputId}
                    aria-describedby={describedBy}
                    type="text"
                    inputMode="numeric"
                    className="rq-input mono"
                    placeholder="123456"
                    value={totpCode}
                    onChange={(e) => {
                      setTotpCode(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <div className="rq-row">
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={totpCode.trim().length < 6}
                  onClick={() => {
                    void handleVerifyTotp();
                  }}
                >
                  Verify &amp; Activate MFA
                </button>
              </div>
            </div>
          ) : null}

          <MutationFeedback
            state={totpFeedback}
            resourceLabel="TOTP enrollment"
            onDismiss={() => {
              setTotpFeedback({ kind: "idle" });
            }}
          />
        </section>

        <section className="rq-card" aria-label="Step 2 Legal Agreements">
          <div className="rq-card-header">
            <h2 className="rq-card-title">2. Legal Agreements (ToS / Privacy / DPA)</h2>
            <StatusBadge status="verified_supported" label="Audit Logged" />
          </div>
          <p className="rq-meta-text">
            Record supplemental clickwrap acceptances alongside your signup Terms of Service and Data
            Processing Addendum.
          </p>

          <div className="rq-grid-2">
            <FormField label="Document">
              {({ inputId, describedBy }) => (
                <select
                  id={inputId}
                  aria-describedby={describedBy}
                  className="rq-select"
                  value={docKind}
                  onChange={(e) => {
                    const v = e.target.value;
                    setDocKind(v === "tos" || v === "dpa" ? v : "privacy");
                  }}
                >
                  <option value="tos">Terms of Service (tos)</option>
                  <option value="privacy">Privacy Policy (privacy)</option>
                  <option value="dpa">Data Processing Addendum (dpa)</option>
                </select>
              )}
            </FormField>
            <FormField label="Version">
              {({ inputId, describedBy }) => (
                <input
                  id={inputId}
                  aria-describedby={describedBy}
                  type="text"
                  className="rq-input mono"
                  value={docVersion}
                  onChange={(e) => {
                    setDocVersion(e.target.value);
                  }}
                />
              )}
            </FormField>
          </div>

          <div className="rq-row">
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                void handleAcceptLegal();
              }}
            >
              Record Acceptance
            </button>
          </div>

          <MutationFeedback
            state={legalFeedback}
            resourceLabel="Legal acceptance"
            onDismiss={() => {
              setLegalFeedback({ kind: "idle" });
            }}
          />
        </section>
      </div>

      <section className="rq-card" aria-label="Next launch steps">
        <h2 className="rq-card-title">3. Regional Billing &amp; Webhook Destinations</h2>
        <div className="rq-row">
          <button
            type="button"
            className="rq-btn rq-btn-primary"
            onClick={() => {
              navigate(buildBillingPath());
            }}
          >
            Configure Plan &amp; Regional Gateway
          </button>
          {primaryWorkspace !== null ? (
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                navigate(
                  buildProjectPath(
                    primaryWorkspace.tenant_id,
                    primaryWorkspace.project_id,
                    "endpoints"
                  )
                );
              }}
            >
              Open Endpoint Wizard ({primaryWorkspace.project_name})
            </button>
          ) : null}
          <button
            type="button"
            className="rq-btn"
            onClick={() => {
              navigate(buildSettingsAuditPath());
            }}
          >
            Review Organization Audit &amp; Privacy
          </button>
        </div>
      </section>
    </div>
  );
}
