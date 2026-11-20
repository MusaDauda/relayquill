import { type JSX, useMemo, useState } from "react";
import { hashCanonicalJson, isCapabilityAvailable } from "@relayquill/contracts";
import { SIGNATURE_MODES, type SignatureMode } from "@relayquill/domain";
import { type EndpointSummaryDto, type RetainedDispatchGrantDto } from "../../api/dtos.js";
import { useActiveScope } from "../../app/scope.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CopyableId } from "../../components/CopyableId.js";
import { DataTable } from "../../components/DataTable.js";
import { FormField } from "../../components/FormField.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { StepUpModal, type StepUpTargetDescriptor } from "../access/StepUpModal.js";
import {
  ENDPOINT_WIZARD_STEP_LABELS,
  createInitialEndpointWizardState,
  getEndpointWizardStepEligibility,
  transitionEndpointWizardStep,
  updateEndpointWizardDraft,
  validateCustodyReferenceId,
  validateNormalizedHttpsUrl
} from "./endpoint-wizard.js";

export function EndpointsPage(): JSX.Element {
  const { api } = useConsoleRuntime();
  const scope = useActiveScope();

  const [showWizard, setShowWizard] = useState(true);
  const [wizard, setWizard] = useState(() => createInitialEndpointWizardState());
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointSummaryDto | null>(null);
  const [newVersionUrl, setNewVersionUrl] = useState("");
  const [grantExpiryUtc, setGrantExpiryUtc] = useState(() =>
    new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")
  );
  const [lifecycleReason, setLifecycleReason] = useState("endpoint_onboarding_or_governance");
  const [feedback, setFeedback] = useState<MutationFeedbackState>({ kind: "idle" });
  const [pendingStepUp, setPendingStepUp] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly execute: (operationProofId: string) => Promise<void>;
  } | null>(null);

  const endpointsQuery = useScopedQuery({
    resource: "project.endpoints",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEndpoints(scope.tenantId, scope.projectId, { limit: 50 }, signal)
  });

  const grantsQuery = useScopedQuery({
    resource: "project.retained_dispatch_grants",
    enabled: selectedEndpoint !== null,
    filter: { endpointId: selectedEndpoint?.endpoint_id },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listRetainedDispatchGrants(
        scope.tenantId,
        scope.projectId,
        selectedEndpoint?.endpoint_id ?? "",
        signal
      )
  });

  const verificationIntentsQuery = useScopedQuery({
    resource: "project.endpoint_verification_intents",
    enabled: selectedEndpoint !== null || wizard.endpointId !== null,
    filter: { endpointId: selectedEndpoint?.endpoint_id ?? wizard.endpointId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEndpointVerificationIntents(
        scope.tenantId,
        scope.projectId,
        selectedEndpoint?.endpoint_id ?? wizard.endpointId ?? "",
        signal
      )
  });

  const urlCheck = useMemo(
    () => validateNormalizedHttpsUrl(wizard.draft.destinationUrl),
    [wizard.draft.destinationUrl]
  );

  const senderRefErr = useMemo(
    () => validateCustodyReferenceId(wizard.draft.senderCustodyRefId, "Sender custody ref ID"),
    [wizard.draft.senderCustodyRefId]
  );
  const receiverRefErr = useMemo(
    () => validateCustodyReferenceId(wizard.draft.receiverCustodyRefId, "Receiver custody ref ID"),
    [wizard.draft.receiverCustodyRefId]
  );

  // Step 1: Register endpoint URL draft
  const handleStep1CreateEndpoint = async (): Promise<void> => {
    if (!urlCheck.valid || urlCheck.normalizedUrl === undefined) {
      return;
    }
    const body = {
      schema_version: 1,
      name: wizard.draft.name.trim(),
      destination_url: urlCheck.normalizedUrl,
      reason_code: "endpoint_onboarding_step_1"
    };
    setFeedback({ kind: "submitting", label: "Step 1: Registering normalized endpoint URL..." });
    const res = await api.createEndpoint(
      scope.tenantId,
      scope.projectId,
      body,
      generateIdempotencyKey("ep-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res, preservedDraft: body });
      return;
    }
    setWizard((prev) => ({
      ...prev,
      endpointId: res.data.endpoint_id,
      endpointVersion: res.data.current_version,
      configurationSha256: res.data.configuration_sha256,
      normalizedHost: res.data.normalized_host ?? urlCheck.normalizedHost ?? null,
      currentStep: 2
    }));
    setFeedback({
      kind: "succeeded",
      title: "Step 1 Complete: Destination Registered",
      detail: `Endpoint ${res.data.endpoint_id} created at v${res.data.current_version}.`
    });
    endpointsQuery.reload();
  };

  // Step 2: Create dual-custody signing key delivery intent (no raw secrets!)
  const handleStep2CreateKeyIntent = async (): Promise<void> => {
    if (wizard.endpointId === null || senderRefErr !== null || receiverRefErr !== null) {
      return;
    }
    const body = {
      schema_version: 1,
      endpoint_version: wizard.endpointVersion ?? "1",
      key_id: wizard.draft.keyIdLabel.trim(),
      sender_custody_destination_id: wizard.draft.senderCustodyRefId.trim(),
      receiver_custody_destination_id: wizard.draft.receiverCustodyRefId.trim(),
      reason_code: "dual_custody_signing_intent"
    };
    setFeedback({
      kind: "submitting",
      label: "Step 2: Provisioning signing key dual-custody intent..."
    });
    const res = await api.createSigningKeyIntent(
      scope.tenantId,
      scope.projectId,
      wizard.endpointId,
      body,
      generateIdempotencyKey("ep-key-intent")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res, preservedDraft: body });
      return;
    }
    setWizard((prev) => ({
      ...prev,
      keyVersionId: res.data.key_version_id,
      currentStep: 3
    }));
    setFeedback({
      kind: "succeeded",
      title: "Step 2 Complete: Signing Key Reference Provisioned",
      detail: `Key version ${res.data.key_version_id} (${res.data.key_id}) issued via dual-custody references.`
    });
  };

  // Step 3: Bind receiver contract readiness & create+activate signing policy
  const handleStep3BindPolicy = async (): Promise<void> => {
    if (wizard.endpointId === null || wizard.keyVersionId === null) {
      return;
    }
    const createBody = {
      schema_version: 1,
      signature_mode: wizard.draft.signatureMode,
      primary_key_version_id: wizard.keyVersionId,
      ...(wizard.draft.receiverContractId.trim().length > 0
        ? {
            receiver_contract_id: wizard.draft.receiverContractId.trim(),
            receiver_contract_version: wizard.draft.receiverContractVersion.trim()
          }
        : {}),
      reason_code: "endpoint_onboarding_policy_bind"
    };
    setFeedback({ kind: "submitting", label: "Step 3: Binding signing policy & contract..." });
    const policyRes = await api.createSigningPolicy(
      scope.tenantId,
      scope.projectId,
      wizard.endpointId,
      createBody,
      generateIdempotencyKey("ep-policy-create")
    );
    if (!policyRes.ok) {
      setFeedback({ kind: "failed", error: policyRes, preservedDraft: createBody });
      return;
    }

    const activateBody = {
      schema_version: 1,
      expected_policy_version: policyRes.data.policy_version,
      policy_sha256: policyRes.data.policy_sha256,
      reason_code: "endpoint_onboarding_policy_activate"
    };
    const actRes = await api.activateSigningPolicy(
      scope.tenantId,
      scope.projectId,
      policyRes.data.policy_id,
      activateBody,
      generateIdempotencyKey("ep-policy-act")
    );
    if (!actRes.ok) {
      setFeedback({ kind: "failed", error: actRes });
      return;
    }

    setWizard((prev) => ({
      ...prev,
      signingPolicyId: policyRes.data.policy_id,
      currentStep: 4
    }));
    setFeedback({
      kind: "succeeded",
      title: "Step 3 Complete: Signing Policy Active",
      detail: `Signing policy ${policyRes.data.policy_id} bound cleanly.`
    });
  };

  // Step 4: Bounded HTTP 204 / HMAC verification intent
  const handleStep4RunVerification = async (): Promise<void> => {
    if (wizard.endpointId === null || wizard.keyVersionId === null) {
      return;
    }
    const body = {
      schema_version: 1,
      endpoint_version: wizard.endpointVersion ?? "1",
      key_version_id: wizard.keyVersionId,
      purpose: "verify_destination_and_key",
      ...(wizard.configurationSha256 !== null
        ? { configuration_sha256: wizard.configurationSha256 }
        : {}),
      ...(wizard.draft.receiverContractId.trim().length > 0
        ? {
            receiver_contract_id: wizard.draft.receiverContractId.trim(),
            receiver_contract_version: wizard.draft.receiverContractVersion.trim()
          }
        : {})
    };
    setFeedback({
      kind: "submitting",
      label: "Step 4: Dispatching bounded HTTPS 204 / HMAC verification probe..."
    });
    const res = await api.createEndpointVerificationIntent(
      scope.tenantId,
      scope.projectId,
      wizard.endpointId,
      body,
      generateIdempotencyKey("ep-verify")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res, preservedDraft: body });
      return;
    }
    const passed =
      res.data.state === "verified" || res.data.proof_digest_sha256 !== null;
    setWizard((prev) => ({
      ...prev,
      verificationIntentId: res.data.intent_id,
      verificationPassed: passed,
      verificationProofSha256: res.data.proof_digest_sha256,
      currentStep: passed ? 5 : 4
    }));
    setFeedback({
      kind: "succeeded",
      title: passed ? "Step 4 Complete: Verification Proof Recorded" : "Verification Intent Queued",
      detail: `Intent ${res.data.intent_id} state=${res.data.state}, attempts=${res.data.attempts_used}/${res.data.max_attempts}.`
    });
    verificationIntentsQuery.reload();
  };

  // Step 6: Activate verified endpoint
  const openStep6Activation = (): void => {
    if (wizard.endpointId === null || wizard.endpointVersion === null) {
      return;
    }
    const endpointId = wizard.endpointId;
    const payload = {
      schema_version: 1,
      expected_version: wizard.endpointVersion,
      ...(wizard.configurationSha256 !== null
        ? { configuration_sha256: wizard.configurationSha256 }
        : {}),
      reason_code: "endpoint_onboarding_activation"
    };
    const canonical = hashCanonicalJson(payload);
    setPendingStepUp({
      descriptor: {
        action: "endpoints.activate",
        actionLabel: "Step 6: Activate Verified Endpoint",
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: endpointId,
        targetVersion: wizard.endpointVersion,
        canonicalCommandSha256: canonical.sha256,
        summary: `Promotes endpoint ${wizard.draft.name} (${urlCheck.normalizedHost ?? endpointId}) to active webhook dispatch.`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: "Step 6: Activating endpoint..." });
        const res = await api.mutateEndpointLifecycle(
          scope.tenantId,
          scope.projectId,
          endpointId,
          "activate",
          { ...payload, operation_proof_id: operationProofId },
          generateIdempotencyKey("ep-activate")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, preservedDraft: payload });
          return;
        }
        setWizard((prev) => ({ ...prev, activated: true }));
        setFeedback({
          kind: "succeeded",
          title: "Step 6 Complete: Endpoint Activated",
          detail: `Endpoint ${endpointId} is now active for verified webhook delivery.`,
          receiptId: res.data.receipt?.id
        });
        endpointsQuery.reload();
      }
    });
  };

  const openEndpointLifecycleStepUp = (
    ep: EndpointSummaryDto,
    action: "pause" | "quarantine" | "resume" | "retire"
  ): void => {
    const payload = {
      schema_version: 1,
      expected_version: ep.current_version,
      reason_code: lifecycleReason.trim() || `endpoint_${action}`
    };
    const canonical = hashCanonicalJson(payload);
    setPendingStepUp({
      descriptor: {
        action: `endpoints.${action}`,
        actionLabel: `Endpoint Lifecycle: ${action} (${ep.name})`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: ep.endpoint_id,
        targetVersion: ep.current_version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Transitions endpoint ${ep.name} (${ep.endpoint_id}) using "${action}".`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: `Executing endpoint ${action}...` });
        const res = await api.mutateEndpointLifecycle(
          scope.tenantId,
          scope.projectId,
          ep.endpoint_id,
          action,
          { ...payload, operation_proof_id: operationProofId },
          generateIdempotencyKey(`ep-${action}`)
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: ep });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: `Endpoint ${action} Committed`,
          detail: `Endpoint ${ep.name} transitioned (${action}).`,
          receiptId: res.data.receipt?.id
        });
        endpointsQuery.reload();
      }
    });
  };

  const handleCreateEndpointVersion = async (ep: EndpointSummaryDto): Promise<void> => {
    const urlRes = validateNormalizedHttpsUrl(newVersionUrl);
    if (!urlRes.valid || urlRes.normalizedUrl === undefined) {
      setFeedback({
        kind: "failed",
        error: {
          ok: false,
          status: 400,
          code: "INVALID_ENDPOINT_URL",
          message: urlRes.reason ?? "Invalid URL",
          acceptance: "known_rejected",
          retryable: false,
          aborted: false,
          fieldErrors: []
        }
      });
      return;
    }
    const res = await api.createEndpointVersion(
      scope.tenantId,
      scope.projectId,
      ep.endpoint_id,
      {
        schema_version: 1,
        expected_version: ep.current_version,
        destination_url: urlRes.normalizedUrl,
        reason_code: "endpoint_url_version_update"
      },
      generateIdempotencyKey("ep-new-ver")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res, currentServerState: ep });
      return;
    }
    setNewVersionUrl("");
    setSelectedEndpoint(res.data);
    setFeedback({
      kind: "succeeded",
      title: "Endpoint Version Created",
      detail: `Created v${res.data.current_version}; run destination re-verification before activating.`
    });
    endpointsQuery.reload();
  };

  const handleCreateRetainedGrant = async (ep: EndpointSummaryDto): Promise<void> => {
    const res = await api.createRetainedDispatchGrant(
      scope.tenantId,
      scope.projectId,
      ep.endpoint_id,
      {
        schema_version: 1,
        retained_endpoint_version: ep.current_version,
        expires_at: grantExpiryUtc.trim(),
        reason_code: "in_flight_drain_retained_grant"
      },
      generateIdempotencyKey("ep-retained-grant")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Retained Dispatch Grant Created",
      detail: `Grant ${res.data.grant_id} created through ${res.data.expires_at}.`
    });
    grantsQuery.reload();
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Webhook Endpoints & 6-Step Onboarding</h1>
          <p className="rq-page-lead">
            Register HTTPS webhook endpoints through strict pinned URL validation, dual-custody
            secret reference IDs, bounded 204/HMAC verification proofs, and retained dispatch
            version grants.
          </p>
        </div>
        <button
          type="button"
          className="rq-btn rq-btn-primary"
          onClick={() => {
            setShowWizard((prev) => !prev);
          }}
        >
          {showWizard ? "Hide Onboarding Wizard" : "Open 6-Step Endpoint Wizard"}
        </button>
      </header>

      <MutationFeedback state={feedback} resourceLabel="Endpoint workflow" />

      {showWizard ? (
        <section className="rq-card" aria-label="6-step endpoint onboarding wizard">
          <div className="rq-card-header">
            <h2 className="rq-section-title">6-Step Endpoint Onboarding Wizard</h2>
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                setWizard(createInitialEndpointWizardState());
              }}
            >
              Reset Wizard
            </button>
          </div>

          <ol className="rq-wizard-steps" aria-label="Wizard steps">
            {ENDPOINT_WIZARD_STEP_LABELS.map((item) => {
              const elig = getEndpointWizardStepEligibility(wizard, item.step);
              const isCurrent = wizard.currentStep === item.step;
              return (
                <li
                  key={item.step}
                  className="rq-wizard-step"
                  data-active={isCurrent ? "true" : "false"}
                >
                  <button
                    type="button"
                    className="rq-btn"
                    disabled={!elig.allowed}
                    title={elig.reason ?? undefined}
                    onClick={() => {
                      setWizard((prev) => transitionEndpointWizardStep(prev, item.step));
                    }}
                  >
                    {item.title}
                  </button>
                  <span className="rq-meta-text">{item.description}</span>
                </li>
              );
            })}
          </ol>

          {wizard.currentStep === 1 ? (
            <div className="rq-card-inset">
              <strong className="rq-label">Step 1: Normalized HTTPS Destination Check</strong>
              <div className="rq-grid-2">
                <FormField label="Endpoint Display Name" required>
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input"
                      placeholder="Payments Receiver Production"
                      value={wizard.draft.name}
                      onChange={(e) => {
                        setWizard((prev) =>
                          updateEndpointWizardDraft(prev, { name: e.target.value })
                        );
                      }}
                    />
                  )}
                </FormField>

                <FormField
                  label="Destination HTTPS URL"
                  errorText={
                    wizard.draft.destinationUrl.trim().length > 0 && !urlCheck.valid
                      ? urlCheck.reason
                      : null
                  }
                  helpText={
                    urlCheck.valid && urlCheck.normalizedHost !== undefined
                      ? `Normalized host: ${urlCheck.normalizedHost}`
                      : "Loopback hosts, userinfo credentials, and plaintext http:// are rejected."
                  }
                  required
                >
                  {({ inputId, hasError }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      aria-invalid={hasError}
                      placeholder="https://webhooks.partner.example/relayquill"
                      value={wizard.draft.destinationUrl}
                      onChange={(e) => {
                        setWizard((prev) =>
                          updateEndpointWizardDraft(prev, { destinationUrl: e.target.value })
                        );
                      }}
                    />
                  )}
                </FormField>
              </div>
              <div className="rq-row">
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={wizard.draft.name.trim().length === 0 || !urlCheck.valid}
                  onClick={() => {
                    void handleStep1CreateEndpoint();
                  }}
                >
                  Save Step 1 & Continue
                </button>
              </div>
            </div>
          ) : null}

          {wizard.currentStep === 2 ? (
            <div className="rq-card-inset">
              <strong className="rq-label">
                Step 2: Dual-Custody Signing Secret Reference IDs (Zero Raw Secrets)
              </strong>
              <div className="rq-grid-3">
                <FormField
                  label="Sender Custody Ref ID"
                  errorText={senderRefErr}
                  required
                >
                  {({ inputId, hasError }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      aria-invalid={hasError}
                      value={wizard.draft.senderCustodyRefId}
                      onChange={(e) => {
                        setWizard((prev) =>
                          updateEndpointWizardDraft(prev, {
                            senderCustodyRefId: e.target.value
                          })
                        );
                      }}
                    />
                  )}
                </FormField>

                <FormField
                  label="Receiver Custody Ref ID"
                  errorText={receiverRefErr}
                  required
                >
                  {({ inputId, hasError }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      aria-invalid={hasError}
                      value={wizard.draft.receiverCustodyRefId}
                      onChange={(e) => {
                        setWizard((prev) =>
                          updateEndpointWizardDraft(prev, {
                            receiverCustodyRefId: e.target.value
                          })
                        );
                      }}
                    />
                  )}
                </FormField>

                <FormField label="Key ID Label" required>
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={wizard.draft.keyIdLabel}
                      onChange={(e) => {
                        setWizard((prev) =>
                          updateEndpointWizardDraft(prev, { keyIdLabel: e.target.value })
                        );
                      }}
                    />
                  )}
                </FormField>
              </div>
              <div className="rq-row">
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={
                    senderRefErr !== null ||
                    receiverRefErr !== null ||
                    wizard.draft.keyIdLabel.trim().length === 0
                  }
                  onClick={() => {
                    void handleStep2CreateKeyIntent();
                  }}
                >
                  Provision Custody Key Intent & Continue
                </button>
              </div>
            </div>
          ) : null}

          {wizard.currentStep === 3 ? (
            <div className="rq-card-inset">
              <strong className="rq-label">
                Step 3: Receiver Readiness & Signing Policy Binding
              </strong>
              <div className="rq-grid-3">
                <FormField label="Signature Mode">
                  {({ inputId }) => (
                    <select
                      id={inputId}
                      className="rq-select"
                      value={wizard.draft.signatureMode}
                      onChange={(e) => {
                        setWizard((prev) =>
                          updateEndpointWizardDraft(prev, {
                            signatureMode: e.target.value as SignatureMode
                          })
                        );
                      }}
                    >
                      {SIGNATURE_MODES.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </select>
                  )}
                </FormField>

                <FormField label="Receiver Contract ID (optional)">
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      placeholder="UUID if bound"
                      value={wizard.draft.receiverContractId}
                      onChange={(e) => {
                        setWizard((prev) =>
                          updateEndpointWizardDraft(prev, {
                            receiverContractId: e.target.value
                          })
                        );
                      }}
                    />
                  )}
                </FormField>

                <FormField label="Receiver Contract Version">
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={wizard.draft.receiverContractVersion}
                      onChange={(e) => {
                        setWizard((prev) =>
                          updateEndpointWizardDraft(prev, {
                            receiverContractVersion: e.target.value
                          })
                        );
                      }}
                    />
                  )}
                </FormField>
              </div>

              <label className="rq-checkbox-row">
                <input
                  type="checkbox"
                  checked={wizard.draft.receiverReadinessAck}
                  onChange={(e) => {
                    setWizard((prev) =>
                      updateEndpointWizardDraft(prev, {
                        receiverReadinessAck: e.target.checked
                      })
                    );
                  }}
                />
                <span>
                  I confirm the receiver endpoint validates HMAC-SHA256 signatures and responds
                  within request timeouts with HTTP 204/2xx.
                </span>
              </label>

              <div className="rq-row">
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={!wizard.draft.receiverReadinessAck}
                  onClick={() => {
                    void handleStep3BindPolicy();
                  }}
                >
                  Bind & Activate Signing Policy
                </button>
              </div>
            </div>
          ) : null}

          {wizard.currentStep === 4 ? (
            <div className="rq-card-inset">
              <strong className="rq-label">
                Step 4: Bounded HTTP 204 / HMAC Verification Proof
              </strong>
              <p className="rq-meta-text">
                Dispatches a bounded verification challenge to{" "}
                <span className="mono">{urlCheck.normalizedUrl ?? wizard.normalizedHost}</span> and
                records a cryptographic <span className="kbd-chip">proof_digest_sha256</span>.
              </p>
              <div className="rq-row">
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  onClick={() => {
                    void handleStep4RunVerification();
                  }}
                >
                  Execute Bounded 204 Verification Probe
                </button>
              </div>
            </div>
          ) : null}

          {wizard.currentStep === 5 ? (
            <div className="rq-card-inset">
              <strong className="rq-label">Step 5: Pre-Activation Integrity Review</strong>
              <dl className="rq-kv-grid">
                <dt>Endpoint ID & Version</dt>
                <dd className="mono">
                  {wizard.endpointId} (v{wizard.endpointVersion})
                </dd>
                <dt>Normalized Host</dt>
                <dd className="mono">{wizard.normalizedHost ?? "unknown"}</dd>
                <dt>Configuration SHA-256</dt>
                <dd className="mono">{wizard.configurationSha256 ?? "pending"}</dd>
                <dt>Verification Proof SHA-256</dt>
                <dd className="mono">{wizard.verificationProofSha256 ?? "missing"}</dd>
                <dt>Signing Policy ID</dt>
                <dd className="mono">{wizard.signingPolicyId ?? "missing"}</dd>
              </dl>
              <div className="rq-row">
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  onClick={() => {
                    setWizard((prev) => transitionEndpointWizardStep(prev, 6));
                  }}
                >
                  Proceed to Step 6 Activation
                </button>
              </div>
            </div>
          ) : null}

          {wizard.currentStep === 6 ? (
            <div className="rq-card-inset">
              <div className="rq-row-between">
                <strong className="rq-label">Step 6: Activate Endpoint</strong>
                <StatusBadge
                  status={wizard.activated ? "active" : "verified"}
                  label={wizard.activated ? "Endpoint Active" : "Ready for Activation"}
                />
              </div>
              <p className="rq-meta-text">
                Endpoint activation requires passkey step-up bound to endpoint ID, version v
                {wizard.endpointVersion}, and configuration SHA-256.
              </p>
              <div className="rq-row">
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={wizard.activated}
                  onClick={openStep6Activation}
                >
                  Activate Endpoint (Step-Up)
                </button>
              </div>
            </div>
          ) : null}
        </section>
      ) : null}

      <ResourceStatePanel
        view={endpointsQuery.view}
        resourceLabel="Webhook endpoints"
        emptyTitle="No webhook endpoints configured yet"
        onRetry={endpointsQuery.reload}
      >
        {(epPage) => (
          <section className="rq-card" aria-label="Configured endpoints table">
            <DataTable<EndpointSummaryDto>
              caption="Project webhook endpoints"
              rows={epPage.items}
              rowKey={(e) => e.endpoint_id}
              columns={[
                {
                  key: "name",
                  header: "Endpoint & Host",
                  render: (e) => (
                    <div className="rq-stack-sm">
                      <strong>{e.name}</strong>
                      <span className="rq-meta-text mono">
                        {e.normalized_host ?? e.destination_url ?? e.endpoint_id}
                      </span>
                    </div>
                  )
                },
                {
                  key: "state",
                  header: "State & Verification",
                  render: (e) => (
                    <div className="rq-row">
                      <StatusBadge status={e.state} />
                      <StatusBadge
                        status={e.verification_state}
                        label={`verify: ${e.verification_state}`}
                      />
                    </div>
                  )
                },
                {
                  key: "version",
                  header: "Version & Epoch",
                  render: (e) => (
                    <span className="mono">
                      v{e.current_version} (sec epoch {e.security_epoch})
                    </span>
                  )
                },
                {
                  key: "actions",
                  header: "Manage",
                  render: (e) => (
                    <div className="rq-row">
                      <button
                        type="button"
                        className="rq-btn"
                        onClick={() => {
                          setSelectedEndpoint(e);
                        }}
                      >
                        Detail & Grants
                      </button>
                      {e.state === "active" ? (
                        <button
                          type="button"
                          className="rq-btn"
                          disabled={
                            !isCapabilityAvailable(e.capabilities ?? [], "endpoints.pause") &&
                            (e.capabilities?.length ?? 0) > 0
                          }
                          onClick={() => {
                            openEndpointLifecycleStepUp(e, "pause");
                          }}
                        >
                          Pause
                        </button>
                      ) : null}
                      {e.state === "paused" || e.state === "quarantined" ? (
                        <button
                          type="button"
                          className="rq-btn rq-btn-primary"
                          onClick={() => {
                            openEndpointLifecycleStepUp(e, "resume");
                          }}
                        >
                          Resume
                        </button>
                      ) : null}
                      {e.state !== "retired" ? (
                        <button
                          type="button"
                          className="rq-btn rq-btn-danger"
                          onClick={() => {
                            openEndpointLifecycleStepUp(e, "retire");
                          }}
                        >
                          Retire
                        </button>
                      ) : null}
                    </div>
                  )
                }
              ]}
            />
          </section>
        )}
      </ResourceStatePanel>

      {selectedEndpoint !== null ? (
        <section className="rq-card" aria-label="Selected endpoint versioning and retained grants">
          <div className="rq-card-header">
            <h2 className="rq-section-title">
              Endpoint Detail: {selectedEndpoint.name} (v{selectedEndpoint.current_version})
            </h2>
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                setSelectedEndpoint(null);
              }}
            >
              Close Detail
            </button>
          </div>

          <dl className="rq-kv-grid">
            <dt>Endpoint ID</dt>
            <dd>
              <CopyableId value={selectedEndpoint.endpoint_id} />
            </dd>
            <dt>Configuration SHA-256</dt>
            <dd>
              <CopyableId value={selectedEndpoint.configuration_sha256} />
            </dd>
            <dt>Policies (URL / Net / Req / Resp)</dt>
            <dd className="mono">
              {selectedEndpoint.url_policy_version} / {selectedEndpoint.network_policy_version} /{" "}
              {selectedEndpoint.request_profile_version} / {selectedEndpoint.response_profile_version}
            </dd>
          </dl>

          <div className="rq-grid-2">
            <FormField label="Create New Endpoint URL Version">
              {({ inputId }) => (
                <div className="rq-row">
                  <input
                    id={inputId}
                    className="rq-input mono"
                    placeholder="https://new-host.partner.example/webhook"
                    value={newVersionUrl}
                    onChange={(e) => {
                      setNewVersionUrl(e.target.value);
                    }}
                  />
                  <button
                    type="button"
                    className="rq-btn"
                    onClick={() => {
                      void handleCreateEndpointVersion(selectedEndpoint);
                    }}
                  >
                    Create Version
                  </button>
                </div>
              )}
            </FormField>

            <FormField label="Lifecycle Reason Code">
              {({ inputId }) => (
                <input
                  id={inputId}
                  className="rq-input mono"
                  value={lifecycleReason}
                  onChange={(e) => {
                    setLifecycleReason(e.target.value);
                  }}
                />
              )}
            </FormField>
          </div>

          <div className="rq-card-inset">
            <div className="rq-row-between">
              <strong className="rq-label">Retained Dispatch Version Grants</strong>
              <div className="rq-row">
                <input
                  aria-label="Retained grant expiry UTC"
                  className="rq-input mono"
                  value={grantExpiryUtc}
                  onChange={(e) => {
                    setGrantExpiryUtc(e.target.value);
                  }}
                />
                <button
                  type="button"
                  className="rq-btn"
                  onClick={() => {
                    void handleCreateRetainedGrant(selectedEndpoint);
                  }}
                >
                  Issue Retained Grant
                </button>
              </div>
            </div>
            <ResourceStatePanel
              view={grantsQuery.view}
              resourceLabel="Retained dispatch grants"
              emptyTitle="No retained dispatch grants"
              onRetry={grantsQuery.reload}
            >
              {(grantsPage) => (
                <DataTable<RetainedDispatchGrantDto>
                  caption="Retained dispatch grants"
                  rows={grantsPage.items}
                  rowKey={(g) => g.grant_id}
                  columns={[
                    {
                      key: "id",
                      header: "Grant & Version",
                      render: (g) => (
                        <span className="mono">
                          {g.grant_id} (ep v{g.retained_endpoint_version})
                        </span>
                      )
                    },
                    {
                      key: "state",
                      header: "State & Expiry",
                      render: (g) => (
                        <div className="rq-row">
                          <StatusBadge status={g.state} />
                          <UtcTimestamp value={g.expires_at} showLocal={false} />
                        </div>
                      )
                    },
                    {
                      key: "revoke",
                      header: "Action",
                      render: (g) =>
                        g.state === "active" ? (
                          <button
                            type="button"
                            className="rq-btn rq-btn-danger"
                            onClick={() => {
                              void (async () => {
                                const res = await api.revokeRetainedDispatchGrant(
                                  scope.tenantId,
                                  scope.projectId,
                                  g.grant_id,
                                  {
                                    schema_version: 1,
                                    expected_version: g.version,
                                    reason_code: "operator_revoke_retained_grant"
                                  },
                                  generateIdempotencyKey("ep-grant-revoke")
                                );
                                if (!res.ok) {
                                  setFeedback({ kind: "failed", error: res });
                                  return;
                                }
                                grantsQuery.reload();
                              })();
                            }}
                          >
                            Revoke Grant
                          </button>
                        ) : null
                    }
                  ]}
                />
              )}
            </ResourceStatePanel>
          </div>
        </section>
      ) : null}

      <StepUpModal
        target={pendingStepUp?.descriptor ?? null}
        onCancel={() => {
          setPendingStepUp(null);
        }}
        onVerified={async (proof) => {
          const current = pendingStepUp;
          setPendingStepUp(null);
          if (current !== null) {
            await current.execute(proof.operationProofId);
          }
        }}
      />
    </div>
  );
}
