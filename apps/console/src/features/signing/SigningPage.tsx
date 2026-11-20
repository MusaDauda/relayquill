import { type JSX, useState } from "react";
import { hashCanonicalJson } from "@relayquill/contracts";
import {
  PRODUCER_SCOPE_ACTIONS,
  type ProducerScopeAction,
  SIGNATURE_MODES,
  type SignatureMode
} from "@relayquill/domain";
import {
  type ProducerSummaryDto,
  type SigningKeyVersionDto,
  type SigningPolicyDto
} from "../../api/dtos.js";
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
import { validateCustodyReferenceId } from "../endpoints/endpoint-wizard.js";

export function SigningPage(): JSX.Element {
  const { api } = useConsoleRuntime();
  const scope = useActiveScope();

  const [selectedEndpointId, setSelectedEndpointId] = useState("");
  const [newKeyId, setNewKeyId] = useState("rk_v2_rotate");
  const [senderCustodyRef, setSenderCustodyRef] = useState("custody-sender-rotate");
  const [receiverCustodyRef, setReceiverCustodyRef] = useState("custody-receiver-rotate");
  const [policyMode, setPolicyMode] = useState<SignatureMode>("bounded_dual_signature");
  const [primaryKeyVersionId, setPrimaryKeyVersionId] = useState("");
  const [overlapKeyVersionId, setOverlapKeyVersionId] = useState("");
  const [overlapEndsAt, setOverlapEndsAt] = useState(() =>
    new Date(Date.now() + 48 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")
  );

  // Producer creation & rq_p1 credential intent state (strictly custody refs)
  const [producerName, setProducerName] = useState("");
  const [producerNamespace, setProducerNamespace] = useState("");
  const [selectedProducerId, setSelectedProducerId] = useState("");
  const [scopeActions, setScopeActions] = useState<readonly ProducerScopeAction[]>([
    "events.admit",
    "events.resolve",
    "events.read_own"
  ]);
  const [credCustodyRef, setCredCustodyRef] = useState("custody-producer-ingest");
  const [credScopeVersion, setCredScopeVersion] = useState("1");
  const [credExpiresAt, setCredExpiresAt] = useState(() =>
    new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")
  );

  const [feedback, setFeedback] = useState<MutationFeedbackState>({ kind: "idle" });
  const [pendingStepUp, setPendingStepUp] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly execute: (operationProofId: string) => Promise<void>;
  } | null>(null);

  const endpointsQuery = useScopedQuery({
    resource: "project.signing_endpoints",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEndpoints(scope.tenantId, scope.projectId, { limit: 100 }, signal)
  });

  const keysQuery = useScopedQuery({
    resource: "project.signing_keys",
    enabled: selectedEndpointId.trim().length > 0,
    filter: { selectedEndpointId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listSigningKeys(scope.tenantId, scope.projectId, selectedEndpointId.trim(), signal)
  });

  const keyIntentsQuery = useScopedQuery({
    resource: "project.signing_key_intents",
    enabled: selectedEndpointId.trim().length > 0,
    filter: { selectedEndpointId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listSigningKeyIntents(
        scope.tenantId,
        scope.projectId,
        selectedEndpointId.trim(),
        signal
      )
  });

  const policiesQuery = useScopedQuery({
    resource: "project.signing_policies",
    enabled: selectedEndpointId.trim().length > 0,
    filter: { selectedEndpointId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listSigningPolicies(scope.tenantId, scope.projectId, selectedEndpointId.trim(), signal)
  });

  const producersQuery = useScopedQuery({
    resource: "project.producers",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listProducers(scope.tenantId, scope.projectId, signal)
  });

  const handleCreateSigningKeyIntent = async (): Promise<void> => {
    const errA = validateCustodyReferenceId(senderCustodyRef, "Sender custody ref");
    const errB = validateCustodyReferenceId(receiverCustodyRef, "Receiver custody ref");
    if (errA !== null || errB !== null) {
      setFeedback({
        kind: "failed",
        error: {
          ok: false,
          status: 400,
          code: "INVALID_CUSTODY_REFERENCE",
          message: errA ?? errB ?? "Invalid custody reference.",
          acceptance: "known_rejected",
          retryable: false,
          aborted: false,
          fieldErrors: []
        }
      });
      return;
    }

    const ep =
      endpointsQuery.view.state === "current"
        ? endpointsQuery.view.data.items.find((x) => x.endpoint_id === selectedEndpointId.trim())
        : undefined;
    const res = await api.createSigningKeyIntent(
      scope.tenantId,
      scope.projectId,
      selectedEndpointId.trim(),
      {
        schema_version: 1,
        endpoint_version: ep?.current_version ?? "1",
        key_id: newKeyId.trim(),
        sender_custody_destination_id: senderCustodyRef.trim(),
        receiver_custody_destination_id: receiverCustodyRef.trim(),
        reason_code: "key_rotation_intent"
      },
      generateIdempotencyKey("sig-key-intent")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setPrimaryKeyVersionId(res.data.key_version_id);
    setFeedback({
      kind: "succeeded",
      title: "Signing Key Intent Issued",
      detail: `Created dual-custody signing intent ${res.data.intent_id} (${res.data.key_id}). Raw key material stays outside the browser.`
    });
    keyIntentsQuery.reload();
    keysQuery.reload();
  };

  const handleCreateSigningPolicy = async (): Promise<void> => {
    const res = await api.createSigningPolicy(
      scope.tenantId,
      scope.projectId,
      selectedEndpointId.trim(),
      {
        schema_version: 1,
        signature_mode: policyMode,
        primary_key_version_id: primaryKeyVersionId.trim(),
        ...(policyMode === "bounded_dual_signature" && overlapKeyVersionId.trim().length > 0
          ? {
              overlap_key_version_id: overlapKeyVersionId.trim(),
              overlap_ends_at: overlapEndsAt.trim()
            }
          : {}),
        reason_code: "signing_policy_rotation"
      },
      generateIdempotencyKey("sig-policy-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Signing Policy Created",
      detail: `Policy ${res.data.policy_id} created in draft (${res.data.signature_mode}).`
    });
    policiesQuery.reload();
  };

  const openActivatePolicy = (policy: SigningPolicyDto): void => {
    const body = {
      schema_version: 1,
      expected_policy_version: policy.policy_version,
      policy_sha256: policy.policy_sha256,
      reason_code: "activate_signing_policy"
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: "signing_policies.activate",
        actionLabel: `Activate Signing Policy v${policy.policy_version}`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: policy.policy_id,
        targetVersion: policy.policy_version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Promotes signing policy ${policy.policy_id} (${policy.signature_mode}) with overlap policy ${policy.policy_sha256.slice(0, 16)}...`
      },
      execute: async (operationProofId: string) => {
        const res = await api.activateSigningPolicy(
          scope.tenantId,
          scope.projectId,
          policy.policy_id,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey("sig-policy-act")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: policy });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Signing Policy Activated",
          detail: `Policy v${policy.policy_version} is now active.`,
          receiptId: res.data.receipt?.id
        });
        policiesQuery.reload();
      }
    });
  };

  const openRevokeSigningKey = (key: SigningKeyVersionDto): void => {
    const body = {
      schema_version: 1,
      expected_version: key.version,
      reason_code: "operator_revoke_signing_key"
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: "signing_keys.revoke",
        actionLabel: `Revoke Signing Key ${key.key_id}`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: key.key_version_id,
        targetVersion: key.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Revokes webhook signing key ${key.key_id} (${key.key_version_id}).`
      },
      execute: async (operationProofId: string) => {
        const res = await api.revokeSigningKey(
          scope.tenantId,
          scope.projectId,
          key.key_version_id,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey("sig-key-revoke")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: key });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Signing Key Revoked",
          detail: `Key ${key.key_id} was revoked.`,
          receiptId: res.data.receipt?.id
        });
        keysQuery.reload();
      }
    });
  };

  const handleCreateProducer = async (): Promise<void> => {
    const res = await api.createProducer(
      scope.tenantId,
      scope.projectId,
      {
        schema_version: 1,
        name: producerName.trim(),
        business_namespace: producerNamespace.trim()
      },
      generateIdempotencyKey("producer-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setProducerName("");
    setSelectedProducerId(res.data.producer_id);
    setFeedback({
      kind: "succeeded",
      title: "Producer Created",
      detail: `Created producer ${res.data.name} under namespace ${res.data.business_namespace}.`
    });
    producersQuery.reload();
  };

  const handleIssueCredentialIntent = (
    producer: ProducerSummaryDto,
    isRotation: boolean
  ): void => {
    const custErr = validateCustodyReferenceId(credCustodyRef, "Custody destination ID");
    if (custErr !== null) {
      setFeedback({
        kind: "failed",
        error: {
          ok: false,
          status: 400,
          code: "INVALID_CUSTODY_REFERENCE",
          message: custErr,
          acceptance: "known_rejected",
          retryable: false,
          aborted: false,
          fieldErrors: []
        }
      });
      return;
    }
    const body = {
      schema_version: 1,
      expected_producer_version: producer.version,
      scope_version: credScopeVersion.trim() || producer.current_scope_version || "1",
      custody_destination_id: credCustodyRef.trim(),
      requested_expires_at: credExpiresAt.trim(),
      reason_code: isRotation ? "producer_credential_rotation" : "producer_credential_issue"
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: isRotation ? "producers.credential_rotate" : "producers.credential_issue",
        actionLabel: `${isRotation ? "Rotate" : "Issue"} rq_p1 Credential Intent (${producer.name})`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: producer.producer_id,
        targetVersion: producer.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Delivers new bounded rq_p1 credential material solely to custody destination ${credCustodyRef.trim()}; never displayed in browser DOM.`
      },
      execute: async (operationProofId: string) => {
        const res = isRotation
          ? await api.rotateProducerCredential(
              scope.tenantId,
              scope.projectId,
              producer.producer_id,
              { ...body, operation_proof_id: operationProofId },
              generateIdempotencyKey("prod-cred-rotate")
            )
          : await api.createProducerCredentialIntent(
              scope.tenantId,
              scope.projectId,
              producer.producer_id,
              { ...body, operation_proof_id: operationProofId },
              generateIdempotencyKey("prod-cred-issue")
            );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: producer });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: isRotation ? "Credential Rotation Intent Issued" : "rq_p1 Credential Intent Issued",
          detail: `Credential dispatched to custody destination ${credCustodyRef.trim()}.`,
          receiptId: res.data.receipt?.id
        });
        producersQuery.reload();
      }
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">
            Signing Key Lifecycle & Producer Credentials (<span className="mono">rq_p1</span>)
          </h1>
          <p className="rq-page-lead">
            Rotate webhook HMAC signing keys using bounded dual-signature overlap windows and
            issue producer <span className="kbd-chip">rq_p1</span> credentials exclusively through
            custody references without ever exposing raw secret material to the browser.
          </p>
        </div>
      </header>

      <MutationFeedback state={feedback} resourceLabel="Signing & Credentials" />

      <section className="rq-card" aria-label="Webhook endpoint signing keys">
        <h2 className="rq-section-title">Webhook Signing Keys & Bounded Dual-Signature Overlap</h2>

        <FormField label="Select Endpoint">
          {({ inputId }) => (
            <select
              id={inputId}
              className="rq-select"
              value={selectedEndpointId}
              onChange={(e) => {
                setSelectedEndpointId(e.target.value);
              }}
            >
              <option value="">Choose endpoint...</option>
              {endpointsQuery.view.state === "current"
                ? endpointsQuery.view.data.items.map((ep) => (
                    <option key={ep.endpoint_id} value={ep.endpoint_id}>
                      {ep.name} ({ep.endpoint_id})
                    </option>
                  ))
                : null}
            </select>
          )}
        </FormField>

        {selectedEndpointId.trim().length > 0 ? (
          <div className="rq-stack">
            <div className="rq-grid-2">
              <div className="rq-card-inset">
                <strong className="rq-label">Create Signing Key Custody Intent</strong>
                <FormField label="Key ID Label">
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={newKeyId}
                      onChange={(e) => {
                        setNewKeyId(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                <FormField label="Sender Custody Destination Ref">
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={senderCustodyRef}
                      onChange={(e) => {
                        setSenderCustodyRef(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                <FormField label="Receiver Custody Destination Ref">
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={receiverCustodyRef}
                      onChange={(e) => {
                        setReceiverCustodyRef(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  onClick={() => {
                    void handleCreateSigningKeyIntent();
                  }}
                >
                  Create Dual-Custody Key Intent
                </button>
              </div>

              <div className="rq-card-inset">
                <strong className="rq-label">Create Overlap Signing Policy</strong>
                <FormField label="Signature Mode">
                  {({ inputId }) => (
                    <select
                      id={inputId}
                      className="rq-select"
                      value={policyMode}
                      onChange={(e) => {
                        setPolicyMode(e.target.value as SignatureMode);
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
                <FormField label="Primary Key Version ID">
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={primaryKeyVersionId}
                      onChange={(e) => {
                        setPrimaryKeyVersionId(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                {policyMode === "bounded_dual_signature" ? (
                  <>
                    <FormField label="Overlap Previous Key Version ID">
                      {({ inputId }) => (
                        <input
                          id={inputId}
                          className="rq-input mono"
                          value={overlapKeyVersionId}
                          onChange={(e) => {
                            setOverlapKeyVersionId(e.target.value);
                          }}
                        />
                      )}
                    </FormField>
                    <FormField label="Overlap Window Ends At (UTC)">
                      {({ inputId }) => (
                        <input
                          id={inputId}
                          className="rq-input mono"
                          value={overlapEndsAt}
                          onChange={(e) => {
                            setOverlapEndsAt(e.target.value);
                          }}
                        />
                      )}
                    </FormField>
                  </>
                ) : null}
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={primaryKeyVersionId.trim().length === 0}
                  onClick={() => {
                    void handleCreateSigningPolicy();
                  }}
                >
                  Create Signing Policy
                </button>
              </div>
            </div>

            <ResourceStatePanel
              view={keysQuery.view}
              resourceLabel="Signing keys"
              emptyTitle="No signing keys provisioned yet"
              onRetry={keysQuery.reload}
            >
              {(keysPage) => (
                <DataTable<SigningKeyVersionDto>
                  caption="Endpoint signing key versions"
                  rows={keysPage.items}
                  rowKey={(k) => k.key_version_id}
                  columns={[
                    {
                      key: "key",
                      header: "Key ID & Algorithm",
                      render: (k) => (
                        <div className="rq-stack-sm">
                          <strong>{k.key_id}</strong>
                          <CopyableId value={k.key_version_id} />
                          <span className="rq-meta-text mono">{k.algorithm}</span>
                        </div>
                      )
                    },
                    {
                      key: "state",
                      header: "Lifecycle State",
                      render: (k) => <StatusBadge status={k.state} />
                    },
                    {
                      key: "actions",
                      header: "Revoke",
                      render: (k) =>
                        k.state !== "revoked" ? (
                          <button
                            type="button"
                            className="rq-btn rq-btn-danger"
                            onClick={() => {
                              openRevokeSigningKey(k);
                            }}
                          >
                            Revoke Key (Step-Up)
                          </button>
                        ) : null
                    }
                  ]}
                />
              )}
            </ResourceStatePanel>

            <ResourceStatePanel
              view={policiesQuery.view}
              resourceLabel="Signing policies"
              emptyTitle="No signing policies defined"
              onRetry={policiesQuery.reload}
            >
              {(polPage) => (
                <DataTable<SigningPolicyDto>
                  caption="Endpoint signing policies"
                  rows={polPage.items}
                  rowKey={(p) => p.policy_id}
                  columns={[
                    {
                      key: "pol",
                      header: "Policy Version & Mode",
                      render: (p) => (
                        <div className="rq-stack-sm">
                          <span className="kbd-chip">
                            v{p.policy_version} — {p.signature_mode}
                          </span>
                          <CopyableId value={p.policy_id} />
                        </div>
                      )
                    },
                    {
                      key: "state",
                      header: "State & Overlap",
                      render: (p) => (
                        <div className="rq-stack-sm">
                          <StatusBadge status={p.state} />
                          {p.overlap_ends_at !== null ? (
                            <UtcTimestamp value={p.overlap_ends_at} />
                          ) : null}
                        </div>
                      )
                    },
                    {
                      key: "activate",
                      header: "Actions",
                      render: (p) =>
                        p.state === "draft" ? (
                          <button
                            type="button"
                            className="rq-btn rq-btn-primary"
                            onClick={() => {
                              openActivatePolicy(p);
                            }}
                          >
                            Activate Policy (Step-Up)
                          </button>
                        ) : null
                    }
                  ]}
                />
              )}
            </ResourceStatePanel>

            <ResourceStatePanel
              view={keyIntentsQuery.view}
              resourceLabel="Signing key custody intents"
              emptyTitle="No pending custody intents"
              onRetry={keyIntentsQuery.reload}
            >
              {(intentsPage) => (
                <div className="rq-card-inset">
                  <strong className="rq-label">
                    Signing Delivery Intents ({intentsPage.items.length})
                  </strong>
                  {intentsPage.items.map((intent) => (
                    <div key={intent.intent_id} className="rq-row-between">
                      <span className="mono">
                        {intent.key_id} -&gt; {intent.sender_custody_destination_id} /{" "}
                        {intent.receiver_custody_destination_id}
                      </span>
                      <StatusBadge status={intent.state} />
                    </div>
                  ))}
                </div>
              )}
            </ResourceStatePanel>
          </div>
        ) : null}
      </section>

      <section className="rq-card" aria-label="Machine producers and rq_p1 credentials">
        <h2 className="rq-section-title">Machine Producers & rq_p1 Credential Intents</h2>

        <div className="rq-grid-3">
          <FormField label="Producer Name">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input"
                placeholder="checkout-service"
                value={producerName}
                onChange={(e) => {
                  setProducerName(e.target.value);
                }}
              />
            )}
          </FormField>
          <FormField label="Immutable Business Namespace">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                placeholder="checkout"
                value={producerNamespace}
                onChange={(e) => {
                  setProducerNamespace(e.target.value);
                }}
              />
            )}
          </FormField>
          <div className="rq-row">
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              disabled={producerName.trim().length === 0 || producerNamespace.trim().length === 0}
              onClick={() => {
                void handleCreateProducer();
              }}
            >
              Create Producer
            </button>
          </div>
        </div>

        <div className="rq-card-inset">
          <strong className="rq-label">Credential Custody Parameters</strong>
          <div className="rq-grid-3">
            <FormField label="Custody Destination ID (No Raw rq_p1 In Browser)">
              {({ inputId }) => (
                <input
                  id={inputId}
                  className="rq-input mono"
                  value={credCustodyRef}
                  onChange={(e) => {
                    setCredCustodyRef(e.target.value);
                  }}
                />
              )}
            </FormField>
            <FormField label="Scope Version">
              {({ inputId }) => (
                <input
                  id={inputId}
                  className="rq-input mono"
                  value={credScopeVersion}
                  onChange={(e) => {
                    setCredScopeVersion(e.target.value);
                  }}
                />
              )}
            </FormField>
            <FormField label="Requested Expiry (UTC)">
              {({ inputId }) => (
                <input
                  id={inputId}
                  className="rq-input mono"
                  value={credExpiresAt}
                  onChange={(e) => {
                    setCredExpiresAt(e.target.value);
                  }}
                />
              )}
            </FormField>
          </div>

          <div className="rq-row">
            {PRODUCER_SCOPE_ACTIONS.map((act) => {
              const checked = scopeActions.includes(act);
              return (
                <label key={act} className="rq-checkbox-row">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) => {
                      setScopeActions((prev) =>
                        e.target.checked
                          ? [...prev, act]
                          : prev.filter((item) => item !== act)
                      );
                    }}
                  />
                  <span className="mono">{act}</span>
                </label>
              );
            })}
          </div>
        </div>

        <ResourceStatePanel
          view={producersQuery.view}
          resourceLabel="Machine producers"
          emptyTitle="No machine producers provisioned yet"
          onRetry={producersQuery.reload}
        >
          {(prodPage) => (
            <DataTable<ProducerSummaryDto>
              caption="Machine producers and rq_p1 credentials"
              rows={prodPage.items}
              rowKey={(p) => p.producer_id}
              columns={[
                {
                  key: "producer",
                  header: "Producer & Namespace",
                  render: (p) => (
                    <div className="rq-stack-sm">
                      <strong>{p.name}</strong>
                      <CopyableId value={p.producer_id} />
                      <span className="rq-meta-text mono">
                        ns={p.business_namespace} / epoch {p.authority_epoch}
                      </span>
                    </div>
                  )
                },
                {
                  key: "creds",
                  header: "Credentials & Scopes",
                  render: (p) => (
                    <div className="rq-stack-sm">
                      <StatusBadge status={p.state} />
                      <span className="rq-meta-text mono">
                        active scope v{p.current_scope_version ?? "none"} | creds:{" "}
                        {p.credentials.length} | intents: {p.credential_intents.length}
                      </span>
                      {p.credentials.map((c) => (
                        <div key={c.credential_id} className="rq-row">
                          <span className="kbd-chip">{c.selector_prefix}...</span>
                          <StatusBadge status={c.state} />
                          {c.state === "active" ? (
                            <button
                              type="button"
                              className="rq-btn rq-btn-danger"
                              onClick={() => {
                                const body = {
                                  schema_version: 1,
                                  expected_version: c.version,
                                  reason_code: "operator_revoke_producer_credential"
                                };
                                const canonical = hashCanonicalJson(body);
                                setPendingStepUp({
                                  descriptor: {
                                    action: "producers.credential_revoke",
                                    actionLabel: `Revoke Credential ${c.selector_prefix}...`,
                                    scopeKind: "project",
                                    tenantId: scope.tenantId,
                                    projectId: scope.projectId,
                                    targetResourceId: c.credential_id,
                                    targetVersion: c.version,
                                    canonicalCommandSha256: canonical.sha256,
                                    summary: `Revokes producer credential ${c.selector_prefix}...`
                                  },
                                  execute: async (operationProofId) => {
                                    const res = await api.revokeProducerCredential(
                                      scope.tenantId,
                                      scope.projectId,
                                      c.credential_id,
                                      { ...body, operation_proof_id: operationProofId },
                                      generateIdempotencyKey("prod-cred-revoke")
                                    );
                                    if (!res.ok) {
                                      setFeedback({ kind: "failed", error: res });
                                      return;
                                    }
                                    producersQuery.reload();
                                  }
                                });
                              }}
                            >
                              Revoke
                            </button>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  )
                },
                {
                  key: "actions",
                  header: "Scope & rq_p1 Actions",
                  render: (p) => (
                    <div className="rq-row">
                      <button
                        type="button"
                        className="rq-btn"
                        onClick={() => {
                          void (async () => {
                            setSelectedProducerId(p.producer_id);
                            const res = await api.createProducerScopeVersion(
                              scope.tenantId,
                              scope.projectId,
                              p.producer_id,
                              {
                                schema_version: 1,
                                allowed_actions: scopeActions
                              },
                              generateIdempotencyKey("prod-scope")
                            );
                            if (!res.ok) {
                              setFeedback({ kind: "failed", error: res });
                              return;
                            }
                            producersQuery.reload();
                          })();
                        }}
                      >
                        Add Scope
                      </button>
                      <button
                        type="button"
                        className="rq-btn rq-btn-primary"
                        onClick={() => {
                          handleIssueCredentialIntent(p, false);
                        }}
                      >
                        Issue rq_p1 Intent (Step-Up)
                      </button>
                      <button
                        type="button"
                        className="rq-btn"
                        onClick={() => {
                          handleIssueCredentialIntent(p, true);
                        }}
                      >
                        Rotate Credential
                      </button>
                    </div>
                  )
                }
              ]}
            />
          )}
        </ResourceStatePanel>
        {selectedProducerId ? (
          <p className="rq-meta-text mono">Last focused producer: {selectedProducerId}</p>
        ) : null}
      </section>

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
