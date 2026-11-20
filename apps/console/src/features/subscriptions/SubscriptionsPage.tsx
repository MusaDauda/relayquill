import { type JSX, useMemo, useState } from "react";
import { hashCanonicalJson } from "@relayquill/contracts";
import { ORDERING_MODES, type OrderingMode } from "@relayquill/domain";
import { type SubscriptionSummaryDto } from "../../api/dtos.js";
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
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { StepUpModal, type StepUpTargetDescriptor } from "../access/StepUpModal.js";
import {
  FILTER_PROFILE_VERSION,
  type FilterAstNode,
  type FilterDefinition,
  evaluateFilterOnLosslessJson,
  validateFilterDefinition
} from "./filter-ast.js";

interface EditablePredicateRow {
  readonly id: string;
  readonly op: "eq" | "neq" | "in" | "not_in" | "exists" | "prefix";
  readonly pointer: string;
  readonly valueText: string;
}

function rowToAstNode(row: EditablePredicateRow): FilterAstNode {
  if (row.op === "exists") {
    return {
      op: "exists",
      pointer: row.pointer.trim(),
      value: row.valueText.trim().toLowerCase() !== "false"
    };
  }
  if (row.op === "prefix") {
    return {
      op: "prefix",
      pointer: row.pointer.trim(),
      value: row.valueText
    };
  }
  if (row.op === "in" || row.op === "not_in") {
    return {
      op: row.op,
      pointer: row.pointer.trim(),
      values: row.valueText
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
    };
  }
  return {
    op: row.op,
    pointer: row.pointer.trim(),
    value: row.valueText.trim()
  };
}

export function SubscriptionsPage(): JSX.Element {
  const { api } = useConsoleRuntime();
  const scope = useActiveScope();

  const [subName, setSubName] = useState("");
  const [endpointId, setEndpointId] = useState("");
  const [endpointVersion, setEndpointVersion] = useState("1");
  const [eventTypeId, setEventTypeId] = useState("");
  const [schemaVersionsCsv, setSchemaVersionsCsv] = useState("1");
  const [orderingMode, setOrderingMode] = useState<OrderingMode>("unordered");
  const [orderingKeyPointer, setOrderingKeyPointer] = useState("/customer_id");
  const [receiverContractId, setReceiverContractId] = useState("");
  const [receiverContractVersion, setReceiverContractVersion] = useState("1");
  const [consumerContractScope, setConsumerContractScope] = useState("default");

  // Typed relayquill.filter.v1 AST builder state
  const [combinator, setCombinator] = useState<"and" | "or">("and");
  const [predicates, setPredicates] = useState<readonly EditablePredicateRow[]>([
    { id: "pred-1", op: "eq", pointer: "/currency", valueText: "USD" }
  ]);
  const [sampleJson, setSampleJson] = useState(`{
  "currency": "USD",
  "amount_minor": 9223372036854775807
}`);
  const reasonCode = "subscription_governance";
  const [feedback, setFeedback] = useState<MutationFeedbackState>({ kind: "idle" });
  const [pendingStepUp, setPendingStepUp] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly execute: (operationProofId: string) => Promise<void>;
  } | null>(null);

  const subscriptionsQuery = useScopedQuery({
    resource: "project.subscriptions",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listSubscriptions(scope.tenantId, scope.projectId, { limit: 50 }, signal)
  });

  const endpointsQuery = useScopedQuery({
    resource: "project.sub_endpoints",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEndpoints(scope.tenantId, scope.projectId, { limit: 100 }, signal)
  });

  const eventTypesQuery = useScopedQuery({
    resource: "project.sub_event_types",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEventTypes(scope.tenantId, scope.projectId, { limit: 100 }, signal)
  });

  const builtFilterDefinition = useMemo<FilterDefinition>(
    () => ({
      version: FILTER_PROFILE_VERSION,
      root: {
        op: combinator,
        children: predicates.map(rowToAstNode)
      }
    }),
    [combinator, predicates]
  );

  const filterValidationErrors = useMemo(
    () => validateFilterDefinition(builtFilterDefinition),
    [builtFilterDefinition]
  );

  const filterEvalPreview = useMemo(
    () => evaluateFilterOnLosslessJson(builtFilterDefinition, sampleJson),
    [builtFilterDefinition, sampleJson]
  );

  const handleCreateSubscription = async (): Promise<void> => {
    const schemaVersions = schemaVersionsCsv
      .split(",")
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n >= 1);
    const body: Record<string, unknown> = {
      schema_version: 1,
      name: subName.trim(),
      endpoint_id: endpointId.trim(),
      endpoint_version: endpointVersion.trim(),
      event_type_id: eventTypeId.trim(),
      selected_schema_versions: schemaVersions.length > 0 ? schemaVersions : [1],
      ordering_mode: orderingMode,
      ...(orderingMode === "strict_per_key"
        ? { ordering_key_pointer: orderingKeyPointer.trim() }
        : {}),
      consumer_contract_scope: consumerContractScope.trim() || "default",
      ...(receiverContractId.trim().length > 0
        ? {
            receiver_contract_id: receiverContractId.trim(),
            receiver_contract_version: receiverContractVersion.trim()
          }
        : {}),
      filter: builtFilterDefinition,
      reason_code: reasonCode.trim() || "create_subscription"
    };

    setFeedback({ kind: "submitting", label: "Creating typed subscription..." });
    const res = await api.createSubscription(
      scope.tenantId,
      scope.projectId,
      body,
      generateIdempotencyKey("sub-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res, preservedDraft: body });
      return;
    }
    setSubName("");
    setFeedback({
      kind: "succeeded",
      title: "Subscription Draft Created",
      detail: `Created ${res.data.name} (${res.data.subscription_id}) with filter ${FILTER_PROFILE_VERSION}.`
    });
    subscriptionsQuery.reload();
  };

  const openVersionMutation = (
    sub: SubscriptionSummaryDto,
    action: "validate" | "activate"
  ): void => {
    const body = {
      schema_version: 1,
      expected_configuration_sha256: sub.configuration_sha256,
      reason_code: reasonCode.trim() || `subscription_${action}`
    };
    if (action === "validate") {
      void (async () => {
        setFeedback({ kind: "submitting", label: "Validating subscription version..." });
        const res = await api.mutateSubscriptionVersion(
          scope.tenantId,
          scope.projectId,
          sub.version_id,
          "validate",
          body,
          generateIdempotencyKey("sub-validate")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: sub });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Subscription Version Validated",
          detail: `Version ${sub.version_id} validated cleanly.`,
          receiptId: res.data.receipt?.id
        });
        subscriptionsQuery.reload();
      })();
      return;
    }

    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: "subscriptions.activate",
        actionLabel: `Activate Subscription ${sub.name} v${sub.current_version}`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: sub.version_id,
        targetVersion: sub.current_version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Activates subscription version ${sub.version_id} (${sub.ordering_mode}) targeting endpoint ${sub.endpoint_id}.`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: "Activating subscription version..." });
        const res = await api.mutateSubscriptionVersion(
          scope.tenantId,
          scope.projectId,
          sub.version_id,
          "activate",
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey("sub-activate")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: sub });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Subscription Version Activated",
          detail: `Subscription ${sub.name} v${sub.current_version} is active.`,
          receiptId: res.data.receipt?.id
        });
        subscriptionsQuery.reload();
      }
    });
  };

  const openControlMutation = (
    sub: SubscriptionSummaryDto,
    action: "pause-future" | "hold-sends" | "pause-all" | "resume-future" | "release-send-hold" | "retire"
  ): void => {
    const body = {
      schema_version: 1,
      expected_version: sub.current_version,
      reason_code: reasonCode.trim() || `sub_${action}`
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: `subscriptions.${action.replace(/-/g, "_")}`,
        actionLabel: `Subscription Control: ${action} (${sub.name})`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: sub.subscription_id,
        targetVersion: sub.current_version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Executes "${action}" on subscription ${sub.name} (${sub.subscription_id}).`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: `Executing ${action}...` });
        const res = await api.mutateSubscriptionControl(
          scope.tenantId,
          scope.projectId,
          sub.subscription_id,
          action,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey(`sub-${action}`)
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: sub });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: `Subscription Control Committed (${action})`,
          detail: `Updated delivery control state for ${sub.name}.`,
          receiptId: res.data.receipt?.id
        });
        subscriptionsQuery.reload();
      }
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Subscriptions & {FILTER_PROFILE_VERSION} AST Builder</h1>
          <p className="rq-page-lead">
            Configure typed webhook routing rules with bounded <span className="kbd-chip">{FILTER_PROFILE_VERSION}</span>{" "}
            filter ASTs, strict per-key ordering pointers, and pause-future/hold-sends lifecycle controls.
          </p>
        </div>
      </header>

      <MutationFeedback state={feedback} resourceLabel="Subscription lifecycle" />

      <section className="rq-card" aria-label="Create subscription with typed filter AST builder">
        <div className="rq-card-header">
          <h2 className="rq-section-title">Create Subscription & Filter AST</h2>
          <StatusBadge
            status={filterValidationErrors.length === 0 ? "active" : "validation_failed"}
            label={filterValidationErrors.length === 0 ? "AST Valid" : "AST Validation Error"}
          />
        </div>

        <div className="rq-grid-3">
          <FormField label="Subscription Name" required>
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input"
                placeholder="High Value USD Orders"
                value={subName}
                onChange={(e) => {
                  setSubName(e.target.value);
                }}
              />
            )}
          </FormField>

          <FormField label="Target Endpoint" required>
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={endpointId}
                onChange={(e) => {
                  const id = e.target.value;
                  setEndpointId(id);
                  const ep =
                    endpointsQuery.view.state === "current"
                      ? endpointsQuery.view.data.items.find((x) => x.endpoint_id === id)
                      : undefined;
                  if (ep !== undefined) {
                    setEndpointVersion(ep.current_version);
                    if (ep.active_receiver_contract_id !== null) {
                      setReceiverContractId(ep.active_receiver_contract_id);
                    }
                    if (ep.active_receiver_contract_version !== null) {
                      setReceiverContractVersion(ep.active_receiver_contract_version);
                    }
                  }
                }}
              >
                <option value="">Select endpoint...</option>
                {endpointsQuery.view.state === "current"
                  ? endpointsQuery.view.data.items.map((ep) => (
                      <option key={ep.endpoint_id} value={ep.endpoint_id}>
                        {ep.name} (v{ep.current_version}, {ep.state})
                      </option>
                    ))
                  : null}
              </select>
            )}
          </FormField>

          <FormField label="Event Type" required>
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={eventTypeId}
                onChange={(e) => {
                  setEventTypeId(e.target.value);
                }}
              >
                <option value="">Select event type...</option>
                {eventTypesQuery.view.state === "current"
                  ? eventTypesQuery.view.data.items.map((et) => (
                      <option key={et.event_type_id} value={et.event_type_id}>
                        {et.type_name}
                      </option>
                    ))
                  : null}
              </select>
            )}
          </FormField>

          <FormField label="Selected Schema Versions (CSV)">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={schemaVersionsCsv}
                onChange={(e) => {
                  setSchemaVersionsCsv(e.target.value);
                }}
              />
            )}
          </FormField>

          <FormField label="Ordering Mode">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={orderingMode}
                onChange={(e) => {
                  setOrderingMode(e.target.value as OrderingMode);
                }}
              >
                {ORDERING_MODES.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            )}
          </FormField>

          {orderingMode === "strict_per_key" ? (
            <FormField label="Strict Ordering Key JSON Pointer" required>
              {({ inputId }) => (
                <input
                  id={inputId}
                  className="rq-input mono"
                  value={orderingKeyPointer}
                  onChange={(e) => {
                    setOrderingKeyPointer(e.target.value);
                  }}
                />
              )}
            </FormField>
          ) : null}

          <FormField label="Consumer Contract Scope">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={consumerContractScope}
                onChange={(e) => {
                  setConsumerContractScope(e.target.value);
                }}
              />
            )}
          </FormField>

          <FormField label="Receiver Contract ID (optional)">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={receiverContractId}
                onChange={(e) => {
                  setReceiverContractId(e.target.value);
                }}
              />
            )}
          </FormField>
        </div>

        <section className="rq-card-inset" aria-label="Typed filter AST predicates">
          <div className="rq-row-between">
            <strong className="rq-label">{FILTER_PROFILE_VERSION} Predicate Tree</strong>
            <div className="rq-row">
              <label className="rq-label" htmlFor="filter-comb-select">
                Root Combinator
              </label>
              <select
                id="filter-comb-select"
                className="rq-select"
                value={combinator}
                onChange={(e) => {
                  setCombinator(e.target.value as "and" | "or");
                }}
              >
                <option value="and">ALL match (and)</option>
                <option value="or">ANY match (or)</option>
              </select>
              <button
                type="button"
                className="rq-btn"
                onClick={() => {
                  setPredicates((prev) => [
                    ...prev,
                    {
                      id: `pred-${Date.now()}`,
                      op: "eq",
                      pointer: "/status",
                      valueText: "confirmed"
                    }
                  ]);
                }}
              >
                Add Predicate
              </button>
            </div>
          </div>

          {predicates.map((row, idx) => (
            <div key={row.id} className="rq-row">
              <select
                aria-label={`Predicate ${idx + 1} operator`}
                className="rq-select"
                value={row.op}
                onChange={(e) => {
                  const op = e.target.value as EditablePredicateRow["op"];
                  setPredicates((prev) =>
                    prev.map((item) => (item.id === row.id ? { ...item, op } : item))
                  );
                }}
              >
                <option value="eq">eq</option>
                <option value="neq">neq</option>
                <option value="in">in (CSV)</option>
                <option value="not_in">not_in (CSV)</option>
                <option value="exists">exists (true/false)</option>
                <option value="prefix">prefix</option>
              </select>
              <input
                aria-label={`Predicate ${idx + 1} JSON pointer`}
                className="rq-input mono"
                value={row.pointer}
                onChange={(e) => {
                  const val = e.target.value;
                  setPredicates((prev) =>
                    prev.map((item) => (item.id === row.id ? { ...item, pointer: val } : item))
                  );
                }}
              />
              <input
                aria-label={`Predicate ${idx + 1} expected value`}
                className="rq-input mono"
                value={row.valueText}
                onChange={(e) => {
                  const val = e.target.value;
                  setPredicates((prev) =>
                    prev.map((item) => (item.id === row.id ? { ...item, valueText: val } : item))
                  );
                }}
              />
              {predicates.length > 1 ? (
                <button
                  type="button"
                  className="rq-btn rq-btn-danger"
                  onClick={() => {
                    setPredicates((prev) => prev.filter((item) => item.id !== row.id));
                  }}
                >
                  Remove
                </button>
              ) : null}
            </div>
          ))}

          {filterValidationErrors.map((err) => (
            <p key={err} className="rq-field-error" role="alert">
              {err}
            </p>
          ))}

          <div className="rq-grid-2">
            <FormField label="Sample Lossless Event JSON (Local AST Test Evaluator)">
              {({ inputId }) => (
                <textarea
                  id={inputId}
                  className="rq-textarea"
                  value={sampleJson}
                  onChange={(e) => {
                    setSampleJson(e.target.value);
                  }}
                />
              )}
            </FormField>
            <div className="rq-stack-sm">
              <strong className="rq-label">
                Compiled AST & Dry Match:{" "}
                <StatusBadge
                  status={filterEvalPreview.matched ? "active" : "draft"}
                  label={filterEvalPreview.matched ? "Matches Sample" : "Does Not Match Sample"}
                />
              </strong>
              <pre className="rq-json-viewer">
                {JSON.stringify(builtFilterDefinition, null, 2)}
              </pre>
            </div>
          </div>
        </section>

        <div className="rq-row">
          <button
            type="button"
            className="rq-btn rq-btn-primary"
            disabled={
              subName.trim().length === 0 ||
              endpointId.trim().length === 0 ||
              eventTypeId.trim().length === 0 ||
              filterValidationErrors.length > 0
            }
            onClick={() => {
              void handleCreateSubscription();
            }}
          >
            Create Subscription
          </button>
        </div>
      </section>

      <ResourceStatePanel
        view={subscriptionsQuery.view}
        resourceLabel="Subscriptions"
        emptyTitle="No subscriptions created yet"
        onRetry={subscriptionsQuery.reload}
      >
        {(subsPage) => (
          <section className="rq-card" aria-label="Subscriptions table">
            <DataTable<SubscriptionSummaryDto>
              caption="Project subscriptions"
              rows={subsPage.items}
              rowKey={(s) => s.subscription_id}
              columns={[
                {
                  key: "sub",
                  header: "Subscription & Endpoint",
                  render: (s) => (
                    <div className="rq-stack-sm">
                      <strong>
                        {s.name} (v{s.current_version})
                      </strong>
                      <CopyableId value={s.subscription_id} />
                      <span className="rq-meta-text mono">
                        ep {s.endpoint_id} v{s.endpoint_version} | pending {s.pending_delivery_count}
                      </span>
                    </div>
                  )
                },
                {
                  key: "ordering",
                  header: "Ordering & Filter",
                  render: (s) => (
                    <div className="rq-stack-sm">
                      <span className="kbd-chip">
                        {s.ordering_mode}
                        {s.ordering_key_pointer !== null ? ` (${s.ordering_key_pointer})` : ""}
                      </span>
                      <span className="rq-meta-text mono">{s.filter_summary}</span>
                    </div>
                  )
                },
                {
                  key: "state",
                  header: "State & Send Hold",
                  render: (s) => (
                    <div className="rq-row">
                      <StatusBadge status={s.state} />
                      {s.send_hold ? <StatusBadge status="held" label="Send Hold Active" /> : null}
                    </div>
                  )
                },
                {
                  key: "actions",
                  header: "Controls",
                  render: (s) => (
                    <div className="rq-row">
                      {s.state === "draft" ? (
                        <>
                          <button
                            type="button"
                            className="rq-btn"
                            onClick={() => {
                              openVersionMutation(s, "validate");
                            }}
                          >
                            Validate
                          </button>
                          <button
                            type="button"
                            className="rq-btn rq-btn-primary"
                            onClick={() => {
                              openVersionMutation(s, "activate");
                            }}
                          >
                            Activate (Step-Up)
                          </button>
                        </>
                      ) : null}
                      {s.state === "active" ? (
                        <>
                          <button
                            type="button"
                            className="rq-btn"
                            onClick={() => {
                              openControlMutation(s, "pause-future");
                            }}
                          >
                            Pause Future
                          </button>
                          <button
                            type="button"
                            className="rq-btn"
                            onClick={() => {
                              openControlMutation(s, "hold-sends");
                            }}
                          >
                            Hold Sends
                          </button>
                          <button
                            type="button"
                            className="rq-btn"
                            onClick={() => {
                              openControlMutation(s, "pause-all");
                            }}
                          >
                            Pause All
                          </button>
                        </>
                      ) : null}
                      {s.state === "paused" ? (
                        <button
                          type="button"
                          className="rq-btn rq-btn-primary"
                          onClick={() => {
                            openControlMutation(s, "resume-future");
                          }}
                        >
                          Resume Future
                        </button>
                      ) : null}
                      {s.send_hold ? (
                        <button
                          type="button"
                          className="rq-btn rq-btn-primary"
                          onClick={() => {
                            openControlMutation(s, "release-send-hold");
                          }}
                        >
                          Release Send Hold
                        </button>
                      ) : null}
                      {s.state !== "retired" ? (
                        <button
                          type="button"
                          className="rq-btn rq-btn-danger"
                          onClick={() => {
                            openControlMutation(s, "retire");
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
