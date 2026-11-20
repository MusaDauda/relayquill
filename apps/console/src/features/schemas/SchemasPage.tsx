import { type JSX, useMemo, useState } from "react";
import { hashCanonicalJson } from "@relayquill/contracts";
import {
  ORDERING_PROFILES,
  type OrderingProfile,
  RECEIPT_PROFILES,
  type ReceiptProfile,
  SCHEMA_COMPATIBILITY_POLICIES,
  type SchemaCompatibilityPolicy
} from "@relayquill/domain";
import {
  type EventTypeDto,
  type ReceiverContractDto,
  type RepresentationProfileDto
} from "../../api/dtos.js";
import { useActiveScope } from "../../app/scope.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CopyableId } from "../../components/CopyableId.js";
import { DataTable } from "../../components/DataTable.js";
import { FormField } from "../../components/FormField.js";
import { LosslessJsonViewer } from "../../components/LosslessJsonViewer.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { StepUpModal, type StepUpTargetDescriptor } from "../access/StepUpModal.js";
import {
  type LosslessProjectionSpec,
  PROJECTION_PROFILE_VERSION,
  type ProjectionMappingRule,
  applyLosslessProjectionSpec
} from "./projection-mapper.js";

type SchemaCatalogTab = "schemas" | "representations" | "contracts";

interface EditableRuleRow {
  readonly id: string;
  readonly op: "copy" | "constant" | "copy_or_default";
  readonly sourcePointer: string;
  readonly targetPointer: string;
  readonly defaultOrConstText: string;
}

const DEFAULT_SOURCE_SAMPLE = `{
  "order_id": "ord_lossless_01",
  "ledger_seq": 9223372036854775807,
  "tax_rate": 0.0825000,
  "customer": { "tier": "enterprise" }
}`;

export function SchemasPage({
  initialTab = "schemas"
}: {
  readonly initialTab?: SchemaCatalogTab | undefined;
}): JSX.Element {
  const { api } = useConsoleRuntime();
  const scope = useActiveScope();

  const [activeTab, setActiveTab] = useState<SchemaCatalogTab>(initialTab);
  const [feedback, setFeedback] = useState<MutationFeedbackState>({ kind: "idle" });

  // Event Types & Schemas form
  const [typeName, setTypeName] = useState("");
  const [selectedEventTypeId, setSelectedEventTypeId] = useState("");
  const [compatPolicy, setCompatPolicy] =
    useState<SchemaCompatibilityPolicy>("additive_compatible");
  const [schemaDefinitionJson, setSchemaDefinitionJson] = useState(
    '{\n  "type": "object",\n  "properties": { "order_id": { "type": "string" } }\n}'
  );

  // Representations & Lossless Projection Mapper
  const [profileName, setProfileName] = useState("");
  const [profileEventTypeId, setProfileEventTypeId] = useState("");
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [sourceSchemaVer, setSourceSchemaVer] = useState(1);
  const [targetSchemaVer, setTargetSchemaVer] = useState(2);
  const [rules, setRules] = useState<readonly EditableRuleRow[]>([
    {
      id: "map-1",
      op: "copy",
      sourcePointer: "/ledger_seq",
      targetPointer: "/sequence",
      defaultOrConstText: ""
    },
    {
      id: "map-2",
      op: "copy_or_default",
      sourcePointer: "/customer/tier",
      targetPointer: "/tier",
      defaultOrConstText: "standard"
    },
    {
      id: "map-3",
      op: "constant",
      sourcePointer: "",
      targetPointer: "/projection_v",
      defaultOrConstText: "2"
    }
  ]);
  const [sampleSourceJson, setSampleSourceJson] = useState(DEFAULT_SOURCE_SAMPLE);

  // Receiver Contracts form
  const [contractEndpointId, setContractEndpointId] = useState("");
  const [contractName, setContractName] = useState("");
  const [contractScope, setContractScope] = useState("default");
  const [selectedContractId, setSelectedContractId] = useState("");
  const [receiptProfile, setReceiptProfile] =
    useState<ReceiptProfile>("receiver_local_commit_v1");
  const [orderingProfile, setOrderingProfile] =
    useState<OrderingProfile>("receiver_strict_key_v1");
  const [allowedBusinessKeysCsv, setAllowedBusinessKeysCsv] = useState("order_id");

  const [pendingStepUp, setPendingStepUp] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly execute: (operationProofId: string) => Promise<void>;
  } | null>(null);

  const eventTypesQuery = useScopedQuery({
    resource: "project.schema_event_types",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEventTypes(scope.tenantId, scope.projectId, { limit: 100 }, signal)
  });

  const representationsQuery = useScopedQuery({
    resource: "project.representation_profiles",
    enabled: activeTab === "representations",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listRepresentationProfiles(scope.tenantId, scope.projectId, signal)
  });

  const receiverContractsQuery = useScopedQuery({
    resource: "project.receiver_contracts",
    enabled: activeTab === "contracts",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listReceiverContracts(scope.tenantId, scope.projectId, signal)
  });

  const projectionSpec = useMemo<LosslessProjectionSpec>(() => {
    const mappings: ProjectionMappingRule[] = rules.map((r) => {
      if (r.op === "copy") {
        return {
          op: "copy",
          sourcePointer: r.sourcePointer.trim(),
          targetPointer: r.targetPointer.trim()
        };
      }
      if (r.op === "constant") {
        return {
          op: "constant",
          targetPointer: r.targetPointer.trim(),
          value: r.defaultOrConstText
        };
      }
      return {
        op: "copy_or_default",
        sourcePointer: r.sourcePointer.trim(),
        targetPointer: r.targetPointer.trim(),
        defaultValue: r.defaultOrConstText
      };
    });
    return {
      profile_version: PROJECTION_PROFILE_VERSION,
      mappings
    };
  }, [rules]);

  const projectionTestResult = useMemo(
    () => applyLosslessProjectionSpec(projectionSpec, sampleSourceJson),
    [projectionSpec, sampleSourceJson]
  );

  const handleCreateEventType = async (): Promise<void> => {
    const res = await api.createEventType(
      scope.tenantId,
      scope.projectId,
      { schema_version: 1, type_name: typeName.trim() },
      generateIdempotencyKey("et-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setTypeName("");
    setSelectedEventTypeId(res.data.event_type_id);
    setFeedback({
      kind: "succeeded",
      title: "Event Type Created",
      detail: `Created event type ${res.data.type_name} (${res.data.event_type_id}).`
    });
    eventTypesQuery.reload();
  };

  const handleCreateSchemaVersion = async (): Promise<void> => {
    let parsedSchema: unknown;
    try {
      parsedSchema = JSON.parse(schemaDefinitionJson);
    } catch {
      setFeedback({
        kind: "failed",
        error: {
          ok: false,
          status: 400,
          code: "INVALID_SCHEMA_JSON",
          message: "Schema definition must be valid JSON.",
          acceptance: "known_rejected",
          retryable: false,
          aborted: false,
          fieldErrors: []
        }
      });
      return;
    }
    const res = await api.createEventSchemaVersion(
      scope.tenantId,
      scope.projectId,
      selectedEventTypeId.trim(),
      {
        schema_version: 1,
        compatibility_policy: compatPolicy,
        definition: parsedSchema
      },
      generateIdempotencyKey("schema-ver-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Schema Version Created",
      detail: "Draft event schema version saved.",
      receiptId: res.data.receipt?.id
    });
    eventTypesQuery.reload();
  };

  const handleCreateProjectionVersion = async (): Promise<void> => {
    const res = await api.createRepresentationProfileVersion(
      scope.tenantId,
      scope.projectId,
      selectedProfileId.trim(),
      {
        schema_version: 1,
        source_schema_version: sourceSchemaVer,
        target_schema_version: targetSchemaVer,
        compiler_profile_version: PROJECTION_PROFILE_VERSION,
        definition: projectionSpec
      },
      generateIdempotencyKey("rep-ver-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Representation Profile Version Created",
      detail: `Saved version (${sourceSchemaVer} -> ${targetSchemaVer}) using ${PROJECTION_PROFILE_VERSION}.`,
      receiptId: res.data.receipt?.id
    });
    representationsQuery.reload();
  };

  const handleCreateReceiverContract = async (): Promise<void> => {
    const res = await api.createReceiverContract(
      scope.tenantId,
      scope.projectId,
      {
        schema_version: 1,
        endpoint_id: contractEndpointId.trim(),
        name: contractName.trim(),
        consumer_contract_scope: contractScope.trim() || "default"
      },
      generateIdempotencyKey("rc-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setSelectedContractId(res.data.contract_id);
    setContractName("");
    setFeedback({
      kind: "succeeded",
      title: "Receiver Contract Created",
      detail: `Created receiver contract ${res.data.name} (${res.data.contract_id}).`
    });
    receiverContractsQuery.reload();
  };

  const handleCreateReceiverContractVersion = async (): Promise<void> => {
    const keys = allowedBusinessKeysCsv
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const res = await api.createReceiverContractVersion(
      scope.tenantId,
      scope.projectId,
      selectedContractId.trim(),
      {
        schema_version: 1,
        envelope_version: 1,
        receipt_profile: receiptProfile,
        ordering_profile: orderingProfile,
        allowed_business_key_ids: keys.length > 0 ? keys : ["order_id"]
      },
      generateIdempotencyKey("rc-ver-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Receiver Contract Version Created",
      detail: "Draft receiver contract version added.",
      receiptId: res.data.receipt?.id
    });
    receiverContractsQuery.reload();
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">
            Schemas, Lossless Projection Mapper & Receiver Contracts
          </h1>
          <p className="rq-page-lead">
            Manage event schema contracts, design deterministic{" "}
            <span className="kbd-chip">{PROJECTION_PROFILE_VERSION}</span> lossless representations
            without precision loss, and verify receiver commit contracts.
          </p>
        </div>
      </header>

      <MutationFeedback state={feedback} resourceLabel="Schema / Contract registry" />

      <div className="rq-tabs" role="tablist" aria-label="Registry sections">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "schemas"}
          className="rq-tab"
          onClick={() => {
            setActiveTab("schemas");
          }}
        >
          Event Types & Schemas
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "representations"}
          className="rq-tab"
          onClick={() => {
            setActiveTab("representations");
          }}
        >
          Derived Representations ({PROJECTION_PROFILE_VERSION})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "contracts"}
          className="rq-tab"
          onClick={() => {
            setActiveTab("contracts");
          }}
        >
          Receiver Contracts
        </button>
      </div>

      {activeTab === "schemas" ? (
        <div className="rq-stack">
          <div className="rq-grid-2">
            <section className="rq-card" aria-label="Create event type">
              <h2 className="rq-section-title">1. Create Event Type</h2>
              <FormField label="Event Type Name" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    placeholder="billing.invoice.settled"
                    value={typeName}
                    onChange={(e) => {
                      setTypeName(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                disabled={typeName.trim().length === 0}
                onClick={() => {
                  void handleCreateEventType();
                }}
              >
                Create Event Type
              </button>
            </section>

            <section className="rq-card" aria-label="Create event schema version">
              <h2 className="rq-section-title">2. Publish Draft Schema Version</h2>
              <FormField label="Event Type" required>
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={selectedEventTypeId}
                    onChange={(e) => {
                      setSelectedEventTypeId(e.target.value);
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
              <FormField label="Compatibility Policy">
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={compatPolicy}
                    onChange={(e) => {
                      setCompatPolicy(e.target.value as SchemaCompatibilityPolicy);
                    }}
                  >
                    {SCHEMA_COMPATIBILITY_POLICIES.map((cp) => (
                      <option key={cp} value={cp}>
                        {cp}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>
              <FormField label="JSON Schema Definition" required>
                {({ inputId }) => (
                  <textarea
                    id={inputId}
                    className="rq-textarea"
                    value={schemaDefinitionJson}
                    onChange={(e) => {
                      setSchemaDefinitionJson(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                disabled={selectedEventTypeId.trim().length === 0}
                onClick={() => {
                  void handleCreateSchemaVersion();
                }}
              >
                Create Schema Version
              </button>
            </section>
          </div>

          <ResourceStatePanel
            view={eventTypesQuery.view}
            resourceLabel="Event types catalog"
            emptyTitle="No event types registered yet"
            onRetry={eventTypesQuery.reload}
          >
            {(etPage) => (
              <section className="rq-card" aria-label="Event schemas table">
                <DataTable<EventTypeDto>
                  caption="Event types and schema versions"
                  rows={etPage.items}
                  rowKey={(et) => et.event_type_id}
                  columns={[
                    {
                      key: "name",
                      header: "Event Type & ID",
                      render: (et) => (
                        <div className="rq-stack-sm">
                          <strong>{et.type_name}</strong>
                          <CopyableId value={et.event_type_id} />
                        </div>
                      )
                    },
                    {
                      key: "state",
                      header: "State & Current Version",
                      render: (et) => (
                        <div className="rq-row">
                          <StatusBadge status={et.state} />
                          <span className="kbd-chip">
                            current v{et.current_schema_version ?? "none"}
                          </span>
                        </div>
                      )
                    },
                    {
                      key: "versions",
                      header: "Schema Versions",
                      render: (et) => (
                        <div className="rq-stack-sm">
                          {et.schema_versions.map((sv) => (
                            <div key={sv.schema_id} className="rq-row">
                              <span className="kbd-chip">v{sv.schema_version}</span>
                              <StatusBadge status={sv.state} />
                              {sv.state === "draft" ? (
                                <button
                                  type="button"
                                  className="rq-btn rq-btn-primary"
                                  onClick={() => {
                                    const body = {
                                      schema_version: 1,
                                      expected_version: sv.version,
                                      definition_sha256: sv.definition_sha256
                                    };
                                    const canonical = hashCanonicalJson(body);
                                    setPendingStepUp({
                                      descriptor: {
                                        action: "event_schema_versions.publish",
                                        actionLabel: `Publish ${et.type_name} Schema v${sv.schema_version}`,
                                        scopeKind: "project",
                                        tenantId: scope.tenantId,
                                        projectId: scope.projectId,
                                        targetResourceId: sv.schema_id,
                                        targetVersion: sv.version,
                                        canonicalCommandSha256: canonical.sha256,
                                        summary: `Publishes immutable schema v${sv.schema_version} for ${et.type_name}.`
                                      },
                                      execute: async (operationProofId) => {
                                        const res = await api.mutateEventSchemaVersion(
                                          scope.tenantId,
                                          scope.projectId,
                                          sv.schema_id,
                                          "publish",
                                          { ...body, operation_proof_id: operationProofId },
                                          generateIdempotencyKey("schema-publish")
                                        );
                                        if (!res.ok) {
                                          setFeedback({ kind: "failed", error: res });
                                          return;
                                        }
                                        eventTypesQuery.reload();
                                      }
                                    });
                                  }}
                                >
                                  Publish (Step-Up)
                                </button>
                              ) : null}
                            </div>
                          ))}
                        </div>
                      )
                    }
                  ]}
                />
              </section>
            )}
          </ResourceStatePanel>
        </div>
      ) : null}

      {activeTab === "representations" ? (
        <div className="rq-stack">
          <section className="rq-card" aria-label="Lossless projection mapper">
            <div className="rq-card-header">
              <h2 className="rq-section-title">
                Lossless Projection Mapper ({PROJECTION_PROFILE_VERSION})
              </h2>
              <StatusBadge
                status={projectionTestResult.ok ? "active" : "validation_failed"}
                label={projectionTestResult.ok ? "Lossless Mapping Valid" : "Mapping Error"}
              />
            </div>

            <div className="rq-grid-3">
              <FormField label="New Profile Name">
                {({ inputId }) => (
                  <div className="rq-row">
                    <input
                      id={inputId}
                      className="rq-input"
                      placeholder="Order V1 -> V2 Projection"
                      value={profileName}
                      onChange={(e) => {
                        setProfileName(e.target.value);
                      }}
                    />
                    <button
                      type="button"
                      className="rq-btn"
                      disabled={profileName.trim().length === 0 || profileEventTypeId.trim().length === 0}
                      onClick={() => {
                        void (async () => {
                          const res = await api.createRepresentationProfile(
                            scope.tenantId,
                            scope.projectId,
                            {
                              schema_version: 1,
                              name: profileName.trim(),
                              event_type_id: profileEventTypeId.trim()
                            },
                            generateIdempotencyKey("rep-profile-create")
                          );
                          if (!res.ok) {
                            setFeedback({ kind: "failed", error: res });
                            return;
                          }
                          setSelectedProfileId(res.data.profile_id);
                          setProfileName("");
                          representationsQuery.reload();
                        })();
                      }}
                    >
                      Create Profile
                    </button>
                  </div>
                )}
              </FormField>

              <FormField label="Event Type">
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={profileEventTypeId}
                    onChange={(e) => {
                      setProfileEventTypeId(e.target.value);
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

              <FormField label="Target Profile ID for New Version">
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={selectedProfileId}
                    onChange={(e) => {
                      setSelectedProfileId(e.target.value);
                    }}
                  >
                    <option value="">Select profile...</option>
                    {representationsQuery.view.state === "current"
                      ? representationsQuery.view.data.items.map((rp) => (
                          <option key={rp.profile_id} value={rp.profile_id}>
                            {rp.name} ({rp.profile_id})
                          </option>
                        ))
                      : null}
                  </select>
                )}
              </FormField>
            </div>

            <div className="rq-grid-2">
              <FormField label="Source Schema Version">
                {({ inputId }) => (
                  <input
                    id={inputId}
                    type="number"
                    min={1}
                    className="rq-input"
                    value={sourceSchemaVer}
                    onChange={(e) => {
                      setSourceSchemaVer(Math.max(1, Number(e.target.value) || 1));
                    }}
                  />
                )}
              </FormField>
              <FormField label="Target Schema Version">
                {({ inputId }) => (
                  <input
                    id={inputId}
                    type="number"
                    min={1}
                    className="rq-input"
                    value={targetSchemaVer}
                    onChange={(e) => {
                      setTargetSchemaVer(Math.max(1, Number(e.target.value) || 1));
                    }}
                  />
                )}
              </FormField>
            </div>

            <section className="rq-card-inset" aria-label="Projection mapping rules">
              <div className="rq-row-between">
                <strong className="rq-label">Projection Rules (copy / constant / copy_or_default)</strong>
                <button
                  type="button"
                  className="rq-btn"
                  onClick={() => {
                    setRules((prev) => [
                      ...prev,
                      {
                        id: `map-${Date.now()}`,
                        op: "copy",
                        sourcePointer: "/order_id",
                        targetPointer: "/id",
                        defaultOrConstText: ""
                      }
                    ]);
                  }}
                >
                  Add Mapping Rule
                </button>
              </div>
              {rules.map((r, idx) => (
                <div key={r.id} className="rq-row">
                  <select
                    aria-label={`Mapping ${idx + 1} operation`}
                    className="rq-select"
                    value={r.op}
                    onChange={(e) => {
                      const op = e.target.value as EditableRuleRow["op"];
                      setRules((prev) =>
                        prev.map((x) => (x.id === r.id ? { ...x, op } : x))
                      );
                    }}
                  >
                    <option value="copy">copy</option>
                    <option value="copy_or_default">copy_or_default</option>
                    <option value="constant">constant</option>
                  </select>
                  {r.op !== "constant" ? (
                    <input
                      aria-label={`Mapping ${idx + 1} source pointer`}
                      className="rq-input mono"
                      placeholder="/source/path"
                      value={r.sourcePointer}
                      onChange={(e) => {
                        const val = e.target.value;
                        setRules((prev) =>
                          prev.map((x) => (x.id === r.id ? { ...x, sourcePointer: val } : x))
                        );
                      }}
                    />
                  ) : null}
                  <input
                    aria-label={`Mapping ${idx + 1} target pointer`}
                    className="rq-input mono"
                    placeholder="/target/path"
                    value={r.targetPointer}
                    onChange={(e) => {
                      const val = e.target.value;
                      setRules((prev) =>
                        prev.map((x) => (x.id === r.id ? { ...x, targetPointer: val } : x))
                      );
                    }}
                  />
                  {r.op !== "copy" ? (
                    <input
                      aria-label={`Mapping ${idx + 1} constant or default`}
                      className="rq-input mono"
                      placeholder="default / constant value"
                      value={r.defaultOrConstText}
                      onChange={(e) => {
                        const val = e.target.value;
                        setRules((prev) =>
                          prev.map((x) =>
                            x.id === r.id ? { ...x, defaultOrConstText: val } : x
                          )
                        );
                      }}
                    />
                  ) : null}
                </div>
              ))}
              {projectionTestResult.errors.map((err) => (
                <p key={err} className="rq-field-error" role="alert">
                  {err}
                </p>
              ))}
            </section>

            <div className="rq-grid-2">
              <FormField label="Sample Original JSON Input (Lossless Tokens)">
                {({ inputId }) => (
                  <textarea
                    id={inputId}
                    className="rq-textarea"
                    value={sampleSourceJson}
                    onChange={(e) => {
                      setSampleSourceJson(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <LosslessJsonViewer
                jsonText={projectionTestResult.outputJsonText ?? "{}"}
                title="Projected Lossless Output Preview"
              />
            </div>

            <div className="rq-row">
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                disabled={selectedProfileId.trim().length === 0 || !projectionTestResult.ok}
                onClick={() => {
                  void handleCreateProjectionVersion();
                }}
              >
                Save Projection Version
              </button>
            </div>
          </section>

          <ResourceStatePanel
            view={representationsQuery.view}
            resourceLabel="Representation profiles"
            emptyTitle="No representation profiles configured"
            onRetry={representationsQuery.reload}
          >
            {(rpPage) => (
              <section className="rq-card" aria-label="Representation profiles list">
                <DataTable<RepresentationProfileDto>
                  caption="Representation profiles"
                  rows={rpPage.items}
                  rowKey={(rp) => rp.profile_id}
                  columns={[
                    {
                      key: "name",
                      header: "Profile",
                      render: (rp) => (
                        <div className="rq-stack-sm">
                          <strong>{rp.name}</strong>
                          <CopyableId value={rp.profile_id} />
                        </div>
                      )
                    },
                    {
                      key: "versions",
                      header: "Versions & Activation",
                      render: (rp) => (
                        <div className="rq-stack-sm">
                          {rp.versions.map((v) => (
                            <div key={v.version_id} className="rq-row">
                              <span className="kbd-chip">
                                v{v.profile_version}: s{v.source_schema_version} -&gt; s
                                {v.target_schema_version}
                              </span>
                              <StatusBadge status={v.state} />
                              {v.state === "draft" ? (
                                <button
                                  type="button"
                                  className="rq-btn rq-btn-primary"
                                  onClick={() => {
                                    const body = {
                                      schema_version: 1,
                                      expected_version: v.version,
                                      definition_sha256: v.definition_sha256
                                    };
                                    const canonical = hashCanonicalJson(body);
                                    setPendingStepUp({
                                      descriptor: {
                                        action: "representation_profiles.activate",
                                        actionLabel: `Activate ${rp.name} v${v.profile_version}`,
                                        scopeKind: "project",
                                        tenantId: scope.tenantId,
                                        projectId: scope.projectId,
                                        targetResourceId: v.version_id,
                                        targetVersion: v.version,
                                        canonicalCommandSha256: canonical.sha256,
                                        summary: `Activates lossless representation profile v${v.profile_version}.`
                                      },
                                      execute: async (operationProofId) => {
                                        const res = await api.mutateRepresentationProfileVersion(
                                          scope.tenantId,
                                          scope.projectId,
                                          v.version_id,
                                          "activate",
                                          { ...body, operation_proof_id: operationProofId },
                                          generateIdempotencyKey("rep-activate")
                                        );
                                        if (!res.ok) {
                                          setFeedback({ kind: "failed", error: res });
                                          return;
                                        }
                                        representationsQuery.reload();
                                      }
                                    });
                                  }}
                                >
                                  Activate (Step-Up)
                                </button>
                              ) : null}
                            </div>
                          ))}
                        </div>
                      )
                    }
                  ]}
                />
              </section>
            )}
          </ResourceStatePanel>
        </div>
      ) : null}

      {activeTab === "contracts" ? (
        <div className="rq-stack">
          <div className="rq-grid-2">
            <section className="rq-card" aria-label="Create receiver contract">
              <h2 className="rq-section-title">1. Create Receiver Contract</h2>
              <FormField label="Endpoint ID" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    value={contractEndpointId}
                    onChange={(e) => {
                      setContractEndpointId(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Contract Name" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input"
                    value={contractName}
                    onChange={(e) => {
                      setContractName(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Consumer Contract Scope">
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    value={contractScope}
                    onChange={(e) => {
                      setContractScope(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                disabled={contractEndpointId.trim().length === 0 || contractName.trim().length === 0}
                onClick={() => {
                  void handleCreateReceiverContract();
                }}
              >
                Create Receiver Contract
              </button>
            </section>

            <section className="rq-card" aria-label="Create receiver contract version">
              <h2 className="rq-section-title">2. Add Contract Version</h2>
              <FormField label="Contract ID" required>
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={selectedContractId}
                    onChange={(e) => {
                      setSelectedContractId(e.target.value);
                    }}
                  >
                    <option value="">Select receiver contract...</option>
                    {receiverContractsQuery.view.state === "current"
                      ? receiverContractsQuery.view.data.items.map((rc) => (
                          <option key={rc.contract_id} value={rc.contract_id}>
                            {rc.name} ({rc.consumer_contract_scope})
                          </option>
                        ))
                      : null}
                  </select>
                )}
              </FormField>
              <FormField label="Receipt Profile">
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={receiptProfile}
                    onChange={(e) => {
                      setReceiptProfile(e.target.value as ReceiptProfile);
                    }}
                  >
                    {RECEIPT_PROFILES.map((rp) => (
                      <option key={rp} value={rp}>
                        {rp}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>
              <FormField label="Ordering Profile">
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={orderingProfile}
                    onChange={(e) => {
                      setOrderingProfile(e.target.value as OrderingProfile);
                    }}
                  >
                    {ORDERING_PROFILES.map((op) => (
                      <option key={op} value={op}>
                        {op}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>
              <FormField label="Allowed Business Key IDs (CSV)">
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    value={allowedBusinessKeysCsv}
                    onChange={(e) => {
                      setAllowedBusinessKeysCsv(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                disabled={selectedContractId.trim().length === 0}
                onClick={() => {
                  void handleCreateReceiverContractVersion();
                }}
              >
                Add Contract Version
              </button>
            </section>
          </div>

          <ResourceStatePanel
            view={receiverContractsQuery.view}
            resourceLabel="Receiver contracts"
            emptyTitle="No receiver contracts defined"
            onRetry={receiverContractsQuery.reload}
          >
            {(rcPage) => (
              <section className="rq-card" aria-label="Receiver contracts table">
                <DataTable<ReceiverContractDto>
                  caption="Receiver contracts"
                  rows={rcPage.items}
                  rowKey={(rc) => rc.contract_id}
                  columns={[
                    {
                      key: "name",
                      header: "Contract & Scope",
                      render: (rc) => (
                        <div className="rq-stack-sm">
                          <strong>{rc.name}</strong>
                          <span className="mono">{rc.consumer_contract_scope}</span>
                        </div>
                      )
                    },
                    {
                      key: "versions",
                      header: "Versions & Verification",
                      render: (rc) => (
                        <div className="rq-stack-sm">
                          {rc.versions.map((v) => (
                            <div key={v.version_id} className="rq-row">
                              <span className="kbd-chip">v{v.contract_version}</span>
                              <span className="kbd-chip">{v.receipt_profile}</span>
                              <StatusBadge status={v.state} />
                              {v.state === "draft" ? (
                                <button
                                  type="button"
                                  className="rq-btn"
                                  onClick={() => {
                                    void (async () => {
                                      const res = await api.mutateReceiverContractVersion(
                                        scope.tenantId,
                                        scope.projectId,
                                        v.version_id,
                                        "verification-intents",
                                        { schema_version: 1, expected_version: v.version },
                                        generateIdempotencyKey("rc-verify")
                                      );
                                      if (!res.ok) {
                                        setFeedback({ kind: "failed", error: res });
                                        return;
                                      }
                                      receiverContractsQuery.reload();
                                    })();
                                  }}
                                >
                                  Verify Contract
                                </button>
                              ) : null}
                              {v.state === "verified" ? (
                                <button
                                  type="button"
                                  className="rq-btn rq-btn-primary"
                                  onClick={() => {
                                    const body = {
                                      schema_version: 1,
                                      expected_version: v.version,
                                      definition_sha256: v.definition_sha256
                                    };
                                    const canonical = hashCanonicalJson(body);
                                    setPendingStepUp({
                                      descriptor: {
                                        action: "receiver_contracts.activate",
                                        actionLabel: `Activate Receiver Contract v${v.contract_version}`,
                                        scopeKind: "project",
                                        tenantId: scope.tenantId,
                                        projectId: scope.projectId,
                                        targetResourceId: v.version_id,
                                        targetVersion: v.version,
                                        canonicalCommandSha256: canonical.sha256,
                                        summary: `Activates receiver contract version ${v.contract_version}.`
                                      },
                                      execute: async (operationProofId) => {
                                        const res = await api.mutateReceiverContractVersion(
                                          scope.tenantId,
                                          scope.projectId,
                                          v.version_id,
                                          "activate",
                                          { ...body, operation_proof_id: operationProofId },
                                          generateIdempotencyKey("rc-activate")
                                        );
                                        if (!res.ok) {
                                          setFeedback({ kind: "failed", error: res });
                                          return;
                                        }
                                        receiverContractsQuery.reload();
                                      }
                                    });
                                  }}
                                >
                                  Activate (Step-Up)
                                </button>
                              ) : null}
                            </div>
                          ))}
                        </div>
                      )
                    }
                  ]}
                />
              </section>
            )}
          </ResourceStatePanel>
        </div>
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
