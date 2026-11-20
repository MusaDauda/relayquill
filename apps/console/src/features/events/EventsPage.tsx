import { type JSX, useEffect, useMemo, useState } from "react";
import {
  type EventContentDto,
  type EventDetailDto,
  type EventListItemDto,
  isCapabilityAvailable
} from "@relayquill/contracts";
import {
  CONTENT_VIEWS,
  type ContentView,
  EVENT_STATES
} from "@relayquill/domain";
import {
  buildScopePartitionKey,
  prepareEventAdmissionCommand,
  type PreparedEventCommand
} from "../../api/prepared-commands.js";
import { buildProjectPath, useConsoleRouter } from "../../app/router.js";
import { useActiveScope } from "../../app/scope.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CopyableId } from "../../components/CopyableId.js";
import { DataTable } from "../../components/DataTable.js";
import { FormField } from "../../components/FormField.js";
import { ConsoleIcon } from "../../components/Icons.js";
import { LiveWatchPanel } from "../../components/LiveWatchPanel.js";
import { LosslessJsonViewer } from "../../components/LosslessJsonViewer.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";
import { formatByteSize } from "../../utils/format.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { inspectLosslessJsonText } from "../../utils/lossless-json.js";

const DEFAULT_EVENT_JSON = `{
  "order_id": "ord_example_1001",
  "amount_minor": 9223372036854775807,
  "currency": "USD"
}`;

export function EventsPage({
  selectedEventId
}: {
  readonly selectedEventId?: string | undefined;
}): JSX.Element {
  const { navigate } = useConsoleRouter();
  const { api, preparedCommands, session } = useConsoleRuntime();
  const scope = useActiveScope();

  // Filter & pagination state
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const [namespaceFilter, setNamespaceFilter] = useState("");
  const [windowFilter, setWindowFilter] = useState("24h");
  const [pageSize, setPageSize] = useState<25 | 100>(25);
  const [cursorStack, setCursorStack] = useState<readonly (string | null)[]>([null]);
  const [showComposer, setShowComposer] = useState(false);

  // Composer state (frozen in memory store before POST)
  const [composeEventTypeId, setComposeEventTypeId] = useState("");
  const [composeSchemaVersion, setComposeSchemaVersion] = useState(1);
  const [composeBusinessKey, setComposeBusinessKey] = useState("");
  const [composeJsonText, setComposeJsonText] = useState(DEFAULT_EVENT_JSON);
  const [composeProducerTime, setComposeProducerTime] = useState("");
  const [composeDeadlineAt, setComposeDeadlineAt] = useState("");
  const [composeIdempotencyKey, setComposeIdempotencyKey] = useState<string>(() =>
    generateIdempotencyKey("evt-admit")
  );
  const [activePrepared, setActivePrepared] = useState<PreparedEventCommand | null>(null);
  const [composeFeedback, setComposeFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });
  const [channelFeedback, setChannelFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });
  const [preparedRefreshTick, setPreparedRefreshTick] = useState(0);

  // Detail content inspection state (explicit load gated by human_data_grants)
  const [selectedContentView, setSelectedContentView] = useState<ContentView>("original");
  const [selectedRepVersion, setSelectedRepVersion] = useState<number | null>(null);
  const [loadedContent, setLoadedContent] = useState<EventContentDto | null>(null);
  const [contentFeedback, setContentFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });

  const currentCursor = cursorStack[cursorStack.length - 1] ?? null;

  const publicationContextQuery = useScopedQuery({
    resource: "project.publication_context",
    fetcher: (signal: AbortSignal) =>
      api.getPublicationContext(scope.tenantId, scope.projectId, signal)
  });

  const eventTypesQuery = useScopedQuery({
    resource: "project.event_types",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEventTypes(scope.tenantId, scope.projectId, { limit: 100 }, signal)
  });

  const eventsQuery = useScopedQuery({
    resource: "project.events",
    filter: {
      eventTypeFilter,
      stateFilter,
      namespaceFilter,
      windowFilter,
      pageSize,
      cursor: currentCursor
    },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEvents(
        scope.tenantId,
        scope.projectId,
        {
          ...(eventTypeFilter.trim().length > 0
            ? { event_type_id: eventTypeFilter.trim() }
            : {}),
          ...(stateFilter.trim().length > 0 ? { state: stateFilter.trim() } : {}),
          ...(namespaceFilter.trim().length > 0
            ? { namespace: namespaceFilter.trim() }
            : {}),
          window: windowFilter,
          limit: pageSize,
          cursor: currentCursor
        },
        signal
      )
  });

  const eventDetailQuery = useScopedQuery({
    resource: "project.event_detail",
    enabled: selectedEventId !== undefined,
    filter: { selectedEventId },
    extractVersion: (d) => d.current_version,
    fetcher: (signal: AbortSignal) =>
      api.getEventDetail(scope.tenantId, scope.projectId, selectedEventId ?? "", signal)
  });

  const eventHistoryQuery = useScopedQuery({
    resource: "project.event_history",
    enabled: selectedEventId !== undefined,
    filter: { selectedEventId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEventHistory(
        scope.tenantId,
        scope.projectId,
        selectedEventId ?? "",
        { limit: 50 },
        signal
      )
  });

  const eventRepsQuery = useScopedQuery({
    resource: "project.event_representations",
    enabled: selectedEventId !== undefined,
    filter: { selectedEventId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEventRepresentations(scope.tenantId, scope.projectId, selectedEventId ?? "", signal)
  });

  useEffect(() => {
    setLoadedContent(null);
    setContentFeedback({ kind: "idle" });
    setSelectedRepVersion(null);
  }, [selectedEventId]);

  const jsonPreview = useMemo(() => inspectLosslessJsonText(composeJsonText), [composeJsonText]);

  const scopePartitionKey = useMemo(
    () => buildScopePartitionKey(scope.principalId, scope.tenantId, scope.projectId),
    [scope.principalId, scope.projectId, scope.tenantId]
  );

  const scopePreparedCommands = useMemo(
    () => {
      void preparedRefreshTick;
      return preparedCommands.listForScope(scopePartitionKey);
    },
    [preparedCommands, preparedRefreshTick, scopePartitionKey]
  );

  const handleEnableHumanChannel = async (): Promise<void> => {
    setChannelFeedback({
      kind: "submitting",
      label: "Provisioning human publication channel for active scope..."
    });
    const res = await api.enableHumanPublicationChannel(
      scope.tenantId,
      scope.projectId,
      generateIdempotencyKey("pub-ctx-enable")
    );
    if (!res.ok) {
      setChannelFeedback({ kind: "failed", error: res });
      return;
    }
    setChannelFeedback({
      kind: "succeeded",
      title: "Human Publication Channel Enabled",
      detail: `Channel ${res.data.publication_channel_id ?? "bound"} ready under namespace ${res.data.namespace ?? "scope"}.`
    });
    publicationContextQuery.reload();
  };

  const handlePrepareAndSubmitEvent = async (retryExisting?: PreparedEventCommand): Promise<void> => {
    let commandToSend = retryExisting ?? null;
    if (commandToSend === null) {
      const ctx =
        publicationContextQuery.view.state === "current"
          ? publicationContextQuery.view.data
          : null;
      if (ctx === null || !ctx.channel_enabled || ctx.publication_channel_id === null || ctx.namespace === null) {
        setComposeFeedback({
          kind: "failed",
          error: {
            ok: false,
            status: 400,
            code: "PUBLICATION_CHANNEL_DISABLED",
            message: "Enable the human publication channel before preparing an event.",
            acceptance: "known_rejected",
            retryable: false,
            aborted: false,
            fieldErrors: []
          }
        });
        return;
      }
      if (!jsonPreview.valid) {
        setComposeFeedback({
          kind: "failed",
          error: {
            ok: false,
            status: 400,
            code: "INVALID_JSON_PAYLOAD",
            message: jsonPreview.error ?? "Payload JSON failed strict validation.",
            acceptance: "known_rejected",
            retryable: false,
            aborted: false,
            fieldErrors: []
          }
        });
        return;
      }

      try {
        const prepared = prepareEventAdmissionCommand({
          scope: {
            tenantId: scope.tenantId,
            projectId: scope.projectId,
            publicationChannelId: ctx.publication_channel_id,
            channelKind: ctx.channel_kind,
            actorPrincipalId: session?.principal_id ?? scope.principalId,
            namespace: ctx.namespace
          },
          eventTypeId: composeEventTypeId.trim(),
          eventSchemaVersion: composeSchemaVersion,
          businessKey: composeBusinessKey.trim(),
          idempotencyKey: composeIdempotencyKey.trim(),
          rawJsonText: composeJsonText,
          ...(composeProducerTime.trim().length > 0
            ? { producerEventTime: composeProducerTime.trim() }
            : {}),
          ...(composeDeadlineAt.trim().length > 0 ? { deadlineAt: composeDeadlineAt.trim() } : {})
        });
        commandToSend = preparedCommands.save(prepared);
        setActivePrepared(commandToSend);
        setPreparedRefreshTick((t) => t + 1);
      } catch (err) {
        setComposeFeedback({
          kind: "failed",
          error: {
            ok: false,
            status: 400,
            code: "INVALID_ADMISSION_COMMAND",
            message: err instanceof Error ? err.message : "Unable to freeze event admission command.",
            acceptance: "known_rejected",
            retryable: false,
            aborted: false,
            fieldErrors: []
          }
        });
        return;
      }
    }

    setComposeFeedback({
      kind: "submitting",
      label: `Submitting frozen admission command ${commandToSend.businessKey} (SHA-256 ${commandToSend.contentSha256.slice(0, 12)}...)`
    });

    const res = await api.admitFrozenEvent(
      scope.tenantId,
      scope.projectId,
      commandToSend.frozenBodyJson,
      commandToSend.idempotencyKey
    );

    if (!res.ok) {
      const nextStatus = res.acceptance === "unknown" ? "acceptance_unknown" : "rejected";
      const updated = preparedCommands.updateStatus(scopePartitionKey, commandToSend.idempotencyKey, {
        status: nextStatus,
        lastErrorCode: res.code,
        lastErrorMessage: res.message
      });
      if (updated !== undefined) {
        setActivePrepared(updated);
      }
      setPreparedRefreshTick((t) => t + 1);
      setComposeFeedback({
        kind: "failed",
        error: res,
        preservedDraft: commandToSend
      });
      return;
    }

    const updated = preparedCommands.updateStatus(scopePartitionKey, commandToSend.idempotencyKey, {
      status: "accepted",
      acceptedEventId: res.data.event.event_id
    });
    if (updated !== undefined) {
      setActivePrepared(updated);
    }
    setPreparedRefreshTick((t) => t + 1);
    setComposeIdempotencyKey(generateIdempotencyKey("evt-admit"));
    setComposeFeedback({
      kind: "succeeded",
      title: res.data.matched_existing ? "Idempotent Event Resolved" : "Event Admitted",
      detail: `Event ${res.data.event.event_id} recorded at sequence ${res.data.event.project_event_sequence}.`,
      receiptId: res.data.receipt.id
    });
    eventsQuery.reload();
  };

  const handleResolveUnknownCommand = async (cmd: PreparedEventCommand): Promise<void> => {
    setComposeFeedback({
      kind: "submitting",
      label: `Resolving uncertain admission for business key ${cmd.businessKey}...`
    });
    const res = await api.resolveEvent(
      scope.tenantId,
      scope.projectId,
      {
        schema_version: 1,
        business_key: cmd.businessKey,
        submitted_shape_sha256: cmd.submittedShapeSha256
      },
      generateIdempotencyKey("evt-resolve")
    );
    if (!res.ok) {
      setComposeFeedback({ kind: "failed", error: res, preservedDraft: cmd });
      return;
    }
    const updated = preparedCommands.updateStatus(scopePartitionKey, cmd.idempotencyKey, {
      status: "accepted",
      acceptedEventId: res.data.event.event_id
    });
    if (updated !== undefined) {
      setActivePrepared(updated);
    }
    setPreparedRefreshTick((t) => t + 1);
    setComposeFeedback({
      kind: "succeeded",
      title: "Admission Outcome Confirmed",
      detail: `Confirmed existing event ${res.data.event.event_id} (fingerprint verified: ${res.data.fingerprint_verified ? "yes" : "no"}).`,
      receiptId: res.data.receipt.id
    });
    navigate(buildProjectPath(scope.tenantId, scope.projectId, "events", res.data.event.event_id));
  };

  const handleInspectPayload = async (detail: EventDetailDto): Promise<void> => {
    setContentFeedback({
      kind: "submitting",
      label: `Requesting ${selectedContentView} payload content (server enforces active human_data_grants)...`
    });
    const res =
      selectedContentView === "original"
        ? await api.getEventOriginalContent(scope.tenantId, scope.projectId, detail.event_id)
        : await api.getEventRepresentationContent(
            scope.tenantId,
            scope.projectId,
            detail.event_id,
            selectedRepVersion ?? 1,
            selectedContentView
          );
    if (!res.ok) {
      setLoadedContent(null);
      setContentFeedback({ kind: "failed", error: res });
      return;
    }
    setLoadedContent(res.data);
    setContentFeedback({
      kind: "succeeded",
      title: `Loaded ${res.data.view} payload`,
      detail: `Verified SHA-256 ${res.data.sha256} (${formatByteSize(res.data.byte_count)}).`
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Events & Admission</h1>
          <p className="rq-page-lead">
            Inspect durable admission envelopes, broker outbox observations, fanout progress, lossless
            original/derived payloads gated by human data grants, or prepare schema-aware test events.
          </p>
        </div>
        <div className="rq-row">
          {selectedEventId !== undefined ? (
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                navigate(buildProjectPath(scope.tenantId, scope.projectId, "events"));
              }}
            >
              Back to Events List
            </button>
          ) : null}
          <button
            type="button"
            className="rq-btn rq-btn-primary"
            onClick={() => {
              setShowComposer((prev) => !prev);
            }}
          >
            {showComposer ? "Hide Publish Composer" : "Prepare & Publish Test Event"}
          </button>
        </div>
      </header>

      <MutationFeedback state={channelFeedback} resourceLabel="Publication context" />

      {showComposer ? (
        <section className="rq-card" aria-label="Schema-aware human publication composer">
          <div className="rq-card-header">
            <h2 className="rq-section-title">Frozen Event Admission Composer</h2>
            <span className="kbd-chip">Memory-Only Replay Protection</span>
          </div>

          <ResourceStatePanel
            view={publicationContextQuery.view}
            resourceLabel="Publication context"
            onRetry={publicationContextQuery.reload}
          >
            {(pubCtx) => (
              <div className="rq-stack">
                {!pubCtx.channel_enabled ? (
                  <div className="rq-state-panel" data-tone="warn" role="status">
                    <div className="rq-row-between">
                      <div>
                        <strong>Human publication channel not yet enabled</strong>
                        <p className="rq-meta-text">
                          Operators with admission rights must enable their bound human publication
                          channel before admitting test events.
                        </p>
                      </div>
                      <button
                        type="button"
                        className="rq-btn rq-btn-primary"
                        disabled={
                          !isCapabilityAvailable(
                            pubCtx.capabilities ?? [],
                            "publication_context.enable"
                          ) &&
                          pubCtx.capabilities !== undefined &&
                          pubCtx.capabilities.length > 0
                        }
                        onClick={() => {
                          void handleEnableHumanChannel();
                        }}
                      >
                        Enable Human Publication Channel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <dl className="rq-kv-grid">
                      <dt>Publication Channel</dt>
                      <dd>
                        <CopyableId value={pubCtx.publication_channel_id ?? "unbound"} />
                      </dd>
                      <dt>Bound Namespace</dt>
                      <dd className="mono">{pubCtx.namespace ?? "none"}</dd>
                      <dt>Channel Budgets</dt>
                      <dd className="mono">
                        decoded max {formatByteSize(pubCtx.budgets.max_decoded_content_bytes)} / encoded max{" "}
                        {formatByteSize(pubCtx.budgets.max_encoded_body_bytes)}
                      </dd>
                    </dl>

                    <div className="rq-grid-2">
                      <FormField label="Allowed Event Type" required>
                        {({ inputId }) => (
                          <select
                            id={inputId}
                            className="rq-select"
                            value={composeEventTypeId}
                            onChange={(e) => {
                              const id = e.target.value;
                              setComposeEventTypeId(id);
                              const matched = pubCtx.allowed_events.find((x) => x.event_type_id === id);
                              if (matched !== undefined && matched.allowed_schema_versions[0] !== undefined) {
                                setComposeSchemaVersion(matched.allowed_schema_versions[0]);
                              }
                            }}
                          >
                            <option value="">Select event type...</option>
                            {pubCtx.allowed_events.map((ev) => (
                              <option key={ev.event_type_id} value={ev.event_type_id}>
                                {ev.event_type_name} ({ev.event_type_id})
                              </option>
                            ))}
                          </select>
                        )}
                      </FormField>

                      <FormField
                        label="Schema Version"
                        helpText="If your allowed events list is empty, publish an event schema version or verify scope grants."
                        required
                      >
                        {({ inputId }) => (
                          <input
                            id={inputId}
                            type="number"
                            min={1}
                            className="rq-input"
                            value={composeSchemaVersion}
                            onChange={(e) => {
                              setComposeSchemaVersion(Math.max(1, Number(e.target.value) || 1));
                            }}
                          />
                        )}
                      </FormField>

                      <FormField label="Business Key" required>
                        {({ inputId }) => (
                          <input
                            id={inputId}
                            className="rq-input mono"
                            placeholder="order-created-20261120-001"
                            value={composeBusinessKey}
                            onChange={(e) => {
                              setComposeBusinessKey(e.target.value);
                            }}
                          />
                        )}
                      </FormField>

                      <FormField label="Idempotency Key" required>
                        {({ inputId }) => (
                          <div className="rq-row">
                            <input
                              id={inputId}
                              className="rq-input mono"
                              value={composeIdempotencyKey}
                              onChange={(e) => {
                                setComposeIdempotencyKey(e.target.value);
                              }}
                            />
                            <button
                              type="button"
                              className="rq-btn"
                              onClick={() => {
                                setComposeIdempotencyKey(generateIdempotencyKey("evt-admit"));
                              }}
                            >
                              Regenerate
                            </button>
                          </div>
                        )}
                      </FormField>

                      <FormField label="Optional Producer Event Time (UTC ISO)">
                        {({ inputId }) => (
                          <input
                            id={inputId}
                            className="rq-input mono"
                            placeholder="2026-11-20T08:00:00Z"
                            value={composeProducerTime}
                            onChange={(e) => {
                              setComposeProducerTime(e.target.value);
                            }}
                          />
                        )}
                      </FormField>

                      <FormField label="Optional Delivery Deadline (UTC ISO)">
                        {({ inputId }) => (
                          <input
                            id={inputId}
                            className="rq-input mono"
                            placeholder="2026-11-20T12:00:00Z"
                            value={composeDeadlineAt}
                            onChange={(e) => {
                              setComposeDeadlineAt(e.target.value);
                            }}
                          />
                        )}
                      </FormField>
                    </div>

                    <FormField
                      label="Event Payload JSON (Lossless Bytes)"
                      errorText={jsonPreview.valid ? null : jsonPreview.error}
                      helpText={`SHA-256 ${jsonPreview.sha256} (${formatByteSize(jsonPreview.byteCount)})`}
                      required
                    >
                      {({ inputId, hasError }) => (
                        <textarea
                          id={inputId}
                          className="rq-textarea"
                          aria-invalid={hasError}
                          value={composeJsonText}
                          onChange={(e) => {
                            setComposeJsonText(e.target.value);
                          }}
                        />
                      )}
                    </FormField>

                    <LosslessJsonViewer
                      jsonText={composeJsonText}
                      title="Prepared Lossless JSON Preview"
                      expectedSha256={jsonPreview.sha256}
                    />

                    <div className="rq-row">
                      <button
                        type="button"
                        className="rq-btn rq-btn-primary"
                        disabled={
                          composeEventTypeId.trim().length === 0 ||
                          composeBusinessKey.trim().length === 0 ||
                          !jsonPreview.valid
                        }
                        onClick={() => {
                          void handlePrepareAndSubmitEvent();
                        }}
                      >
                        Freeze & Admit Event
                      </button>
                    </div>

                    <MutationFeedback
                      state={composeFeedback}
                      resourceLabel="Event admission"
                      onRetry={
                        activePrepared !== null
                          ? () => {
                              void handlePrepareAndSubmitEvent(activePrepared);
                            }
                          : undefined
                      }
                      onResolveOriginal={
                        activePrepared !== null
                          ? () => {
                              void handleResolveUnknownCommand(activePrepared);
                            }
                          : undefined
                      }
                    />

                    {scopePreparedCommands.length > 0 ? (
                      <section className="rq-card-inset" aria-label="In-memory prepared commands">
                        <strong className="rq-label">
                          Prepared Commands in Active Scope ({scopePreparedCommands.length})
                        </strong>
                        <DataTable<PreparedEventCommand>
                          caption="In-memory frozen event commands"
                          rows={scopePreparedCommands}
                          rowKey={(cmd) => `${cmd.scopeKey}:${cmd.idempotencyKey}`}
                          columns={[
                            {
                              key: "key",
                              header: "Business Key / Idempotency",
                              render: (cmd) => (
                                <div className="rq-stack-sm">
                                  <span className="mono">{cmd.businessKey}</span>
                                  <span className="rq-meta-text mono">{cmd.idempotencyKey}</span>
                                </div>
                              )
                            },
                            {
                              key: "status",
                              header: "Status",
                              render: (cmd) => <StatusBadge status={cmd.status} />
                            },
                            {
                              key: "actions",
                              header: "Actions",
                              render: (cmd) => (
                                <div className="rq-row">
                                  {cmd.status !== "accepted" ? (
                                    <button
                                      type="button"
                                      className="rq-btn"
                                      onClick={() => {
                                        void handlePrepareAndSubmitEvent(cmd);
                                      }}
                                    >
                                      Resend Exact Frozen Bytes
                                    </button>
                                  ) : null}
                                  {cmd.status === "acceptance_unknown" ? (
                                    <button
                                      type="button"
                                      className="rq-btn"
                                      onClick={() => {
                                        void handleResolveUnknownCommand(cmd);
                                      }}
                                    >
                                      Resolve Original
                                    </button>
                                  ) : null}
                                  {cmd.acceptedEventId !== undefined ? (
                                    <button
                                      type="button"
                                      className="rq-btn"
                                      onClick={() => {
                                        navigate(
                                          buildProjectPath(
                                            scope.tenantId,
                                            scope.projectId,
                                            "events",
                                            cmd.acceptedEventId
                                          )
                                        );
                                      }}
                                    >
                                      Open Event
                                    </button>
                                  ) : null}
                                </div>
                              )
                            }
                          ]}
                        />
                      </section>
                    ) : null}
                  </>
                )}
              </div>
            )}
          </ResourceStatePanel>
        </section>
      ) : null}

      {selectedEventId !== undefined ? (
        <div className="rq-stack">
          <ResourceStatePanel
            view={eventDetailQuery.view}
            resourceLabel="Event detail"
            onRetry={eventDetailQuery.reload}
          >
            {(detail) => (
              <div className="rq-stack">
                <section className="rq-card" aria-label="Event summary and stage metadata">
                  <div className="rq-card-header">
                    <div className="rq-row">
                      <h2 className="rq-section-title">
                        {detail.event_type ?? detail.event_type_id} (v{detail.event_schema_version})
                      </h2>
                      <StatusBadge status={detail.current_state} />
                      <StatusBadge status={detail.fanout.state} label={`Fanout: ${detail.fanout.state}`} />
                    </div>
                    <CopyableId value={detail.event_id} label="Event ID" />
                  </div>

                  <dl className="rq-kv-grid">
                    <dt>Business Key</dt>
                    <dd className="mono">{detail.business_key}</dd>
                    <dt>Namespace / Channel</dt>
                    <dd className="mono">
                      {detail.namespace} / {detail.publication_channel_id}
                    </dd>
                    <dt>Project Event Sequence</dt>
                    <dd className="mono">
                      {detail.project_event_sequence} (topology v{detail.topology_version})
                    </dd>
                    <dt>Accepted At</dt>
                    <dd>
                      <UtcTimestamp value={detail.accepted_at} />
                    </dd>
                    <dt>Deadline At</dt>
                    <dd>
                      <UtcTimestamp value={detail.deadline_at} />
                    </dd>
                    <dt>Original Content SHA-256</dt>
                    <dd>
                      <CopyableId value={detail.original_content_sha256} /> (
                      {formatByteSize(detail.original_content_byte_count)})
                    </dd>
                    <dt>Submitted / Effective Hash</dt>
                    <dd className="mono">
                      submitted={detail.submitted_shape_sha256.slice(0, 16)}... / effective=
                      {detail.effective_request_sha256.slice(0, 16)}...
                    </dd>
                  </dl>

                  <div className="rq-row">
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        navigate(buildProjectPath(scope.tenantId, scope.projectId, "deliveries"));
                      }}
                    >
                      Investigate Deliveries
                    </button>
                  </div>
                </section>

                <LiveWatchPanel
                  streamId={`event:${detail.event_id}`}
                  path={`/api/v1/tenants/${encodeURIComponent(scope.tenantId)}/projects/${encodeURIComponent(scope.projectId)}/watch/events/${encodeURIComponent(detail.event_id)}`}
                  label="Event Lifecycle Stream"
                  onEvent={() => {
                    eventDetailQuery.reload();
                    eventHistoryQuery.reload();
                  }}
                  onResyncRequired={() => {
                    eventDetailQuery.reload();
                    eventHistoryQuery.reload();
                  }}
                />

                <div className="rq-grid-2">
                  <section className="rq-card" aria-label="Broker outbox publication timeline">
                    <div className="rq-card-header">
                      <h3 className="rq-card-title">Outbox & Broker Publication</h3>
                      <StatusBadge status={detail.publication.state} />
                    </div>
                    <dl className="rq-kv-grid">
                      <dt>Outbox ID</dt>
                      <dd>
                        <CopyableId value={detail.publication.outbox_id} />
                      </dd>
                      <dt>Publication Generation</dt>
                      <dd className="mono">{detail.publication.current_publication_generation}</dd>
                      <dt>Observation State</dt>
                      <dd>
                        <StatusBadge status={detail.publication.observation_state} />
                      </dd>
                      {detail.publication.latest_observation !== null ? (
                        <>
                          <dt>Latest Broker Stream Seq</dt>
                          <dd className="mono">
                            {detail.publication.latest_observation.stream_name}#
                            {detail.publication.latest_observation.stream_sequence} (gen{" "}
                            {detail.publication.latest_observation.broker_generation_id})
                          </dd>
                          <dt>Observed At</dt>
                          <dd>
                            <UtcTimestamp value={detail.publication.latest_observation.observed_at} />
                          </dd>
                        </>
                      ) : null}
                      {detail.publication.last_safe_error_code !== null ? (
                        <>
                          <dt>Last Safe Error Code</dt>
                          <dd className="mono">{detail.publication.last_safe_error_code}</dd>
                        </>
                      ) : null}
                    </dl>
                  </section>

                  <section className="rq-card" aria-label="Fanout and delivery generation counts">
                    <div className="rq-card-header">
                      <h3 className="rq-card-title">Fanout & Delivery Materialization</h3>
                      <StatusBadge status={detail.fanout.state} />
                    </div>
                    <dl className="rq-kv-grid">
                      <dt>Evaluated / Matched</dt>
                      <dd className="mono">
                        {detail.fanout.examined_count} examined / {detail.fanout.matched_count} matched (
                        {detail.fanout.delivery_count} deliveries)
                      </dd>
                      <dt>Materialized Through Seq</dt>
                      <dd className="mono">{detail.fanout.project_materialized_through_event_sequence}</dd>
                      <dt>Original Deliveries</dt>
                      <dd className="mono">
                        total {detail.delivery_counts.original.total_deliveries}, acked{" "}
                        {detail.delivery_counts.original.http_acknowledged_count}, receipts{" "}
                        {detail.delivery_counts.original.verified_receipt_count}, dead-letter{" "}
                        {detail.delivery_counts.original.dead_letter_count}
                      </dd>
                      <dt>Replay Deliveries</dt>
                      <dd className="mono">
                        total {detail.delivery_counts.replay.total_deliveries}, acked{" "}
                        {detail.delivery_counts.replay.http_acknowledged_count}, receipts{" "}
                        {detail.delivery_counts.replay.verified_receipt_count}
                      </dd>
                    </dl>
                  </section>
                </div>

                <section className="rq-card" aria-label="Data-grant gated event payload inspector">
                  <div className="rq-card-header">
                    <h3 className="rq-card-title">Payload & Representation Inspector</h3>
                    <StatusBadge
                      status={detail.content_availability.availability}
                      label={`Original Content: ${detail.content_availability.availability}`}
                    />
                  </div>
                  <p className="rq-meta-text">
                    Reading event payload bytes requires an active{" "}
                    <span className="kbd-chip">events.content.read</span> human data grant (scoped to
                    own namespace or approved project) and server-side audit logging.
                  </p>

                  <ResourceStatePanel
                    view={eventRepsQuery.view}
                    resourceLabel="Derived representations"
                    emptyTitle="No derived representations"
                    emptyDescription="This event only has original admitted content."
                  >
                    {(repsPage) => (
                      <div className="rq-row">
                        <FormField label="Representation Version">
                          {({ inputId }) => (
                            <select
                              id={inputId}
                              className="rq-select"
                              value={
                                selectedRepVersion ??
                                repsPage.items[0]?.representation_version ??
                                ""
                              }
                              onChange={(e) => {
                                setSelectedRepVersion(Number(e.target.value));
                              }}
                            >
                              {repsPage.items.map((rep) => (
                                <option
                                  key={rep.wire_envelope_id}
                                  value={rep.representation_version}
                                >
                                  v{rep.representation_version} ({rep.availability} /{" "}
                                  {formatByteSize(rep.byte_count)})
                                </option>
                              ))}
                            </select>
                          )}
                        </FormField>
                      </div>
                    )}
                  </ResourceStatePanel>

                  <div className="rq-row">
                    <FormField label="Content View">
                      {({ inputId }) => (
                        <select
                          id={inputId}
                          className="rq-select"
                          value={selectedContentView}
                          onChange={(e) => {
                            const next = e.target.value as ContentView;
                            setSelectedContentView(next);
                            if (
                              next !== "original" &&
                              selectedRepVersion === null &&
                              eventRepsQuery.view.state === "current" &&
                              eventRepsQuery.view.data.items[0] !== undefined
                            ) {
                              setSelectedRepVersion(
                                eventRepsQuery.view.data.items[0].representation_version
                              );
                            }
                          }}
                        >
                          {CONTENT_VIEWS.map((viewOpt) => (
                            <option key={viewOpt} value={viewOpt}>
                              {viewOpt}
                            </option>
                          ))}
                        </select>
                      )}
                    </FormField>
                    <button
                      type="button"
                      className="rq-btn rq-btn-primary"
                      disabled={
                        !isCapabilityAvailable(detail.capabilities, "events.content.read") &&
                        detail.capabilities.length > 0
                      }
                      onClick={() => {
                        void handleInspectPayload(detail);
                      }}
                    >
                      <ConsoleIcon name="info" />
                      <span>Load Authorized {selectedContentView} Bytes</span>
                    </button>
                  </div>

                  <MutationFeedback state={contentFeedback} resourceLabel="Event content" />

                  {loadedContent !== null ? (
                    <LosslessJsonViewer
                      base64Data={loadedContent.data}
                      title={`Authorized ${loadedContent.view} Payload (SHA-256 verified)`}
                      expectedSha256={loadedContent.sha256}
                    />
                  ) : null}
                </section>

                <section className="rq-card" aria-label="Event lifecycle stage history">
                  <h3 className="rq-card-title">Stage History Timeline</h3>
                  <ResourceStatePanel
                    view={eventHistoryQuery.view}
                    resourceLabel="Event history"
                    emptyTitle="No lifecycle history entries yet"
                    onRetry={eventHistoryQuery.reload}
                  >
                    {(histPage) => (
                      <ol className="rq-timeline">
                        {histPage.items.map((entry) => (
                          <li key={entry.event_sequence} className="rq-timeline-item">
                            <div className="rq-row-between">
                              <div className="rq-row">
                                <span className="kbd-chip">#{entry.event_sequence}</span>
                                <strong>{entry.event_kind}</strong>
                                <span className="kbd-chip">
                                  schema v{entry.event_schema_version}
                                </span>
                              </div>
                              <UtcTimestamp value={entry.recorded_at} />
                            </div>
                            <pre className="rq-json-viewer">
                              {JSON.stringify(entry.safe_facts, null, 2)}
                            </pre>
                          </li>
                        ))}
                      </ol>
                    )}
                  </ResourceStatePanel>
                </section>
              </div>
            )}
          </ResourceStatePanel>
        </div>
      ) : null}

      <section className="rq-card" aria-label="Event filter controls">
        <div className="rq-grid-3">
          <FormField label="Event Type">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={eventTypeFilter}
                onChange={(e) => {
                  setEventTypeFilter(e.target.value);
                  setCursorStack([null]);
                }}
              >
                <option value="">All event types</option>
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

          <FormField label="Event State">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={stateFilter}
                onChange={(e) => {
                  setStateFilter(e.target.value);
                  setCursorStack([null]);
                }}
              >
                <option value="">All states</option>
                {EVENT_STATES.map((st) => (
                  <option key={st} value={st}>
                    {st}
                  </option>
                ))}
              </select>
            )}
          </FormField>

          <FormField label="Namespace Filter">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                placeholder="billing"
                value={namespaceFilter}
                onChange={(e) => {
                  setNamespaceFilter(e.target.value);
                  setCursorStack([null]);
                }}
              />
            )}
          </FormField>

          <FormField label="Window">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={windowFilter}
                onChange={(e) => {
                  setWindowFilter(e.target.value);
                  setCursorStack([null]);
                }}
              >
                <option value="1h">Last 1h</option>
                <option value="24h">Last 24h</option>
                <option value="7d">Last 7d</option>
              </select>
            )}
          </FormField>
        </div>
      </section>

      <ResourceStatePanel
        view={eventsQuery.view}
        resourceLabel="Events list"
        emptyTitle="No admitted events match the current filters"
        emptyDescription="Broaden the window/state filters or publish a test event via the Human Publication Composer."
        onRetry={eventsQuery.reload}
      >
        {(eventsPage) => (
          <section className="rq-card" aria-label="Admitted events table">
            <DataTable<EventListItemDto>
              caption="Project admitted events"
              rows={eventsPage.items}
              rowKey={(ev) => ev.event_id}
              pagination={{
                pageSize,
                pageIndex: cursorStack.length - 1,
                onPageSizeChange: (nextSize) => {
                  setPageSize(nextSize);
                  setCursorStack([null]);
                },
                hasPrev: cursorStack.length > 1,
                hasNext:
                  (eventsPage.page.has_more ?? eventsPage.page.next_cursor !== null) &&
                  eventsPage.page.next_cursor !== null,
                onPrev: () => {
                  setCursorStack((prev) => (prev.length > 1 ? prev.slice(0, -1) : prev));
                },
                onNext: () => {
                  if (eventsPage.page.next_cursor !== null) {
                    const nextCursor = eventsPage.page.next_cursor;
                    setCursorStack((prev) => [...prev, nextCursor]);
                  }
                }
              }}
              columns={[
                {
                  key: "seq",
                  header: "Seq / Accepted",
                  render: (ev) => (
                    <div className="rq-stack-sm">
                      <span className="kbd-chip">#{ev.project_event_sequence}</span>
                      <UtcTimestamp value={ev.accepted_at} />
                    </div>
                  )
                },
                {
                  key: "type",
                  header: "Event Type & Business Key",
                  render: (ev) => (
                    <div className="rq-stack-sm">
                      <strong>
                        {ev.event_type ?? ev.event_type_id} v{ev.event_schema_version}
                      </strong>
                      <span className="mono">{ev.business_key}</span>
                    </div>
                  )
                },
                {
                  key: "state",
                  header: "Lifecycle",
                  render: (ev) => (
                    <div className="rq-row">
                      <StatusBadge status={ev.current_state} />
                      <StatusBadge status={ev.fanout_state} label={`fanout: ${ev.fanout_state}`} />
                    </div>
                  )
                },
                {
                  key: "namespace",
                  header: "Namespace",
                  render: (ev) => <span className="mono">{ev.namespace}</span>
                },
                {
                  key: "inspect",
                  header: "Inspect",
                  render: (ev) => (
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        navigate(
                          buildProjectPath(scope.tenantId, scope.projectId, "events", ev.event_id)
                        );
                      }}
                    >
                      Inspect Timeline
                    </button>
                  )
                }
              ]}
            />
          </section>
        )}
      </ResourceStatePanel>
    </div>
  );
}
