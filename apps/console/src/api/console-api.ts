import { createCommercialConsoleApiMethods } from "./commercial-api.js";
import {
  type AdmitEventResultDto,
  type AttemptSummaryDto,
  type DeliveryAggregateSummaryDto,
  type DeliveryRequestContentDto,
  type DeliverySummaryDto,
  type EventContentDto,
  type EventDetailDto,
  type EventHistoryEntryDto,
  type EventListItemDto,
  type EventRepresentationSummaryDto,
  type LateDeliveryObservationDto,
  type PaginatedData,
  type PublicationContextDto,
  type ReceiverReceiptObservationDto,
  type ReplayProposalDto,
  type ResolveEventResultDto,
  type SuppressionProposalDto,
  parseAdmitEventResult,
  parseAttemptSummary,
  parseDeliveryAggregateSummary,
  parseDeliveryRequestContentDto,
  parseDeliverySummary,
  parseEventContentDto,
  parseEventDetail,
  parseEventHistoryEntry,
  parseEventRepresentationSummary,
  parsePaginatedData,
  parseReceiverReceiptObservation
} from "@relayquill/contracts";
import { type ContentView, type DeliveryPopulation } from "@relayquill/domain";
import { type ConsoleHttpClient, type HttpApiResult } from "./http-client.js";
import {
  type AuditEventDto,
  type CapacityAndDispatchDto,
  type CompletedEnrollmentDto,
  type DeliveryHistoryEntryDto,
  type DeliveryNetworkDecisionDto,
  type EndpointCircuitDto,
  type EndpointSummaryDto,
  type EndpointVerificationIntentDto,
  type EnrollmentIntentDto,
  type EnrollmentPasskeyOptionsDto,
  type EventTypeDto,
  type GenericMutationResultDto,
  type HumanDataGrantDto,
  type InstallationStatusDto,
  type OrderSkipProposalDto,
  type OrderingCutoverPlanDto,
  type OrderingKeySummaryDto,
  type OrderingMemberDto,
  type PlatformRoleAssignmentDto,
  type ProducerSummaryDto,
  type ProjectMembershipDto,
  type ProjectOverviewDto,
  type RatePolicyChangeDto,
  type ReceiverContractDto,
  type RecoveryReferenceDto,
  type RepresentationProfileDto,
  type RetainedDispatchGrantDto,
  type RetentionHoldDto,
  type SessionContextDto,
  type SignInCompleteDto,
  type SignInOptionsDto,
  type SigningKeyIntentDto,
  type SigningKeyVersionDto,
  type SigningPolicyDto,
  type StepUpCompleteDto,
  type StepUpOptionsDto,
  type SubscriptionSummaryDto,
  type TenantSummaryDto,
  type TraceReferenceDto,
  parsePlainObjectDto,
  parseSessionContextDto
} from "./dtos.js";

function encodeQuery(params: Record<string, string | number | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && String(v).length > 0) {
      sp.set(k, String(v));
    }
  }
  const str = sp.toString();
  return str.length > 0 ? `?${str}` : "";
}

function projectBase(tenantId: string, projectId: string): string {
  return `/api/v1/tenants/${encodeURIComponent(tenantId)}/projects/${encodeURIComponent(projectId)}`;
}

function parseList<T>(parseItem: (raw: unknown) => T): (raw: unknown) => PaginatedData<T> {
  return (raw) => parsePaginatedData(raw, (item) => parseItem(item));
}

export function createConsoleApi(http: ConsoleHttpClient) {
  return {
    // Session & Access
    getSessionContext(signal?: AbortSignal): Promise<HttpApiResult<SessionContextDto>> {
      return http.request({
        method: "GET",
        path: "/api/v1/session/context",
        parseData: parseSessionContextDto,
        signal
      });
    },
    ...createCommercialConsoleApiMethods(http),
    logout(idempotencyKey: string): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/session/logout",
        bodyObj: { schema_version: 1 },
        idempotencyKey,
        parseData: (raw) => (raw === undefined ? {} : parsePlainObjectDto(raw))
      });
    },
    revokeOtherSessions(
      body: { readonly schema_version: 1; readonly operation_proof_id: string; readonly canonical_command_sha256: string },
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/session/revoke-others",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    createEnrollmentIntent(
      body:
        | { readonly schema_version: 1; readonly purpose: "first_platform_admin" }
        | { readonly schema_version: 1; readonly purpose: "invited_human"; readonly invited_intent_reference: string }
        | { readonly schema_version: 1; readonly purpose: "restricted_factor_recovery"; readonly target_recovery_reference: string },
      idempotencyKey: string
    ): Promise<HttpApiResult<EnrollmentIntentDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/access/enrollment-intents",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<EnrollmentIntentDto>(raw)
      });
    },
    getEnrollmentIntent(intentId: string, signal?: AbortSignal): Promise<HttpApiResult<EnrollmentIntentDto>> {
      return http.request({
        method: "GET",
        path: `/api/v1/access/enrollment-intents/${encodeURIComponent(intentId)}`,
        parseData: (raw) => parsePlainObjectDto<EnrollmentIntentDto>(raw),
        signal
      });
    },
    requestEnrollmentPasskeyOptions(
      intentId: string,
      body: { readonly schema_version: 1; readonly intent_version: string; readonly authenticator_label: string },
      idempotencyKey: string
    ): Promise<HttpApiResult<EnrollmentPasskeyOptionsDto>> {
      return http.request({
        method: "POST",
        path: `/api/v1/access/enrollment-intents/${encodeURIComponent(intentId)}/passkey-options`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<EnrollmentPasskeyOptionsDto>(raw)
      });
    },
    completeEnrollmentPasskey(
      intentId: string,
      body: { readonly schema_version: 1; readonly auth_challenge_id: string; readonly response: unknown },
      idempotencyKey: string
    ): Promise<HttpApiResult<CompletedEnrollmentDto>> {
      return http.request({
        method: "POST",
        path: `/api/v1/access/enrollment-intents/${encodeURIComponent(intentId)}/passkey-complete`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<CompletedEnrollmentDto>(raw)
      });
    },
    requestSignInOptions(idempotencyKey: string): Promise<HttpApiResult<SignInOptionsDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/access/sign-in/options",
        bodyObj: { schema_version: 1 },
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<SignInOptionsDto>(raw)
      });
    },
    completeSignIn(
      body: { readonly schema_version: 1; readonly auth_challenge_id: string; readonly response: unknown },
      idempotencyKey: string
    ): Promise<HttpApiResult<SignInCompleteDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/access/sign-in/complete",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<SignInCompleteDto>(raw)
      });
    },
    requestStepUpOptions(
      body: {
        readonly schema_version: 1;
        readonly action: string;
        readonly scope_kind: "installation" | "tenant" | "project";
        readonly tenant_id: string | null;
        readonly project_id: string | null;
        readonly target_resource_id: string;
        readonly target_version: string;
        readonly canonical_command_sha256: string;
      },
      idempotencyKey: string
    ): Promise<HttpApiResult<StepUpOptionsDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/session/step-up/options",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<StepUpOptionsDto>(raw)
      });
    },
    completeStepUp(
      body: { readonly schema_version: 1; readonly auth_challenge_id: string; readonly response: unknown },
      idempotencyKey: string
    ): Promise<HttpApiResult<StepUpCompleteDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/session/step-up/complete",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<StepUpCompleteDto>(raw)
      });
    },

    // Platform
    getHealthReady(signal?: AbortSignal): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "GET",
        path: "/api/v1/health/ready",
        parseData: (raw) => parsePlainObjectDto(raw),
        signal
      });
    },
    getInstallationStatus(signal?: AbortSignal): Promise<HttpApiResult<InstallationStatusDto>> {
      return http.request({
        method: "GET",
        path: "/api/v1/platform/installation",
        parseData: (raw) => parsePlainObjectDto<InstallationStatusDto>(raw),
        signal
      });
    },
    listTenants(
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<TenantSummaryDto>>> {
      return http.request({
        method: "GET",
        path: `/api/v1/platform/tenants${encodeQuery({ limit: query.limit, cursor: query.cursor ?? undefined })}`,
        parseData: parseList((raw) => parsePlainObjectDto<TenantSummaryDto>(raw)),
        signal
      });
    },
    createTenant(
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/platform/tenants",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    mutateTenant(
      tenantId: string,
      action: "suspend" | "restore" | "retire",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      const path =
        action === "retire"
          ? `/api/v1/tenants/${encodeURIComponent(tenantId)}/retire`
          : `/api/v1/platform/tenants/${encodeURIComponent(tenantId)}/${action}`;
      return http.request({
        method: "POST",
        path,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listPlatformRoles(
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<PlatformRoleAssignmentDto>>> {
      return http.request({
        method: "GET",
        path: `/api/v1/platform/role-assignments${encodeQuery({ limit: query.limit, cursor: query.cursor ?? undefined })}`,
        parseData: parseList((raw) => parsePlainObjectDto<PlatformRoleAssignmentDto>(raw)),
        signal
      });
    },
    assignPlatformRole(
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/platform/role-assignments",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    revokePlatformRole(
      assignmentId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `/api/v1/platform/role-assignments/${encodeURIComponent(assignmentId)}/revoke`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listRecoveryReferences(
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<RecoveryReferenceDto>>> {
      return http.request({
        method: "GET",
        path: `/api/v1/platform/recovery-references${encodeQuery({ limit: query.limit, cursor: query.cursor ?? undefined })}`,
        parseData: parseList((raw) => parsePlainObjectDto<RecoveryReferenceDto>(raw)),
        signal
      });
    },
    listPlatformAudit(
      query: { readonly limit?: number; readonly cursor?: string | null; readonly action?: string },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<AuditEventDto>>> {
      return http.request({
        method: "GET",
        path: `/api/v1/platform/audit${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined,
          action: query.action
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<AuditEventDto>(raw)),
        signal
      });
    },
    createProject(
      tenantId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `/api/v1/tenants/${encodeURIComponent(tenantId)}/projects`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },

    // Project Overview & Control
    getProjectOverview(
      tenantId: string,
      projectId: string,
      query: { readonly window?: string; readonly population?: DeliveryPopulation },
      signal?: AbortSignal
    ): Promise<HttpApiResult<ProjectOverviewDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/overview${encodeQuery({
          window: query.window,
          population: query.population
        })}`,
        parseData: (raw) => parsePlainObjectDto<ProjectOverviewDto>(raw),
        signal
      });
    },
    getDeliverySummary(
      tenantId: string,
      projectId: string,
      query: { readonly population?: DeliveryPopulation; readonly window?: string },
      signal?: AbortSignal
    ): Promise<HttpApiResult<DeliveryAggregateSummaryDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/delivery-summary${encodeQuery({
          population: query.population,
          window: query.window
        })}`,
        parseData: (raw) => parseDeliveryAggregateSummary(raw),
        signal
      });
    },
    mutateProjectAdmission(
      tenantId: string,
      projectId: string,
      action: "pause-admission" | "resume-admission" | "retire",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },

    // Publication & Events
    getPublicationContext(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PublicationContextDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/publication-context`,
        parseData: (raw) => parsePlainObjectDto<PublicationContextDto>(raw),
        signal
      });
    },
    enableHumanPublicationChannel(
      tenantId: string,
      projectId: string,
      idempotencyKey: string
    ): Promise<HttpApiResult<PublicationContextDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/publication-context/enable`,
        bodyObj: { schema_version: 1 },
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<PublicationContextDto>(raw)
      });
    },
    admitFrozenEvent(
      tenantId: string,
      projectId: string,
      frozenBodyJson: string,
      idempotencyKey: string
    ): Promise<HttpApiResult<AdmitEventResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/events`,
        bodyJson: frozenBodyJson,
        idempotencyKey,
        parseData: (raw) => parseAdmitEventResult(raw)
      });
    },
    resolveEvent(
      tenantId: string,
      projectId: string,
      body: { readonly schema_version: 1; readonly business_key: string; readonly submitted_shape_sha256?: string },
      idempotencyKey: string
    ): Promise<HttpApiResult<ResolveEventResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/events/resolve`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<ResolveEventResultDto>(raw)
      });
    },
    listEvents(
      tenantId: string,
      projectId: string,
      query: {
        readonly event_type_id?: string;
        readonly state?: string;
        readonly namespace?: string;
        readonly window?: string;
        readonly limit?: number;
        readonly cursor?: string | null;
      },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<EventListItemDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/events${encodeQuery({
          event_type_id: query.event_type_id,
          state: query.state,
          namespace: query.namespace,
          window: query.window,
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<EventListItemDto>(raw)),
        signal
      });
    },
    getEventDetail(
      tenantId: string,
      projectId: string,
      eventId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<EventDetailDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/events/${encodeURIComponent(eventId)}`,
        parseData: (raw) => parseEventDetail(raw),
        signal
      });
    },
    listEventHistory(
      tenantId: string,
      projectId: string,
      eventId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<EventHistoryEntryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/events/${encodeURIComponent(eventId)}/history${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parseEventHistoryEntry(raw)),
        signal
      });
    },
    getEventOriginalContent(
      tenantId: string,
      projectId: string,
      eventId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<EventContentDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/events/${encodeURIComponent(eventId)}/content`,
        parseData: (raw) => parseEventContentDto(raw),
        signal
      });
    },
    listEventRepresentations(
      tenantId: string,
      projectId: string,
      eventId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<EventRepresentationSummaryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/events/${encodeURIComponent(eventId)}/representations`,
        parseData: parseList((raw) => parseEventRepresentationSummary(raw)),
        signal
      });
    },
    getEventRepresentationContent(
      tenantId: string,
      projectId: string,
      eventId: string,
      representationVersion: number,
      view: ContentView,
      signal?: AbortSignal
    ): Promise<HttpApiResult<EventContentDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/events/${encodeURIComponent(eventId)}/representations/${representationVersion}/content${encodeQuery({ view })}`,
        parseData: (raw) => parseEventContentDto(raw),
        signal
      });
    },

    // Deliveries, Attempts, Receipts, Network & Replay
    listDeliveries(
      tenantId: string,
      projectId: string,
      query: {
        readonly event_id?: string;
        readonly endpoint_id?: string;
        readonly state?: string;
        readonly outcome_class?: string;
        readonly population?: DeliveryPopulation;
        readonly limit?: number;
        readonly cursor?: string | null;
      },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<DeliverySummaryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries${encodeQuery({
          event_id: query.event_id,
          endpoint_id: query.endpoint_id,
          state: query.state,
          outcome_class: query.outcome_class,
          population: query.population,
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parseDeliverySummary(raw)),
        signal
      });
    },
    getDeliveryDetail(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<DeliverySummaryDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}`,
        parseData: (raw) => parseDeliverySummary(raw),
        signal
      });
    },
    listDeliveryAttempts(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<AttemptSummaryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/attempts${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parseAttemptSummary(raw)),
        signal
      });
    },
    listDeliveryHistory(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<DeliveryHistoryEntryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/history${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<DeliveryHistoryEntryDto>(raw)),
        signal
      });
    },
    listDeliveryLateObservations(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<LateDeliveryObservationDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/late-observations`,
        parseData: parseList((raw) => parsePlainObjectDto<LateDeliveryObservationDto>(raw)),
        signal
      });
    },
    listDeliveryNetworkDecisions(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<DeliveryNetworkDecisionDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/network-decisions`,
        parseData: parseList((raw) => parsePlainObjectDto<DeliveryNetworkDecisionDto>(raw)),
        signal
      });
    },
    getDeliveryRequestContent(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<DeliveryRequestContentDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/request-content`,
        parseData: (raw) => parseDeliveryRequestContentDto(raw),
        signal
      });
    },
    listDeliveryReceiverReceipts(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<ReceiverReceiptObservationDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/receiver-receipts`,
        parseData: parseList((raw) => parseReceiverReceiptObservation(raw)),
        signal
      });
    },
    listDeliveryTraceReferences(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<TraceReferenceDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/trace-references`,
        parseData: parseList((raw) => parsePlainObjectDto<TraceReferenceDto>(raw)),
        signal
      });
    },

    // Replays & Suppressions
    listReplayProposals(
      tenantId: string,
      projectId: string,
      query: { readonly state?: string; readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<ReplayProposalDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/replay-proposals${encodeQuery({
          state: query.state,
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<ReplayProposalDto>(raw)),
        signal
      });
    },
    createReplayProposal(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<ReplayProposalDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/replay-proposals`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<ReplayProposalDto>(raw)
      });
    },
    reviewReplayProposal(
      tenantId: string,
      projectId: string,
      proposalId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/replay-proposals/${encodeURIComponent(proposalId)}/reviews`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    admitReplayProposal(
      tenantId: string,
      projectId: string,
      proposalId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/replay-proposals/${encodeURIComponent(proposalId)}/admit`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    withdrawReplayProposal(
      tenantId: string,
      projectId: string,
      proposalId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/replay-proposals/${encodeURIComponent(proposalId)}/withdraw`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listSuppressionProposals(
      tenantId: string,
      projectId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<SuppressionProposalDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/suppression-proposals${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<SuppressionProposalDto>(raw)),
        signal
      });
    },
    createSuppressionProposal(
      tenantId: string,
      projectId: string,
      deliveryId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<SuppressionProposalDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/deliveries/${encodeURIComponent(deliveryId)}/suppression-proposals`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<SuppressionProposalDto>(raw)
      });
    },
    reviewOrAdmitSuppressionProposal(
      tenantId: string,
      projectId: string,
      proposalId: string,
      action: "reviews" | "admit",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/suppression-proposals/${encodeURIComponent(proposalId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },

    // Ordering & Circuits
    listOrderingKeys(
      tenantId: string,
      projectId: string,
      query: { readonly subscription_id?: string; readonly state?: string; readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<OrderingKeySummaryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/ordering-keys${encodeQuery({
          subscription_id: query.subscription_id,
          state: query.state,
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<OrderingKeySummaryDto>(raw)),
        signal
      });
    },
    listOrderingMembers(
      tenantId: string,
      projectId: string,
      keyId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<OrderingMemberDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/ordering-keys/${encodeURIComponent(keyId)}/members${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<OrderingMemberDto>(raw)),
        signal
      });
    },
    listOrderSkipProposals(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<OrderSkipProposalDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/order-skip-proposals`,
        parseData: parseList((raw) => parsePlainObjectDto<OrderSkipProposalDto>(raw)),
        signal
      });
    },
    createOrderSkipProposal(
      tenantId: string,
      projectId: string,
      keyId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<OrderSkipProposalDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/ordering-keys/${encodeURIComponent(keyId)}/skip-proposals`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<OrderSkipProposalDto>(raw)
      });
    },
    mutateOrderSkipProposal(
      tenantId: string,
      projectId: string,
      proposalId: string,
      action: "reviews" | "admit",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/order-skip-proposals/${encodeURIComponent(proposalId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listOrderingCutovers(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<OrderingCutoverPlanDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/ordering-cutovers`,
        parseData: parseList((raw) => parsePlainObjectDto<OrderingCutoverPlanDto>(raw)),
        signal
      });
    },
    createOrderingCutover(
      tenantId: string,
      projectId: string,
      subscriptionId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<OrderingCutoverPlanDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/subscriptions/${encodeURIComponent(subscriptionId)}/ordering-cutovers`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<OrderingCutoverPlanDto>(raw)
      });
    },
    mutateOrderingCutover(
      tenantId: string,
      projectId: string,
      planId: string,
      action: "begin" | "activate" | "abort",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/ordering-cutovers/${encodeURIComponent(planId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    getEndpointCircuit(
      tenantId: string,
      projectId: string,
      endpointId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<EndpointCircuitDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/circuits`,
        parseData: (raw) => parsePlainObjectDto<EndpointCircuitDto>(raw),
        signal
      });
    },
    requestCircuitProbe(
      tenantId: string,
      projectId: string,
      endpointId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/circuits/request-probe`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },

    // Endpoints, Signing & Retained Grants
    listEndpoints(
      tenantId: string,
      projectId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<EndpointSummaryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/endpoints${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<EndpointSummaryDto>(raw)),
        signal
      });
    },
    createEndpoint(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<EndpointSummaryDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/endpoints`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<EndpointSummaryDto>(raw)
      });
    },
    createEndpointVersion(
      tenantId: string,
      projectId: string,
      endpointId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<EndpointSummaryDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/versions`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<EndpointSummaryDto>(raw)
      });
    },
    mutateEndpointLifecycle(
      tenantId: string,
      projectId: string,
      endpointId: string,
      action: "activate" | "pause" | "quarantine" | "resume" | "retire",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    createSigningKeyIntent(
      tenantId: string,
      projectId: string,
      endpointId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<SigningKeyIntentDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/signing-key-intents`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<SigningKeyIntentDto>(raw)
      });
    },
    listSigningKeyIntents(
      tenantId: string,
      projectId: string,
      endpointId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<SigningKeyIntentDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/signing-key-intents`,
        parseData: parseList((raw) => parsePlainObjectDto<SigningKeyIntentDto>(raw)),
        signal
      });
    },
    listSigningKeys(
      tenantId: string,
      projectId: string,
      endpointId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<SigningKeyVersionDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/signing-keys`,
        parseData: parseList((raw) => parsePlainObjectDto<SigningKeyVersionDto>(raw)),
        signal
      });
    },
    revokeSigningKey(
      tenantId: string,
      projectId: string,
      keyVersionId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/signing-keys/${encodeURIComponent(keyVersionId)}/revoke`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listSigningPolicies(
      tenantId: string,
      projectId: string,
      endpointId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<SigningPolicyDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/signing-policies`,
        parseData: parseList((raw) => parsePlainObjectDto<SigningPolicyDto>(raw)),
        signal
      });
    },
    createSigningPolicy(
      tenantId: string,
      projectId: string,
      endpointId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<SigningPolicyDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/signing-policies`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<SigningPolicyDto>(raw)
      });
    },
    activateSigningPolicy(
      tenantId: string,
      projectId: string,
      policyId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/signing-policies/${encodeURIComponent(policyId)}/activate`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    createEndpointVerificationIntent(
      tenantId: string,
      projectId: string,
      endpointId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<EndpointVerificationIntentDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/verification-intents`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<EndpointVerificationIntentDto>(raw)
      });
    },
    listEndpointVerificationIntents(
      tenantId: string,
      projectId: string,
      endpointId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<EndpointVerificationIntentDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/verification-intents`,
        parseData: parseList((raw) => parsePlainObjectDto<EndpointVerificationIntentDto>(raw)),
        signal
      });
    },
    listRetainedDispatchGrants(
      tenantId: string,
      projectId: string,
      endpointId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<RetainedDispatchGrantDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/retained-dispatch-grants`,
        parseData: parseList((raw) => parsePlainObjectDto<RetainedDispatchGrantDto>(raw)),
        signal
      });
    },
    createRetainedDispatchGrant(
      tenantId: string,
      projectId: string,
      endpointId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<RetainedDispatchGrantDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/endpoints/${encodeURIComponent(endpointId)}/retained-dispatch-grants`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<RetainedDispatchGrantDto>(raw)
      });
    },
    revokeRetainedDispatchGrant(
      tenantId: string,
      projectId: string,
      grantId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/retained-dispatch-grants/${encodeURIComponent(grantId)}/revoke`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },

    // Subscriptions, Schemas, Representations & Receiver Contracts
    listSubscriptions(
      tenantId: string,
      projectId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<SubscriptionSummaryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/subscriptions${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<SubscriptionSummaryDto>(raw)),
        signal
      });
    },
    createSubscription(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<SubscriptionSummaryDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/subscriptions`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<SubscriptionSummaryDto>(raw)
      });
    },
    createSubscriptionVersion(
      tenantId: string,
      projectId: string,
      subscriptionId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<SubscriptionSummaryDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/subscriptions/${encodeURIComponent(subscriptionId)}/versions`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<SubscriptionSummaryDto>(raw)
      });
    },
    mutateSubscriptionVersion(
      tenantId: string,
      projectId: string,
      versionId: string,
      action: "validate" | "activate",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/subscription-versions/${encodeURIComponent(versionId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    mutateSubscriptionControl(
      tenantId: string,
      projectId: string,
      subscriptionId: string,
      action: "pause-future" | "hold-sends" | "pause-all" | "resume-future" | "release-send-hold" | "retire",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/subscriptions/${encodeURIComponent(subscriptionId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listEventTypes(
      tenantId: string,
      projectId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<EventTypeDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/event-types${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<EventTypeDto>(raw)),
        signal
      });
    },
    createEventType(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<EventTypeDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/event-types`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<EventTypeDto>(raw)
      });
    },
    createEventSchemaVersion(
      tenantId: string,
      projectId: string,
      typeId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/event-types/${encodeURIComponent(typeId)}/schema-versions`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    mutateEventSchemaVersion(
      tenantId: string,
      projectId: string,
      schemaId: string,
      action: "validate" | "publish" | "retire",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/event-schema-versions/${encodeURIComponent(schemaId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listRepresentationProfiles(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<RepresentationProfileDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/representation-profiles`,
        parseData: parseList((raw) => parsePlainObjectDto<RepresentationProfileDto>(raw)),
        signal
      });
    },
    createRepresentationProfile(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<RepresentationProfileDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/representation-profiles`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<RepresentationProfileDto>(raw)
      });
    },
    createRepresentationProfileVersion(
      tenantId: string,
      projectId: string,
      profileId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/representation-profiles/${encodeURIComponent(profileId)}/versions`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    mutateRepresentationProfileVersion(
      tenantId: string,
      projectId: string,
      versionId: string,
      action: "activate" | "retire",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/representation-profile-versions/${encodeURIComponent(versionId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listReceiverContracts(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<ReceiverContractDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/receiver-contracts`,
        parseData: parseList((raw) => parsePlainObjectDto<ReceiverContractDto>(raw)),
        signal
      });
    },
    createReceiverContract(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<ReceiverContractDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/receiver-contracts`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<ReceiverContractDto>(raw)
      });
    },
    createReceiverContractVersion(
      tenantId: string,
      projectId: string,
      contractId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/receiver-contracts/${encodeURIComponent(contractId)}/versions`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    mutateReceiverContractVersion(
      tenantId: string,
      projectId: string,
      versionId: string,
      action: "verification-intents" | "activate",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/receiver-contract-versions/${encodeURIComponent(versionId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },

    // Producers
    listProducers(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<ProducerSummaryDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/producers`,
        parseData: parseList((raw) => parsePlainObjectDto<ProducerSummaryDto>(raw)),
        signal
      });
    },
    createProducer(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<ProducerSummaryDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/producers`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<ProducerSummaryDto>(raw)
      });
    },
    createProducerScopeVersion(
      tenantId: string,
      projectId: string,
      producerId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/producers/${encodeURIComponent(producerId)}/scope-versions`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    activateProducerScope(
      tenantId: string,
      projectId: string,
      scopeId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/producer-scopes/${encodeURIComponent(scopeId)}/activate`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    createProducerCredentialIntent(
      tenantId: string,
      projectId: string,
      producerId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/producers/${encodeURIComponent(producerId)}/credential-intents`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    rotateProducerCredential(
      tenantId: string,
      projectId: string,
      producerId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/producers/${encodeURIComponent(producerId)}/credential-rotations`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    revokeProducerCredential(
      tenantId: string,
      projectId: string,
      credentialId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/producer-credentials/${encodeURIComponent(credentialId)}/revoke`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    mutateProducerLifecycle(
      tenantId: string,
      projectId: string,
      producerId: string,
      action: "suspend" | "retire",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/producers/${encodeURIComponent(producerId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },

    // Limits, Capacity, Memberships, Data Grants, Retention & Audit
    getCapacityAndDispatch(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<CapacityAndDispatchDto>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/capacity`,
        parseData: (raw) => parsePlainObjectDto<CapacityAndDispatchDto>(raw),
        signal
      });
    },
    listRatePolicyChanges(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<RatePolicyChangeDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/rate-policy-changes`,
        parseData: parseList((raw) => parsePlainObjectDto<RatePolicyChangeDto>(raw)),
        signal
      });
    },
    proposeRatePolicyChange(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<RatePolicyChangeDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/rate-policy-changes`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<RatePolicyChangeDto>(raw)
      });
    },
    activateRatePolicyChange(
      tenantId: string,
      projectId: string,
      changeId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/rate-policy-changes/${encodeURIComponent(changeId)}/activate`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listMemberships(
      tenantId: string,
      projectId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<ProjectMembershipDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/memberships${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<ProjectMembershipDto>(raw)),
        signal
      });
    },
    createMembership(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<ProjectMembershipDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/memberships`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<ProjectMembershipDto>(raw)
      });
    },
    mutateMembership(
      tenantId: string,
      projectId: string,
      membershipId: string,
      action: "change-role" | "suspend" | "revoke",
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/memberships/${encodeURIComponent(membershipId)}/${action}`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listDataGrants(
      tenantId: string,
      projectId: string,
      query: { readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<HumanDataGrantDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/data-grants${encodeQuery({
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<HumanDataGrantDto>(raw)),
        signal
      });
    },
    createDataGrant(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<HumanDataGrantDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/data-grants`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<HumanDataGrantDto>(raw)
      });
    },
    revokeDataGrant(
      tenantId: string,
      projectId: string,
      grantId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/data-grants/${encodeURIComponent(grantId)}/revoke`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listRetentionHolds(
      tenantId: string,
      projectId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<RetentionHoldDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/retention-holds`,
        parseData: parseList((raw) => parsePlainObjectDto<RetentionHoldDto>(raw)),
        signal
      });
    },
    createRetentionHold(
      tenantId: string,
      projectId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<RetentionHoldDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/retention-holds`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<RetentionHoldDto>(raw)
      });
    },
    releaseRetentionHold(
      tenantId: string,
      projectId: string,
      holdId: string,
      body: Record<string, unknown>,
      idempotencyKey: string
    ): Promise<HttpApiResult<GenericMutationResultDto>> {
      return http.request({
        method: "POST",
        path: `${projectBase(tenantId, projectId)}/retention-holds/${encodeURIComponent(holdId)}/release`,
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto(raw)
      });
    },
    listProjectAudit(
      tenantId: string,
      projectId: string,
      query: { readonly action?: string; readonly target_kind?: string; readonly limit?: number; readonly cursor?: string | null },
      signal?: AbortSignal
    ): Promise<HttpApiResult<PaginatedData<AuditEventDto>>> {
      return http.request({
        method: "GET",
        path: `${projectBase(tenantId, projectId)}/audit${encodeQuery({
          action: query.action,
          target_kind: query.target_kind,
          limit: query.limit,
          cursor: query.cursor ?? undefined
        })}`,
        parseData: parseList((raw) => parsePlainObjectDto<AuditEventDto>(raw)),
        signal
      });
    }
  };
}

export type ConsoleApi = ReturnType<typeof createConsoleApi>;
