import {
  type DeliveryId,
  type EventId,
  NotFoundDomainError,
  type ProjectId,
  type TenantId,
  parseDeliveryId,
  parseEventId,
  parseProjectId,
  parseTenantId
} from "@relayquill/domain";
import {
  type AdmissionEvidenceRecord,
  type BrokerPublicationEvidenceRecord,
  type EvidenceRepositoryPort,
  type HttpAttemptEvidenceRecord,
  type TelemetryPort,
  type UnitOfWorkPort,
  type VerifiedReceiptEvidenceRecord,
  noopTelemetryPort
} from "./ports.js";

export interface EventEvidenceBoundaryView {
  readonly eventId: EventId;
  readonly admission: AdmissionEvidenceRecord;
  readonly brokerPublication: BrokerPublicationEvidenceRecord | null;
  readonly httpAttempts: readonly HttpAttemptEvidenceRecord[];
  readonly verifiedReceipts: readonly VerifiedReceiptEvidenceRecord[];
  readonly summary: {
    readonly accepted: boolean;
    readonly publishedToBroker: boolean;
    readonly httpAcknowledged: boolean;
    readonly receiverReceiptVerified: boolean;
    readonly hasRejectedOrConflictingReceipt: boolean;
  };
}

export interface DeliveryEvidenceBoundaryView {
  readonly deliveryId: DeliveryId;
  readonly eventId: EventId;
  readonly admission: AdmissionEvidenceRecord | null;
  readonly brokerPublication: BrokerPublicationEvidenceRecord | null;
  readonly httpAttempts: readonly HttpAttemptEvidenceRecord[];
  readonly verifiedReceipts: readonly VerifiedReceiptEvidenceRecord[];
  readonly summary: {
    readonly accepted: boolean;
    readonly publishedToBroker: boolean;
    readonly httpAcknowledged: boolean;
    readonly receiverReceiptVerified: boolean;
    readonly hasRejectedOrConflictingReceipt: boolean;
  };
}

export interface EvidenceServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly evidenceRepo: EvidenceRepositoryPort<TTx>;
  readonly telemetry?: TelemetryPort | undefined;
}

function buildEvidenceSummary(boundaries: {
  readonly admission?: AdmissionEvidenceRecord | undefined;
  readonly brokerPublication?: BrokerPublicationEvidenceRecord | undefined;
  readonly httpAttempts: readonly HttpAttemptEvidenceRecord[];
  readonly verifiedReceipts: readonly VerifiedReceiptEvidenceRecord[];
}): EventEvidenceBoundaryView["summary"] {
  const accepted = boundaries.admission !== undefined;
  const publishedToBroker =
    boundaries.brokerPublication !== undefined &&
    boundaries.brokerPublication.state === "published";
  const httpAcknowledged = boundaries.httpAttempts.some((attempt) => attempt.httpAcknowledged);
  const receiverReceiptVerified = boundaries.verifiedReceipts.some(
    (receipt) => receipt.state === "verified"
  );
  const hasRejectedOrConflictingReceipt = boundaries.verifiedReceipts.some(
    (receipt) => receipt.state === "rejected" || receipt.state === "conflicting"
  );

  return Object.freeze({
    accepted,
    publishedToBroker,
    httpAcknowledged,
    receiverReceiptVerified,
    hasRejectedOrConflictingReceipt
  });
}

export class EvidenceService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #evidenceRepo: EvidenceRepositoryPort<TTx>;
  readonly #telemetry: TelemetryPort;

  constructor(deps: EvidenceServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#evidenceRepo = deps.evidenceRepo;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Returns strictly separated admission, broker publication, HTTP delivery attempt,
   * and verified receiver receipt evidence boundaries for an event.
   */
  async getEventEvidence(input: {
    readonly tenantId: TenantId | string;
    readonly projectId: ProjectId | string;
    readonly eventId: EventId | string;
  }): Promise<EventEvidenceBoundaryView> {
    const span = this.#telemetry.startSpan("relayquill.evidence.get_event_evidence");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const eventId = parseEventId(input.eventId, "eventId");

      const raw = await this.#uow.inTransaction((tx) =>
        this.#evidenceRepo.readEventEvidence(tx, tenantId, projectId, eventId)
      );

      if (raw.admission === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Event "${eventId}" not found in project "${projectId}"`
        });
      }

      const view: EventEvidenceBoundaryView = Object.freeze({
        eventId,
        admission: raw.admission,
        brokerPublication: raw.brokerPublication ?? null,
        httpAttempts: Object.freeze([...raw.httpAttempts]),
        verifiedReceipts: Object.freeze([...raw.verifiedReceipts]),
        summary: buildEvidenceSummary(raw)
      });

      span.end({ code: "OK" });
      return view;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "event_evidence_failed"
      });
      throw err;
    }
  }

  /**
   * Returns strictly separated evidence boundaries scoped to a specific delivery generation
   * while preserving admission and broker publication provenance on its parent event.
   */
  async getDeliveryEvidence(input: {
    readonly tenantId: TenantId | string;
    readonly projectId: ProjectId | string;
    readonly deliveryId: DeliveryId | string;
  }): Promise<DeliveryEvidenceBoundaryView> {
    const span = this.#telemetry.startSpan("relayquill.evidence.get_delivery_evidence");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const deliveryId = parseDeliveryId(input.deliveryId, "deliveryId");

      const raw = await this.#uow.inTransaction((tx) =>
        this.#evidenceRepo.readDeliveryEvidence(tx, tenantId, projectId, deliveryId)
      );

      if (raw.admission === undefined && raw.httpAttempts.length === 0) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Delivery "${deliveryId}" not found in project "${projectId}"`
        });
      }

      const view: DeliveryEvidenceBoundaryView = Object.freeze({
        deliveryId,
        eventId: raw.eventId,
        admission: raw.admission ?? null,
        brokerPublication: raw.brokerPublication ?? null,
        httpAttempts: Object.freeze([...raw.httpAttempts]),
        verifiedReceipts: Object.freeze([...raw.verifiedReceipts]),
        summary: buildEvidenceSummary(raw)
      });

      span.end({ code: "OK" });
      return view;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "delivery_evidence_failed"
      });
      throw err;
    }
  }
}
