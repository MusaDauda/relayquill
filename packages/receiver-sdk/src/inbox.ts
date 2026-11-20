import { type Temporal } from "@js-temporal/polyfill";
import { parsePositiveInt64BigInt } from "@relayquill/contracts";
import {
  type CanonicalUtcTimestamp,
  type EventId,
  type OrderingDomainId,
  type ProjectId,
  type ReceiverOrderHeadState,
  type Sha256Hex,
  evaluateReceiverOrderAcceptance,
  formatUtcTimestamp,
  nowUtcInstant
} from "@relayquill/domain";
import {
  type EndpointKeyMetadata,
  type SigningKeyHandle,
  type VerifyDeliverySuccess
} from "@relayquill/signing";
import { ReceiverConflictError, toReceiverSdkError } from "./errors.js";
import { type ReceiverKeyResolverInput } from "./keys.js";
import {
  type SignedDeliveryReceiptResponse,
  createSignedDeliveryReceipt
} from "./receipt.js";

export type IdempotentDeliveryOutcome = "accepted" | "already_committed" | "replay_append";

export interface ReceiverBusinessCommitAnchor {
  readonly projectId: ProjectId;
  readonly consumerEventKey: Sha256Hex;
  readonly eventId: EventId;
  readonly originalFactsSha256: Sha256Hex;
  readonly committedAt: CanonicalUtcTimestamp;
}

export interface ReceiverOrderPositionAnchor {
  readonly consumerEventKey: Sha256Hex;
  readonly originalFactsSha256: Sha256Hex;
  readonly committedAt: CanonicalUtcTimestamp;
}

export interface ReceiverOrderHeadRecord {
  readonly headState: ReceiverOrderHeadState;
  readonly nextExpectedSequence: bigint;
}

export interface ReceiverInboxTransactionContext {
  getBusinessAnchor(
    projectId: ProjectId,
    consumerEventKey: Sha256Hex
  ): Promise<ReceiverBusinessCommitAnchor | null> | ReceiverBusinessCommitAnchor | null;
  saveBusinessAnchor(anchor: ReceiverBusinessCommitAnchor): Promise<void> | void;
  getOrderHead(
    projectId: ProjectId,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex
  ): Promise<ReceiverOrderHeadRecord | null> | ReceiverOrderHeadRecord | null;
  saveOrderHead(
    projectId: ProjectId,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex,
    record: ReceiverOrderHeadRecord
  ): Promise<void> | void;
  getOrderPositionAnchor(
    projectId: ProjectId,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex,
    sequence: bigint
  ): Promise<ReceiverOrderPositionAnchor | null> | ReceiverOrderPositionAnchor | null;
  saveOrderPositionAnchor(
    projectId: ProjectId,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex,
    sequence: bigint,
    anchor: ReceiverOrderPositionAnchor
  ): Promise<void> | void;
}

export interface ReceiverInboxAdapter {
  runInTransaction<T>(fn: (tx: ReceiverInboxTransactionContext) => Promise<T>): Promise<T>;
}

export class InMemoryReceiverInboxAdapter implements ReceiverInboxAdapter {
  #businessAnchors = new Map<string, ReceiverBusinessCommitAnchor>();
  #orderHeads = new Map<string, ReceiverOrderHeadRecord>();
  #orderPositions = new Map<string, ReceiverOrderPositionAnchor>();
  #txQueue: Promise<void> = Promise.resolve();

  static #businessKey(projectId: ProjectId, consumerEventKey: Sha256Hex): string {
    return `${projectId}:${consumerEventKey}`;
  }

  static #orderHeadKey(
    projectId: ProjectId,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex
  ): string {
    return `${projectId}:${orderingDomainId}:${orderingKeySha256}`;
  }

  static #orderPositionKey(
    projectId: ProjectId,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex,
    sequence: bigint
  ): string {
    return `${projectId}:${orderingDomainId}:${orderingKeySha256}:${sequence.toString(10)}`;
  }

  getBusinessAnchor(
    projectId: ProjectId,
    consumerEventKey: Sha256Hex
  ): ReceiverBusinessCommitAnchor | null {
    return this.#businessAnchors.get(
      InMemoryReceiverInboxAdapter.#businessKey(projectId, consumerEventKey)
    ) ?? null;
  }

  getOrderHead(
    projectId: ProjectId,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex
  ): ReceiverOrderHeadRecord | null {
    return this.#orderHeads.get(
      InMemoryReceiverInboxAdapter.#orderHeadKey(projectId, orderingDomainId, orderingKeySha256)
    ) ?? null;
  }

  setOrderHeadState(
    projectId: ProjectId,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex,
    headState: ReceiverOrderHeadState,
    nextExpectedSequence?: bigint
  ): void {
    const key = InMemoryReceiverInboxAdapter.#orderHeadKey(
      projectId,
      orderingDomainId,
      orderingKeySha256
    );
    const existing = this.#orderHeads.get(key);
    this.#orderHeads.set(
      key,
      Object.freeze({
        headState,
        nextExpectedSequence: nextExpectedSequence ?? existing?.nextExpectedSequence ?? 1n
      })
    );
  }

  async runInTransaction<T>(fn: (tx: ReceiverInboxTransactionContext) => Promise<T>): Promise<T> {
    const prev = this.#txQueue;
    let release!: () => void;
    this.#txQueue = new Promise<void>((resolve) => {
      release = resolve;
    });

    await prev;

    const businessSnapshot = new Map(this.#businessAnchors);
    const headSnapshot = new Map(this.#orderHeads);
    const positionSnapshot = new Map(this.#orderPositions);

    const tx: ReceiverInboxTransactionContext = {
      getBusinessAnchor: (projectId, consumerEventKey) =>
        this.#businessAnchors.get(
          InMemoryReceiverInboxAdapter.#businessKey(projectId, consumerEventKey)
        ) ?? null,
      saveBusinessAnchor: (anchor) => {
        this.#businessAnchors.set(
          InMemoryReceiverInboxAdapter.#businessKey(anchor.projectId, anchor.consumerEventKey),
          Object.freeze({ ...anchor })
        );
      },
      getOrderHead: (projectId, orderingDomainId, orderingKeySha256) =>
        this.#orderHeads.get(
          InMemoryReceiverInboxAdapter.#orderHeadKey(projectId, orderingDomainId, orderingKeySha256)
        ) ?? null,
      saveOrderHead: (projectId, orderingDomainId, orderingKeySha256, record) => {
        this.#orderHeads.set(
          InMemoryReceiverInboxAdapter.#orderHeadKey(projectId, orderingDomainId, orderingKeySha256),
          Object.freeze({ ...record })
        );
      },
      getOrderPositionAnchor: (projectId, orderingDomainId, orderingKeySha256, sequence) =>
        this.#orderPositions.get(
          InMemoryReceiverInboxAdapter.#orderPositionKey(
            projectId,
            orderingDomainId,
            orderingKeySha256,
            sequence
          )
        ) ?? null,
      saveOrderPositionAnchor: (projectId, orderingDomainId, orderingKeySha256, sequence, anchor) => {
        this.#orderPositions.set(
          InMemoryReceiverInboxAdapter.#orderPositionKey(
            projectId,
            orderingDomainId,
            orderingKeySha256,
            sequence
          ),
          Object.freeze({ ...anchor })
        );
      }
    };

    try {
      return await fn(tx);
    } catch (err) {
      this.#businessAnchors = businessSnapshot;
      this.#orderHeads = headSnapshot;
      this.#orderPositions = positionSnapshot;
      throw err;
    } finally {
      release();
    }
  }
}

export interface ReceiverDeliveryMutationContext {
  readonly verifiedDelivery: VerifyDeliverySuccess;
  readonly committedAt: CanonicalUtcTimestamp;
}

export interface ExecuteIdempotentDeliveryInput {
  readonly verifiedDelivery: VerifyDeliverySuccess;
  readonly inbox: ReceiverInboxAdapter;
  readonly onBusinessMutation: (ctx: ReceiverDeliveryMutationContext) => Promise<void> | void;
  readonly now?: Temporal.Instant | undefined;
  readonly receiptId?: string | undefined;
  readonly keyHandle?: SigningKeyHandle | undefined;
  readonly keyMetadata?: EndpointKeyMetadata | undefined;
  readonly keyProvider?: ReceiverKeyResolverInput | undefined;
}

export interface ExecuteIdempotentDeliveryResult {
  readonly outcome: IdempotentDeliveryOutcome;
  readonly mutatedBusinessState: boolean;
  readonly advancedOrderingHead: boolean;
  readonly committedAt: CanonicalUtcTimestamp;
  readonly nextExpectedSequence?: bigint | undefined;
  readonly receipt?: SignedDeliveryReceiptResponse | undefined;
}

export async function executeIdempotentDelivery(
  input: ExecuteIdempotentDeliveryInput
): Promise<ExecuteIdempotentDeliveryResult> {
  const { verifiedDelivery, inbox } = input;
  const { headers, decodedEnvelope } = verifiedDelivery;
  const projectId = headers.project_id;
  const consumerEventKey = headers.consumer_key;
  const eventId = headers.event_id;
  const originalFactsSha256 = decodedEnvelope.original_facts_sha256;
  const commitNow = formatUtcTimestamp(input.now ?? nowUtcInstant());

  const txResult = await inbox.runInTransaction(async (tx) => {
    const existingBusiness = await tx.getBusinessAnchor(projectId, consumerEventKey);
    if (
      existingBusiness !== null &&
      existingBusiness.originalFactsSha256 !== originalFactsSha256
    ) {
      throw new ReceiverConflictError({
        code: "IDEMPOTENCY_CONFLICT",
        message: `Delivery facts for consumer_event_key "${consumerEventKey}" conflict with prior commit`
      });
    }

    if (headers.ordering === undefined) {
      if (existingBusiness !== null) {
        return {
          outcome: "already_committed" as const,
          mutatedBusinessState: false,
          advancedOrderingHead: false,
          committedAt: existingBusiness.committedAt,
          nextExpectedSequence: undefined
        };
      }

      await input.onBusinessMutation({
        verifiedDelivery,
        committedAt: commitNow
      });
      await tx.saveBusinessAnchor({
        projectId,
        consumerEventKey,
        eventId,
        originalFactsSha256,
        committedAt: commitNow
      });

      return {
        outcome: "accepted" as const,
        mutatedBusinessState: true,
        advancedOrderingHead: false,
        committedAt: commitNow,
        nextExpectedSequence: undefined
      };
    }

    const { ordering_domain_id: orderingDomainId, ordering_key_sha256: orderingKeySha256 } =
      headers.ordering;
    const incomingSequence = parsePositiveInt64BigInt(
      headers.ordering.ordering_sequence,
      "ordering_sequence"
    );

    const currentHead: ReceiverOrderHeadRecord =
      (await tx.getOrderHead(projectId, orderingDomainId, orderingKeySha256)) ?? {
        headState: "active",
        nextExpectedSequence: 1n
      };

    const existingPos = await tx.getOrderPositionAnchor(
      projectId,
      orderingDomainId,
      orderingKeySha256,
      incomingSequence
    );

    const alreadyCommittedAtSequence = existingPos !== null;
    const incomingMatchesCommittedAnchor =
      existingPos !== null &&
      existingPos.consumerEventKey === consumerEventKey &&
      existingPos.originalFactsSha256 === originalFactsSha256;

    let orderEval;
    try {
      orderEval = evaluateReceiverOrderAcceptance({
        headState: currentHead.headState,
        nextExpectedSequence: currentHead.nextExpectedSequence,
        incomingSequence,
        alreadyCommittedAtSequence,
        incomingMatchesCommittedAnchor
      });
    } catch (err) {
      throw toReceiverSdkError(err);
    }

    if (orderEval.acceptanceKind === "duplicate_business_anchor") {
      const committedAt = existingBusiness?.committedAt ?? existingPos?.committedAt ?? commitNow;
      return {
        outcome: "already_committed" as const,
        mutatedBusinessState: false,
        advancedOrderingHead: false,
        committedAt,
        nextExpectedSequence: orderEval.nextExpectedSequence
      };
    }

    if (existingBusiness !== null) {
      // Ordered replay append advances sequence head without re-executing business side effects.
      await tx.saveOrderHead(projectId, orderingDomainId, orderingKeySha256, {
        headState: currentHead.headState,
        nextExpectedSequence: orderEval.nextExpectedSequence
      });
      await tx.saveOrderPositionAnchor(
        projectId,
        orderingDomainId,
        orderingKeySha256,
        incomingSequence,
        {
          consumerEventKey,
          originalFactsSha256,
          committedAt: existingBusiness.committedAt
        }
      );

      return {
        outcome: "replay_append" as const,
        mutatedBusinessState: false,
        advancedOrderingHead: true,
        committedAt: existingBusiness.committedAt,
        nextExpectedSequence: orderEval.nextExpectedSequence
      };
    }

    await input.onBusinessMutation({
      verifiedDelivery,
      committedAt: commitNow
    });
    await tx.saveBusinessAnchor({
      projectId,
      consumerEventKey,
      eventId,
      originalFactsSha256,
      committedAt: commitNow
    });
    await tx.saveOrderHead(projectId, orderingDomainId, orderingKeySha256, {
      headState: currentHead.headState,
      nextExpectedSequence: orderEval.nextExpectedSequence
    });
    await tx.saveOrderPositionAnchor(
      projectId,
      orderingDomainId,
      orderingKeySha256,
      incomingSequence,
      {
        consumerEventKey,
        originalFactsSha256,
        committedAt: commitNow
      }
    );

    return {
      outcome: "accepted" as const,
      mutatedBusinessState: true,
      advancedOrderingHead: true,
      committedAt: commitNow,
      nextExpectedSequence: orderEval.nextExpectedSequence
    };
  });

  let receipt: SignedDeliveryReceiptResponse | undefined;
  if (input.keyHandle !== undefined || input.keyProvider !== undefined) {
    receipt = await createSignedDeliveryReceipt({
      verifiedDelivery,
      committedAt: txResult.committedAt,
      receiptId: input.receiptId,
      keyHandle: input.keyHandle,
      keyMetadata: input.keyMetadata,
      keyProvider: input.keyProvider,
      now: input.now
    });
  }

  return Object.freeze({
    outcome: txResult.outcome,
    mutatedBusinessState: txResult.mutatedBusinessState,
    advancedOrderingHead: txResult.advancedOrderingHead,
    committedAt: txResult.committedAt,
    ...(txResult.nextExpectedSequence !== undefined
      ? { nextExpectedSequence: txResult.nextExpectedSequence }
      : {}),
    ...(receipt !== undefined ? { receipt } : {})
  });
}
