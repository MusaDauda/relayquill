import {
  ValidationDomainError,
  parseEventId,
  parseProjectId,
  parseTenantId
} from "@relayquill/domain";
import {
  type PgAdapter,
  readEventCausalChain,
  readInstallationStatus,
  readProjectQueueHealth
} from "@relayquill/postgres";
import { sendIpcFrame } from "@relayquill/runtime";
import { type OperatorChannelClient } from "./access.js";

export type DiagnosticsSubcommand = "summary" | "project" | "event";

export interface RunDiagnosticsCommandOptions {
  readonly subcommand: DiagnosticsSubcommand;
  readonly pgAdapter?: PgAdapter | undefined;
  readonly operatorEndpoint?: string | undefined;
  readonly operatorClient?: OperatorChannelClient | undefined;
  readonly tenantId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly eventId?: string | undefined;
  readonly limit?: number | undefined;
}

export async function runDiagnosticsCommand(
  options: RunDiagnosticsCommandOptions
): Promise<Record<string, unknown>> {
  const maxRows = Math.min(200, Math.max(1, options.limit ?? 50));

  if (options.operatorClient !== undefined || options.operatorEndpoint !== undefined) {
    const req = {
      op: "diagnostics.inspect",
      subcommand: options.subcommand,
      ...(options.tenantId !== undefined ? { tenant_id: options.tenantId } : {}),
      ...(options.projectId !== undefined ? { project_id: options.projectId } : {}),
      ...(options.eventId !== undefined ? { event_id: options.eventId } : {}),
      limit: maxRows
    };
    const reply =
      options.operatorClient !== undefined
        ? await options.operatorClient.send<Record<string, unknown>>(req)
        : await sendIpcFrame<Record<string, unknown>>(options.operatorEndpoint!, req, {
            verifySecurity: true
          });
    return reply;
  }

  if (options.pgAdapter === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "diagnostics command requires either database configuration or operator_channel IPC"
    });
  }

  return options.pgAdapter.withTransaction(
    options.pgAdapter.configuredRole,
    async (tx) => {
      const installation = await readInstallationStatus(tx);

      if (options.subcommand === "summary") {
        const tenantCount = await tx.query<{ cnt: number }>(
          "SELECT count(*)::integer AS cnt FROM rq.tenants"
        );
        const projectCount = await tx.query<{ cnt: number }>(
          "SELECT count(*)::integer AS cnt FROM rq.projects"
        );
        return {
          ok: true,
          subcommand: "summary",
          redactedPayloads: true,
          installation,
          tenantCount: tenantCount.rows[0]?.cnt ?? 0,
          projectCount: projectCount.rows[0]?.cnt ?? 0
        };
      }

      const tenantId = parseTenantId(options.tenantId, "tenant_id");
      const projectId = parseProjectId(options.projectId, "project_id");

      if (options.subcommand === "project") {
        const queueHealth = await readProjectQueueHealth(tx, tenantId, projectId);
        return {
          ok: true,
          subcommand: "project",
          redactedPayloads: true,
          installation,
          tenantId,
          projectId,
          queueHealth: {
            pendingOutboxCount: queueHealth.pendingOutboxCount.toString(10),
            activeFanoutCount: queueHealth.activeFanoutCount.toString(10),
            readyDeliveryCount: queueHealth.readyDeliveryCount.toString(10),
            sendingDeliveryCount: queueHealth.sendingDeliveryCount.toString(10),
            retryWaitDeliveryCount: queueHealth.retryWaitDeliveryCount.toString(10),
            openHoldCount: queueHealth.openHoldCount.toString(10)
          }
        };
      }

      const eventId = parseEventId(options.eventId, "event_id");
      const chain = await readEventCausalChain(tx, tenantId, projectId, eventId, maxRows);
      const attemptsByDelivery: Record<string, unknown> = {};
      for (const [delId, attempts] of chain.attemptsByDeliveryId.entries()) {
        attemptsByDelivery[delId] = attempts.map((a) => ({
          attemptId: a.attemptId,
          attemptNumber: a.attemptNumber,
          state: a.state,
          responseStatus: a.responseStatus ?? null,
          outcomeClass: a.outcomeClass ?? null
        }));
      }

      return {
        ok: true,
        subcommand: "event",
        redactedPayloads: true,
        event: chain.event ?? null,
        fanout: chain.fanout ?? null,
        historyCount: chain.history.length,
        deliveriesCount: chain.deliveries.length,
        attemptsByDelivery
      };
    },
    { readOnly: true }
  );
}
