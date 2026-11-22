import { type FastifyInstance } from "fastify";
import { type ApiContext } from "../context.js";
import { registerEndpointAndSigningRoutes } from "./endpoints-and-signing.js";
import { registerProducerAndGovernanceRoutes } from "./producers-and-governance.js";
import { registerReplayAndOrderingRoutes } from "./replays-and-ordering.js";
import { registerSchemaAndSubscriptionRoutes } from "./schemas-and-subscriptions.js";

export function registerGovernanceAndStreamsRoutes(app: FastifyInstance, ctx: ApiContext): void {
  registerEndpointAndSigningRoutes(app, ctx);
  registerSchemaAndSubscriptionRoutes(app, ctx);
  registerReplayAndOrderingRoutes(app, ctx);
  registerProducerAndGovernanceRoutes(app, ctx);
}
