import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  PRODUCER_CREDENTIAL_PREFIX,
  ValidationDomainError,
  formatUtcTimestamp,
  nowUtcInstant,
  parseProducerCredentialId,
  parseSha256Hex,
  parseSigningDeliveryIntentId
} from "@relayquill/domain";
import {
  type PgAdapter,
  finalizeProducerCredentialIntent,
  finalizeSigningDeliveryIntent,
  readInstallationStatus
} from "@relayquill/postgres";
import { type SecretProvider } from "@relayquill/runtime";

export interface SigningDeliverOptions {
  readonly pgAdapter: PgAdapter;
  readonly secretProvider: SecretProvider;
  readonly intentId?: string | undefined;
  readonly kind?: "signing_key" | "producer_credential" | undefined;
  readonly now?: Temporal.Instant | undefined;
}

export interface DeliveredIntentSummary {
  readonly kind: "signing_key" | "producer_credential";
  readonly intentId: string;
  readonly state: string;
  readonly destinationRefs: readonly string[];
  readonly keyDigestSha256?: string | undefined;
  readonly credentialId?: string | undefined;
}

export interface SigningDeliverResult {
  readonly ok: true;
  readonly delivered: readonly DeliveredIntentSummary[];
}

export async function runSigningDeliver(
  options: SigningDeliverOptions
): Promise<SigningDeliverResult> {
  const kind = options.kind ?? "signing_key";
  const now = options.now ?? nowUtcInstant();
  const delivered: DeliveredIntentSummary[] = [];

  if (kind === "signing_key") {
    const intents = await options.pgAdapter.withTransaction(
      options.pgAdapter.configuredRole,
      async (tx) => {
        const inst = await readInstallationStatus(tx);
        const rows =
          options.intentId !== undefined
            ? await tx.query<Record<string, unknown>>(
                `SELECT sdi.id, sdi.control_epoch, sdi.sender_destination_reference,
                        sdi.receiver_destination_reference, sdi.expires_at,
                        skv.key_id, skv.key_version
                   FROM rq.signing_delivery_intents sdi
                   JOIN rq.signing_key_versions skv ON skv.id = sdi.key_version_id
                  WHERE sdi.id = $1::uuid AND sdi.state IN ('requested', 'approved')
                  FOR UPDATE`,
                [parseSigningDeliveryIntentId(options.intentId, "intent_id")]
              )
            : await tx.query<Record<string, unknown>>(
                `SELECT sdi.id, sdi.control_epoch, sdi.sender_destination_reference,
                        sdi.receiver_destination_reference, sdi.expires_at,
                        skv.key_id, skv.key_version
                   FROM rq.signing_delivery_intents sdi
                   JOIN rq.signing_key_versions skv ON skv.id = sdi.key_version_id
                  WHERE sdi.state IN ('requested', 'approved')
                    AND sdi.expires_at > pg_catalog.clock_timestamp()
                  ORDER BY sdi.created_at ASC
                  LIMIT 50
                  FOR UPDATE`
              );
        return { controlEpoch: inst.controlEpoch, rows: rows.rows };
      }
    );

    for (const row of intents.rows) {
      const intentId = parseSigningDeliveryIntentId(row["id"], "id");
      const senderRef = String(row["sender_destination_reference"]);
      const receiverRef = String(row["receiver_destination_reference"]);
      const keyVersion = String(row["key_version"]);
      const rawKey = crypto.randomBytes(32);

      try {
        const keyDigest = parseSha256Hex(
          crypto.createHash("sha256").update(rawKey).digest("hex"),
          "keyDigestSha256"
        );
        const rawExpiresAt = row["expires_at"];
        const expiresAt =
          typeof rawExpiresAt === "string"
            ? rawExpiresAt
            : rawExpiresAt instanceof Date
              ? rawExpiresAt.toISOString()
              : undefined;

        if (!options.secretProvider.putSecret) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "Configured SecretProvider does not support putSecret"
          });
        }
        await options.secretProvider.putSecret(senderRef, rawKey, {
          version: keyVersion,
          ...(expiresAt !== undefined ? { expiresAt } : {})
        });
        await options.secretProvider.putSecret(receiverRef, rawKey, {
          version: keyVersion,
          ...(expiresAt !== undefined ? { expiresAt } : {})
        });

        const finalized = await options.pgAdapter.withTransaction(
          "rq_signing_issuer",
          async (tx) =>
            finalizeSigningDeliveryIntent(tx, {
              intentId,
              controlEpoch: intents.controlEpoch,
              nextState: "delivered"
            })
        );

        delivered.push({
          kind: "signing_key",
          intentId: finalized.intentId,
          state: finalized.state,
          destinationRefs: [senderRef, receiverRef],
          keyDigestSha256: keyDigest
        });
      } finally {
        rawKey.fill(0);
      }
    }

    return { ok: true, delivered };
  }

  if (kind !== "producer_credential") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported signing deliver kind "${String(kind)}"`
    });
  }

  const credIntents = await options.pgAdapter.withTransaction(
    options.pgAdapter.configuredRole,
    async (tx) => {
      const inst = await readInstallationStatus(tx);
      const rows =
        options.intentId !== undefined
          ? await tx.query<Record<string, unknown>>(
              `SELECT id, custody_destination_reference, requested_expiry, scope_version
                 FROM rq.producer_credential_intents
                WHERE id = $1::uuid AND state IN ('requested', 'approved')
                FOR UPDATE`,
              [options.intentId]
            )
          : await tx.query<Record<string, unknown>>(
              `SELECT id, custody_destination_reference, requested_expiry, scope_version
                 FROM rq.producer_credential_intents
                WHERE state IN ('requested', 'approved')
                  AND expires_at > pg_catalog.clock_timestamp()
                ORDER BY created_at ASC
                LIMIT 50
                FOR UPDATE`
            );
      return { controlEpoch: inst.controlEpoch, rows: rows.rows };
    }
  );

  for (const row of credIntents.rows) {
    const intentId = String(row["id"]);
    const destRef = String(row["custody_destination_reference"]);
    const credentialId = parseProducerCredentialId(crypto.randomUUID(), "credential_id");
    const secretBytes = crypto.randomBytes(32);
    const tokenString = `${PRODUCER_CREDENTIAL_PREFIX}${credentialId}.${secretBytes.toString("base64url")}`;
    const secretDigestSha256 = crypto
      .createHash("sha256")
      .update(secretBytes)
      .digest("hex");

    try {
      const requestedExpiry =
        typeof row["requested_expiry"] === "string"
          ? row["requested_expiry"]
          : formatUtcTimestamp(now.add({ hours: 24 * 7 }));

      if (!options.secretProvider.putSecret) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "Configured SecretProvider does not support putSecret"
        });
      }
      await options.secretProvider.putSecret(destRef, tokenString, {
        version: String(row["scope_version"]),
        expiresAt: requestedExpiry
      });

      const finalized = await options.pgAdapter.withTransaction(
        "rq_signing_issuer",
        async (tx) =>
          finalizeProducerCredentialIntent(tx, {
            intentId,
            controlEpoch: credIntents.controlEpoch,
            nextState: "delivered",
            credentialId,
            secretDigestSha256: parseSha256Hex(secretDigestSha256, "secretDigestSha256"),
            expiresAt: requestedExpiry
          })
      );

      delivered.push({
        kind: "producer_credential",
        intentId: finalized.intentId,
        state: finalized.state,
        destinationRefs: [destRef],
        credentialId: finalized.credentialId
      });
    } finally {
      secretBytes.fill(0);
    }
  }

  return { ok: true, delivered };
}
