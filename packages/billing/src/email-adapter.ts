import crypto from "node:crypto";
import net from "node:net";
import {
  DependencyUnavailableDomainError,
  type EmailOutboxTemplateCode,
  ValidationDomainError
} from "@relayquill/domain";
import { type PgTransactionClient } from "@relayquill/postgres";

export interface TransactionalEmailMessage {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
  readonly html: string;
  readonly idempotencyKey: string;
  readonly templateCode: EmailOutboxTemplateCode;
}

export interface TransactionalEmailReceipt {
  readonly provider: "resend" | "postmark" | "ses" | "mailpit" | "memory";
  readonly messageId: string;
  readonly acceptedAt: string;
}

export interface TransactionalEmailAdapter {
  readonly provider: TransactionalEmailReceipt["provider"];
  send(message: TransactionalEmailMessage): Promise<TransactionalEmailReceipt>;
}

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtVar(val: unknown, fallback = ""): string {
  if (typeof val === "string") {
    return val;
  }
  if (typeof val === "number" || typeof val === "boolean") {
    return String(val);
  }
  return fallback;
}

function renderTemplateCopy(
  templateCode: EmailOutboxTemplateCode,
  vars: Readonly<Record<string, unknown>>
): { readonly subject: string; readonly headline: string; readonly summary: string } {
  const period = typeof vars["period_month"] === "string" ? vars["period_month"] : "current billing cycle";
  switch (templateCode) {
    case "verify_email":
      return {
        subject: "Confirm your Relayquill workspace",
        headline: "Welcome to Relayquill",
        summary: `Verify ownership for ${fmtVar(vars["org_name"], "your organization")} to enable team invitations and webhook notifications.`
      };
    case "quota_alert_70":
      return {
        subject: "Relayquill usage reached 70% of monthly allowance",
        headline: "70% Quota Advisory",
        summary: `You have consumed ${fmtVar(vars["used_units"])} of ${fmtVar(vars["included_units"])} units during ${period}.`
      };
    case "quota_alert_85":
      return {
        subject: "Relayquill usage reached 85% of monthly allowance",
        headline: "85% Quota Advisory",
        summary: `You have reached 85% of your included monthly quota (${period}). Review your plan limits in Billing Settings.`
      };
    case "quota_alert_95":
      return {
        subject: "Action recommended: 95% of monthly Relayquill quota used",
        headline: "95% Quota Warning",
        summary: `Your organization has reached 95% of its monthly quota (${period}). Hard-cap plans pause new admissions at 100%.`
      };
    case "quota_spike_3x":
      return {
        subject: "Relayquill traffic spike detected (>3x hourly baseline)",
        headline: "3x Delivery Traffic Spike Detected",
        summary: `Observed ${fmtVar(vars["hourly_units"])} delivery units in hour ${fmtVar(vars["hour_bucket"])}.`
      };
    case "dunning_notice_1":
    case "dunning_notice_3":
    case "dunning_notice_5":
    case "dunning_notice_7": {
      const stage = templateCode.split("_").pop() ?? "1";
      return {
        subject: `Payment retry needed (notice ${stage} of 7-day grace period)`,
        headline: "Billing Payment Attention Required",
        summary:
          "Your latest renewal invoice could not be collected. Deliveries remain protected during your 7-day grace period."
      };
    }
    case "break_glass_notice":
      return {
        subject: "Security notice: 15-minute read-only support access started",
        headline: "Temporary Read-Only Support Access Logged",
        summary:
          "A time-boxed 15-minute read-only support inspection session was opened and recorded in your immutable audit log."
      };
    case "gdpr_erasure_receipt":
      return {
        subject: "Relayquill GDPR erasure completion receipt",
        headline: "Organization Data Erasure Completed",
        summary:
          "PII across PostgreSQL, ephemeral cache, and payload objects has been purged and tax records anonymized."
      };
  }
}

/**
 * Renders HTML and plain-text copies cleanly with HTML-entity escaping across all variables.
 */
export function renderTransactionalTemplate(
  templateCode: EmailOutboxTemplateCode,
  vars: Readonly<Record<string, unknown>>
): { readonly subject: string; readonly text: string; readonly html: string } {
  const copy = renderTemplateCopy(templateCode, vars);
  const detailsText = JSON.stringify(vars, null, 2);
  const text = `${copy.headline}\n\n${copy.summary}\n\nDetails:\n${detailsText}\n`;
  const html = [
    "<!doctype html>",
    "<html><body style=\"font-family:Inter,Arial,sans-serif;color:#111827;padding:24px\">",
    `<h2 style="margin:0 0 12px 0">${escapeHtml(copy.headline)}</h2>`,
    `<p style="margin:0 0 16px 0;line-height:1.5">${escapeHtml(copy.summary)}</p>`,
    `<pre style="background:#f3f4f6;padding:12px;border-radius:6px;font-size:12px">${escapeHtml(detailsText)}</pre>`,
    "</body></html>"
  ].join("");
  return { subject: copy.subject, text, html };
}

/**
 * Sends transactional email via Resend REST API with `Idempotency-Key` support.
 */
export function createResendEmailAdapter(options: {
  readonly apiKey: string;
  readonly fromEmail: string;
  readonly apiBaseUrl?: string | undefined;
  readonly fetchImpl?: typeof fetch | undefined;
}): TransactionalEmailAdapter {
  const apiKey = options.apiKey.trim();
  if (apiKey.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Resend apiKey must be non-empty"
    });
  }
  const baseUrl = (options.apiBaseUrl ?? "https://api.resend.com").replace(/\/+$/, "");
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  const adapter: TransactionalEmailAdapter = {
    provider: "resend",
    async send(msg) {
      const res = await fetchImpl(`${baseUrl}/emails`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "idempotency-key": msg.idempotencyKey
        },
        body: JSON.stringify({
          from: options.fromEmail,
          to: [msg.to],
          subject: msg.subject,
          text: msg.text,
          html: msg.html,
          headers: { "X-Entity-Ref-ID": msg.idempotencyKey }
        })
      });
      const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      if (!res.ok || typeof json["id"] !== "string") {
        throw new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: `Resend email dispatch failed (${res.status})`
        });
      }
      return {
        provider: "resend",
        messageId: json["id"],
        acceptedAt: new Date().toISOString()
      };
    }
  };
  return Object.freeze(adapter);
}

/**
 * Sends transactional email via Postmark REST API.
 */
export function createPostmarkEmailAdapter(options: {
  readonly serverToken: string;
  readonly fromEmail: string;
  readonly apiBaseUrl?: string | undefined;
  readonly fetchImpl?: typeof fetch | undefined;
}): TransactionalEmailAdapter {
  const token = options.serverToken.trim();
  if (token.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Postmark serverToken must be non-empty"
    });
  }
  const baseUrl = (options.apiBaseUrl ?? "https://api.postmarkapp.com").replace(/\/+$/, "");
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  const adapter: TransactionalEmailAdapter = {
    provider: "postmark",
    async send(msg) {
      const res = await fetchImpl(`${baseUrl}/email`, {
        method: "POST",
        headers: {
          "x-postmark-server-token": token,
          accept: "application/json",
          "content-type": "application/json"
        },
        body: JSON.stringify({
          From: options.fromEmail,
          To: msg.to,
          Subject: msg.subject,
          TextBody: msg.text,
          HtmlBody: msg.html,
          MessageStream: "outbound"
        })
      });
      const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      const msgId = typeof json["MessageID"] === "string" ? json["MessageID"] : undefined;
      if (!res.ok || msgId === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: `Postmark email dispatch failed (${res.status})`
        });
      }
      return {
        provider: "postmark",
        messageId: msgId,
        acceptedAt: new Date().toISOString()
      };
    }
  };
  return Object.freeze(adapter);
}

function hmacSha256(key: string | Buffer, data: string): Buffer {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest();
}

/**
 * Sends transactional email via AWS SES v2 HTTP API signed with zero-dependency SigV4.
 */
export function createAwsSesEmailAdapter(options: {
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  readonly region: string;
  readonly fromEmail: string;
  readonly fetchImpl?: typeof fetch | undefined;
}): TransactionalEmailAdapter {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const host = `email.${options.region}.amazonaws.com`;
  const pathName = "/v2/email/outbound-emails";

  const adapter: TransactionalEmailAdapter = {
    provider: "ses",
    async send(msg) {
      const now = new Date();
      const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
      const dateStamp = amzDate.slice(0, 8);
      const bodyStr = JSON.stringify({
        FromEmailAddress: options.fromEmail,
        Destination: { ToAddresses: [msg.to] },
        Content: {
          Simple: {
            Subject: { Data: msg.subject, Charset: "UTF-8" },
            Body: {
              Text: { Data: msg.text, Charset: "UTF-8" },
              Html: { Data: msg.html, Charset: "UTF-8" }
            }
          }
        }
      });
      const payloadHash = crypto.createHash("sha256").update(bodyStr, "utf8").digest("hex");
      const canonicalHeaders = `content-type:application/json\nhost:${host}\nx-amz-date:${amzDate}\n`;
      const signedHeaders = "content-type;host;x-amz-date";
      const canonicalRequest = [
        "POST",
        pathName,
        "",
        canonicalHeaders,
        signedHeaders,
        payloadHash
      ].join("\n");
      const scope = `${dateStamp}/${options.region}/ses/aws4_request`;
      const stringToSign = [
        "AWS4-HMAC-SHA256",
        amzDate,
        scope,
        crypto.createHash("sha256").update(canonicalRequest, "utf8").digest("hex")
      ].join("\n");

      const kDate = hmacSha256(`AWS4${options.secretAccessKey}`, dateStamp);
      const kRegion = hmacSha256(kDate, options.region);
      const kService = hmacSha256(kRegion, "ses");
      const kSigning = hmacSha256(kService, "aws4_request");
      const signature = crypto.createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");

      const res = await fetchImpl(`https://${host}${pathName}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-amz-date": amzDate,
          authorization: `AWS4-HMAC-SHA256 Credential=${options.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`
        },
        body: bodyStr
      });
      const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      const msgId = typeof json["MessageId"] === "string" ? json["MessageId"] : undefined;
      if (!res.ok || msgId === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: `AWS SES dispatch failed (${res.status})`
        });
      }
      return {
        provider: "ses",
        messageId: msgId,
        acceptedAt: now.toISOString()
      };
    }
  };
  return Object.freeze(adapter);
}

/**
 * Minimal SMTP client over `node:net` targeting local Mailpit (`127.0.0.1:5025`) with zero third-party deps.
 */
export function createMailpitSmtpEmailAdapter(options: {
  readonly host?: string | undefined;
  readonly port?: number | undefined;
  readonly fromEmail: string;
}): TransactionalEmailAdapter {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 5025;

  const adapter: TransactionalEmailAdapter = {
    provider: "mailpit",
    async send(msg) {
      const msgId = `<${crypto.randomUUID()}@relayquill.local>`;
      await new Promise<void>((resolve, reject) => {
        const sock = net.createConnection({ host, port });
        let step = 0;
        let buf = "";
        const sendLine = (line: string): void => {
          sock.write(`${line}\r\n`);
        };
        sock.setTimeout(3000, () => {
          sock.destroy();
          reject(new Error("Mailpit SMTP timeout"));
        });
        sock.once("error", reject);
        sock.on("data", (chunk: Buffer) => {
          buf += chunk.toString("utf8");
          if (!buf.endsWith("\r\n")) {
            return;
          }
          const lastLine = buf.trim().split("\n").pop() ?? "";
          if (!/^\d{3} /.test(lastLine)) {
            return;
          }
          const code = Number.parseInt(lastLine.slice(0, 3), 10);
          buf = "";
          if (code >= 400) {
            sock.destroy();
            reject(new Error(`SMTP error ${code}: ${lastLine}`));
            return;
          }
          if (step === 0) {
            step = 1;
            sendLine("EHLO relayquill.local");
          } else if (step === 1) {
            step = 2;
            sendLine(`MAIL FROM:<${options.fromEmail}>`);
          } else if (step === 2) {
            step = 3;
            sendLine(`RCPT TO:<${msg.to}>`);
          } else if (step === 3) {
            step = 4;
            sendLine("DATA");
          } else if (step === 4) {
            step = 5;
            const safeBody = [
              `From: ${options.fromEmail}`,
              `To: ${msg.to}`,
              `Subject: ${msg.subject}`,
              `Message-ID: ${msgId}`,
              "MIME-Version: 1.0",
              "Content-Type: text/plain; charset=utf-8",
              "",
              msg.text.replace(/\r?\n\./g, "\r\n.."),
              "."
            ].join("\r\n");
            sendLine(safeBody);
          } else if (step === 5) {
            step = 6;
            sendLine("QUIT");
          } else {
            sock.end();
            resolve();
          }
        });
      });
      return {
        provider: "mailpit",
        messageId: msgId,
        acceptedAt: new Date().toISOString()
      };
    }
  };
  return Object.freeze(adapter);
}

export interface InMemoryEmailRecord extends TransactionalEmailMessage {
  readonly messageId: string;
  readonly acceptedAt: string;
}

/**
 * In-memory email sink for offline unit/API tests and zero-config local runs.
 */
export function createInMemoryEmailAdapter(): TransactionalEmailAdapter & {
  readonly sent: InMemoryEmailRecord[];
} {
  const sent: InMemoryEmailRecord[] = [];
  return {
    provider: "memory",
    sent,
    async send(message) {
      const acceptedAt = new Date().toISOString();
      const messageId = `mem_${crypto.randomUUID()}`;
      sent.push({ ...message, messageId, acceptedAt });
      return Promise.resolve({
        provider: "memory",
        messageId,
        acceptedAt
      });
    }
  };
}

/**
 * Resolves the active email delivery backend strictly from environment configuration.
 */
export function selectTransactionalEmailAdapterFromEnv(
  env: Readonly<Record<string, string | undefined>> = process.env
): TransactionalEmailAdapter {
  const fromEmail = env["EMAIL_FROM"]?.trim() || "no-reply@relayquill.local";
  const forced = env["EMAIL_PROVIDER"]?.trim().toLowerCase();

  if (forced === "resend" || (!forced && (env["RESEND_API_KEY"]?.trim() ?? "").length > 0)) {
    return createResendEmailAdapter({
      apiKey: env["RESEND_API_KEY"]?.trim() ?? "",
      fromEmail
    });
  }
  if (
    forced === "postmark" ||
    (!forced && (env["POSTMARK_SERVER_TOKEN"]?.trim() ?? "").length > 0)
  ) {
    return createPostmarkEmailAdapter({
      serverToken: env["POSTMARK_SERVER_TOKEN"]?.trim() ?? "",
      fromEmail
    });
  }
  if (
    forced === "ses" ||
    (!forced &&
      (env["AWS_ACCESS_KEY_ID"]?.trim() ?? "").length > 0 &&
      (env["AWS_SECRET_ACCESS_KEY"]?.trim() ?? "").length > 0)
  ) {
    return createAwsSesEmailAdapter({
      accessKeyId: env["AWS_ACCESS_KEY_ID"]?.trim() ?? "",
      secretAccessKey: env["AWS_SECRET_ACCESS_KEY"]?.trim() ?? "",
      region: env["AWS_REGION"]?.trim() || "us-east-1",
      fromEmail
    });
  }
  if (forced === "mailpit" || (!forced && (env["SMTP_HOST"]?.trim() ?? "").length > 0)) {
    return createMailpitSmtpEmailAdapter({
      host: env["SMTP_HOST"]?.trim() || "127.0.0.1",
      port: Number(env["SMTP_PORT"] || "5025"),
      fromEmail
    });
  }
  return createInMemoryEmailAdapter();
}

export interface EmailOutboxDrainSummary {
  readonly scanned: number;
  readonly dispatched: number;
  readonly failedPermanent: number;
  readonly retried: number;
}

/**
 * Drains a bounded batch of pending `rq.email_outbox` records cleanly with retry / permanent-failure tracking.
 */
export async function drainPendingEmailOutboxBatch(
  tx: PgTransactionClient,
  adapter: TransactionalEmailAdapter,
  options: { readonly limit?: number | undefined; readonly maxAttempts?: number | undefined } = {}
): Promise<EmailOutboxDrainSummary> {
  const limit = Math.max(1, Math.min(100, options.limit ?? 25));
  const maxAttempts = Math.max(1, options.maxAttempts ?? 5);

  const rowsRes = await tx.query<{
    id: string;
    idempotency_key: string;
    template_code: EmailOutboxTemplateCode;
    recipient_email: string;
    template_vars: Record<string, unknown>;
    attempt_count: number;
  }>(
    `SELECT id, idempotency_key, template_code, recipient_email, template_vars, attempt_count
       FROM rq.email_outbox
      WHERE state = 'pending'
      ORDER BY created_at ASC
      LIMIT $1::int
      FOR UPDATE SKIP LOCKED`,
    [limit]
  );

  let dispatched = 0;
  let failedPermanent = 0;
  let retried = 0;

  for (const row of rowsRes.rows) {
    const rendered = renderTransactionalTemplate(row.template_code, row.template_vars ?? {});
    try {
      const receipt = await adapter.send({
        to: row.recipient_email,
        subject: rendered.subject,
        text: rendered.text,
        html: rendered.html,
        idempotencyKey: row.idempotency_key,
        templateCode: row.template_code
      });
      await tx.query(
        `UPDATE rq.email_outbox
            SET state = 'dispatched',
                provider_msg_id = $2::text,
                attempt_count = attempt_count + 1,
                dispatched_at = pg_catalog.clock_timestamp()
          WHERE id = $1::uuid`,
        [row.id, receipt.messageId]
      );
      dispatched += 1;
    } catch {
      const nextAttempts = Number(row.attempt_count ?? 0) + 1;
      const nextState = nextAttempts >= maxAttempts ? "failed_permanent" : "pending";
      await tx.query(
        `UPDATE rq.email_outbox
            SET state = $2::text,
                attempt_count = $3::int
          WHERE id = $1::uuid`,
        [row.id, nextState, nextAttempts]
      );
      if (nextState === "failed_permanent") {
        failedPermanent += 1;
      } else {
        retried += 1;
      }
    }
  }

  return {
    scanned: rowsRes.rows.length,
    dispatched,
    failedPermanent,
    retried
  };
}
