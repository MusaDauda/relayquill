import {
  type BillingCancelResponseDto,
  type BillingCheckoutResponseDto,
  type BillingPortalResponseDto,
  type BillingSubscriptionViewDto,
  type BillingUsageViewDto,
  type BreakGlassCreateResponseDto,
  type BreakGlassRevokeResponseDto,
  type CommercialBillingIntervalDto,
  type CommercialBillingProviderDto,
  type CommercialLoginResponseDto,
  type CommercialPlanTierDto,
  type CommercialSignupResponseDto,
  type CustomerSettingsAuditDto,
  type GdprErasureRequestDto,
  type LegalAcceptResponseDto,
  type PublicStatusDto,
  type TotpEnrollResponseDto,
  type TotpVerifyResponseDto,
  parsePlainObjectDto
} from "./dtos.js";
import { type HttpApiResult } from "./http-client.js";

export interface ConsoleHttpTransport {
  request<T>(options: {
    readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
    readonly path: string;
    readonly bodyObj?: unknown;
    readonly idempotencyKey?: string | undefined;
    readonly parseData: (raw: unknown) => T;
    readonly signal?: AbortSignal | undefined;
  }): Promise<HttpApiResult<T>>;
}

function buildOptionalQuery(
  entries: readonly (readonly [string, string | undefined])[]
): string {
  const params = new URLSearchParams();
  for (const [k, v] of entries) {
    if (v !== undefined && v.trim().length > 0) {
      params.set(k, v.trim());
    }
  }
  const encoded = params.toString();
  return encoded.length > 0 ? `?${encoded}` : "";
}

/** Commercial SaaS, regional billing, legal, status, break-glass, and GDPR API methods. */
export function createCommercialConsoleApiMethods(http: ConsoleHttpTransport) {
  return {
    getPublicStatus(signal?: AbortSignal): Promise<HttpApiResult<PublicStatusDto>> {
      return http.request({
        method: "GET",
        path: "/api/v1/status",
        parseData: (raw) => parsePlainObjectDto<PublicStatusDto>(raw),
        signal
      });
    },
    commercialSignup(
      body: {
        readonly email: string;
        readonly password: string;
        readonly org_name: string;
        readonly accept_legal: true;
        readonly tos_version: string;
        readonly dpa_version: string;
      },
      idempotencyKey: string
    ): Promise<HttpApiResult<CommercialSignupResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/auth/signup",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<CommercialSignupResponseDto>(raw)
      });
    },
    commercialLogin(
      body: {
        readonly email: string;
        readonly password: string;
        readonly totp_code?: string | undefined;
      },
      idempotencyKey: string
    ): Promise<HttpApiResult<CommercialLoginResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/auth/login",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<CommercialLoginResponseDto>(raw)
      });
    },
    enrollTotp(idempotencyKey: string): Promise<HttpApiResult<TotpEnrollResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/auth/mfa/totp/enroll",
        bodyObj: { schema_version: 1 },
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<TotpEnrollResponseDto>(raw)
      });
    },
    verifyTotp(
      body: { readonly totp_code: string },
      idempotencyKey: string
    ): Promise<HttpApiResult<TotpVerifyResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/auth/mfa/totp/verify",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<TotpVerifyResponseDto>(raw)
      });
    },
    acceptLegal(
      body: {
        readonly document_kind: "tos" | "privacy" | "dpa";
        readonly doc_version: string;
        readonly tenant_id?: string | undefined;
      },
      idempotencyKey: string
    ): Promise<HttpApiResult<LegalAcceptResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/legal/accept",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<LegalAcceptResponseDto>(raw)
      });
    },
    getBillingSubscription(
      query: {
        readonly tenant_id?: string | undefined;
        readonly country?: string | undefined;
        readonly currency?: string | undefined;
      } = {},
      signal?: AbortSignal
    ): Promise<HttpApiResult<BillingSubscriptionViewDto>> {
      return http.request({
        method: "GET",
        path: `/api/v1/billing/subscription${buildOptionalQuery([
          ["tenant_id", query.tenant_id],
          ["country", query.country],
          ["currency", query.currency]
        ])}`,
        parseData: (raw) => parsePlainObjectDto<BillingSubscriptionViewDto>(raw),
        signal
      });
    },
    getBillingUsage(
      query: {
        readonly tenant_id?: string | undefined;
        readonly period_month?: string | undefined;
      } = {},
      signal?: AbortSignal
    ): Promise<HttpApiResult<BillingUsageViewDto>> {
      return http.request({
        method: "GET",
        path: `/api/v1/billing/usage${buildOptionalQuery([
          ["tenant_id", query.tenant_id],
          ["period_month", query.period_month]
        ])}`,
        parseData: (raw) => parsePlainObjectDto<BillingUsageViewDto>(raw),
        signal
      });
    },
    createBillingCheckout(
      body: {
        readonly plan_tier: Exclude<CommercialPlanTierDto, "free">;
        readonly billing_interval: CommercialBillingIntervalDto;
        readonly seat_count?: number | undefined;
        readonly country_code?: string | undefined;
        readonly currency?: string | undefined;
        readonly provider?: CommercialBillingProviderDto | undefined;
        readonly tenant_id?: string | undefined;
        readonly success_url?: string | undefined;
        readonly cancel_url?: string | undefined;
        readonly trial_days?: number | undefined;
      },
      idempotencyKey: string
    ): Promise<HttpApiResult<BillingCheckoutResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/billing/checkout",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<BillingCheckoutResponseDto>(raw)
      });
    },
    createBillingPortal(
      body: {
        readonly return_url?: string | undefined;
        readonly tenant_id?: string | undefined;
      },
      idempotencyKey: string
    ): Promise<HttpApiResult<BillingPortalResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/billing/portal",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<BillingPortalResponseDto>(raw)
      });
    },
    cancelBillingSubscription(
      body: { readonly tenant_id?: string | undefined },
      idempotencyKey: string
    ): Promise<HttpApiResult<BillingCancelResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/billing/cancel",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<BillingCancelResponseDto>(raw)
      });
    },
    getSettingsAudit(
      query: { readonly tenant_id?: string | undefined } = {},
      signal?: AbortSignal
    ): Promise<HttpApiResult<CustomerSettingsAuditDto>> {
      return http.request({
        method: "GET",
        path: `/api/v1/settings/audit${buildOptionalQuery([["tenant_id", query.tenant_id]])}`,
        parseData: (raw) => parsePlainObjectDto<CustomerSettingsAuditDto>(raw),
        signal
      });
    },
    createBreakGlassSession(
      body: {
        readonly target_tenant_id: string;
        readonly reason: string;
        readonly ttl_minutes?: number | undefined;
        readonly mfa_verified: true;
      },
      idempotencyKey: string
    ): Promise<HttpApiResult<BreakGlassCreateResponseDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/ops/break-glass",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<BreakGlassCreateResponseDto>(raw)
      });
    },
    revokeBreakGlassSession(
      breakGlassId: string,
      idempotencyKey: string
    ): Promise<HttpApiResult<BreakGlassRevokeResponseDto>> {
      return http.request({
        method: "POST",
        path: `/api/v1/ops/break-glass/${encodeURIComponent(breakGlassId)}/revoke`,
        bodyObj: { schema_version: 1 },
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<BreakGlassRevokeResponseDto>(raw)
      });
    },
    requestGdprErasure(
      body: {
        readonly confirm_phrase: "DELETE ORGANIZATION";
        readonly password?: string | undefined;
        readonly totp_code?: string | undefined;
      },
      idempotencyKey: string
    ): Promise<HttpApiResult<GdprErasureRequestDto>> {
      return http.request({
        method: "POST",
        path: "/api/v1/orgs/me/erasure-request",
        bodyObj: body,
        idempotencyKey,
        parseData: (raw) => parsePlainObjectDto<GdprErasureRequestDto>(raw)
      });
    },
    getGdprErasureStatus(
      requestId: string,
      signal?: AbortSignal
    ): Promise<HttpApiResult<GdprErasureRequestDto>> {
      return http.request({
        method: "GET",
        path: `/api/v1/orgs/me/erasure-request/${encodeURIComponent(requestId)}`,
        parseData: (raw) => parsePlainObjectDto<GdprErasureRequestDto>(raw),
        signal
      });
    }
  };
}
