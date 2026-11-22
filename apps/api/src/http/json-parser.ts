import { ValidationDomainError } from "@relayquill/domain";
import { parseStrictJsonObject } from "@relayquill/contracts";

export const DEFAULT_API_BODY_LIMIT_BYTES = 131_072 as const; // 128 KiB
export const EVENT_ADMISSION_BODY_LIMIT_BYTES = 524_288 as const; // 512 KiB

/**
 * Decodes raw HTTP body bytes as strict UTF-8 and parses an outer JSON object while
 * rejecting duplicate JSON keys, lone surrogates, and non-object roots.
 */
export function parseStrictHttpJsonBuffer(
  rawBody: Buffer,
  options: { readonly allowEmpty?: boolean | undefined } = {}
): Record<string, unknown> {
  if (rawBody.byteLength === 0) {
    if (options.allowEmpty === true) {
      return {};
    }
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Request body must be a non-empty JSON object",
      fieldErrors: [{ path: "body", code: "INVALID_VALUE" }]
    });
  }

  let text: string;
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    text = decoder.decode(rawBody);
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Request body is not valid UTF-8",
      fieldErrors: [{ path: "body", code: "INVALID_VALUE" }]
    });
  }

  return parseStrictJsonObject(text, { fieldPath: "body" });
}
