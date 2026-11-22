import { ValidationDomainError } from "@relayquill/domain";

export class HttpStatusDomainError extends ValidationDomainError {
  readonly httpStatus: number;

  constructor(httpStatus: number, message: string, fieldPath = "headers") {
    super({
      code: "INVALID_VALUE",
      message,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
    this.httpStatus = httpStatus;
  }
}

const SINGLE_OCCURRENCE_HEADERS = [
  "content-type",
  "content-encoding",
  "authorization",
  "idempotency-key",
  "x-csrf-token",
  "x-relayquill-csrf",
  "x-relayquill-step-up",
  "origin",
  "last-event-id"
] as const;

export function collectRawHeadersMap(
  rawHeaders: readonly string[]
): ReadonlyMap<string, readonly string[]> {
  const map = new Map<string, string[]>();
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const rawName = rawHeaders[i];
    const rawVal = rawHeaders[i + 1];
    if (rawName === undefined || rawVal === undefined) {
      continue;
    }
    const key = rawName.toLowerCase();
    let arr = map.get(key);
    if (arr === undefined) {
      arr = [];
      map.set(key, arr);
    }
    arr.push(rawVal);
  }
  return map;
}

export function assertStrictRawHeaders(rawHeaders: readonly string[]): ReadonlyMap<string, readonly string[]> {
  const map = collectRawHeadersMap(rawHeaders);
  for (const name of SINGLE_OCCURRENCE_HEADERS) {
    const values = map.get(name);
    if (values !== undefined && values.length > 1) {
      throw new HttpStatusDomainError(
        400,
        `Duplicate HTTP header "${name}" is forbidden`,
        `headers.${name}`
      );
    }
  }
  const contentEncoding = map.get("content-encoding")?.[0];
  if (contentEncoding !== undefined && contentEncoding.trim().length > 0) {
    throw new HttpStatusDomainError(
      415,
      `Unsupported Content-Encoding "${contentEncoding.trim()}"; request compression is not permitted`,
      "headers.content-encoding"
    );
  }
  return map;
}

export function extractSingleRawHeader(
  headerMap: ReadonlyMap<string, readonly string[]>,
  headerName: string
): string | undefined {
  const values = headerMap.get(headerName.toLowerCase());
  if (values === undefined || values.length === 0) {
    return undefined;
  }
  if (values.length > 1) {
    throw new HttpStatusDomainError(
      400,
      `Duplicate HTTP header "${headerName.toLowerCase()}" is forbidden`,
      `headers.${headerName.toLowerCase()}`
    );
  }
  const value = values[0];
  if (value === undefined || value.includes("\0")) {
    throw new HttpStatusDomainError(
      400,
      `Malformed HTTP header "${headerName.toLowerCase()}"`,
      `headers.${headerName.toLowerCase()}`
    );
  }
  return value.trim();
}

export function assertJsonMediaTypeHeader(
  headerMap: ReadonlyMap<string, readonly string[]>
): void {
  const contentType = extractSingleRawHeader(headerMap, "content-type");
  if (contentType === undefined || contentType.length === 0) {
    throw new HttpStatusDomainError(
      415,
      "Content-Type: application/json is required",
      "headers.content-type"
    );
  }
  const [mediaTypeRaw, ...params] = contentType.split(";").map((s) => s.trim().toLowerCase());
  if (mediaTypeRaw !== "application/json") {
    throw new HttpStatusDomainError(
      415,
      `Unsupported Content-Type "${mediaTypeRaw ?? ""}"; expected application/json`,
      "headers.content-type"
    );
  }
  for (const param of params) {
    if (param.length === 0) {
      continue;
    }
    if (param.startsWith("charset=")) {
      const charset = param.slice("charset=".length).replace(/^"|"$/g, "");
      if (charset !== "utf-8") {
        throw new HttpStatusDomainError(
          415,
          `Unsupported Content-Type charset "${charset}"; expected utf-8`,
          "headers.content-type"
        );
      }
    } else {
      throw new HttpStatusDomainError(
        415,
        `Unsupported Content-Type parameter "${param}"`,
        "headers.content-type"
      );
    }
  }
}

export function extractHeaderRecordFromMap(
  headerMap: ReadonlyMap<string, readonly string[]>
): Readonly<Record<string, string | readonly string[] | undefined>> {
  const out: Record<string, string | readonly string[] | undefined> = {};
  for (const [k, values] of headerMap.entries()) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      continue;
    }
    if (values.length === 1) {
      out[k] = values[0];
    } else if (values.length > 1) {
      out[k] = [...values];
    }
  }
  return out;
}
