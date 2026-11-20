import { type JSX, useMemo, useState } from "react";
import { formatByteSize } from "../utils/format.js";
import {
  decodeBase64JsonLossless,
  inspectLosslessJsonText
} from "../utils/lossless-json.js";
import { CopyableId } from "./CopyableId.js";
import { StatusBadge } from "./StatusBadge.js";

export function LosslessJsonViewer({
  jsonText,
  base64Data,
  title = "Lossless JSON Payload",
  expectedSha256,
  maxPreviewChars = 48_000
}: {
  readonly jsonText?: string | undefined;
  readonly base64Data?: string | undefined;
  readonly title?: string | undefined;
  readonly expectedSha256?: string | undefined;
  readonly maxPreviewChars?: number | undefined;
}): JSX.Element {
  const [rawMode, setRawMode] = useState(false);

  const inspection = useMemo(() => {
    if (base64Data !== undefined) {
      try {
        const decoded = decodeBase64JsonLossless(base64Data);
        const textCheck = inspectLosslessJsonText(decoded.rawText);
        return {
          valid: decoded.validJson,
          rawText: decoded.rawText,
          formattedText: decoded.formattedText,
          precisionRiskPaths: decoded.precisionRiskPaths,
          byteCount: textCheck.byteCount,
          sha256: textCheck.sha256,
          error: decoded.error
        };
      } catch (err) {
        return {
          valid: false,
          rawText: "",
          formattedText: "",
          precisionRiskPaths: [] as readonly string[],
          byteCount: 0,
          sha256: null as string | null,
          error: err instanceof Error ? err.message : "Failed to decode base64 UTF-8 payload."
        };
      }
    }

    const source = jsonText ?? "";
    const textCheck = inspectLosslessJsonText(source);
    return {
      valid: textCheck.valid,
      rawText: source,
      formattedText: textCheck.formattedText ?? source,
      precisionRiskPaths: textCheck.precisionRiskPaths,
      byteCount: textCheck.byteCount,
      sha256: textCheck.sha256,
      error: textCheck.error
    };
  }, [base64Data, jsonText]);

  const displayed = rawMode ? inspection.rawText : inspection.formattedText;
  const truncated = displayed.length > maxPreviewChars;
  const safeText = truncated ? `${displayed.slice(0, maxPreviewChars)}\n... [truncated preview]` : displayed;
  const shaMismatch =
    expectedSha256 !== undefined &&
    inspection.sha256 !== null &&
    expectedSha256.toLowerCase() !== inspection.sha256.toLowerCase();

  return (
    <section className="rq-card-inset" aria-label={title}>
      <div className="rq-row-between">
        <div className="rq-row">
          <strong className="rq-label">{title}</strong>
          <StatusBadge
            tone={inspection.valid ? "ok" : "error"}
            icon={inspection.valid ? "check" : "error"}
            label={inspection.valid ? "Lossless Verified" : "Invalid JSON"}
          />
          {inspection.precisionRiskPaths.length > 0 ? (
            <StatusBadge
              tone="info"
              icon="shield"
              label={`Exact Tokens Preserved (${inspection.precisionRiskPaths.length})`}
            />
          ) : null}
          {shaMismatch ? (
            <StatusBadge tone="error" icon="alert" label="SHA-256 Mismatch" />
          ) : null}
        </div>
        <div className="rq-row">
          <span className="rq-meta-text mono">{formatByteSize(inspection.byteCount)}</span>
          <button
            type="button"
            className="rq-btn"
            onClick={() => {
              setRawMode((prev) => !prev);
            }}
          >
            {rawMode ? "Formatted View" : "Raw Bytes Text"}
          </button>
        </div>
      </div>

      {inspection.sha256 !== null ? (
        <CopyableId label="UTF-8 SHA-256" value={inspection.sha256} compact />
      ) : null}

      {inspection.precisionRiskPaths.length > 0 ? (
        <p className="rq-meta-text">
          High-precision numeric tokens rendered verbatim without floating-point coercion:{" "}
          <span className="mono">{inspection.precisionRiskPaths.slice(0, 6).join(", ")}</span>
          {inspection.precisionRiskPaths.length > 6 ? " ..." : ""}
        </p>
      ) : null}

      {inspection.error !== undefined ? (
        <p className="rq-field-error" role="alert">
          {inspection.error}
        </p>
      ) : null}

      <pre className="rq-json-viewer">
        <code>{safeText}</code>
      </pre>
    </section>
  );
}
