import { parentPort } from "node:worker_threads";
import {
  DomainError,
  type SerializedDomainError
} from "@relayquill/domain";
import { evaluateParsedEvent } from "./evaluator.js";
import { compileFilterAst, evaluateFilter } from "./filter.js";
import {
  type OrderingDigestScope,
  compileOrderingExtractor,
  extractOrderingKey
} from "./ordering-extractor.js";
import { parseEventJsonBytes } from "./parser.js";
import {
  type CompiledEventSchema,
  compileEventSchemaFromBytes
} from "./profile.js";
import { compileProjectionProfile } from "./projection-profile.js";
import { executeProjection } from "./projection.js";

export type WorkerRequestMessage =
  | {
      readonly id: number;
      readonly kind: "compile_schema";
      readonly rawBytes: Uint8Array;
    }
  | {
      readonly id: number;
      readonly kind: "validate_event";
      readonly eventBytes: Uint8Array;
      readonly compiledSchema?: CompiledEventSchema | undefined;
      readonly schemaBytes?: Uint8Array | undefined;
      readonly maxWorkUnits?: number | undefined;
      readonly maxDiagnostics?: number | undefined;
    }
  | {
      readonly id: number;
      readonly kind: "evaluate_filter_and_extract";
      readonly eventBytes: Uint8Array;
      readonly compiledSchema: CompiledEventSchema;
      readonly filterAst?: unknown;
      readonly orderingExtractor?: unknown;
      readonly orderingScope?: OrderingDigestScope | undefined;
    }
  | {
      readonly id: number;
      readonly kind: "execute_projection";
      readonly sourceBytes: Uint8Array;
      readonly sourceSchema: CompiledEventSchema;
      readonly targetSchema: CompiledEventSchema;
      readonly profileDefinition: unknown;
    };

export type WorkerResponseMessage =
  | { readonly id: number; readonly ok: true; readonly result: unknown }
  | { readonly id: number; readonly ok: false; readonly error: SerializedDomainError };

function serializeWorkerError(err: unknown): SerializedDomainError {
  if (err instanceof DomainError) {
    return err.toJSON();
  }
  return {
    name: "LimitExceededDomainError",
    code: "SCHEMA_EVALUATION_LIMIT",
    message: "Schema worker evaluation failed",
    retryable: false,
    acceptance: "known_rejected"
  };
}

function handleWorkerMessage(msg: WorkerRequestMessage): unknown {
  switch (msg.kind) {
    case "compile_schema": {
      return compileEventSchemaFromBytes(msg.rawBytes);
    }

    case "validate_event": {
      const schema =
        msg.compiledSchema ??
        (msg.schemaBytes !== undefined ? compileEventSchemaFromBytes(msg.schemaBytes) : undefined);
      if (schema === undefined) {
        throw new DomainError({
          code: "INVALID_VALUE",
          message: "validate_event requires compiledSchema or schemaBytes"
        });
      }
      const parsed = parseEventJsonBytes(msg.eventBytes);
      const evaluation = evaluateParsedEvent(schema, parsed.value, {
        maxWorkUnits: msg.maxWorkUnits,
        maxDiagnostics: msg.maxDiagnostics
      });
      return {
        valid: evaluation.valid,
        diagnostics: evaluation.diagnostics,
        totalDiagnosticsObserved: evaluation.totalDiagnosticsObserved,
        workUnitsUsed: evaluation.workUnitsUsed,
        byteCount: parsed.byteCount,
        sha256: parsed.sha256,
        nodeCount: parsed.nodeCount,
        maxObservedDepth: parsed.maxObservedDepth
      };
    }

    case "evaluate_filter_and_extract": {
      const parsed = parseEventJsonBytes(msg.eventBytes);
      const evaluation = evaluateParsedEvent(msg.compiledSchema, parsed.value);
      if (!evaluation.valid) {
        return {
          schemaValid: false,
          diagnostics: evaluation.diagnostics,
          matched: false
        };
      }
      const compiledFilter =
        msg.filterAst !== undefined && msg.filterAst !== null
          ? compileFilterAst(msg.filterAst, [msg.compiledSchema])
          : null;
      const matched = evaluateFilter(compiledFilter, parsed.value);
      if (!matched) {
        return {
          schemaValid: true,
          diagnostics: [],
          matched: false
        };
      }
      let orderingResult: ReturnType<typeof extractOrderingKey> | undefined;
      if (msg.orderingExtractor !== undefined && msg.orderingExtractor !== null) {
        const compiledExtractor = compileOrderingExtractor(msg.orderingExtractor, [
          msg.compiledSchema
        ]);
        orderingResult = extractOrderingKey(parsed.value, compiledExtractor, msg.orderingScope);
      }
      return {
        schemaValid: true,
        diagnostics: [],
        matched: true,
        ...(orderingResult !== undefined ? { ordering: orderingResult } : {})
      };
    }

    case "execute_projection": {
      const compiledProfile = compileProjectionProfile(
        msg.profileDefinition,
        msg.sourceSchema,
        msg.targetSchema
      );
      const executed = executeProjection(compiledProfile, msg.sourceBytes);
      return {
        compilerProfileVersion: executed.compilerProfileVersion,
        sourceByteCount: executed.sourceByteCount,
        sourceContentSha256: executed.sourceContentSha256,
        derivedJson: executed.derivedJson,
        derivedBytes: executed.derivedBytes,
        derivedByteCount: executed.derivedByteCount,
        derivedContentSha256: executed.derivedContentSha256,
        targetSchemaVersion: executed.targetSchemaVersion,
        provenance: executed.provenance
      };
    }
  }
}

if (parentPort !== null) {
  parentPort.on("message", (msg: WorkerRequestMessage) => {
    try {
      const result = handleWorkerMessage(msg);
      const response: WorkerResponseMessage = { id: msg.id, ok: true, result };
      parentPort!.postMessage(response);
    } catch (err) {
      const response: WorkerResponseMessage = {
        id: msg.id,
        ok: false,
        error: serializeWorkerError(err)
      };
      parentPort!.postMessage(response);
    }
  });
}
