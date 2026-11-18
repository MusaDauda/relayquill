import { UnsupportedStateTransitionError, type SafeResourceRef } from "./errors.js";

export type TransitionMatrix<S extends string> = Readonly<Record<S, readonly S[]>>;

export function canTransition<S extends string>(
  matrix: TransitionMatrix<S>,
  from: S,
  to: S
): boolean {
  const allowed: readonly S[] | undefined = matrix[from];
  return allowed !== undefined && allowed.includes(to);
}

export function assertTransition<S extends string>(
  entity: string,
  matrix: TransitionMatrix<S>,
  from: S,
  to: S,
  resourceRef?: SafeResourceRef
): void {
  if (!canTransition(matrix, from, to)) {
    throw new UnsupportedStateTransitionError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Transition for ${entity} from "${from}" to "${to}" is not allowed`,
      ...(resourceRef !== undefined ? { resourceRef } : {})
    });
  }
}

export function assertNever(value: never, context = "Unexpected value"): never {
  throw new UnsupportedStateTransitionError({
    code: "INVARIANT_VIOLATION",
    message: `${context}: ${String(value)}`
  });
}
