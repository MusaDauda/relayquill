import { type JSX, type ReactNode, useId } from "react";

export interface FieldWrapperRenderContext {
  readonly inputId: string;
  readonly describedBy: string | undefined;
  readonly hasError: boolean;
}

export function FormField({
  label,
  helpText,
  errorText,
  required = false,
  children
}: {
  readonly label: string;
  readonly helpText?: string | undefined;
  readonly errorText?: string | null | undefined;
  readonly required?: boolean | undefined;
  readonly children: (ctx: FieldWrapperRenderContext) => ReactNode;
}): JSX.Element {
  const inputId = useId();
  const helpId = useId();
  const errorId = useId();
  const hasError = typeof errorText === "string" && errorText.trim().length > 0;
  const ids: string[] = [];
  if (helpText !== undefined) {
    ids.push(helpId);
  }
  if (hasError) {
    ids.push(errorId);
  }
  const describedBy = ids.length > 0 ? ids.join(" ") : undefined;

  return (
    <div className="rq-field">
      <label className="rq-label" htmlFor={inputId}>
        {label}
        {required ? " (required)" : ""}
      </label>
      {children({ inputId, describedBy, hasError })}
      {helpText !== undefined ? (
        <p id={helpId} className="rq-help">
          {helpText}
        </p>
      ) : null}
      {hasError ? (
        <p id={errorId} className="rq-field-error" role="alert">
          {errorText}
        </p>
      ) : null}
    </div>
  );
}
