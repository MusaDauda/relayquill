import { type JSX, type ReactNode, useEffect, useId, useRef } from "react";
import { ConsoleIcon } from "./Icons.js";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex=\"-1\"])"
].join(", ");

function getFocusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (el) => !el.hasAttribute("aria-hidden") && el.offsetParent !== null
  );
}

export function Modal({
  open,
  title,
  description,
  preventClose = false,
  onClose,
  footer,
  children
}: {
  readonly open: boolean;
  readonly title: string;
  readonly description?: string | undefined;
  readonly preventClose?: boolean | undefined;
  readonly onClose: () => void;
  readonly footer?: ReactNode | undefined;
  readonly children: ReactNode;
}): JSX.Element | null {
  const titleId = useId();
  const descId = useId();
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) {
      return;
    }

    triggerRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const dialogEl = dialogRef.current;
    if (dialogEl !== null) {
      const focusables = getFocusableElements(dialogEl);
      const first = focusables[0];
      if (first !== undefined) {
        first.focus();
      } else {
        dialogEl.focus();
      }
    }

    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        if (!preventClose) {
          event.preventDefault();
          onClose();
        }
        return;
      }

      if (event.key === "Tab" && dialogRef.current !== null) {
        const focusables = getFocusableElements(dialogRef.current);
        if (focusables.length === 0) {
          event.preventDefault();
          return;
        }
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (first === undefined || last === undefined) {
          return;
        }
        const active = document.activeElement;
        if (event.shiftKey) {
          if (active === first || !dialogRef.current.contains(active)) {
            event.preventDefault();
            last.focus();
          }
        } else if (active === last || !dialogRef.current.contains(active)) {
          event.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      const returnTarget = triggerRef.current;
      if (returnTarget !== null && returnTarget.isConnected) {
        returnTarget.focus();
      }
    };
  }, [onClose, open, preventClose]);

  if (!open) {
    return null;
  }

  return (
    <div
      className="rq-modal-backdrop"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget && !preventClose) {
          onClose();
        }
      }}
    >
      <div
        ref={dialogRef}
        className="rq-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        {...(description !== undefined ? { "aria-describedby": descId } : {})}
        tabIndex={-1}
      >
        <div className="rq-row-between">
          <h2 id={titleId} className="rq-section-title">
            {title}
          </h2>
          <button
            type="button"
            className="rq-btn"
            disabled={preventClose}
            aria-label={`Close ${title}`}
            onClick={onClose}
          >
            <ConsoleIcon name="close" />
            <span>Close</span>
          </button>
        </div>

        {description !== undefined ? (
          <p id={descId} className="rq-meta-text">
            {description}
          </p>
        ) : null}

        <div className="rq-stack">{children}</div>

        {footer !== undefined ? <div className="rq-row-between">{footer}</div> : null}
      </div>
    </div>
  );
}
