import { type JSX, type ReactNode, useId } from "react";
import { ConsoleIcon } from "./Icons.js";

export interface DataTableColumn<T> {
  readonly key: string;
  readonly header: string;
  readonly render: (row: T) => ReactNode;
}

export interface DataTablePagination {
  readonly pageSize: 25 | 100;
  readonly onPageSizeChange: (nextSize: 25 | 100) => void;
  readonly hasPrev: boolean;
  readonly hasNext: boolean;
  readonly onPrev: () => void;
  readonly onNext: () => void;
  readonly pageIndex?: number | undefined;
}

export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  emptyMessage = "No matching records in this scope.",
  pagination
}: {
  readonly caption: string;
  readonly columns: readonly DataTableColumn<T>[];
  readonly rows: readonly T[];
  readonly rowKey: (row: T) => string;
  readonly emptyMessage?: string | undefined;
  readonly pagination?: DataTablePagination | undefined;
}): JSX.Element {
  const pageSizeId = useId();

  return (
    <div className="rq-stack-sm">
      <div className="rq-table-wrap">
        <table className="rq-table">
          <caption className="visually-hidden">{caption}</caption>
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col.key} scope="col">
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="rq-meta-text">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={rowKey(row)}>
                  {columns.map((col) => (
                    <td key={col.key}>{col.render(row)}</td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {pagination !== undefined ? (
        <div className="rq-row-between" aria-label={`${caption} pagination`}>
          <div className="rq-row">
            <label htmlFor={pageSizeId} className="rq-label">
              Rows per page
            </label>
            <select
              id={pageSizeId}
              className="rq-select"
              value={pagination.pageSize}
              onChange={(event) => {
                const parsed = Number(event.target.value) === 100 ? 100 : 25;
                pagination.onPageSizeChange(parsed);
              }}
            >
              <option value={25}>25</option>
              <option value={100}>100</option>
            </select>
            {pagination.pageIndex !== undefined ? (
              <span className="rq-meta-text mono">Page {pagination.pageIndex + 1}</span>
            ) : null}
          </div>

          <div className="rq-row">
            <button
              type="button"
              className="rq-btn"
              disabled={!pagination.hasPrev}
              onClick={pagination.onPrev}
            >
              <ConsoleIcon name="chevron_left" />
              <span>Previous</span>
            </button>
            <button
              type="button"
              className="rq-btn"
              disabled={!pagination.hasNext}
              onClick={pagination.onNext}
            >
              <span>Next</span>
              <ConsoleIcon name="chevron_right" />
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
