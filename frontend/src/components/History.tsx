import { useEffect, useState } from "react";
import { api } from "../api";
import { S, card, btn, inp } from "../types";
import { dl } from "../api";
import ScanTable from "./ScanTable";

interface HistoryProps {
  open: (id: number) => void;
}

export default function History({ open }: HistoryProps) {
  const [page, setPage] = useState(1);
  const [cat, setCat] = useState("");
  const [data, setData] = useState<S>();
  const [err, setErr] = useState("");

  useEffect(() => {
    setData(undefined);
    api(`/scans?page=${page}&size=10${cat ? `&category=${cat}` : ""}`)
      .then(setData)
      .catch((x) => setErr(x.message));
  }, [page, cat]);

  return (
    <div className={`${card} space-y-4`}>
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          className={`${inp} !w-auto min-w-[140px]`}
          value={cat}
          onChange={(x) => { setCat(x.target.value); setPage(1); }}
        >
          <option value="">All Risks</option>
          <option>High</option>
          <option>Suspicious</option>
          <option>Low</option>
        </select>
        <button
          className={btn}
          onClick={() => dl("/scans/export.csv", "scan_history.csv").catch((x) => setErr(x.message))}
        >
          ⬇ Export CSV
        </button>
      </div>

      {/* Error */}
      {err && (
        <p className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-300">{err}</p>
      )}

      {/* Table or states */}
      {!data ? (
        <div className="flex items-center gap-2 py-4 text-slate-400">
          <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading history…
        </div>
      ) : data.items.length ? (
        <ScanTable rows={data.items} open={open} />
      ) : (
        <p className="py-4 text-sm text-slate-400">No scans found for the selected filter.</p>
      )}

      {/* Pagination */}
      <div className="flex items-center gap-3 border-t border-cyan-900/30 pt-4">
        <button className={btn} disabled={page <= 1} onClick={() => setPage(page - 1)}>
          ← Prev
        </button>
        <span className="text-sm text-slate-400">Page {page}</span>
        <button
          className={btn}
          disabled={!data || page * 10 >= data.total}
          onClick={() => setPage(page + 1)}
        >
          Next →
        </button>
        {data && (
          <span className="ml-auto text-xs text-slate-500">{data.total} total scans</span>
        )}
      </div>
    </div>
  );
}
