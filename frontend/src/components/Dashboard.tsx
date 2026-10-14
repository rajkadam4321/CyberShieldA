import { useEffect, useState } from "react";
import { api } from "../api";
import { S, card } from "../types";
import ScanTable from "./ScanTable";

interface DashboardProps {
  open: (id: number) => void;
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className={`${card} flex flex-col gap-1`}>
      <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</p>
      <p className={`text-4xl font-extrabold ${color}`}>{value}</p>
    </div>
  );
}

export default function Dashboard({ open }: DashboardProps) {
  const [d, setD] = useState<S>();
  const [rec, setRec] = useState<S[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    Promise.all([api("/dashboard"), api("/scans?size=100")])
      .then(([a, b]) => { setD(a); setRec(b.items); })
      .catch((x) => setErr(x.message));
  }, []);

  if (err) return (
    <p className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-300">{err}</p>
  );
  if (!d) return (
    <div className="flex items-center gap-2 text-slate-400">
      <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
      Loading dashboard…
    </div>
  );

  const days: Record<string, number> = {};
  rec.forEach((s) => {
    const k = s.created_at.slice(0, 10);
    days[k] = (days[k] ?? 0) + 1;
  });
  const keys = Object.keys(days).sort().slice(-7);
  const mx = Math.max(1, ...keys.map((k) => days[k]));

  return (
    <div className="space-y-5">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Scans"  value={d.total}      color="text-cyan-300"    />
        <StatCard label="High Risk"    value={d.high}       color="text-red-400"     />
        <StatCard label="Suspicious"   value={d.suspicious} color="text-amber-300"   />
        <StatCard label="Lower Risk"   value={d.low}        color="text-emerald-300" />
      </div>

      {/* Charts row */}
      <div className="grid gap-4 md:grid-cols-2">
        <div className={card}>
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Scan Types</h3>
          <div className="flex items-center gap-6">
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-300">{d.url}</p>
              <p className="text-xs text-slate-500">URL</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-purple-300">{d.file}</p>
              <p className="text-xs text-slate-500">File</p>
            </div>
          </div>
        </div>

        <div className={card}>
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Activity (Last 7 Days)</h3>
          {keys.length ? (
            <div className="flex h-24 items-end gap-1.5">
              {keys.map((k) => (
                <div key={k} className="flex flex-1 flex-col items-center gap-1">
                  <div
                    className="w-full rounded-t bg-gradient-to-t from-cyan-600 to-cyan-400 transition-all duration-500"
                    style={{ height: `${(days[k] / mx) * 80}px` }}
                  />
                  <span className="text-[9px] text-slate-500">{k.slice(5)}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-400">No scans yet. Run your first scan.</p>
          )}
        </div>
      </div>

      {/* Recent scans */}
      <div className={card}>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Recent Scans</h3>
        {rec.length ? (
          <ScanTable rows={rec.slice(0, 5)} open={open} />
        ) : (
          <p className="text-sm text-slate-400">Nothing here yet.</p>
        )}
      </div>
    </div>
  );
}
