import { S, card, btn } from "../types";
import { dl } from "../api";
import Badge from "./Badge";

interface ResultProps {
  s: S;
}

export default function Result({ s }: ResultProps) {
  const items: S[] = s.findings ?? [];
  const barColor =
    s.category === "High"
      ? "bg-red-500"
      : s.category === "Suspicious"
      ? "bg-amber-400"
      : "bg-emerald-400";

  return (
    <div className={`${card} space-y-5`}>
      {/* Score header */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="text-center">
          <span className="text-5xl font-extrabold text-cyan-300">{s.score}</span>
          <span className="text-lg text-slate-400">/100</span>
          <p className="text-xs text-slate-500 mt-0.5">Risk Score</p>
        </div>
        <div className="flex flex-col gap-2">
          <Badge c={s.category} />
          <span className="text-xs text-slate-500">Mode: {s.mode}</span>
        </div>
      </div>

      {/* Score bar */}
      <div className="h-2.5 rounded-full bg-slate-700/60">
        <div
          className={`h-2.5 rounded-full transition-all duration-700 ${barColor}`}
          style={{ width: `${s.score}%` }}
        />
      </div>

      {/* Target */}
      <p className="break-all rounded-lg bg-[#0a1628] px-3 py-2 text-sm text-slate-300 font-mono">
        {s.target}
      </p>

      {/* Metadata */}
      {s.metadata && (
        <div>
          <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-400">Metadata</h3>
          <dl className="grid gap-1.5 text-sm sm:grid-cols-2">
            {Object.entries(s.metadata).map(([k, v]) => (
              <div key={k} className="break-all rounded bg-[#0a1628] px-2 py-1">
                <dt className="inline text-slate-400">{k}: </dt>
                <dd className="inline text-slate-200">
                  {typeof v === "object" ? JSON.stringify(v) : String(v)}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      {/* Threat indicators */}
      <div>
        <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-400">
          Threat Indicators
        </h3>
        {items.length ? (
          <ul className="space-y-2 text-sm">
            {items.map((f: S, i: number) => (
              <li key={i} className="flex items-start gap-2 rounded-lg bg-red-500/5 border border-red-500/10 p-2.5">
                <span className="mt-0.5 shrink-0 text-amber-400">⚠</span>
                <span>
                  <b className="text-amber-300">{f.indicator}</b>
                  <span className="text-slate-400"> (+{f.points})</span>
                  {" – "}
                  <span className="text-slate-300">{f.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-slate-400">
            ✅ No threat indicators found. This does not guarantee safety.
          </p>
        )}
      </div>

      {/* Recommendations */}
      {(s.recommendations ?? []).length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-400">
            Recommendations
          </h3>
          <ul className="list-none space-y-1.5 text-sm">
            {(s.recommendations as string[]).map((r, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="mt-0.5 text-cyan-400">›</span>
                <span className="text-slate-300">{r}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between flex-wrap gap-3 border-t border-cyan-900/30 pt-4">
        <p className="text-xs text-slate-500">
          {s.disclaimer} · Scanned {s.created_at && new Date(s.created_at).toLocaleString()}
        </p>
        <button
          className={btn}
          onClick={() =>
            dl(`/scans/${s.id}/report.pdf`, `cybershield_${s.id}.pdf`).catch((e) =>
              alert(e.message)
            )
          }
        >
          ⬇ Download PDF Report
        </button>
      </div>
    </div>
  );
}
