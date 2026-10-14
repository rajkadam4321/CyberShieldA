import { S } from "../types";
import Badge from "./Badge";

interface ScanTableProps {
  rows: S[];
  open: (id: number) => void;
}

export default function ScanTable({ rows, open }: ScanTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-cyan-900/30">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-cyan-900/30 bg-[#0a1628]">
          <tr>
            {["Type", "Target", "Score", "Risk", "Date"].map((h) => (
              <th key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((s) => (
            <tr
              key={s.id}
              className="cursor-pointer border-b border-cyan-900/20 transition-colors duration-150 hover:bg-cyan-500/5"
              onClick={() => open(s.id)}
            >
              <td className="px-4 py-3">
                <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300 font-mono">
                  {s.kind}
                </span>
              </td>
              <td className="max-w-[14rem] truncate px-4 py-3 text-slate-300 font-mono text-xs">
                {s.target}
              </td>
              <td className="px-4 py-3 font-semibold text-cyan-300">{s.score}</td>
              <td className="px-4 py-3">
                <Badge c={s.category} />
              </td>
              <td className="px-4 py-3 text-slate-400 text-xs">
                {new Date(s.created_at).toLocaleDateString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
