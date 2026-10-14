import { col } from "../types";

interface BadgeProps {
  c: string;
}

export default function Badge({ c }: BadgeProps) {
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${col[c] ?? "bg-slate-700 text-slate-300"}`}>
      {c}
    </span>
  );
}
