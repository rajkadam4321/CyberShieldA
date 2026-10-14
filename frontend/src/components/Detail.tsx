import { useEffect, useState } from "react";
import { api } from "../api";
import { S } from "../types";
import Result from "./Result";

interface DetailProps {
  id: number;
}

export default function Detail({ id }: DetailProps) {
  const [s, setS] = useState<S>();
  const [err, setErr] = useState("");

  useEffect(() => {
    setS(undefined);
    setErr("");
    api(`/scans/${id}`).then(setS).catch((x) => setErr(x.message));
  }, [id]);

  if (err) return (
    <p className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-300">{err}</p>
  );

  if (!s) return (
    <div className="flex items-center gap-2 text-slate-400">
      <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
      Loading scan details…
    </div>
  );

  return <Result s={s} />;
}
