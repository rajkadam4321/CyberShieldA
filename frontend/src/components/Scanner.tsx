import { useState, FormEvent } from "react";
import { api } from "../api";
import { S, card, btn, inp } from "../types";
import Result from "./Result";

interface ScannerProps {
  kind: "url" | "file";
}

export default function Scanner({ kind }: ScannerProps) {
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<S>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(ev: FormEvent) {
    ev.preventDefault();
    setError("");
    setResult(undefined);
    setLoading(true);
    try {
      if (kind === "url") {
        setResult(await api("/scans/url", { method: "POST", body: JSON.stringify({ url }) }));
      } else {
        const fd = new FormData();
        fd.append("file", file!);
        setResult(await api("/scans/file", { method: "POST", body: fd }));
      }
    } catch (x: any) {
      setError(x.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-5">
      <form onSubmit={handleSubmit} className={`${card} space-y-4`}>
        <div className="flex items-start gap-3">
          <span className="mt-0.5 text-2xl">{kind === "url" ? "🔗" : "📁"}</span>
          <div>
            <h3 className="font-semibold text-slate-100">
              {kind === "url" ? "URL Scanner" : "File Analyzer"}
            </h3>
            <p className="mt-0.5 text-sm text-slate-400">
              {kind === "url"
                ? "The URL is analysed as text only — it is never visited or fetched."
                : "Files are analysed statically and never executed. Maximum 5 MB."}
            </p>
          </div>
        </div>

        {kind === "url" ? (
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm">🔗</span>
            <input
              className={`${inp} pl-9`}
              placeholder="https://example.com/suspicious-link"
              value={url}
              onChange={(x) => setUrl(x.target.value)}
              required
            />
          </div>
        ) : (
          <div>
            <label className="block w-full cursor-pointer rounded-lg border-2 border-dashed border-slate-600 bg-[#0a1628] p-6 text-center transition-colors duration-200 hover:border-cyan-500/50 hover:bg-cyan-500/5">
              <span className="block text-3xl mb-2">📂</span>
              <span className="block text-sm text-slate-400">
                {file ? (
                  <span className="text-cyan-300 font-medium">{file.name}</span>
                ) : (
                  <>Click to select a file <span className="text-slate-500">(max 5 MB)</span></>
                )}
              </span>
              <input
                type="file"
                className="hidden"
                onChange={(x) => setFile(x.target.files?.[0] ?? null)}
                required
              />
            </label>
          </div>
        )}

        {error && (
          <div className="flex items-start gap-2 rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-300">
            <svg className="mt-0.5 h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            {error}
          </div>
        )}

        <button className={btn} disabled={loading}>
          {loading ? (
            <span className="flex items-center gap-2">
              <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Scanning…
            </span>
          ) : (
            `🔍 Scan ${kind === "url" ? "URL" : "File"}`
          )}
        </button>
      </form>

      {result && <Result s={result} />}
    </div>
  );
}
