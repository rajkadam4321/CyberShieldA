import { useState, useEffect, useRef } from "react";
import { api, dl } from "../api";
import { S, card, btn, inp, col } from "../types";

export default function SystemScanner() {
  const [scanType, setScanType] = useState<"quick" | "full" | "custom">("quick");
  const [customPath, setCustomPath] = useState("C:\\Users\\Asus\\AppData\\Local\\Temp");
  const [engineStatus, setEngineStatus] = useState<S>();
  const [activeScan, setActiveScan] = useState<S>();
  const [history, setHistory] = useState<S[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionError, setActionError] = useState("");
  const [remediatingId, setRemediatingId] = useState<number | null>(null);
  const [confirmQuarantineId, setConfirmQuarantineId] = useState<number | null>(null);
  const pollTimer = useRef<any>(null);

  // Fetch engine status and past scans on mount
  useEffect(() => {
    loadEngineStatus();
    loadHistory();
    checkActiveScan();
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, []);

  // Polling when a scan is actively running or paused
  useEffect(() => {
    if (activeScan && (activeScan.status === "running" || activeScan.status === "paused")) {
      if (!pollTimer.current) {
        pollTimer.current = setInterval(checkActiveScan, 1500);
      }
    } else {
      if (pollTimer.current) {
        clearInterval(pollTimer.current);
        pollTimer.current = null;
      }
    }
  }, [activeScan?.status]);

  async function loadEngineStatus() {
    try {
      const res = await api("/system-scans/engine-status");
      setEngineStatus(res);
    } catch {
      /* ignore */
    }
  }

  async function loadHistory() {
    try {
      const res = await api("/system-scans?size=10");
      setHistory(res.items || []);
    } catch {
      /* ignore */
    }
  }

  async function checkActiveScan() {
    try {
      const res = await api("/system-scans/active");
      if (res && res.id) {
        setActiveScan(res);
        if (res.status === "completed" || res.status === "cancelled") {
          loadHistory();
        }
      }
    } catch {
      /* ignore */
    }
  }

  async function handleStartScan() {
    setActionError("");
    setLoading(true);
    try {
      const res = await api("/system-scans/start", {
        method: "POST",
        body: JSON.stringify({
          scan_type: scanType,
          target_path: scanType === "custom" ? customPath : "",
        }),
      });
      setActiveScan({
        id: res.id,
        scan_type: res.scan_type,
        status: "running",
        files_examined: 0,
        files_skipped: 0,
        errors_count: 0,
        findings_count: 0,
        progress_pct: 0,
        duration_seconds: 0,
        findings: [],
      });
      loadHistory();
    } catch (err: any) {
      setActionError(err.message || "Failed to start scan");
    } finally {
      setLoading(false);
    }
  }

  async function handlePause() {
    if (!activeScan) return;
    try {
      await api(`/system-scans/${activeScan.id}/pause`, { method: "POST" });
      checkActiveScan();
    } catch (err: any) {
      setActionError(err.message);
    }
  }

  async function handleResume() {
    if (!activeScan) return;
    try {
      await api(`/system-scans/${activeScan.id}/resume`, { method: "POST" });
      checkActiveScan();
    } catch (err: any) {
      setActionError(err.message);
    }
  }

  async function handleCancel() {
    if (!activeScan) return;
    try {
      await api(`/system-scans/${activeScan.id}/cancel`, { method: "POST" });
      checkActiveScan();
    } catch (err: any) {
      setActionError(err.message);
    }
  }

  async function handleRemediate(findingId: number, action: "quarantine" | "ignore") {
    setRemediatingId(findingId);
    setActionError("");
    try {
      await api(`/system-scans/findings/${findingId}/remediate`, {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      setConfirmQuarantineId(null);
      // Refresh current scan details
      if (activeScan) {
        const updated = await api(`/system-scans/${activeScan.id}`);
        setActiveScan(updated);
      }
    } catch (err: any) {
      setActionError(err.message);
    } finally {
      setRemediatingId(null);
    }
  }

  async function viewHistoricalScan(id: number) {
    try {
      const scanData = await api(`/system-scans/${id}`);
      setActiveScan(scanData);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (err: any) {
      setActionError(err.message);
    }
  }

  const isScanning = activeScan?.status === "running";
  const isPaused = activeScan?.status === "paused";
  const findings: S[] = activeScan?.findings || [];

  return (
    <div className="space-y-6">
      {/* ── Top Header & Engine Status Banner ── */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className={`${card} lg:col-span-2 flex flex-col justify-between`}>
          <div>
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/15 text-2xl ring-1 ring-cyan-500/30">
                🛡️
              </span>
              <div>
                <h3 className="text-lg font-bold text-slate-100">
                  Local Windows System & Malware Scanner
                </h3>
                <p className="text-xs text-slate-400">
                  Inspects local files, startup persistence entries, and integrates with Microsoft Defender.
                </p>
              </div>
            </div>
            <p className="mt-4 text-xs leading-relaxed text-slate-300">
              CyberShield performs non-destructive local system audits. Suspicious files are never executed.
              Remediation and quarantine require your explicit authorization.
            </p>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-cyan-900/30 pt-3 text-xs text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              Direct Windows Execution
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-cyan-400" />
              Chunked Streaming Hashing
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-purple-400" />
              Explicit Quarantine Control
            </span>
          </div>
        </div>

        {/* Engine Status Card */}
        <div className={`${card} flex flex-col justify-between`}>
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Antivirus Engine Status
            </p>
            <div className="mt-2 flex items-center gap-2">
              <span
                className={`h-2.5 w-2.5 rounded-full ${
                  engineStatus?.available ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
                }`}
              />
              <span className="text-sm font-bold text-slate-200">
                {engineStatus?.engine || "Detecting..."}
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-400">
              {engineStatus?.available
                ? "Microsoft Defender CLI (MpCmdRun.exe) active on this machine."
                : "Using CyberShield native signature & heuristic inspection engine."}
            </p>
          </div>

          <div className="mt-4 border-t border-cyan-900/30 pt-3 text-xs text-slate-400">
            <p>
              Verified Signature DB:{" "}
              <span className="font-semibold text-cyan-300">
                {engineStatus?.signature_db_count ?? 5} Signatures Loaded
              </span>
            </p>
          </div>
        </div>
      </div>

      {/* ── Scan Configuration Controls ── */}
      <div className={`${card} space-y-4`}>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyan-900/30 pb-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
            Scan Configuration
          </h4>
          <div className="flex rounded-lg bg-[#0a1628] p-1 border border-slate-700/60">
            <button
              onClick={() => setScanType("quick")}
              disabled={isScanning || isPaused}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-all ${
                scanType === "quick"
                  ? "bg-cyan-500 text-slate-950 font-bold shadow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              ⚡ Quick Scan
            </button>
            <button
              onClick={() => setScanType("full")}
              disabled={isScanning || isPaused}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-all ${
                scanType === "full"
                  ? "bg-cyan-500 text-slate-950 font-bold shadow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              🌐 Full System Scan
            </button>
            <button
              onClick={() => setScanType("custom")}
              disabled={isScanning || isPaused}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-all ${
                scanType === "custom"
                  ? "bg-cyan-500 text-slate-950 font-bold shadow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              📂 Custom Path Scan
            </button>
          </div>
        </div>

        {/* Scan scope explanation */}
        <div className="text-xs text-slate-400">
          {scanType === "quick" && (
            <p>
              <strong className="text-slate-300">Quick Scan:</strong> Checks user Startup persistence folders,
              Windows autorun registry keys, %TEMP%, Downloads, and requests a Microsoft Defender quick pass.
            </p>
          )}
          {scanType === "full" && (
            <p>
              <strong className="text-slate-300">Full System Scan:</strong> Streams across accessible drive files
              using chunked hashing and signature verification. System files and permissions errors are safely handled.
            </p>
          )}
          {scanType === "custom" && (
            <div className="space-y-2">
              <label className="block text-xs font-medium text-slate-300">
                Target Folder or File Path to Inspect:
              </label>
              <input
                className={inp}
                value={customPath}
                onChange={(e) => setCustomPath(e.target.value)}
                placeholder="C:\Users\Username\TargetFolder"
                disabled={isScanning || isPaused}
              />
              <p className="text-[11px] text-slate-500">
                Network UNC paths (\\) and device namespace paths (\\.\) are blocked for security.
              </p>
            </div>
          )}
        </div>

        {/* Action button controls */}
        <div className="flex flex-wrap items-center gap-3 pt-2">
          {!isScanning && !isPaused ? (
            <button
              onClick={handleStartScan}
              disabled={loading}
              className={btn}
            >
              {loading ? "Starting..." : `Start ${scanType.toUpperCase()} Scan`}
            </button>
          ) : (
            <>
              {isScanning ? (
                <button
                  onClick={handlePause}
                  className="rounded-lg bg-amber-500/20 border border-amber-500/40 px-4 py-2 font-semibold text-amber-300 hover:bg-amber-500/30 transition-all text-sm"
                >
                  ⏸ Pause Scan
                </button>
              ) : (
                <button
                  onClick={handleResume}
                  className="rounded-lg bg-emerald-500/20 border border-emerald-500/40 px-4 py-2 font-semibold text-emerald-300 hover:bg-emerald-500/30 transition-all text-sm"
                >
                  ▶ Resume Scan
                </button>
              )}
              <button
                onClick={handleCancel}
                className="rounded-lg bg-red-500/20 border border-red-500/40 px-4 py-2 font-semibold text-red-300 hover:bg-red-500/30 transition-all text-sm"
              >
                ⏹ Cancel Scan
              </button>
            </>
          )}

          {activeScan?.id && (
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => dl(`/system-scans/${activeScan.id}/report.pdf`, `CyberShield_SysScan_${activeScan.id}.pdf`)}
                className="rounded-lg border border-slate-700 bg-[#0a1628] px-3 py-2 text-xs font-semibold text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-all"
              >
                📄 PDF Report
              </button>
              <button
                onClick={() => dl(`/system-scans/${activeScan.id}/export.csv`, `findings_scan_${activeScan.id}.csv`)}
                className="rounded-lg border border-slate-700 bg-[#0a1628] px-3 py-2 text-xs font-semibold text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-all"
              >
                📊 CSV Export
              </button>
            </div>
          )}
        </div>

        {actionError && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-xs text-red-300">
            {actionError}
          </div>
        )}
      </div>

      {/* ── Active Scan Live Progress Panel ── */}
      {activeScan && (
        <div className={`${card} space-y-4 border-cyan-500/40`}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="text-xl">
                {activeScan.status === "running" ? "🔄" : activeScan.status === "completed" ? "✅" : "⚠️"}
              </span>
              <div>
                <h4 className="font-bold text-slate-100">
                  Scan #{activeScan.id} — {activeScan.scan_type?.toUpperCase()}
                </h4>
                <p className="text-xs text-slate-400">
                  Target: {activeScan.target_path || "System Targets"}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span
                className={`rounded-full px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${
                  activeScan.status === "running"
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 animate-pulse"
                    : activeScan.status === "completed"
                    ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                    : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                }`}
              >
                {activeScan.status}
              </span>
              <span className="text-xs font-mono text-slate-400">
                ⏱ {activeScan.duration_seconds ?? 0}s
              </span>
            </div>
          </div>

          {/* Progress bar */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs text-slate-400">
              <span>Examining filesystem artifacts...</span>
              <span className="font-bold text-cyan-300">{activeScan.progress_pct ?? 0}%</span>
            </div>
            <div className="h-2 w-full rounded-full bg-slate-800">
              <div
                className="h-2 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                style={{ width: `${Math.min(activeScan.progress_pct ?? 0, 100)}%` }}
              />
            </div>
            {activeScan.current_file && (
              <p className="truncate font-mono text-[11px] text-slate-500">
                Scanning: {activeScan.current_file}
              </p>
            )}
          </div>

          {/* Counters Grid */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 pt-2">
            <div className="rounded-lg bg-[#0a1628] p-3 text-center border border-slate-800">
              <p className="text-2xl font-extrabold text-cyan-300">{activeScan.files_examined ?? 0}</p>
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Examined</p>
            </div>
            <div className="rounded-lg bg-[#0a1628] p-3 text-center border border-slate-800">
              <p className="text-2xl font-extrabold text-slate-400">{activeScan.files_skipped ?? 0}</p>
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Skipped</p>
            </div>
            <div className="rounded-lg bg-[#0a1628] p-3 text-center border border-slate-800">
              <p className="text-2xl font-extrabold text-amber-400">{activeScan.errors_count ?? 0}</p>
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Access Errors</p>
            </div>
            <div className="rounded-lg bg-[#0a1628] p-3 text-center border border-slate-800">
              <p className="text-2xl font-extrabold text-red-400">{findings.length}</p>
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Threat Findings</p>
            </div>
          </div>
        </div>
      )}

      {/* ── Threat Detections Table ── */}
      <div className={card}>
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
            Threat Detections & Anomalies ({findings.length})
          </h4>
          <span className="text-xs text-slate-500">
            Real scan findings only — no fabricated threats
          </span>
        </div>

        {findings.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-700/60 p-8 text-center text-slate-400">
            <span className="text-3xl block mb-2">🛡️</span>
            <p className="text-sm font-medium text-slate-300">
              No threat detections or persistence anomalies found.
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Run a Quick or Custom scan to inspect your system.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-cyan-900/40 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Malware / Indicator</th>
                  <th className="py-2.5 px-3">Detection Source</th>
                  <th className="py-2.5 px-3">File / Target</th>
                  <th className="py-2.5 px-3">Recommended Action</th>
                  <th className="py-2.5 px-3 text-right">Remediation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {findings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-3">
                      <span className={`inline-block rounded px-2 py-0.5 font-bold ${col[f.severity] || col.Medium}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-semibold text-slate-100">
                      <div>{f.malware_name}</div>
                      <div className="text-[10px] text-slate-400 font-normal">{f.description}</div>
                    </td>
                    <td className="py-3 px-3 text-cyan-300 font-medium">
                      {f.detection_source}
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px] max-w-[200px] truncate text-slate-300" title={f.file_path}>
                      {f.file_path}
                      {f.file_hash && (
                        <div className="text-[10px] text-slate-500 truncate">SHA256: {f.file_hash.slice(0, 16)}...</div>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-400 text-[11px]">
                      {f.recommended_action}
                    </td>
                    <td className="py-3 px-3 text-right">
                      {f.status === "quarantined" ? (
                        <span className="rounded bg-purple-500/20 border border-purple-500/40 px-2 py-1 text-[11px] font-bold text-purple-300">
                          Quarantined
                        </span>
                      ) : f.status === "ignored" ? (
                        <span className="rounded bg-slate-700/50 px-2 py-1 text-[11px] text-slate-400">
                          Ignored
                        </span>
                      ) : confirmQuarantineId === f.id ? (
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleRemediate(f.id, "quarantine")}
                            disabled={remediatingId === f.id}
                            className="rounded bg-red-600 px-2.5 py-1 text-[10px] font-bold text-white hover:bg-red-500"
                          >
                            Confirm
                          </button>
                          <button
                            onClick={() => setConfirmQuarantineId(null)}
                            className="rounded bg-slate-700 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-600"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setConfirmQuarantineId(f.id)}
                            className="rounded bg-red-500/20 border border-red-500/30 px-2 py-1 text-[11px] font-semibold text-red-300 hover:bg-red-500/30 transition-colors"
                          >
                            Quarantine
                          </button>
                          <button
                            onClick={() => handleRemediate(f.id, "ignore")}
                            className="rounded bg-slate-800 border border-slate-700 px-2 py-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
                          >
                            Ignore
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Past Scans History ── */}
      <div className={card}>
        <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3">
          Recent System Scans
        </h4>
        {history.length === 0 ? (
          <p className="text-xs text-slate-500 py-3">No previous system scans recorded.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-cyan-900/40 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2 px-3">Scan ID</th>
                  <th className="py-2 px-3">Mode</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3">Examined</th>
                  <th className="py-2 px-3">Findings</th>
                  <th className="py-2 px-3">Duration</th>
                  <th className="py-2 px-3">Date</th>
                  <th className="py-2 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {history.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-3 font-mono font-semibold text-cyan-300">
                      CS-SYS-{String(s.id).padStart(4, "0")}
                    </td>
                    <td className="py-2.5 px-3 uppercase text-[11px] text-slate-200 font-bold">
                      {s.scan_type}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                          s.status === "completed"
                            ? "bg-emerald-500/20 text-emerald-300"
                            : s.status === "cancelled"
                            ? "bg-slate-700 text-slate-300"
                            : "bg-cyan-500/20 text-cyan-300"
                        }`}
                      >
                        {s.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">{s.files_examined}</td>
                    <td className="py-2.5 px-3 font-bold text-red-400">{s.findings_count}</td>
                    <td className="py-2.5 px-3 text-slate-400">{s.duration_seconds}s</td>
                    <td className="py-2.5 px-3 text-slate-400">{s.started_at?.slice(0, 16).replace("T", " ")}</td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => viewHistoricalScan(s.id)}
                        className="rounded border border-slate-700 px-2 py-1 text-[11px] text-slate-300 hover:border-cyan-400 hover:text-cyan-300 transition-colors"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
