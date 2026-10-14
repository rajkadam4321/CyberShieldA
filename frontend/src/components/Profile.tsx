import { useEffect, useState } from "react";
import { api } from "../api";
import { S, card, btn } from "../types";

interface ProfileProps {
  onLogout: () => void;
}

export default function Profile({ onLogout }: ProfileProps) {
  const [user, setUser] = useState<S>();

  useEffect(() => {
    api("/users/me").then(setUser).catch(() => {});
  }, []);

  return (
    <div className="max-w-md space-y-5">
      {/* User card */}
      <div className={card}>
        <div className="flex items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-cyan-500/15 ring-2 ring-cyan-500/30 text-2xl font-bold text-cyan-300">
            {user?.username?.[0]?.toUpperCase() ?? "?"}
          </div>
          <div>
            <p className="text-lg font-semibold text-slate-100">{user?.username ?? "Loading…"}</p>
            <p className="text-xs text-slate-500">Member account</p>
          </div>
        </div>
      </div>

      {/* Info card */}
      <div className={card}>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">About</h3>
        <p className="text-sm text-slate-400 leading-relaxed">
          CyberShield is an <b className="text-slate-300">academic prototype</b> for exploring AI-based
          threat detection techniques. It is not a replacement for enterprise security products or
          professional penetration testing.
        </p>
      </div>

      {/* Logout */}
      <div className={card}>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Session</h3>
        <button
          className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm font-semibold text-red-300 transition-all duration-200 hover:bg-red-500/20 hover:text-red-200"
          onClick={() => { if (confirm("Are you sure you want to log out?")) onLogout(); }}
        >
          🚪 Log Out
        </button>
      </div>
    </div>
  );
}
