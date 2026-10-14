import { useState, FormEvent } from "react";
import { api } from "../api";

interface AuthModalProps {
  onIn: () => void;
  onClose?: () => void;
}

type Tab = "signin" | "register";

export default function AuthModal({ onIn, onClose }: AuthModalProps) {
  const [tab, setTab] = useState<Tab>("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const switchTab = (t: Tab) => {
    setTab(t);
    setError("");
    setSuccess("");
  };

  async function handleSubmit(ev: FormEvent) {
    ev.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      const body = JSON.stringify({ username, password });
      if (tab === "register") {
        await api("/auth/register", { method: "POST", body });
        setSuccess("Account created successfully! You can now sign in.");
        setTab("signin");
        setPassword("");
      } else {
        const r = await api("/auth/login", { method: "POST", body });
        sessionStorage.setItem("t", r.access_token);
        onIn();
      }
    } catch (x: any) {
      setError(x.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    /* Backdrop */
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 auth-modal-backdrop">
      {/* Modal card */}
      <div className="auth-modal-card relative w-full max-w-md animate-modal-in">
        {/* Animated gradient border via pseudo element (handled by CSS) */}
        <div className="auth-modal-inner rounded-2xl bg-[#0f2038] p-8 shadow-2xl">

          {/* Close button */}
          {onClose && (
            <button
              onClick={onClose}
              className="absolute right-4 top-4 text-slate-400 transition-colors hover:text-slate-100"
              aria-label="Close"
            >
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}

          {/* Header */}
          <div className="mb-6 text-center">
            <div className="mb-3 inline-flex h-16 w-16 items-center justify-center rounded-full bg-cyan-500/10 ring-2 ring-cyan-500/30 shield-pulse">
              <span className="text-3xl">🛡</span>
            </div>
            <h1 className="text-2xl font-bold text-slate-100">CyberShield</h1>
            <p className="mt-1 text-sm text-slate-400">AI-powered security threat detection</p>
          </div>

          {/* Tab Pills */}
          <div className="mb-6 flex rounded-xl bg-[#0a1628] p-1">
            <button
              type="button"
              onClick={() => switchTab("signin")}
              className={`flex-1 rounded-lg py-2 text-sm font-semibold transition-all duration-300 ${
                tab === "signin"
                  ? "bg-gradient-to-r from-cyan-500 to-cyan-600 text-slate-900 shadow-lg shadow-cyan-900/40"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => switchTab("register")}
              className={`flex-1 rounded-lg py-2 text-sm font-semibold transition-all duration-300 ${
                tab === "register"
                  ? "bg-gradient-to-r from-cyan-500 to-cyan-600 text-slate-900 shadow-lg shadow-cyan-900/40"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Register
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username field */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Username
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">
                  👤
                </span>
                <input
                  type="text"
                  className="w-full rounded-lg border border-slate-600 bg-[#0a1628] py-2.5 pl-10 pr-4 text-slate-100 placeholder-slate-500 outline-none transition-all duration-200 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20"
                  placeholder="your_username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  minLength={3}
                  maxLength={32}
                  autoComplete="username"
                />
              </div>
            </div>

            {/* Password field */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Password
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">
                  🔒
                </span>
                <input
                  type={showPass ? "text" : "password"}
                  className="w-full rounded-lg border border-slate-600 bg-[#0a1628] py-2.5 pl-10 pr-12 text-slate-100 placeholder-slate-500 outline-none transition-all duration-200 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20"
                  placeholder="Minimum 8 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                  autoComplete={tab === "signin" ? "current-password" : "new-password"}
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 transition-colors hover:text-slate-200"
                  tabIndex={-1}
                  aria-label={showPass ? "Hide password" : "Show password"}
                >
                  {showPass ? (
                    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                    </svg>
                  ) : (
                    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  )}
                </button>
              </div>
            </div>

            {/* Register extra hint */}
            {tab === "register" && (
              <p className="text-xs text-slate-500">
                Username: 3–32 characters — letters, digits, <code className="text-slate-400">_ . -</code> only.
              </p>
            )}

            {/* Error message */}
            {error && (
              <div className="flex items-start gap-2 rounded-lg bg-red-500/10 p-3 text-sm text-red-300 border border-red-500/20">
                <svg className="mt-0.5 h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            {/* Success message */}
            {success && (
              <div className="flex items-start gap-2 rounded-lg bg-emerald-500/10 p-3 text-sm text-emerald-300 border border-emerald-500/20">
                <svg className="mt-0.5 h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>{success}</span>
              </div>
            )}

            {/* Submit button */}
            <button
              type="submit"
              disabled={loading}
              className="relative w-full overflow-hidden rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-600 py-2.5 font-semibold text-slate-900 shadow-lg shadow-cyan-900/40 transition-all duration-200 hover:from-cyan-400 hover:to-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  {tab === "signin" ? "Signing in…" : "Creating account…"}
                </span>
              ) : (
                tab === "signin" ? "Sign In" : "Create Account"
              )}
            </button>
          </form>

          {/* Footer */}
          <p className="mt-4 text-center text-xs text-slate-500">
            Secured with end-to-end encryption · Academic prototype
          </p>
        </div>
      </div>
    </div>
  );
}
