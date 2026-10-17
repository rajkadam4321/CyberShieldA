import { useState, ReactNode } from "react";
import { tok } from "./api";
import { api } from "./api";
import LandingHero from "./components/LandingHero";
import Sidebar from "./components/Sidebar";
import Dashboard from "./components/Dashboard";
import Scanner from "./components/Scanner";
import History from "./components/History";
import Detail from "./components/Detail";
import Quiz from "./components/Quiz";
import Profile from "./components/Profile";

import SystemScanner from "./components/SystemScanner";
import ModelEvaluation from "./components/ModelEvaluation";

const PAGE_TITLES: Record<string, string> = {
  dash:   "Dashboard",
  sys:    "System Security & Malware Scanner",
  url:    "URL Scanner",
  file:   "File Analyzer",
  eval:   "Model Benchmark & Evaluation",
  hist:   "History",
  quiz:   "Awareness Quiz",
  me:     "Profile",
  detail: "Scan Details",
};

export default function App() {
  const [authed, setAuthed] = useState(!!tok());
  const [page, setPage] = useState("dash");
  const [detailId, setDetailId] = useState(0);
  const [menuOpen, setMenuOpen] = useState(false);
  const [username, setUsername] = useState<string>();

  // Fetch username once after login
  const handleLogin = () => {
    setAuthed(true);
    api("/users/me").then((u) => setUsername(u.username)).catch(() => {});
  };

  const handleLogout = () => {
    sessionStorage.removeItem("t");
    setAuthed(false);
    setUsername(undefined);
    setPage("dash");
  };

  const openDetail = (id: number) => {
    setDetailId(id);
    setPage("detail");
  };

  const navigate = (p: string) => {
    setPage(p);
    setMenuOpen(false);
  };

  // ── Unauthenticated: show landing with modal ──
  if (!authed) {
    return <LandingHero onIn={handleLogin} />;
  }

  // ── Authenticated: render page content ──
  const pages: Record<string, ReactNode> = {
    dash:   <Dashboard open={openDetail} />,
    sys:    <SystemScanner />,
    url:    <Scanner kind="url" />,
    file:   <Scanner kind="file" />,
    eval:   <ModelEvaluation />,
    hist:   <History open={openDetail} />,
    detail: <Detail id={detailId} />,
    quiz:   <Quiz />,
    me:     <Profile onLogout={handleLogout} />,
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[#0a1628] text-slate-100">
      {/* ── Mobile overlay ── */}
      {menuOpen && (
        <div
          className="fixed inset-0 z-20 bg-black/60 backdrop-blur-sm md:hidden"
          onClick={() => setMenuOpen(false)}
        />
      )}

      {/* ── Sidebar (desktop: always shown, mobile: slide-over) ── */}
      <div
        className={`fixed inset-y-0 left-0 z-30 w-60 transition-transform duration-300 md:static md:z-auto md:translate-x-0 ${
          menuOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <Sidebar
          page={page}
          onNav={navigate}
          username={username}
          onLogout={handleLogout}
        />
      </div>

      {/* ── Main content ── */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center gap-4 border-b border-cyan-900/30 bg-[#0a1628] px-4 py-3 md:px-6">
          {/* Mobile hamburger */}
          <button
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 md:hidden"
            onClick={() => setMenuOpen(!menuOpen)}
            aria-label="Open menu"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>

          <div className="flex flex-1 items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-100">
              {PAGE_TITLES[page] ?? "Scan Details"}
            </h2>
            {/* Back button for detail view */}
            {page === "detail" && (
              <button
                className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-400 transition-colors hover:border-slate-500 hover:text-slate-200"
                onClick={() => setPage("hist")}
              >
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
                Back to History
              </button>
            )}
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          {pages[page]}
        </main>
      </div>
    </div>
  );
}
