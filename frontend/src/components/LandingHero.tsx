import { useState } from "react";
import AuthModal from "./AuthModal";

interface LandingHeroProps {
  onIn: () => void;
}

const features = [
  { icon: "🔗", label: "URL Scan", desc: "Detect phishing & malicious links" },
  { icon: "📁", label: "File Analysis", desc: "Static malware detection" },
  { icon: "🤖", label: "AI-Powered", desc: "Heuristic threat scoring" },
  { icon: "📊", label: "Reports", desc: "Detailed PDF threat reports" },
];

export default function LandingHero({ onIn }: LandingHeroProps) {
  const [showModal, setShowModal] = useState(false);

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#0a1628]">
      {/* Animated background grid */}
      <div className="pointer-events-none absolute inset-0 bg-cyber-grid opacity-20" />
      {/* Glow orbs */}
      <div className="pointer-events-none absolute -left-32 top-1/4 h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute -right-32 bottom-1/4 h-96 w-96 rounded-full bg-purple-500/10 blur-3xl" />

      <div className="relative z-10 flex min-h-screen flex-col items-center justify-center px-4 text-center">
        {/* Animated Shield */}
        <div className="mb-8 animate-float">
          <div className="relative inline-flex h-28 w-28 items-center justify-center rounded-full bg-cyan-500/10 ring-2 ring-cyan-500/30">
            <div className="absolute inset-0 rounded-full animate-ping-slow bg-cyan-400/10" />
            <span className="text-6xl">🛡</span>
          </div>
        </div>

        {/* Title */}
        <h1 className="mb-4 text-5xl font-extrabold tracking-tight sm:text-6xl">
          <span className="text-slate-100">Cyber</span>
          <span className="bg-gradient-to-r from-cyan-400 to-cyan-300 bg-clip-text text-transparent">Shield</span>
        </h1>

        <p className="mb-2 text-xl font-medium text-slate-300">
          AI-Powered Cybersecurity Threat Detection
        </p>
        <p className="mb-10 max-w-lg text-sm text-slate-500">
          Analyse URLs and files for phishing, malware, and social engineering threats
          using heuristic AI scoring — before you click or open anything suspicious.
        </p>

        {/* CTA Buttons */}
        <div className="mb-14 flex flex-wrap items-center justify-center gap-3">
          <button
            onClick={() => setShowModal(true)}
            className="rounded-xl bg-gradient-to-r from-cyan-500 to-cyan-600 px-8 py-3 font-bold text-slate-900 shadow-lg shadow-cyan-900/40 transition-all duration-200 hover:from-cyan-400 hover:to-cyan-500 hover:shadow-cyan-400/30"
          >
            Get Started →
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="rounded-xl border border-cyan-800 px-8 py-3 font-semibold text-cyan-300 transition-all duration-200 hover:border-cyan-500 hover:text-cyan-100 hover:bg-cyan-500/10"
          >
            Sign In
          </button>
        </div>

        {/* Feature Pills */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {features.map((f) => (
            <div
              key={f.label}
              className="flex flex-col items-center gap-2 rounded-xl border border-cyan-900/40 bg-[#0f2038] px-4 py-4 shadow-lg shadow-cyan-900/10 transition-all duration-200 hover:border-cyan-700/60 hover:bg-[#132840]"
            >
              <span className="text-2xl">{f.icon}</span>
              <span className="text-sm font-semibold text-slate-200">{f.label}</span>
              <span className="text-center text-xs text-slate-500">{f.desc}</span>
            </div>
          ))}
        </div>

        {/* Footer note */}
        <p className="mt-12 text-xs text-slate-600">
          Academic prototype · Not a substitute for enterprise security products
        </p>
      </div>

      {/* Auth Modal */}
      {showModal && (
        <AuthModal onIn={onIn} onClose={() => setShowModal(false)} />
      )}
    </div>
  );
}
