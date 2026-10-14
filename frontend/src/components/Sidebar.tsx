interface SidebarProps {
  page: string;
  onNav: (page: string) => void;
  username?: string;
  onLogout: () => void;
}

const navItems: { key: string; icon: string; label: string }[] = [
  { key: "dash",   icon: "📊", label: "Dashboard"     },
  { key: "url",    icon: "🔗", label: "URL Scanner"   },
  { key: "file",   icon: "📁", label: "File Analyzer" },
  { key: "hist",   icon: "📋", label: "History"       },
  { key: "quiz",   icon: "🎓", label: "Awareness"     },
  { key: "me",     icon: "👤", label: "Profile"       },
];

export default function Sidebar({ page, onNav, username, onLogout }: SidebarProps) {
  return (
    <aside className="flex h-full flex-col border-r border-cyan-900/40 bg-[#07101f]">
      {/* Brand */}
      <div className="flex items-center gap-3 border-b border-cyan-900/30 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 text-xl ring-1 ring-cyan-500/30">
          🛡
        </div>
        <div>
          <p className="text-base font-bold text-cyan-400 leading-tight">CyberShield</p>
          <p className="text-[10px] text-slate-500 leading-tight">Threat Intelligence</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navItems.map(({ key, icon, label }) => (
          <button
            key={key}
            onClick={() => onNav(key)}
            className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${
              page === key
                ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/20"
                : "text-slate-400 hover:bg-slate-800/70 hover:text-slate-200"
            }`}
          >
            <span className="text-base">{icon}</span>
            {label}
            {page === key && (
              <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400" />
            )}
          </button>
        ))}
      </nav>

      {/* User + Logout */}
      <div className="border-t border-cyan-900/30 px-3 py-4 space-y-2">
        {username && (
          <div className="flex items-center gap-2 rounded-lg bg-[#0a1628] px-3 py-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-cyan-500/20 text-xs font-bold text-cyan-300">
              {username[0]?.toUpperCase()}
            </div>
            <span className="truncate text-sm text-slate-300">{username}</span>
          </div>
        )}
        <button
          onClick={onLogout}
          className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-slate-400 transition-all duration-200 hover:bg-red-500/10 hover:text-red-300"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
          </svg>
          Log out
        </button>
      </div>
    </aside>
  );
}
