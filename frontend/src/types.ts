export type S = Record<string, any>;

export const card = "rounded-xl border border-cyan-900/50 bg-[#0f2038] p-5 shadow-lg shadow-cyan-900/20";
export const btn = "rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-600 px-4 py-2 font-semibold text-slate-900 hover:from-cyan-400 hover:to-cyan-500 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed";
export const inp = "w-full rounded-lg border border-slate-600 bg-[#0a1628] px-3 py-2 outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all duration-200";
export const col: Record<string, string> = {
  High: "bg-red-500/20 text-red-300 border border-red-500/30",
  Suspicious: "bg-amber-500/20 text-amber-300 border border-amber-500/30",
  Low: "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30",
};
