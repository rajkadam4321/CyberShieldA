import { useEffect, useState, FormEvent, ReactNode } from "react";
type S = Record<string, any>;
const tok = () => sessionStorage.getItem("t");
async function api(path: string, opts: RequestInit = {}, blob = false): Promise<any> {
  const h: Record<string, string> = {};
  if (tok()) h.Authorization = `Bearer ${tok()}`;
  if (typeof opts.body === "string") h["Content-Type"] = "application/json";
  const r = await fetch("/api/v1" + path, { ...opts, headers: h });
  if (r.status === 401 && tok()) { sessionStorage.removeItem("t"); location.reload(); }
  if (!r.ok) { let m = r.statusText; try { const j = await r.json(); m = typeof j.detail === "string" ? j.detail : j.detail?.[0]?.msg ?? m; } catch { /* ignore */ } throw new Error(m); }
  return blob ? r.blob() : r.json();
}
async function dl(path: string, name: string) {
  const b = await api(path, {}, true); const a = document.createElement("a");
  a.href = URL.createObjectURL(b); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
const card = "rounded-xl border border-cyan-900/50 bg-[#0f2038] p-5";
const btn = "rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-slate-900 hover:bg-cyan-400 disabled:opacity-50";
const inp = "w-full rounded-lg border border-slate-600 bg-[#0a1628] px-3 py-2 outline-none focus:border-cyan-400";
const col: Record<string, string> = { High: "bg-red-500/20 text-red-300", Suspicious: "bg-amber-500/20 text-amber-300", Low: "bg-emerald-500/20 text-emerald-300" };
const Badge = ({ c }: { c: string }) => <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${col[c]}`}>{c}</span>;
const Err = ({ m }: { m: string }) => m ? <p role="alert" className="rounded-lg bg-red-500/15 p-2 text-sm text-red-300">{m}</p> : null;

function Auth({ onIn }: { onIn: () => void }) {
  const [reg, setReg] = useState(false), [u, setU] = useState(""), [p, setP] = useState(""), [e, setE] = useState(""), [ok, setOk] = useState(""), [b, setB] = useState(false);
  async function go(ev: FormEvent) {
    ev.preventDefault(); setE(""); setOk(""); setB(true);
    try {
      const body = JSON.stringify({ username: u, password: p });
      if (reg) { await api("/auth/register", { method: "POST", body }); setReg(false); setOk("Account created. Please log in."); }
      else { const r = await api("/auth/login", { method: "POST", body }); sessionStorage.setItem("t", r.access_token); onIn(); }
    } catch (x: any) { setE(x.message); } finally { setB(false); }
  }
  return <div className="grid min-h-screen place-items-center p-4"><form onSubmit={go} className={`${card} w-full max-w-sm space-y-4`}>
    <h1 className="text-2xl font-bold text-cyan-400">🛡 CyberShield</h1><p className="text-sm text-slate-400">{reg ? "Create account" : "Sign in"}</p>
    <input className={inp} placeholder="Username (3-32: letters, digits, _ . -)" value={u} onChange={e => setU(e.target.value)} required minLength={3} maxLength={32} />
    <input className={inp} type="password" placeholder="Password (min 8)" value={p} onChange={e => setP(e.target.value)} required minLength={8} />
    <Err m={e} />{ok && <p className="text-sm text-emerald-300">{ok}</p>}
    <button className={btn + " w-full"} disabled={b}>{b ? "Please wait…" : reg ? "Register" : "Login"}</button>
    <button type="button" className="text-sm text-cyan-300 underline" onClick={() => { setReg(!reg); setE(""); }}>{reg ? "Have an account? Login" : "New here? Register"}</button>
  </form></div>;
}

function Result({ s }: { s: S }) {
  const items = s.findings ?? [];
  return <div className={card + " space-y-4"}>
    <div className="flex flex-wrap items-center gap-3"><span className="text-4xl font-bold text-cyan-300">{s.score}<span className="text-lg text-slate-400">/100</span></span><Badge c={s.category} />
      <span className="text-xs text-slate-400">Mode: {s.mode}</span></div>
    <div className="h-2 rounded bg-slate-700"><div className={`h-2 rounded ${s.category === "High" ? "bg-red-500" : s.category === "Suspicious" ? "bg-amber-400" : "bg-emerald-400"}`} style={{ width: `${s.score}%` }} /></div>
    <p className="break-all text-sm text-slate-300">{s.target}</p>
    {s.metadata && <dl className="grid gap-1 text-sm sm:grid-cols-2">{Object.entries(s.metadata).map(([k, v]) => <div key={k} className="break-all"><dt className="inline text-slate-400">{k}: </dt><dd className="inline">{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd></div>)}</dl>}
    <div><h3 className="font-semibold">Threat indicators</h3>{items.length ? <ul className="mt-1 space-y-1 text-sm">{items.map((f: S, i: number) => <li key={i}><b className="text-amber-300">{f.indicator}</b> (+{f.points}) – {f.detail}</li>)}</ul> : <p className="text-sm text-slate-400">No indicators found. This does not guarantee safety.</p>}</div>
    <div><h3 className="font-semibold">Recommendations</h3><ul className="list-disc pl-5 text-sm">{(s.recommendations ?? []).map((r: string, i: number) => <li key={i}>{r}</li>)}</ul></div>
    <p className="text-xs text-slate-400">{s.disclaimer} Scanned {s.created_at && new Date(s.created_at).toLocaleString()}</p>
    <button className={btn} onClick={() => dl(`/scans/${s.id}/report.pdf`, `cybershield_${s.id}.pdf`).catch(e => alert(e.message))}>Download PDF report</button>
  </div>;
}

function Dashboard({ open }: { open: (id: number) => void }) {
  const [d, setD] = useState<S>(), [rec, setRec] = useState<S[]>([]), [e, setE] = useState("");
  useEffect(() => { Promise.all([api("/dashboard"), api("/scans?size=100")]).then(([a, b]) => { setD(a); setRec(b.items); }).catch(x => setE(x.message)); }, []);
  if (e) return <Err m={e} />; if (!d) return <p>Loading…</p>;
  const days: Record<string, number> = {}; rec.forEach(s => { const k = s.created_at.slice(0, 10); days[k] = (days[k] ?? 0) + 1; });
  const keys = Object.keys(days).sort().slice(-7), mx = Math.max(1, ...keys.map(k => days[k]));
  const stat = (l: string, v: number, c = "text-cyan-300") => <div className={card}><p className="text-sm text-slate-400">{l}</p><p className={`text-3xl font-bold ${c}`}>{v}</p></div>;
  return <div className="space-y-5"><div className="grid grid-cols-2 gap-4 lg:grid-cols-4">{stat("Total scans", d.total)}{stat("High risk", d.high, "text-red-400")}{stat("Suspicious", d.suspicious, "text-amber-300")}{stat("Lower risk", d.low, "text-emerald-300")}</div>
    <div className="grid gap-4 md:grid-cols-2"><div className={card}><h3 className="mb-2 font-semibold">URL vs file scans</h3><p>URL: {d.url} · File: {d.file}</p></div>
      <div className={card}><h3 className="mb-2 font-semibold">Activity (last days)</h3>{keys.length ? <div className="flex h-24 items-end gap-2">{keys.map(k => <div key={k} className="flex-1 text-center text-[10px]"><div className="rounded-t bg-cyan-500" style={{ height: `${(days[k] / mx) * 80}px` }} />{k.slice(5)}</div>)}</div> : <p className="text-sm text-slate-400">No scans yet. Run your first scan.</p>}</div></div>
    <div className={card}><h3 className="mb-2 font-semibold">Recent scans</h3>{rec.length ? <ScanTable rows={rec.slice(0, 5)} open={open} /> : <p className="text-sm text-slate-400">Nothing here yet.</p>}</div></div>;
}
function ScanTable({ rows, open }: { rows: S[]; open: (id: number) => void }) {
  return <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-slate-400"><tr><th>Type</th><th>Target</th><th>Score</th><th>Risk</th><th>Date</th></tr></thead><tbody>
    {rows.map(s => <tr key={s.id} className="cursor-pointer border-t border-slate-700 hover:bg-slate-800" onClick={() => open(s.id)}><td>{s.kind}</td><td className="max-w-[16rem] truncate">{s.target}</td><td>{s.score}</td><td><Badge c={s.category} /></td><td>{new Date(s.created_at).toLocaleDateString()}</td></tr>)}</tbody></table></div>;
}

function Scanner({ kind }: { kind: "url" | "file" }) {
  const [v, setV] = useState(""), [f, setF] = useState<File | null>(null), [r, setR] = useState<S>(), [e, setE] = useState(""), [b, setB] = useState(false);
  async function go(ev: FormEvent) {
    ev.preventDefault(); setE(""); setR(undefined); setB(true);
    try {
      if (kind === "url") setR(await api("/scans/url", { method: "POST", body: JSON.stringify({ url: v }) }));
      else { const fd = new FormData(); fd.append("file", f!); setR(await api("/scans/file", { method: "POST", body: fd })); }
    } catch (x: any) { setE(x.message); } finally { setB(false); }
  }
  return <div className="space-y-4"><form onSubmit={go} className={card + " space-y-3"}>
    <p className="text-sm text-slate-400">{kind === "url" ? "The URL is analysed as text only; it is never visited." : "Files are analysed statically and never executed. Max 5 MB by default."}</p>
    {kind === "url" ? <input className={inp} placeholder="https://example.com/login" value={v} onChange={x => setV(x.target.value)} required />
      : <input className={inp} type="file" onChange={x => setF(x.target.files?.[0] ?? null)} required />}
    <Err m={e} /><button className={btn} disabled={b}>{b ? "Scanning…" : "Scan"}</button></form>{r && <Result s={r} />}</div>;
}

function History({ open }: { open: (id: number) => void }) {
  const [pg, setPg] = useState(1), [cat, setCat] = useState(""), [d, setD] = useState<S>(), [e, setE] = useState("");
  useEffect(() => { api(`/scans?page=${pg}&size=10${cat ? `&category=${cat}` : ""}`).then(setD).catch(x => setE(x.message)); }, [pg, cat]);
  return <div className={card + " space-y-3"}><div className="flex flex-wrap gap-2">
    <select className={inp + " !w-auto"} value={cat} onChange={x => { setCat(x.target.value); setPg(1); }}><option value="">All risks</option><option>High</option><option>Suspicious</option><option>Low</option></select>
    <button className={btn} onClick={() => dl("/scans/export.csv", "scan_history.csv").catch(x => setE(x.message))}>Export CSV</button></div><Err m={e} />
    {!d ? <p>Loading…</p> : d.items.length ? <ScanTable rows={d.items} open={open} /> : <p className="text-sm text-slate-400">No scans found.</p>}
    <div className="flex items-center gap-3"><button className={btn} disabled={pg <= 1} onClick={() => setPg(pg - 1)}>Prev</button><span className="text-sm">Page {pg}</span>
      <button className={btn} disabled={!d || pg * 10 >= d.total} onClick={() => setPg(pg + 1)}>Next</button></div></div>;
}
function Detail({ id }: { id: number }) {
  const [s, setS] = useState<S>(), [e, setE] = useState("");
  useEffect(() => { api(`/scans/${id}`).then(setS).catch(x => setE(x.message)); }, [id]);
  return e ? <Err m={e} /> : s ? <Result s={s} /> : <p>Loading…</p>;
}

function Quiz() {
  const [qs, setQs] = useState<S[]>([]), [a, setA] = useState<number[]>([]), [res, setRes] = useState<S>(), [e, setE] = useState(""), [hist, setH] = useState<S[]>([]);
  const load = () => { api("/awareness/quiz").then(x => { setQs(x.questions); setA(x.questions.map(() => -1)); }).catch(x => setE(x.message)); api("/awareness/attempts").then(setH).catch(() => {}); };
  useEffect(load, []);
  async function sub() { try { setRes(await api("/awareness/quiz/submit", { method: "POST", body: JSON.stringify({ answers: a }) })); api("/awareness/attempts").then(setH); } catch (x: any) { setE(x.message); } }
  return <div className="space-y-4"><div className={card}><h3 className="font-semibold">Awareness tips</h3><ul className="list-disc pl-5 text-sm text-slate-300">
    <li>Phishing signs: urgency, look-alike domains, unexpected attachments, requests for passwords.</li><li>Use unique passphrases, a password manager and multi-factor authentication.</li><li>Type official addresses yourself instead of clicking unexpected links.</li></ul></div>
    {qs.map((q, i) => <div key={q.id} className={card}><p className="mb-2 font-semibold">{i + 1}. {q.question}</p>{q.options.map((o: string, j: number) => <label key={j} className="block text-sm"><input type="radio" name={`q${i}`} disabled={!!res} checked={a[i] === j} onChange={() => setA(a.map((x, k) => k === i ? j : x))} /> {o}</label>)}
      {res && <p className={`mt-2 text-sm ${res.results[i].correct ? "text-emerald-300" : "text-red-300"}`}>{res.results[i].correct ? "Correct. " : "Incorrect. "}{res.results[i].explanation}</p>}</div>)}
    <Err m={e} />{res ? <div className={card}>Score: <b>{res.score}/{res.total}</b> <button className={btn + " ml-3"} onClick={() => { setRes(undefined); load(); }}>Retry</button></div>
      : <button className={btn} disabled={a.includes(-1)} onClick={sub}>Submit</button>}
    {hist.length > 0 && <div className={card}><h3 className="font-semibold">Past attempts</h3>{hist.map((h, i) => <p key={i} className="text-sm">{new Date(h.created_at).toLocaleString()} – {h.score}/{h.total}</p>)}</div>}</div>;
}
function Profile({ out }: { out: () => void }) {
  const [u, setU] = useState<S>(); useEffect(() => { api("/users/me").then(setU).catch(() => {}); }, []);
  return <div className={card + " space-y-3"}><p>User: <b>{u?.username}</b></p><p className="text-xs text-slate-400">Academic prototype. Not a replacement for enterprise security products.</p>
    <button className={btn} onClick={() => { if (confirm("Log out?")) out(); }}>Logout</button></div>;
}

export default function App() {
  const [ok, setOk] = useState(!!tok()), [pg, setPg] = useState("dash"), [sel, setSel] = useState(0), [menu, setMenu] = useState(false);
  if (!ok) return <Auth onIn={() => setOk(true)} />;
  const open = (id: number) => { setSel(id); setPg("detail"); };
  const out = () => { sessionStorage.removeItem("t"); setOk(false); };
  const nav: [string, string][] = [["dash", "Dashboard"], ["url", "URL Scanner"], ["file", "File Analyzer"], ["hist", "History"], ["quiz", "Awareness"], ["me", "Profile"]];
  const pages: Record<string, ReactNode> = { dash: <Dashboard open={open} />, url: <Scanner kind="url" />, file: <Scanner kind="file" />, hist: <History open={open} />, detail: <Detail id={sel} />, quiz: <Quiz />, me: <Profile out={out} /> };
  return <div className="min-h-screen md:flex">
    <aside className="border-b border-cyan-900/50 bg-[#07101f] p-4 md:w-56 md:border-b-0 md:border-r"><div className="flex items-center justify-between"><h1 className="text-xl font-bold text-cyan-400">🛡 CyberShield</h1><button className="md:hidden" onClick={() => setMenu(!menu)}>☰</button></div>
      <nav className={`${menu ? "block" : "hidden"} mt-4 space-y-1 md:block`}>{nav.map(([k, l]) => <button key={k} onClick={() => { setPg(k); setMenu(false); }} className={`block w-full rounded-lg px-3 py-2 text-left ${pg === k ? "bg-cyan-500/20 text-cyan-300" : "hover:bg-slate-800"}`}>{l}</button>)}</nav></aside>
    <main className="flex-1 p-4 md:p-6"><h2 className="mb-4 text-xl font-semibold">{nav.find(n => n[0] === pg)?.[1] ?? "Scan details"}</h2>{pages[pg]}</main></div>;
}
