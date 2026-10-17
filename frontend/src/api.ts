export const tok = () => sessionStorage.getItem("t");

export const getApiBaseUrl = (): string => {
  const envUrl = import.meta.env.VITE_API_BASE_URL;
  if (envUrl && typeof envUrl === "string") {
    return envUrl.replace(/\/+$/, "");
  }
  return "";
};

export async function api(path: string, opts: RequestInit = {}, blob = false): Promise<any> {
  const h: Record<string, string> = {};
  if (tok()) h.Authorization = `Bearer ${tok()}`;
  if (typeof opts.body === "string") h["Content-Type"] = "application/json";
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}/api/v1${path}`;
  const r = await fetch(url, { ...opts, headers: h });
  if (r.status === 401 && tok()) { sessionStorage.removeItem("t"); location.reload(); }
  if (!r.ok) {
    let m = r.statusText;
    try { const j = await r.json(); m = typeof j.detail === "string" ? j.detail : j.detail?.[0]?.msg ?? m; } catch { /* ignore */ }
    throw new Error(m);
  }
  return blob ? r.blob() : r.json();
}

export async function dl(path: string, name: string) {
  const b = await api(path, {}, true);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(b); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
