"""Static file analysis. Files are NEVER executed or extracted; archives are only listed."""
import hashlib, io, re, zipfile
DANGEROUS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com", ".hta", ".lnk", ".sh"}
MACRO = {".docm", ".xlsm", ".pptm"}
DOCS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".zip"}
SIGS = [(b"MZ", "exe"), (b"%PDF", "pdf"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"),
        (b"PK\x03\x04", "zip"), (b"\x7fELF", "elf"), (b"Rar!", "rar"), (b"7z\xbc\xaf", "7z")]
EXT_SIG = {".exe": "exe", ".dll": "exe", ".scr": "exe", ".pdf": "pdf", ".png": "png", ".jpg": "jpg", ".jpeg": "jpg", ".gif": "gif",
           ".zip": "zip", ".docx": "zip", ".xlsx": "zip", ".pptx": "zip", ".docm": "zip", ".xlsm": "zip", ".jar": "zip"}

def safe_name(name: str) -> str:
    n = re.sub(r"[\x00-\x1f]", "", name.replace("\\", "/").split("/")[-1]).strip()
    return (n or "unnamed")[:100]

def analyze(name: str, data: bytes) -> dict:
    fn = safe_name(name); low = fn.lower(); exts = re.findall(r"\.[a-z0-9]{1,6}", low); ext = exts[-1] if exts else ""
    sig = next((s for m, s in SIGS if data.startswith(m)), "unknown")
    F = []
    def add(i, d, p): F.append({"indicator": i, "detail": d, "points": p})
    if ext in DANGEROUS: add("Executable/script extension", f"'{ext}' files can run code.", 30)
    if ext in MACRO: add("Macro-enabled Office file", "Macros can run code when enabled.", 25)
    if len(exts) >= 2 and exts[-1] in DANGEROUS and exts[-2] in DOCS: add("Double extension", f"'{fn}' looks like a document but ends in '{ext}'.", 35)
    if sig == "exe" and ext not in {".exe", ".dll", ".scr"}: add("Extension/signature mismatch", "Content is a Windows executable but the name says otherwise.", 40)
    elif ext in EXT_SIG and sig != "unknown" and EXT_SIG[ext] != sig: add("Extension/signature mismatch", f"Name says '{ext}' but content looks like '{sig}'.", 30)
    elif ext in EXT_SIG and sig == "unknown": add("Signature not recognised", f"Content does not match a typical '{ext}' file.", 15)
    if sig == "elf" and ext != ".elf": add("Linux executable content", "ELF binary detected.", 20)
    arch = None
    if sig == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist(); total = sum(i.file_size for i in infos)
                arch = {"entries": len(infos), "uncompressed_bytes": total}
                if len(infos) > 1000: add("Very many archive entries", f"{len(infos)} entries.", 15)
                if total > 100 * max(len(data), 1) and total > 10_000_000: add("Possible zip bomb", "Extreme compression ratio.", 30)
                if any(i.filename.startswith(("/", "\\")) or ".." in i.filename.replace("\\", "/").split("/") for i in infos):
                    add("Path traversal in archive", "Entry names try to escape the extraction folder.", 40)
                bad = [i.filename for i in infos if any(i.filename.lower().endswith(e) for e in DANGEROUS)]
                if bad and ext not in DANGEROUS: add("Executable inside archive", "e.g. " + ", ".join(b[:40] for b in bad[:3]), 20)
                if any(i.flag_bits & 1 for i in infos): add("Encrypted entries", "Contents cannot be inspected.", 10)
        except zipfile.BadZipFile: add("Corrupt archive", "ZIP structure is invalid.", 10)
    score = min(sum(f["points"] for f in F), 100)
    cat = "Low" if score < 30 else "Suspicious" if score < 60 else "High"
    recs = ["Never open files from unknown senders; do not enable macros.", "Scan the file with up-to-date antivirus before opening.",
            "Low score does NOT mean safe: static checks cannot detect all malware."]
    if cat != "Low": recs.insert(0, "Do not open or run this file. Delete it or send it to your security team.")
    return {"score": score, "category": cat, "findings": F, "recommendations": recs,
            "metadata": {"filename": fn, "extension": ext or "(none)", "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                         "detected_signature": sig, **({"archive": arch} if arch else {})},
            "disclaimer": "Static heuristics only; cannot prove a file is safe. Academic prototype."}
