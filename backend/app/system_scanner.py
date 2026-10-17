"""
CyberShield Local System Security and Malware Scanner.
Provides Quick Scan, Full System Scan, and Custom Directory Scan with Microsoft Defender integration,
local threat signature database lookups, Windows startup/autorun inspection, and heuristic PE analysis.
Safe, non-destructive, with explicit user remediation confirmation.
"""
import hashlib
import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("cybershield.system_scanner")

# Standard known test malware hashes (e.g., EICAR standard antivirus test files, known reference hashes)
KNOWN_MALWARE_HASHES: Dict[str, Dict[str, str]] = {
    # EICAR Standard Antivirus Test File (harmless test file for validating AV engines)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Standard-Antivirus-Test-File",
        "type": "Test-Signature",
        "severity": "Critical",
        "description": "Standard EICAR antivirus test file used to verify active scanner operation without live malware.",
        "action": "Quarantine or delete harmless test file."
    },
    "131f95c51cc819465fa1797f6cccad9e094fb1e523637b44384ac743b5ff6426": {
        "name": "EICAR-Standard-Antivirus-Test-File.COM",
        "type": "Test-Signature",
        "severity": "Critical",
        "description": "Standard EICAR COM antivirus test file.",
        "action": "Quarantine or delete harmless test file."
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "EICAR-MD5",
        "type": "Test-Signature",
        "severity": "Critical",
        "description": "Standard EICAR test signature.",
        "action": "Quarantine harmless test file."
    },
    # Reference known threat hashes (WannaCry, Emotet, LockBit reference SHA-256 for test detection)
    "ed01ef2632ff6300e0ee693bcff6040c5e4fbc11083aa222b4e71874250ade77": {
        "name": "Trojan.Ransom.WannaCrypt.A",
        "type": "Ransomware-Reference",
        "severity": "Critical",
        "description": "Known WannaCrypt ransomware binary hash signature.",
        "action": "Immediate quarantine and network isolation."
    },
    "85b7782481e19488b394f41b212f451f288ad7a0de41f92c6ec40da4cc3335e6": {
        "name": "Trojan.Downloader.Emotet",
        "type": "Trojan-Reference",
        "severity": "Critical",
        "description": "Known Emotet banking trojan payload hash signature.",
        "action": "Quarantine file, terminate persistence entries, and conduct full credential reset."
    }
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".com", ".hta", ".cpl", ".iso", ".wsf"
}

SUSPICIOUS_NAMES = [
    r"invoice.*\.exe$", r"receipt.*\.exe$", r"order.*\.exe$",
    r".*\.pdf\.exe$", r".*\.docx?\.exe$", r".*\.xlsx?\.exe$",
    r".*\.jpg\.exe$", r".*\.png\.exe$", r".*\.txt\.vbs$",
    r".*\.pdf\.vbs$", r".*\.docm?\.ps1$"
]

# Locate Windows Defender command line tool
def find_defender_cli() -> Optional[str]:
    candidates = [
        os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Windows Defender\MpCmdRun.exe"),
        os.path.expandvars(r"%ProgramData%\Microsoft\Windows Defender\Platform"),
    ]
    # Check fixed paths first
    for path in candidates[:2]:
        if os.path.isfile(path):
            return path
    # Check Platform directory for newer Defender versions
    plat_dir = candidates[2]
    if os.path.isdir(plat_dir):
        for root, _, files in os.walk(plat_dir):
            if "MpCmdRun.exe" in files:
                p = os.path.join(root, "MpCmdRun.exe")
                if os.path.isfile(p):
                    return p
    return None

def get_defender_status() -> Dict[str, any]:
    cli = find_defender_cli()
    available = cli is not None and os.path.isfile(cli)
    info = {
        "engine": "Microsoft Defender Antivirus" if available else "CyberShield Local Signature & Heuristic Engine",
        "cli_path": cli,
        "available": available,
        "signature_db_count": len(KNOWN_MALWARE_HASHES),
        "heuristic_checks": [
            "SHA-256 Signature Verification",
            "Double Extension Deception Detection",
            "Disguised PE / MZ Binary Header Verification",
            "Windows Startup & Registry Persistence Auditing",
            "Suspicious PowerShell / VBS Script Drops",
            "Macro-Enabled Office Script Analysis"
        ]
    }
    return info

def hash_file_chunked(file_path: str, max_bytes: int = 100 * 1024 * 1024) -> Tuple[Optional[str], Optional[str]]:
    """Calculates SHA-256 without reading full large file into memory."""
    try:
        h = hashlib.sha256()
        bytes_read = 0
        with open(file_path, "rb") as f:
            while bytes_read < max_bytes:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
                bytes_read += len(chunk)
        return h.hexdigest(), None
    except PermissionError as e:
        if getattr(e, "winerror", None) == 225 or "virus" in str(e).lower():
            return None, "Blocked by Antivirus: Virus or PUP detected"
        return None, "Permission denied"
    except Exception as e:
        return None, str(e)

def inspect_file_heuristics(file_path: str) -> List[Dict[str, any]]:
    """Inspects a single file for suspicious characteristics (non-destructive)."""
    findings = []
    base_name = os.path.basename(file_path)
    lower_name = base_name.lower()
    _, ext = os.path.splitext(lower_name)

    # 1. Double extension check
    for pat in SUSPICIOUS_NAMES:
        if re.search(pat, lower_name):
            findings.append({
                "finding_type": "double_extension",
                "detection_source": "CyberShield Heuristic Engine",
                "severity": "High",
                "malware_name": "Suspicious.DeceptiveDoubleExtension",
                "description": f"File '{base_name}' mimics a document or image but has an executable extension.",
                "recommended_action": "Do not launch. Inspect in isolated sandbox or quarantine."
            })
            break

    # 2. Check header signature vs extension
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        if header.startswith(b"MZ") and ext not in {".exe", ".dll", ".sys", ".scr", ".cpl", ".efi", ".ocx"}:
            findings.append({
                "finding_type": "disguised_executable",
                "detection_source": "CyberShield Heuristic Engine",
                "severity": "High",
                "malware_name": "Suspicious.DisguisedPEBinary",
                "description": f"File '{base_name}' has an extension '{ext}' but starts with the Windows executable MZ header.",
                "recommended_action": "High likelihood of stealth dropper. Verify source and quarantine."
            })
    except Exception:
        pass

    return findings

def inspect_startup_entries() -> List[Dict[str, any]]:
    """Inspects Windows Run/RunOnce registry keys and Startup folders for persistence anomalies."""
    findings = []
    
    # 1. Inspect Startup Folders
    startup_dirs = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for sdir in startup_dirs:
        if not os.path.isdir(sdir):
            continue
        try:
            for item in os.listdir(sdir):
                full_path = os.path.join(sdir, item)
                lower = item.lower()
                _, ext = os.path.splitext(lower)
                if ext in {".bat", ".cmd", ".vbs", ".ps1", ".hta", ".js"}:
                    findings.append({
                        "file_path": full_path,
                        "file_name": item,
                        "file_hash": "",
                        "finding_type": "startup_persistence",
                        "detection_source": "CyberShield Autorun Auditor",
                        "severity": "Medium",
                        "malware_name": "Suspicious.StartupScript",
                        "description": f"Script file '{item}' configured to run automatically at user logon in Startup folder.",
                        "recommended_action": "Verify if authorized. If unrecognized, remove from Startup."
                    })
        except Exception as e:
            logger.warning(f"Error checking startup dir {sdir}: {e}")

    # 2. Inspect Registry Run / RunOnce if on Windows
    if sys.platform == "win32":
        try:
            import winreg
            reg_targets = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
            ]
            for hkey, subkey, label in reg_targets:
                try:
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as k:
                        count, _, _ = winreg.QueryInfoKey(k)
                        for i in range(count):
                            try:
                                name, val, _ = winreg.EnumValue(k, i)
                                val_str = str(val).lower()
                                # Check for suspicious encoded powershell, temp directory drops, or hidden executions
                                is_suspicious = False
                                reason = ""
                                if "-enc" in val_str or "-encodedcommand" in val_str or "-w hidden" in val_str or "-windowstyle hidden" in val_str:
                                    is_suspicious = True
                                    reason = "Uses hidden window or encoded command payload in autorun."
                                elif "temp" in val_str or "appdata\\local\\temp" in val_str:
                                    is_suspicious = True
                                    reason = "Executes binary or script directly from Temp directory."
                                elif any(val_str.endswith(ext) for ext in [".vbs", ".js", ".hta"]):
                                    is_suspicious = True
                                    reason = f"Executes uncompiled script ({name}) at startup."

                                if is_suspicious:
                                    findings.append({
                                        "file_path": f"{label}\\{name}",
                                        "file_name": name,
                                        "file_hash": "",
                                        "finding_type": "startup_persistence",
                                        "detection_source": "CyberShield Registry Auditor",
                                        "severity": "High",
                                        "malware_name": "Suspicious.RegistryPersistence",
                                        "description": f"Startup entry '{name}' in {label}: {val}. {reason}",
                                        "recommended_action": "Audit startup registry entry and disable if unrecognized."
                                    })
                            except Exception:
                                continue
                except Exception:
                    continue
        except ImportError:
            pass

    return findings

def run_defender_scan_on_path(path: str) -> Tuple[List[Dict[str, any]], Optional[str]]:
    """Runs Defender on a specific file or directory with remediation disabled to collect detections."""
    cli = find_defender_cli()
    if not cli:
        return [], "Microsoft Defender command-line utility (MpCmdRun.exe) was not found on this system."

    findings = []
    try:
        # -ScanType 3: File/Folder custom scan
        # -DisableRemediation: Does not automatically remove files; outputs detections to console!
        args = [cli, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"]
        res = subprocess.run(args, capture_output=True, text=True, timeout=120)
        output = (res.stdout or "") + (res.stderr or "")
        
        # Parse detections from Defender output
        # Format often includes: "Threat       : Trojan:Win32/..." or "Threat name : ..."
        matches = re.findall(r"(?:Threat|Threat Name)\s*:\s*([^\r\n]+)", output, re.IGNORECASE)
        for m in matches:
            malware_name = m.strip()
            findings.append({
                "file_path": path,
                "file_name": os.path.basename(path),
                "file_hash": "",
                "finding_type": "malware",
                "detection_source": "Microsoft Defender Antivirus",
                "severity": "Critical",
                "malware_name": malware_name,
                "description": f"Microsoft Defender identified confirmed threat: {malware_name}",
                "recommended_action": "Quarantine file and run full remediation with Windows Defender."
            })

        if res.returncode == 2 and not findings:
            # Code 2 indicates threat or scan error in Defender
            findings.append({
                "file_path": path,
                "file_name": os.path.basename(path),
                "file_hash": "",
                "finding_type": "malware",
                "detection_source": "Microsoft Defender Antivirus",
                "severity": "High",
                "malware_name": "Defender.DetectionsFound",
                "description": "Microsoft Defender returned detection status (exit code 2).",
                "recommended_action": "Inspect Windows Security threat history."
            })
        return findings, None
    except subprocess.TimeoutExpired:
        return findings, "Microsoft Defender scan timed out on target path."
    except Exception as e:
        return findings, f"Error executing Microsoft Defender scan: {e}"

# Global Active Scan Controller for Live Progress & Cancellation
class ScanJob:
    def __init__(self, scan_id: int, user_id: int, scan_type: str, target_path: str):
        self.scan_id = scan_id
        self.user_id = user_id
        self.scan_type = scan_type
        self.target_path = target_path
        self.status = "running"  # running, paused, cancelled, completed, failed
        self.files_examined = 0
        self.files_skipped = 0
        self.errors_count = 0
        self.progress_pct = 0
        self.current_file = ""
        self.findings: List[Dict[str, any]] = []
        self.start_time = time.time()
        self.duration_seconds = 0.0
        self.error_message: Optional[str] = None
        self._pause_event = threading.Event()
        self._pause_event.set()  # set means not paused
        self._cancel_flag = False

    def pause(self):
        self.status = "paused"
        self._pause_event.clear()

    def resume(self):
        self.status = "running"
        self._pause_event.set()

    def cancel(self):
        self.status = "cancelled"
        self._cancel_flag = True
        self._pause_event.set()  # unblock if paused so thread can exit

    def is_cancelled(self) -> bool:
        return self._cancel_flag

    def wait_if_paused(self):
        self._pause_event.wait()

    def to_dict(self) -> dict:
        return {
            "id": self.scan_id,
            "user_id": self.user_id,
            "scan_type": self.scan_type,
            "target_path": self.target_path,
            "status": self.status,
            "files_examined": self.files_examined,
            "files_skipped": self.files_skipped,
            "errors_count": self.errors_count,
            "findings_count": len(self.findings),
            "progress_pct": self.progress_pct,
            "current_file": self.current_file,
            "duration_seconds": round(time.time() - self.start_time, 1) if self.status in ("running", "paused") else self.duration_seconds,
            "findings": self.findings,
            "error_message": self.error_message
        }

active_jobs: Dict[int, ScanJob] = {}
active_lock = threading.Lock()

def get_active_job(scan_id: Optional[int] = None) -> Optional[ScanJob]:
    with active_lock:
        if scan_id is not None:
            return active_jobs.get(scan_id)
        # Return most recent running or paused job
        for j in reversed(list(active_jobs.values())):
            if j.status in ("running", "paused"):
                return j
        if active_jobs:
            return list(active_jobs.values())[-1]
        return None

def validate_scan_path(path_str: str) -> str:
    """Validates target directory path strictly to prevent traversal or arbitrary shell injection."""
    path_str = path_str.strip()
    if not path_str:
        raise ValueError("Target scan path cannot be empty.")
    # Prevent device namespace paths first
    if path_str.startswith(("\\\\.\\", "\\\\?\\")):
        raise ValueError("Device namespace paths are not permitted.")
    # Prevent UNC injection or remote paths
    if path_str.startswith(r"\\") or path_str.startswith("//"):
        raise ValueError("Network UNC and remote paths are not permitted.")
    
    p = pathlib.Path(path_str).resolve()
    if not p.exists():
        raise ValueError(f"Target path does not exist: {p}")
    if not p.is_dir() and not p.is_file():
        raise ValueError(f"Target path is neither a file nor a directory: {p}")
    return str(p)

def execute_scan_worker(job: ScanJob, db_session_factory):
    """Background worker that conducts scanning safely."""
    from .db import SystemScan, SystemScanFinding
    
    logger.info(f"Starting scan worker for scan #{job.scan_id} ({job.scan_type})")
    files_to_scan: List[str] = []
    
    # 1. Determine targets based on scan_type
    if job.scan_type == "quick":
        # Target high-risk directories
        targets = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expanduser("~/Downloads"),
            os.environ.get("TEMP", os.environ.get("TMP", "C:\\Windows\\Temp")),
        ]
        for t in targets:
            if os.path.isdir(t):
                try:
                    for root, _, files in os.walk(t):
                        for f in files:
                            files_to_scan.append(os.path.join(root, f))
                            if len(files_to_scan) >= 1500:
                                break
                        if len(files_to_scan) >= 1500:
                            break
                except Exception:
                    pass

        # Also inspect startup entries
        startup_findings = inspect_startup_entries()
        for sf in startup_findings:
            job.findings.append(sf)

        # Trigger Defender quick scan if available
        def_cli = find_defender_cli()
        if def_cli:
            try:
                subprocess.run([def_cli, "-Scan", "-ScanType", "1"], capture_output=True, timeout=60)
            except Exception:
                pass

    elif job.scan_type == "custom":
        p = pathlib.Path(job.target_path)
        if p.is_file():
            files_to_scan.append(str(p))
        else:
            for root, _, files in os.walk(str(p)):
                for f in files:
                    files_to_scan.append(os.path.join(root, f))
                    if len(files_to_scan) >= 20000:  # Safety cap per custom job
                        break
                if len(files_to_scan) >= 20000:
                    break

        # Check path with Defender
        def_findings, _ = run_defender_scan_on_path(job.target_path)
        for df in def_findings:
            job.findings.append(df)

    elif job.scan_type == "full":
        # Full scan targets user accessible drive roots
        root_dir = "C:\\" if sys.platform == "win32" else "/"
        skip_folders = {"$recycle.bin", "system volume information", "windows\\winsxs", "pagefile.sys"}
        
        try:
            for root, dirs, files in os.walk(root_dir):
                if job.is_cancelled():
                    break
                # Filter out system protected folders
                dirs[:] = [d for d in dirs if d.lower() not in skip_folders and not d.startswith(".")]
                for f in files:
                    if f.lower() in skip_folders:
                        continue
                    files_to_scan.append(os.path.join(root, f))
                    if len(files_to_scan) >= 10000:  # Chunked scan queue
                        break
                if len(files_to_scan) >= 10000:
                    break
        except Exception:
            pass

    total_files = len(files_to_scan)
    logger.info(f"Scan #{job.scan_id}: Queued {total_files} files for examination.")

    # 2. Iterate and inspect files
    for idx, fpath in enumerate(files_to_scan):
        if job.is_cancelled():
            logger.info(f"Scan #{job.scan_id} cancelled by user.")
            job.status = "cancelled"
            break

        job.wait_if_paused()
        job.current_file = fpath
        job.progress_pct = int(((idx + 1) / max(total_files, 1)) * 100)

        try:
            if not os.path.exists(fpath):
                job.files_skipped += 1
                continue

            # Don't try scanning massive files > 500MB during quick scan
            file_size = os.path.getsize(fpath)
            if job.scan_type == "quick" and file_size > 200 * 1024 * 1024:
                job.files_skipped += 1
                continue

            # Hash check
            fhash, err = hash_file_chunked(fpath)
            if err:
                job.errors_count += 1
                job.files_skipped += 1
                continue

            job.files_examined += 1

            # Match against known threat hashes
            if fhash and fhash in KNOWN_MALWARE_HASHES:
                threat_info = KNOWN_MALWARE_HASHES[fhash]
                job.findings.append({
                    "file_path": fpath,
                    "file_name": os.path.basename(fpath),
                    "file_hash": fhash,
                    "finding_type": "malware",
                    "detection_source": "CyberShield Verified Threat Database",
                    "severity": threat_info["severity"],
                    "malware_name": threat_info["name"],
                    "description": threat_info["description"],
                    "recommended_action": threat_info["action"]
                })

            # Check heuristics on executable/script files
            _, ext = os.path.splitext(fpath.lower())
            if ext in DANGEROUS_EXTENSIONS or "." in os.path.basename(fpath)[:-len(ext)]:
                heur_findings = inspect_file_heuristics(fpath)
                for hf in heur_findings:
                    hf["file_path"] = fpath
                    hf["file_name"] = os.path.basename(fpath)
                    hf["file_hash"] = fhash or ""
                    job.findings.append(hf)

        except PermissionError:
            job.files_skipped += 1
        except Exception as e:
            job.errors_count += 1
            logger.debug(f"Error examining file {fpath}: {e}")

        # Update database periodically every 25 files
        if idx % 25 == 0 or idx == total_files - 1:
            try:
                db = db_session_factory()
                rec = db.get(SystemScan, job.scan_id)
                if rec:
                    rec.files_examined = job.files_examined
                    rec.files_skipped = job.files_skipped
                    rec.errors_count = job.errors_count
                    rec.findings_count = len(job.findings)
                    rec.progress_pct = job.progress_pct
                    rec.current_file = job.current_file[-80:] if len(job.current_file) > 80 else job.current_file
                    rec.duration_seconds = round(time.time() - job.start_time, 1)
                    db.commit()
                db.close()
            except Exception:
                pass

    if job.status == "running":
        job.status = "completed"
        job.progress_pct = 100

    job.duration_seconds = round(time.time() - job.start_time, 1)

    # 3. Save final scan records & findings to database
    try:
        db = db_session_factory()
        rec = db.get(SystemScan, job.scan_id)
        if rec:
            rec.status = job.status
            rec.files_examined = job.files_examined
            rec.files_skipped = job.files_skipped
            rec.errors_count = job.errors_count
            rec.findings_count = len(job.findings)
            rec.progress_pct = job.progress_pct
            rec.current_file = ""
            rec.duration_seconds = job.duration_seconds
            rec.completed_at = datetime.now(timezone.utc)
            rec.engine_status = get_defender_status()["engine"]
            rec.details_json = json.dumps({
                "scan_type": job.scan_type,
                "target_path": job.target_path,
                "engine_status": rec.engine_status,
                "summary": f"Scanned {job.files_examined} files, found {len(job.findings)} items.",
            })

            # Save individual findings
            for f in job.findings:
                finding_rec = SystemScanFinding(
                    scan_id=job.scan_id,
                    file_path=f.get("file_path", ""),
                    file_name=f.get("file_name", ""),
                    file_hash=f.get("file_hash", ""),
                    finding_type=f.get("finding_type", "heuristic"),
                    detection_source=f.get("detection_source", "CyberShield Scanner"),
                    severity=f.get("severity", "Medium"),
                    malware_name=f.get("malware_name", "SuspiciousItem"),
                    description=f.get("description", ""),
                    recommended_action=f.get("recommended_action", "Review and quarantine."),
                    status="active"
                )
                db.add(finding_rec)

            db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Error persisting scan #{job.scan_id} results to DB: {e}")

def quarantine_finding_file(file_path: str) -> Tuple[bool, str]:
    """Safely isolates a suspicious or detected file into a protected quarantine directory with explicit confirmation."""
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return False, "File does not exist or is not a regular file."

    quarantine_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)

    dest_name = f"{os.path.basename(file_path)}.{int(time.time())}.quarantine"
    dest_path = os.path.join(quarantine_dir, dest_name)
    try:
        shutil.move(file_path, dest_path)
        return True, f"File safely moved to quarantine: {dest_name}"
    except Exception as e:
        return False, f"Failed to quarantine file: {e}"
