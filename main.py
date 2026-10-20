from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import logging
import os
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import requests
import uvicorn

# ==============================================================================
# 1. SHA-256 HASH UTILITY
# ==============================================================================

CHUNK_SIZE = 1024 * 1024


def sha256(path: Union[Path, str], chunk_size: int = CHUNK_SIZE) -> str:
    """Calculates the SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        chunk = f.read(chunk_size)
        while chunk:
            h.update(chunk)
            chunk = f.read(chunk_size)
    return h.hexdigest()


# Aliases for backward compatibility
sha256_hash = sha256
hashing = sha256


# ==============================================================================
# 2. EVIDENCE STORE & FASTAPI WEB APP (fin.py)
# ==============================================================================

DB_FILE = "evidence.db"
store = Path("evidence_store")
store.mkdir(exist_ok=True)

app = FastAPI(title="Evidence_Log")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    """Connect to the SQLite evidence database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence_list (
            artifact_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id             TEXT NOT NULL,
            original_filename   TEXT NOT NULL,
            stored_path         TEXT NOT NULL,
            size_bytes          INTEGER NOT NULL,
            sha256              TEXT NOT NULL UNIQUE,
            added_at_utc        TEXT NOT NULL,
            remarks             TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


@app.post("/evidence_list")
async def upload(
    case_id: str = Form(...),
    file: UploadFile = File(...),
    Remarks: Optional[str] = Form(None),
):
    """Store uploaded evidence, record metadata, and verify hash uniqueness."""
    temp_path = store / (uuid.uuid4().hex + ".tmp")

    with open(temp_path, "wb") as out_file:
        chunk = await file.read(CHUNK_SIZE)
        while chunk:
            out_file.write(chunk)
            chunk = await file.read(CHUNK_SIZE)

    result = sha256(temp_path)
    size = temp_path.stat().st_size
    final_path = store / result

    conn = get_db()
    existance = conn.execute(
        "SELECT artifact_id FROM evidence_list WHERE sha256 = ?", (result,)
    ).fetchone()

    if existance:
        temp_path.unlink(missing_ok=True)
        conn.close()
        raise HTTPException(
            status_code=409,
            detail=f'Already stored as an evidence {existance["artifact_id"]}',
        )

    temp_path.rename(final_path)

    now_iso = datetime.now(timezone.utc).isoformat()
    record = conn.execute(
        """INSERT INTO evidence_list
        (case_id, original_filename, stored_path, size_bytes, sha256, added_at_utc, remarks)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (case_id, file.filename, str(final_path), size, result, now_iso, Remarks),
    )
    conn.commit()
    latest_id = record.lastrowid
    conn.close()

    return {
        "artifact_id": latest_id,
        "sha256": result,
        "size_bytes": size,
        "Time (UTC)": now_iso,
    }


@app.get("/evidence_list")
def list_evidence():
    """Retrieve all evidence log entries."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence_list ORDER BY artifact_id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/evidence_list/{artifact_id}/verify")
def verify(artifact_id: int):
    """Verify stored evidence file integrity against its recorded SHA-256 hash."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM evidence_list WHERE artifact_id = ?", (artifact_id,)
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="No such evidence logged.")

    path = Path(row["stored_path"])
    if not path.is_file():
        return {"status": "missing"}

    if sha256(path) == row["sha256"]:
        return {"status": "intact"}
    else:
        return {"status": "MODIFIED"}


@app.get("/evidence_list/{artifact_id}/download")
def download_evidence(artifact_id: int):
    """Download the original evidence artifact."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM evidence_list WHERE artifact_id = ?", (artifact_id,)
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="No such evidence logged.")

    file_path = Path(row["stored_path"])
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file missing on server disk.")

    return FileResponse(
        path=file_path,
        filename=row["original_filename"],
        media_type="application/octet-stream",
    )


@app.post("/evidence_list/{artifact_id}/analyze")
def analyze_artifact(artifact_id: int, key: Optional[str] = None):
    """Analyze a specific logged evidence artifact with Gemini AI."""
    from gemini_analyzer import query_gemini_api, get_api_key

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM evidence_list WHERE artifact_id = ?", (artifact_id,)
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="Artifact not found.")

    file_path = Path(row["stored_path"])
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="File missing on disk.")

    api_key = get_api_key(key)
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Gemini API Key missing. Set GEMINI_API_KEY environment variable or provide 'key' parameter.",
        )

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")[:40000]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read artifact: {e}")

    prompt = (
        f"You are a Lead DFIR Security Analyst. Analyze this Windows forensic evidence artifact:\n"
        f"- Artifact ID: {artifact_id}\n"
        f"- Original Filename: {row['original_filename']}\n"
        f"- Case ID: {row['case_id']}\n"
        f"- Remarks: {row['remarks']}\n\n"
        f"ARTIFACT CONTENT (Sample):\n```\n{content}\n```\n\n"
        f"Provide a threat assessment with risk level (LOW/MEDIUM/HIGH/CRITICAL), anomalies detected, and recommended next steps."
    )

    ok, response = query_gemini_api(prompt, api_key)
    if not ok:
        raise HTTPException(status_code=502, detail=response)

    return {
        "artifact_id": artifact_id,
        "filename": row["original_filename"],
        "analysis": response,
    }


if Path("static").is_dir():
    app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def home_ui():
    """Serve the Web UI dashboard."""
    index_path = Path("static/index.html")
    if index_path.is_file():
        return FileResponse(str(index_path))
    return {"message": "Evidence Log API is online."}


# ==============================================================================
# 3. EVIDENCE UPLOAD CLIENT (evidence_upload.py)
# ==============================================================================


def wake_server(api: str = "https://sutram2026.onrender.com", wait: int = 90) -> bool:
    """Send healthcheck ping to wake up the server (e.g. Render spin-up)."""
    try:
        r = requests.get(f"{api.rstrip('/')}/docs", timeout=wait)
        return r.status_code == 200
    except requests.RequestException:
        return False


def upload_evidence(
    path: Union[Path, str],
    case_id: str,
    remarks: Optional[str] = None,
    api: str = "https://sutram2026.onrender.com",
):
    """Upload a local evidence file to the evidence server and verify hash match."""
    path = Path(path)
    if not path.is_file():
        return "failed", f"Local file not found: {path}", None

    local_hash = sha256(path)

    try:
        with open(path, "rb") as report:
            r = requests.post(
                f"{api.rstrip('/')}/evidence_list",
                data={"case_id": case_id, "Remarks": remarks or ""},
                files={"file": (path.name, report)},
                timeout=(20, 500),
            )
    except requests.RequestException as e:
        return "failed", f"request denied {e}", None

    if r.status_code == 409:
        return "duplicate", r.json().get("detail", "already stored"), None

    if r.status_code != 200:
        return "failed", f"HTTP {r.status_code}: {r.text}", None

    body = r.json()
    server_hash = body.get("sha256")
    artifact_id = body.get("artifact_id")

    if server_hash != local_hash:
        return (
            "hash_mismatch",
            f"local {local_hash}, server {server_hash}",
            artifact_id,
        )

    return "uploaded", "hash matches", artifact_id


# ==============================================================================
# 4. WINDOWS FORENSIC COLLECTOR (collect.py)
# ==============================================================================

UTC_TEMPLATE = "@{n='NAME';e={if ($_.PROP) { $_.PROP.ToUniversalTime().ToString('o') }}}"


def csv_col(name: str, time_prop: str) -> str:
    return UTC_TEMPLATE.replace("NAME", name).replace("PROP", time_prop)


COMMANDS = {
    "timezone": "Get-TimeZone | Select-Object Id,DisplayName,BaseUtcOffset",
    "os_info": (
        "Get-CimInstance Win32_OperatingSystem | Select-Object CSName,Caption,Version,"
        + csv_col("LastBootUtc", "LastBootUpTime")
    ),
    "processes": (
        "Get-CimInstance Win32_Process | Select-Object "
        "ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,"
        + csv_col("CreatedUtc", "CreationDate")
    ),
    "tcp_connections": (
        "Get-NetTCPConnection | Select-Object "
        "LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess"
    ),
    "udp_endpoints": "Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess",
    "dns_cache": "Get-DnsClientCache | Select-Object Entry,Name,Type,Data",
    "arp_neighbors": "Get-NetNeighbor | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias",
    "scheduled_tasks": "Get-ScheduledTask | Select-Object TaskName,TaskPath,State",
    "services": "Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName",
    "local_users": (
        "Get-LocalUser | Select-Object Name,Enabled,"
        + csv_col("LastLogonUtc", "LastLogon")
        + ","
        + csv_col("PasswordLastSetUtc", "PasswordLastSet")
    ),
    "local_admins": "Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass,PrincipalSource",
    "logons": (
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 500 "
        "| Select-Object "
        + csv_col("TimeUtc", "TimeCreated")
        + ",Id,Message"
    ),
}

EVTX_LOGS = ["Security", "System", "Microsoft-Windows-PowerShell/Operational"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def admin_check() -> bool:
    """Check if the current process has Windows Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def run_powershell(command: str, output_path: Path):
    """Execute a PowerShell command and export results to CSV."""
    safe_path = str(output_path).replace("'", "''")
    full = f"{command} | Export-Csv -Path '{safe_path}' -NoTypeInformation -Encoding UTF8"

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", full],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return "failed", full, "timed out after 300 seconds"

    stderr = result.stderr.strip()
    if "No events were found" in stderr:
        return "empty", full, "no matching events"
    if result.returncode != 0:
        return "failed", full, stderr or f"exit code {result.returncode}"
    if not output_path.is_file() or output_path.stat().st_size == 0:
        return "empty", full, "command produced no output"
    return "ok", full, stderr


def run_wevtutil(log_name: str, output_path: Path):
    """Export Windows Event Log (.evtx) using wevtutil."""
    cmd = ["wevtutil", "epl", log_name, str(output_path)]
    full_cmd = " ".join(cmd)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return "failed", full_cmd, "timed out after 600 seconds"

    if result.returncode != 0 or not output_path.is_file():
        return "failed", full_cmd, result.stderr.strip() or f"exit code {result.returncode}"
    return "ok", full_cmd, ""


def make_row(name: str, status: str, out_path: Path, command: str, detail: str):
    """Construct one row for manifest.csv."""
    exists = out_path.is_file()
    return {
        "name": name,
        "status": status,
        "file": out_path.name if exists else "",
        "size_bytes": out_path.stat().st_size if exists else 0,
        "sha256": sha256(out_path) if exists else "",
        "collected_at_utc": utc_now().isoformat(),
        "command": command,
        "detail": detail,
    }


def add_upload_result(
    row: dict, out_path: Path, do_upload: bool, case_id: str, api: str, host: str
):
    """Optionally upload an artifact and populate manifest upload columns."""
    row["upload_status"] = ""
    row["artifact_id"] = ""
    row["upload_detail"] = ""

    if do_upload and row["status"] == "ok":
        remarks = (
            f"{row['name']} collected from {host} at {row['collected_at_utc']} UTC. "
            f"Command: {row['command']}"
        )
        up_status, up_detail, artifact_id = upload_evidence(out_path, case_id, remarks, api)
        row["upload_status"] = up_status
        row["artifact_id"] = artifact_id if artifact_id is not None else ""
        row["upload_detail"] = up_detail
    return row


def run_collection(
    out_base: str,
    upload: bool = False,
    case_id: Optional[str] = None,
    api: str = "https://sutram2026.onrender.com",
    skip_admin_check: bool = False,
    analyze: bool = False,
    gemini_key: Optional[str] = None,
    gemini_model: str = "gemini-2.5-flash",
):
    """Main collection routine for gathering host forensic artifacts."""
    if upload and not case_id:
        sys.exit("Error: --case is required when --upload is specified.")

    if not skip_admin_check and not admin_check():
        sys.exit("Error: Run this from an Administrator terminal (or pass --skip-admin-check).")

    if upload:
        print(f"Contacting evidence server at {api} ...")
        if not wake_server(api):
            sys.exit(f"Error: Could not reach {api}. Collection aborted.")

    host = socket.gethostname()
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(out_base).expanduser().resolve() / f"{host}_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    if out_dir.drive.upper() == os.environ.get("SystemDrive", "C:").upper():
        print("Warning: Output is on the system drive. In casework, use an external drive.")

    logging.Formatter.converter = time.gmtime  # log in UTC
    log_file = out_dir / "collection.log"
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)sZ  %(levelname)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        force=True,
    )
    logging.info("Collection started on %s, output in %s", host, out_dir)

    rows = []

    # 1. Collect PowerShell command outputs
    for name, command in COMMANDS.items():
        out_path = out_dir / f"{name}.csv"
        print(f"Collecting {name} ...")
        status, full, detail = run_powershell(command, out_path)
        logging.info("%s: %s %s", name, status, detail)
        row = make_row(name, status, out_path, full, detail)
        rows.append(add_upload_result(row, out_path, upload, case_id, api, host))
        print(f"  {status}")

    # 2. Collect EVTX Logs
    for log in EVTX_LOGS:
        name = "evtx_" + log.replace("/", "_")
        out_path = out_dir / f"{name}.evtx"
        print(f"Exporting log {log} ...")
        status, full, detail = run_wevtutil(log, out_path)
        logging.info("%s: %s %s", name, status, detail)
        row = make_row(name, status, out_path, full, detail)
        rows.append(add_upload_result(row, out_path, upload, case_id, api, host))
        print(f"  {status}")

    # 3. Write Manifest
    manifest = out_dir / "manifest.csv"
    if rows:
        with open(manifest, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    logging.info("Collection finished")
    logging.shutdown()

    # AI Threat Analysis with Gemini
    ai_report_file = None
    if analyze:
        try:
            from gemini_analyzer import analyze_evidence_folder

            print("\n" + "=" * 60)
            print("Running Gemini AI Forensic Analysis ...")
            print("=" * 60)
            ok, report_text, ai_report_file = analyze_evidence_folder(
                out_dir, api_key=gemini_key, model=gemini_model
            )
            if ok:
                print("\n--- GEMINI AI FORENSIC REPORT SUMMARY ---")
                preview = report_text[:1200] + (
                    "\n... [Full analysis saved in ai_analysis_report.md]"
                    if len(report_text) > 1200
                    else ""
                )
                print(preview)
            else:
                print(f"[!] Gemini analysis note: {report_text}")
        except Exception as e:
            print(f"[!] Could not run Gemini analysis: {e}")

    # 4. Upload Manifest, Log, and AI Report
    if upload:
        print("\nUploading manifest, log, and reports ...")
        upload_files = [manifest, log_file]
        if ai_report_file and ai_report_file.is_file():
            upload_files.append(ai_report_file)

        for f in upload_files:
            if f.is_file():
                remarks = f"{f.name} for collection on {host} ({stamp})"
                up_status, up_detail, artifact_id = upload_evidence(f, case_id, remarks, api)
                print(f"  {f.name}: {up_status} {up_detail}")

    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("ok", "empty", "failed")}
    print(f"\nDone: {counts['ok']} ok, {counts['empty']} empty, {counts['failed']} failed")
    print(f"Output folder: {out_dir}")
    print("\nHashes to record in case notes:")
    all_noted = [manifest, log_file]
    if ai_report_file and ai_report_file.is_file():
        all_noted.append(ai_report_file)
    for f in all_noted:
        if f.is_file():
            print(f"  {sha256(f)}  {f.name}")


# ==============================================================================
# 5. CLI INTERFACE
# ==============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Unified Evidence System (Server, Collector, Uploader & AI Analyzer)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Operational mode")

    # Mode: Server
    server_p = subparsers.add_parser("server", help="Run the Evidence Log FastAPI web server")
    server_p.add_argument(
        "--host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)"
    )
    server_p.add_argument(
        "--port", type=int, default=8000, help="Port to listen on (default: 8000)"
    )
    server_p.add_argument(
        "--reload", action="store_true", help="Enable live reload for development"
    )

    # Mode: Collect (Windows forensic data collection)
    collect_p = subparsers.add_parser(
        "collect", help="Collect forensic evidence from this Windows host"
    )
    collect_p.add_argument(
        "--out", required=True, help="Destination directory for collected files"
    )
    collect_p.add_argument(
        "--upload",
        action="store_true",
        help="Upload collected artifacts to evidence server",
    )
    collect_p.add_argument("--case", help="Case ID (required with --upload)")
    collect_p.add_argument(
        "--api",
        default="https://sutram2026.onrender.com",
        help="Evidence API server URL",
    )
    collect_p.add_argument(
        "--skip-admin-check",
        action="store_true",
        help="Skip administrator privilege check",
    )
    collect_p.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze collected forensic data using Google Gemini AI",
    )
    collect_p.add_argument(
        "--gemini-key",
        help="Google Gemini API key (or set GEMINI_API_KEY env var)",
    )
    collect_p.add_argument(
        "--gemini-model",
        default="gemini-2.5-flash",
        help="Gemini model to use (default: gemini-2.5-flash)",
    )

    # Mode: Upload (Single evidence file upload)
    upload_p = subparsers.add_parser(
        "upload", help="Upload a single evidence file to the evidence server"
    )
    upload_p.add_argument("--file", required=True, help="Path to evidence file to upload")
    upload_p.add_argument("--case", required=True, help="Case ID")
    upload_p.add_argument(
        "--remarks", default="", help="Remarks or notes about the evidence"
    )
    upload_p.add_argument(
        "--api",
        default="https://sutram2026.onrender.com",
        help="Evidence API server URL",
    )

    # Mode: Analyze (Standalone AI analysis of evidence folder)
    analyze_p = subparsers.add_parser(
        "analyze", help="Analyze an existing forensic evidence folder with Gemini AI"
    )
    analyze_p.add_argument(
        "--folder", required=True, help="Path to evidence folder containing CSV files"
    )
    analyze_p.add_argument(
        "--gemini-key", help="Google Gemini API key (or set GEMINI_API_KEY env var)"
    )
    analyze_p.add_argument(
        "--gemini-model",
        default="gemini-2.5-flash",
        help="Gemini model to use (default: gemini-2.5-flash)",
    )

    # Global options for backward-compatibility when called without subcommand:
    parser.add_argument(
        "--out", help="Convenience alias: collect evidence into output folder"
    )
    parser.add_argument(
        "--upload", action="store_true", help="Convenience alias: upload collected evidence"
    )
    parser.add_argument("--case", help="Case ID")
    parser.add_argument(
        "--api",
        default="https://sutram2026.onrender.com",
        help="Evidence API server URL",
    )
    parser.add_argument(
        "--skip-admin-check",
        action="store_true",
        help="Skip administrator privilege check",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze collected forensic data using Google Gemini AI",
    )
    parser.add_argument(
        "--gemini-key",
        help="Google Gemini API key (or set GEMINI_API_KEY env var)",
    )
    parser.add_argument(
        "--gemini-model",
        default="gemini-2.5-flash",
        help="Gemini model to use (default: gemini-2.5-flash)",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Route based on subcommand or top-level flags
    if args.subcommand == "server":
        print(f"Starting Evidence Log Server on http://{args.host}:{args.port}")
        uvicorn.run("main:app", host=args.host, port=args.port, reload=args.reload)

    elif args.subcommand == "upload":
        print(f"Uploading {args.file} to {args.api} for case {args.case} ...")
        status, detail, artifact_id = upload_evidence(
            args.file, args.case, args.remarks, args.api
        )
        print(f"Result: {status} | Detail: {detail} | Artifact ID: {artifact_id}")

    elif args.subcommand == "analyze":
        from gemini_analyzer import analyze_evidence_folder

        print(f"Analyzing evidence folder {args.folder} with Gemini ({args.gemini_model}) ...")
        ok, report_text, out_file = analyze_evidence_folder(
            args.folder, api_key=args.gemini_key, model=args.gemini_model
        )
        if ok:
            print("\n" + "=" * 80)
            print("GEMINI FORENSIC THREAT REPORT:")
            print("=" * 80 + "\n")
            print(report_text)
        else:
            print(f"\n[!] Analysis failed: {report_text}")
            sys.exit(1)

    elif args.subcommand == "collect" or args.out:
        out_path = args.out
        run_collection(
            out_base=out_path,
            upload=args.upload,
            case_id=args.case,
            api=args.api,
            skip_admin_check=args.skip_admin_check,
            analyze=args.analyze,
            gemini_key=args.gemini_key,
            gemini_model=args.gemini_model,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
