import subprocess
import argparse
import csv
import ctypes
import hashlib
import logging
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from evidence_upload import upload_evidence,wake_server

chunk_size = 1024*1024

UTC_TEMPLATE = "@{n='NAME';e={if ($_.PROP) { $_.PROP.ToUniversalTime().ToString('o') }}}"

def csv_col(name, time):
    return UTC_TEMPLATE.replace("NAME",name).replace("PROP",time)

COMMANDS = {
    "timezone": "Get-TimeZone | Select-Object Id,DisplayName,BaseUtcOffset",
    "os_info": ("Get-CimInstance Win32_OperatingSystem | Select-Object CSName,Caption,Version,"
                + csv_col("LastBootUtc", "LastBootUpTime")),
    "processes": ("Get-CimInstance Win32_Process | Select-Object "
                  "ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,"
                  + csv_col("CreatedUtc", "CreationDate")),
    "tcp_connections": ("Get-NetTCPConnection | Select-Object "
                        "LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess"),
    "udp_endpoints": "Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess",
    "dns_cache": "Get-DnsClientCache | Select-Object Entry,Name,Type,Data",
    "arp_neighbors": "Get-NetNeighbor | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias",
    "scheduled_tasks": "Get-ScheduledTask | Select-Object TaskName,TaskPath,State",
    "services": "Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName",
    "local_users": ("Get-LocalUser | Select-Object Name,Enabled,"
                    + csv_col("LastLogonUtc", "LastLogon") + ","
                    + csv_col("PasswordLastSetUtc", "PasswordLastSet")),
    "local_admins": "Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass,PrincipalSource",
    "logons": ("Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 500 "
               "| Select-Object " + csv_col("TimeUtc", "TimeCreated") + ",Id,Message"),
}

EVTX_LOGS = ["Security", "System", "Microsoft-Windows-PowerShell/Operational"]

def utc():
    return datetime.now(timezone.utc)

def admin_check():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except AttributeError:
        return False

def hashing(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        chunk = f.read(chunk_size)
        while chunk:
            h.update(chunk)
            chunk = f.read(chunk_size)
    return h.hexdigest()

def run_powershell(command, output_path):
    safe_path = str(output_path).replace("'", "''")
    full = f"{command} | Export-Csv -Path '{safe_path}' -NoTypeInformation -Encoding UTF8"

    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Noninteractive", "-Command", full], capture_output=True, text=True,timeout=300)
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

def run_wevtutil(log_name, output_path):
    cmd = ["wevtutil","epl", log_name, str(output_path)]
    full_cmd = " ".join(cmd)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return "failed", full_cmd, "timed out after 600 seconds"

    if result.returncode != 0 or not output_path.is_file():
        return "failed", full_cmd, result.stderr.strip() or f"exit code {result.returncode}"
    return "ok", full_cmd, ""

def make_row(name, status, out_path, command, detail):
    """One line of the manifest."""
    exists = out_path.is_file()
    return {
        "name": name,
        "status": status,
        "file": out_path.name if exists else "",
        "size_bytes": out_path.stat().st_size if exists else 0,
        "sha256": hashing(out_path) if exists else "",
        "collected_at_utc": utc().isoformat(),
        "command": command,
        "detail": detail,
    }
def add_upload_result(row, out_path, args, host):
    row["upload_status"] = ""
    row["artifact_id"] = ""
    row["upload_detail"] = ""

    if args.upload and row["status"] == "ok":
        remarks = (f"{row['name']} collected from {host} at {row['collected_at_utc']} UTC. "
                   f"Command: {row['command']}")
        up_status, up_detail, artifact_id = upload_evidence(out_path, args.case, remarks, args.api)
        row["upload_status"] = up_status
        row["artifact_id"] = artifact_id if artifact_id is not None else ""
        row["upload_detail"] = up_detail
    return row

def main():
    p = argparse.ArgumentParser(description="Collect forensic data from this Windows host.")
    p.add_argument("--out", required=True, help="output folder, ideally on an external drive")
    p.add_argument("--upload", action="store_true", help="also upload each file to the evidence web app")
    p.add_argument("--case", help="case ID (required with --upload)")
    p.add_argument("--api", default="https://sutram2026.onrender.com/", help="base address of the evidence web app")
    p.add_argument("--analyze", action="store_true", help="analyze collected artifacts using Gemini AI")
    p.add_argument("--gemini-key", help="Google Gemini API key (or set GEMINI_API_KEY env var)")
    p.add_argument("--gemini-model", default="gemini-2.5-flash", help="Gemini model to use (default: gemini-2.5-flash)")
    args = p.parse_args()

    if args.upload and not args.case:
        sys.exit("--case is required with --upload")
 
    if not admin_check():
        sys.exit("Run this from an Administrator terminal.")
    if args.upload:
        print("Contacting the evidence server")
        if not wake_server(args.api):
            sys.exit(f"Could not reach {args.api}. Nothing was collected.")

    host = socket.gethostname()
    stamp = utc().strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out).expanduser().resolve() / f"{host}_{stamp}"
    out_dir.mkdir(parents=True)
 
    if out_dir.drive.upper() == os.environ.get("SystemDrive", "C:").upper():
        print("Warning: output is on the system drive. In real casework use an external drive.")
 
    logging.Formatter.converter = time.gmtime          # log in UTC
    logging.basicConfig(
        filename=out_dir / "collection.log",
        level=logging.INFO,
        format="%(asctime)sZ  %(levelname)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logging.info("Collection started on %s, output in %s", host, out_dir)
 
    rows = []
 
    for name, command in COMMANDS.items():
        out_path = out_dir / f"{name}.csv"
        print(f"Collecting {name} ...")
        status, full, detail = run_powershell(command, out_path)
        logging.info("%s: %s %s", name, status, detail)
        rows.append(add_upload_result(make_row(name, status, out_path, full, detail), out_path, args, host))
        print(f"  {status}")
 
    for log in EVTX_LOGS:
        name = "evtx_" + log.replace("/", "_")
        out_path = out_dir / f"{name}.evtx"
        print(f"Exporting log {log} ...")
        status, full, detail = run_wevtutil(log, out_path)
        logging.info("%s: %s %s", name, status, detail)
        rows.append(add_upload_result(make_row(name, status, out_path, full, detail), out_path, args, host))
        print(f"  {status}")
 
    manifest = out_dir / "manifest.csv"
    with open(manifest, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
 
    logging.info("Collection finished")
    logging.shutdown()  

    # AI Analysis with Gemini
    ai_report_file = None
    if args.analyze:
        try:
            from gemini_analyzer import analyze_evidence_folder
            print("\n" + "=" * 60)
            print("Running Gemini AI Forensic Analysis ...")
            print("=" * 60)
            ok, report_text, ai_report_file = analyze_evidence_folder(
                out_dir, api_key=args.gemini_key, model=args.gemini_model
            )
            if ok:
                print("\n--- GEMINI AI FORENSIC REPORT SUMMARY ---")
                preview = report_text[:1200] + ("\n... [Full analysis saved in ai_analysis_report.md]" if len(report_text) > 1200 else "")
                print(preview)
            else:
                print(f"[!] Gemini analysis note: {report_text}")
        except Exception as e:
            print(f"[!] Could not run Gemini analysis: {e}")

    if args.upload:
        print("\nUploading manifest, log, and reports ...")
        upload_files = [manifest, out_dir / "collection.log"]
        if ai_report_file and ai_report_file.is_file():
            upload_files.append(ai_report_file)

        for f in upload_files:
            remarks = f"{f.name} for the collection on {host} ({stamp})"
            up_status, up_detail, artifact_id = upload_evidence(f, args.case, remarks, args.api)
            print(f"  {f.name}: {up_status} {up_detail}")                               
 
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("ok", "empty", "failed")}
    print(f"\nDone: {counts['ok']} ok, {counts['empty']} empty, {counts['failed']} failed")
    print(f"Output folder: {out_dir}")
    print("\nWrite these hashes in your case notes (nothing else vouches for these files):")
    all_noted = [manifest, out_dir / "collection.log"]
    if ai_report_file and ai_report_file.is_file():
        all_noted.append(ai_report_file)
    for f in all_noted:
        print(f"  {hashing(f)}  {f.name}")
 
 
if __name__ == "__main__":
    main()