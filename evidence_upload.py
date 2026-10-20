import hashlib
import requests
from pathlib import Path

def sha256(path):
    h = hashlib.sha256()
    chunk_size = 1024*1024
    with open(path, "rb") as f:
        chunk = f.read(chunk_size)
        while chunk:
            h.update(chunk)
            chunk = f.read(chunk_size)
    return h.hexdigest()

def upload_evidence(path,case_id,remarks,api="https://sutram2026.onrender.com"):
    path = Path(path)
    local_hash = sha256(path)

    try:
        with open(path, "rb") as report:
            r = requests.post(f"{api}/evidence_list",   data={"case_id": case_id, "Remarks":remarks},
                              files={"file":(path.name, report)},
                              timeout=(20,500))
                              
    except requests.RequestException as e:
        return "failed", f"request denied {e}", None

    if r.status_code == 409:
        return "duplicate", r.json().get("detail", "already stored"), None
 
    if r.status_code != 200:
        return "failed", f"HTTP {r.status_code}: {r.text}", None

    body = r.json()
    if body["sha256"] != local_hash:
        return ("hash_mismatch",
                f"local {local_hash}, server {body['sha256']}",
                body.get("artifact_id"))
 
    return "uploaded", "hash matches", body["artifact_id"]
def wake_server(api, wait=90):
    
    try:
        r = requests.get(f"{api}/docs", timeout=wait)
        return r.status_code == 200
    except requests.RequestException:
        return False
        