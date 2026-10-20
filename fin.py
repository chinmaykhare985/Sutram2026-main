import hashlib
import sqlite3
import uuid
from datetime import datetime,timezone
from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel



app = FastAPI(title="Evidence_Log")
store = Path("evidence_store")
store.mkdir(exist_ok=True)
DB_FILE = "evidence.db"



def get_db():
    # Connect to the database
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

connect = get_db()
connect.execute("""
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
connect.commit()
connect.close()

def sha256(path, chunk_size = 1024*1024):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        chunk = f.read(chunk_size)
        while chunk:
            h.update(chunk)
            chunk = f.read(chunk_size)
    return h.hexdigest() 

@app.post("/evidence_list")
async def upload(case_id:str = Form(...), file: UploadFile = File(...), Remarks:str= Form(None)):
    temp_path = store / (uuid.uuid4().hex + ".tmp")
    chunk_size = 1024*1024

    with open(temp_path,"wb") as out_file:
        chunk = await file.read(chunk_size)
        while chunk:
            out_file.write(chunk)
            chunk = await file.read(chunk_size)
    result = sha256(temp_path)
    size = temp_path.stat().st_size

    final_path = store/result
    

    conn = get_db()
    existance = conn.execute(
        "SELECT artifact_id FROM evidence_list WHERE sha256 = ?", (result,)).fetchone()
    if existance:
        temp_path.unlink()
        conn.close()
        raise HTTPException(409, f'Already stored as an evidence {existance["artifact_id"]}')
    temp_path.rename(final_path)

    record = conn.execute( 
        """INSERT INTO evidence_list
        (case_id, original_filename, stored_path, size_bytes, sha256, added_at_utc, remarks) VALUES (?,?,?,?,?,?,?)""",
        (case_id, file.filename, str(final_path), size, result, datetime.now(timezone.utc).isoformat(), Remarks)

    )
    conn.commit()
    latest_id = record.lastrowid
    conn.close()
    return {"artifact_id": latest_id, "sha256": result, "size_bytes": size, "Time (UTC)": datetime.now(timezone.utc).isoformat()}

@app.get("/evidence_list")
def list_evidence():
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence_list").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/evidence_list/{artifact_id}/verify")
def verify(artifact_id:int):
    conn = get_db()
    row = conn.execute('''
    SELECT * FROM evidence_list WHERE artifact_id = ?''',(artifact_id,)).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(404, "No such evidence logged.")

    path = Path(row["stored_path"])
    if not path.is_file():
        return {"status":"missing"}

    if sha256(path) == row["sha256"]:
        return {"status":"intact"}
    else:
        return {"status":"MODIFIED"}

@app.get("/evidence_list/{artifact_id}/download")
def download_evidence(artifact_id:int):
    conn = get_db()
    row = conn.execute("SELECT * FROM evidence_list WHERE  artifact_id = ?",(artifact_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such evidence logged.")
    file_path = Path(row["stored_path"])
    if file_path.is_file == False:
        raise HTTPException(404, "Evidence file missing on server disk.")
    return FileResponse(
        path=file_path,
        filename=row["original_filename"],
        media_type="application/octet-stream"
    )



app.mount("/static", StaticFiles(directory="static"), name="static")
@app.get("/")
def home_ui():
    return FileResponse("static/index.html")
