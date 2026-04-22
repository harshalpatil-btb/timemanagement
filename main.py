"""
TimeTrack MVP v2 - Backend API
Optimized for 30 non-technical users, auto Windows username detection
FastAPI + SQLite (Render free tier deployment)
"""

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import sqlite3, hashlib, secrets, time, os, pathlib
from datetime import datetime, date, timedelta
from pydantic import BaseModel
from typing import Optional

DB_PATH        = os.environ.get("DB_PATH", "timetrack.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")

# ── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS machines (
            id            TEXT PRIMARY KEY,
            computer_name TEXT NOT NULL,
            windows_user  TEXT NOT NULL,
            display_name  TEXT,
            first_seen    INTEGER NOT NULL,
            last_seen     INTEGER,
            api_key       TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS heartbeats (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id TEXT NOT NULL,
            ts         INTEGER NOT NULL,
            status     TEXT NOT NULL,
            source     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS daily_summary (
            machine_id TEXT NOT NULL,
            day        TEXT NOT NULL,
            active_sec INTEGER DEFAULT 0,
            idle_sec   INTEGER DEFAULT 0,
            PRIMARY KEY(machine_id, day)
        );
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token      TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_hb ON heartbeats(machine_id, ts);
    """)
    db.commit()
    db.close()

# ── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="TimeTrack", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer(auto_error=False)

# ── Auth helpers ──────────────────────────────────────────────────────────────

def verify_machine(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(401, "Missing key")
    db = get_db()
    row = db.execute("SELECT * FROM machines WHERE api_key=?", (creds.credentials,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(401, "Invalid key")
    return dict(row)

def verify_admin(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(401)
    db = get_db()
    now = int(time.time())
    row = db.execute("SELECT 1 FROM admin_sessions WHERE token=? AND expires_at>?",
                     (creds.credentials, now)).fetchone()
    db.close()
    if not row:
        raise HTTPException(401, "Invalid or expired session")

# ── Models ────────────────────────────────────────────────────────────────────

class RegisterReq(BaseModel):
    machine_id:    str
    computer_name: str
    windows_user:  str

class HeartbeatReq(BaseModel):
    status:    str            # active | idle
    source:    str            # agent | extension
    timestamp: Optional[int] = None

class AdminLogin(BaseModel):
    password: str

class PatchMachine(BaseModel):
    display_name: Optional[str] = None

# ── Machine registration ───────────────────────────────────────────────────────

@app.post("/api/machines/register")
def register(body: RegisterReq):
    db = get_db()
    existing = db.execute("SELECT * FROM machines WHERE id=?", (body.machine_id,)).fetchone()
    if existing:
        db.close()
        return {"api_key": existing["api_key"], "new": False}

    key = secrets.token_urlsafe(32)
    now = int(time.time())
    # display_name defaults to "COMPUTER — user"
    display = f"{body.computer_name} — {body.windows_user}"
    db.execute(
        "INSERT INTO machines(id,computer_name,windows_user,display_name,first_seen,last_seen,api_key)"
        " VALUES(?,?,?,?,?,?,?)",
        (body.machine_id, body.computer_name, body.windows_user, display, now, now, key)
    )
    db.commit()
    db.close()
    return {"api_key": key, "new": True}

# ── Heartbeat ─────────────────────────────────────────────────────────────────

@app.post("/api/heartbeat")
def heartbeat(body: HeartbeatReq, machine: dict = Depends(verify_machine)):
    if body.status not in ("active", "idle"):
        raise HTTPException(400, "bad status")

    ts  = body.timestamp or int(time.time())
    day = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
    mid = machine["id"]

    db = get_db()
    db.execute("INSERT INTO heartbeats(machine_id,ts,status,source) VALUES(?,?,?,?)",
               (mid, ts, body.status, body.source))
    db.execute("UPDATE machines SET last_seen=? WHERE id=?", (ts, mid))
    db.execute("INSERT OR IGNORE INTO daily_summary(machine_id,day,active_sec,idle_sec) VALUES(?,?,0,0)",
               (mid, day))
    col = "active_sec" if body.status == "active" else "idle_sec"
    db.execute(f"UPDATE daily_summary SET {col}={col}+30 WHERE machine_id=? AND day=?", (mid, day))
    db.commit()
    db.close()
    return {"ok": True}

# ── Admin auth ────────────────────────────────────────────────────────────────

@app.post("/api/admin/login")
def login(body: AdminLogin):
    if not secrets.compare_digest(
        hashlib.sha256(body.password.encode()).hexdigest(),
        hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    ):
        raise HTTPException(401, "Wrong password")
    token = secrets.token_urlsafe(32)
    db = get_db()
    now = int(time.time())
    db.execute("DELETE FROM admin_sessions WHERE expires_at<?", (now,))
    db.execute("INSERT INTO admin_sessions VALUES(?,?)", (token, now + 86400 * 7))
    db.commit()
    db.close()
    return {"token": token}

@app.post("/api/admin/logout")
def logout(creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds:
        db = get_db()
        db.execute("DELETE FROM admin_sessions WHERE token=?", (creds.credentials,))
        db.commit()
        db.close()
    return {"ok": True}

# ── Admin data ────────────────────────────────────────────────────────────────

@app.get("/api/admin/machines")
def list_machines(_=Depends(verify_admin)):
    db  = get_db()
    now = int(time.time())
    today = date.today().isoformat()
    rows = db.execute("SELECT * FROM machines ORDER BY last_seen DESC").fetchall()
    out  = []

    for m in rows:
        m = dict(m)
        s = db.execute("SELECT active_sec,idle_sec FROM daily_summary WHERE machine_id=? AND day=?",
                       (m["id"], today)).fetchone()
        total = db.execute("SELECT COALESCE(SUM(active_sec+idle_sec),0) FROM daily_summary WHERE machine_id=?",
                           (m["id"],)).fetchone()[0]

        age = now - (m["last_seen"] or 0)
        if age < 90:
            lhb = db.execute("SELECT status FROM heartbeats WHERE machine_id=? ORDER BY ts DESC LIMIT 1",
                             (m["id"],)).fetchone()
            cur = lhb["status"] if lhb else "unknown"
        else:
            cur = "offline"

        trend = []
        for i in range(6, -1, -1):
            d = (date.today() - timedelta(days=i)).isoformat()
            r = db.execute("SELECT active_sec,idle_sec FROM daily_summary WHERE machine_id=? AND day=?",
                           (m["id"], d)).fetchone()
            trend.append({"date": d, "active": r["active_sec"] if r else 0, "idle": r["idle_sec"] if r else 0})

        out.append({
            "id":            m["id"],
            "computer_name": m["computer_name"],
            "windows_user":  m["windows_user"],
            "display_name":  m["display_name"] or m["computer_name"],
            "first_seen":    m["first_seen"],
            "last_seen":     m["last_seen"],
            "status":        cur,
            "today_active":  s["active_sec"] if s else 0,
            "today_idle":    s["idle_sec"]   if s else 0,
            "total":         total,
            "trend":         trend,
        })

    db.close()
    return out

@app.get("/api/admin/stats")
def stats(_=Depends(verify_admin)):
    db    = get_db()
    now   = int(time.time())
    today = date.today().isoformat()
    total   = db.execute("SELECT COUNT(*) FROM machines").fetchone()[0]
    online  = db.execute("SELECT COUNT(*) FROM machines WHERE last_seen>?", (now-90,)).fetchone()[0]
    act_sec = db.execute("SELECT COALESCE(SUM(active_sec),0) FROM daily_summary WHERE day=?",
                         (today,)).fetchone()[0]
    db.close()
    return {"total": total, "online": online, "today_active_sec": act_sec}

@app.patch("/api/admin/machines/{mid}")
def patch_machine(mid: str, body: PatchMachine, _=Depends(verify_admin)):
    db = get_db()
    if body.display_name is not None:
        db.execute("UPDATE machines SET display_name=? WHERE id=?", (body.display_name, mid))
    db.commit()
    db.close()
    return {"ok": True}

@app.delete("/api/admin/machines/{mid}")
def del_machine(mid: str, _=Depends(verify_admin)):
    db = get_db()
    for t in ("heartbeats", "daily_summary", "machines"):
        db.execute(f"DELETE FROM {t} WHERE {'machine_id' if t != 'machines' else 'id'}=?", (mid,))
    db.commit()
    db.close()
    return {"ok": True}

@app.get("/health")
def health():
    return {"ok": True, "ts": int(time.time())}

# Serve dashboard from /dashboard folder if it exists
dash = pathlib.Path("dashboard")
if dash.exists():
    app.mount("/", StaticFiles(directory="dashboard", html=True), name="static")
