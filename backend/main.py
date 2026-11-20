"""SafeCircle API. Personal safety companion; does not contact emergency services."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, model_validator

DB_PATH = Path(os.getenv("DATABASE_PATH", "./data/safecircle.db"))
SECRET = os.getenv("SECRET_KEY", "")
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))
FRONTEND_ORIGINS = [o.strip() for o in os.getenv("FRONTEND_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
app = FastAPI(title="SafeCircle API", version="1.0.0", description="Private safety planning APIs. No emergency service integration.")
app.add_middleware(CORSMiddleware, allow_origins=FRONTEND_ORIGINS, allow_credentials=False, allow_methods=["GET", "POST", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])

def utcnow():
    return datetime.now(timezone.utc).isoformat()

@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def init_db():
    with connect() as db:
        db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', relationship TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS incidents_user_date ON incidents(user_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS contacts_user ON contacts(user_id);
        """)
        # Minimize retention: remove old event records at startup and on writes.
        db.execute("DELETE FROM incidents WHERE created_at < ?", (datetime.fromtimestamp(time.time() - 90 * 86400, timezone.utc).isoformat(),))

init_db()

class Register(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=10, max_length=256)

class Login(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)

class ContactIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    phone: str = Field(default="", max_length=30)
    email: str = Field(default="", max_length=254)
    relationship: str = Field(default="", max_length=60)
    @model_validator(mode="after")
    def has_channel(self):
        if not self.phone.strip() and not self.email.strip():
            raise ValueError("Add a phone number or email address so you can reach this contact.")
        if self.email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", self.email):
            raise ValueError("Enter a valid contact email address.")
        if self.phone and not re.fullmatch(r"[+()\d.\-\s]{5,30}", self.phone):
            raise ValueError("Enter a valid phone number.")
        return self

class IncidentIn(BaseModel):
    kind: str = Field(pattern="^(sos|checkin)$")
    message: str = Field(default="", max_length=500)
    # Deliberately discard coordinates: never persist location.
    location: Optional[dict] = None

def password_digest(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310_000).hex()

def sign_token(uid: int) -> str:
    if not SECRET or len(SECRET) < 32:
        raise HTTPException(503, "Server authentication is not configured. Set SECRET_KEY to a random value of at least 32 characters.")
    payload = f"{uid}:{int(time.time()) + TOKEN_TTL}"
    mac = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{mac}"

def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in to continue.")
    try:
        uid_s, exp_s, mac = authorization[7:].split(":", 2)
        payload = f"{uid_s}:{exp_s}"
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not SECRET or not hmac.compare_digest(mac, expected) or int(exp_s) < time.time():
            raise ValueError()
        uid = int(uid_s)
    except (ValueError, TypeError):
        raise HTTPException(401, "Your session expired. Please sign in again.")
    with connect() as db:
        row = db.execute("SELECT id, name, email FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        raise HTTPException(401, "Your account could not be found. Please sign in again.")
    return dict(row)

def user_payload(uid):
    with connect() as db:
        row = db.execute("SELECT id,name,email,created_at FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row)

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SafeCircle API"}

@app.post("/api/auth/register", status_code=201)
def register(data: Register):
    salt = secrets.token_hex(16)
    try:
        with connect() as db:
            cursor = db.execute("INSERT INTO users(name,email,password_hash,password_salt,created_at) VALUES(?,?,?,?,?)", (data.name.strip(), data.email.lower(), password_digest(data.password, salt), salt, utcnow()))
            uid = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with this email already exists. Try signing in instead.")
    return {"access_token": sign_token(uid), "token_type": "bearer", "user": user_payload(uid)}

@app.post("/api/auth/login")
def login(data: Login):
    with connect() as db:
        row = db.execute("SELECT id,password_hash,password_salt FROM users WHERE email=?", (data.email.lower(),)).fetchone()
    if not row or not hmac.compare_digest(password_digest(data.password, row["password_salt"]), row["password_hash"]):
        raise HTTPException(401, "Email or password is incorrect.")
    return {"access_token": sign_token(row["id"]), "token_type": "bearer", "user": user_payload(row["id"])}

@app.get("/api/me")
def me(user=Depends(current_user)):
    return user

@app.get("/api/contacts")
def contacts(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("SELECT id,name,phone,email,relationship,created_at FROM contacts WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return [dict(row) for row in rows]

@app.post("/api/contacts", status_code=201)
def add_contact(data: ContactIn, user=Depends(current_user)):
    with connect() as db:
        cursor = db.execute("INSERT INTO contacts(user_id,name,phone,email,relationship,created_at) VALUES(?,?,?,?,?,?)", (user["id"], data.name.strip(), data.phone.strip(), data.email.strip().lower(), data.relationship.strip(), utcnow()))
        row = db.execute("SELECT id,name,phone,email,relationship,created_at FROM contacts WHERE id=?", (cursor.lastrowid,)).fetchone()
    return dict(row)

@app.delete("/api/contacts/{contact_id}", status_code=204)
def delete_contact(contact_id: int, user=Depends(current_user)):
    with connect() as db:
        cur = db.execute("DELETE FROM contacts WHERE id=? AND user_id=?", (contact_id, user["id"]))
    if not cur.rowcount:
        raise HTTPException(404, "Contact not found.")

@app.get("/api/incidents")
def incidents(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("SELECT id,kind,message,created_at FROM incidents WHERE user_id=? ORDER BY id DESC LIMIT 100", (user["id"],)).fetchall()
    return [dict(row) for row in rows]

@app.post("/api/incidents", status_code=201)
def create_incident(data: IncidentIn, user=Depends(current_user)):
    with connect() as db:
        db.execute("DELETE FROM incidents WHERE created_at < ?", (datetime.fromtimestamp(time.time() - 90 * 86400, timezone.utc).isoformat(),))
        cur = db.execute("INSERT INTO incidents(user_id,kind,message,created_at) VALUES(?,?,?,?)", (user["id"], data.kind, data.message.strip(), utcnow()))
        row = db.execute("SELECT id,kind,message,created_at FROM incidents WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)

@app.get("/api/admin/overview")
def admin_overview(user=Depends(current_user)):
    # An account must be allowlisted; no self-service account can grant itself admin.
    allowed = {x.strip().lower() for x in os.getenv("ADMIN_EMAILS", "").split(",") if x.strip()}
    if user["email"].lower() not in allowed:
        raise HTTPException(403, "Admin access is not enabled for this account.")
    with connect() as db:
        totals = db.execute("SELECT (SELECT COUNT(*) FROM users) AS users,(SELECT COUNT(*) FROM contacts) AS contacts,(SELECT COUNT(*) FROM incidents WHERE kind='sos') AS sos_90d").fetchone()
    return {"totals": dict(totals), "note": "Aggregate counts only; no user locations or contact details are exposed."}

# The container serves the built single-page app from the same origin as the API.
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="frontend")
