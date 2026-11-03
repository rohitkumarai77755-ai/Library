"""
Personal Notes & Image Library  (single file: main.py)

Run locally:   python main.py          ->  http://127.0.0.1:8000
Run in Docker: docker build -t library .
               docker run -p 8000:8000 -e MONGO_URL="mongodb+srv://..." library
Render:        Start Command = python main.py   (do NOT use --reload)

What it does:
  * First page: product description + one-step email login (no password, no sign-up).
  * Each email is an isolated vault. The server identifies you from a session cookie,
    so one email never sees or deletes another email's data.
  * Dashboard: paste (Ctrl+V), drag & drop or upload images/text, press Save.
    "Text file" button: type a file name + text and save.
  * Everything is listed date-wise (oldest first by default) with search,
    date filter and type filter. NEW tag disappears after 24 hours.
  * Click any item to open it on the same page in a viewer with an X button,
    previous/next, swipe, keyboard arrows and a thumbnail strip.
  * Date and time are taken automatically from the browser.

Environment variables:
  MONGO_URL      default mongodb://localhost:27017  (MONGODB_URI / MONGODB_URL also accepted)
  MONGO_DB       default personal_library
  MAX_IMAGE_MB   default 10
  SESSION_DAYS   default 30
  COOKIE_SECURE  set to 1 when served over HTTPS (automatic on Render)
  HOST           default 0.0.0.0  (reachable from anywhere)
  PORT           default 8000     (Render sets this automatically)

Settings can also be placed in a .env file next to this file.
Health check: GET /healthz shows whether MongoDB is connected and the last error.
"""

import importlib.util
import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# Auto-install dependencies when run outside Docker without requirements.txt
# ---------------------------------------------------------------------------
_PACKAGES = {
    "fastapi": "fastapi",
    "uvicorn": "uvicorn[standard]",
    "pymongo": "pymongo",
    "python_multipart": "python-multipart",
    "email_validator": "email-validator",
    "dotenv": "python-dotenv",
    "certifi": "certifi",
    "dns": "dnspython",
}
_missing = [pkg for mod, pkg in _PACKAGES.items() if importlib.util.find_spec(mod) is None]
if _missing:
    print(f"Installing missing packages: {', '.join(_missing)} ...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", *_missing])

import hashlib
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import certifi
import uvicorn
from bson import Binary, ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import PyMongoError

# Load settings from a .env file next to this script (real environment variables take priority)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# ---------------------------------------------------------------------------
# Config  (never hardcode real credentials in code; use environment variables)
# ---------------------------------------------------------------------------
MONGO_URL = (os.getenv("MONGO_URL") or os.getenv("MONGODB_URI") or os.getenv("MONGODB_URL")
             or "mongodb://localhost:27017").strip().strip('"').strip("'")
MONGO_DB = os.getenv("MONGO_DB", "personal_library")
MAX_IMAGE_MB = int(os.getenv("MAX_IMAGE_MB", "10"))
MAX_IMAGE_BYTES = MAX_IMAGE_MB * 1024 * 1024
MAX_TEXT_CHARS = 50_000
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "30"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1" if os.getenv("RENDER") else "0") == "1"
COOKIE_NAME = "lib_session"
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")   # 0.0.0.0 = accept connections from anywhere

_mongo_opts = {"serverSelectionTimeoutMS": 20000, "connectTimeoutMS": 20000}
if MONGO_URL.startswith("mongodb+srv://") or "tls=true" in MONGO_URL.lower() or "ssl=true" in MONGO_URL.lower():
    _mongo_opts["tlsCAFile"] = certifi.where()   # trusted CA bundle for Atlas / TLS connections
client = MongoClient(MONGO_URL, **_mongo_opts)
db = client[MONGO_DB]
notes = db["saved_items"]      # one document per saved text / image
images = db["library_images"]  # raw image bytes
users = db["users"]            # one record per email
sessions = db["sessions"]      # login sessions (auto-expire)


def _mask(url: str) -> str:
    """Hide the password when printing the connection string."""
    return re.sub(r"://([^:/@]+):([^@]+)@", r"://\1:****@", url)


_db_ready = False
_db_error = ""


def _explain(err: str) -> str:
    if "TLSV1_ALERT_INTERNAL_ERROR" in err or "SSL handshake failed" in err:
        return ("Atlas refused the connection. Check: (1) Network Access has 0.0.0.0/0 in the SAME "
                "project as this cluster, (2) the cluster is not paused, (3) MONGO_URL is correct.")
    if "Authentication failed" in err or "bad auth" in err:
        return "Wrong database username or password in MONGO_URL."
    if "localhost:27017" in err:
        return "MONGO_URL is not set, so the app tried localhost. Set MONGO_URL in your environment."
    return "Check MONGO_URL and the MongoDB Atlas network access list."


def ensure_db() -> None:
    """Connect once and create indexes. Raises HTTP 503 (instead of crashing the app) if MongoDB is unreachable."""
    global _db_ready, _db_error
    if _db_ready:
        return
    try:
        client.admin.command("ping")
        notes.create_index([("email", 1), ("created_at", -1)])
        images.create_index([("email", 1)])
        users.create_index("email", unique=True)
        sessions.create_index("token_hash", unique=True)
        sessions.create_index("expires_at", expireAfterSeconds=0)
        _db_ready = True
        _db_error = ""
        print("MongoDB connected.")
    except PyMongoError as exc:
        _db_error = str(exc)[:500]
        raise HTTPException(status_code=503, detail="Database is not reachable. " + _explain(_db_error))


@asynccontextmanager
async def lifespan(_: FastAPI):
    print(f"Using MongoDB: {_mask(MONGO_URL)}  (database: {MONGO_DB})")
    try:
        ensure_db()
    except HTTPException as exc:
        print(f"WARNING: MongoDB is not reachable yet; will retry on each request.\n  Hint: {exc.detail}\n  Details: {_db_error}")
    yield
    client.close()


app = FastAPI(title="Personal Notes & Image Library", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def clean_email(value: str) -> str:
    try:
        return validate_email((value or "").strip(), check_deliverability=False).normalized.lower()
    except (EmailNotValidError, AttributeError):
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")


def parse_dt(value: str) -> datetime:
    try:
        return as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date filter.")


def browser_time_or_now(value: Optional[str]) -> datetime:
    """Use the timestamp the browser sent; fall back to server time if missing or implausible."""
    now = utc_now()
    if value:
        try:
            t = as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
            if abs(t - now) <= timedelta(days=1):
                return t
        except ValueError:
            pass
    return now


def to_object_id(value: str) -> ObjectId:
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=404, detail="Item not found.")


def serialize(doc: dict) -> dict:
    created = as_utc(doc["created_at"])
    return {
        "id": str(doc["_id"]),
        "name": doc.get("title", ""),   # only set for "text file" items
        "text": doc.get("text", ""),
        "kind": doc.get("kind", "text"),
        "created_at": created.isoformat(),
        "has_image": bool(doc.get("image_id")),
    }


# ---------------------------------------------------------------------------
# Email login (no password). The server keeps the identity in a session cookie
# and scopes every query to it; the browser never tells the server "who" it is.
# ---------------------------------------------------------------------------
class LoginBody(BaseModel):
    email: str


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def start_session(response: Response, email: str) -> None:
    token = secrets.token_urlsafe(32)
    sessions.insert_one({
        "token_hash": token_digest(token),
        "email": email,
        "created_at": utc_now(),
        "expires_at": utc_now() + timedelta(days=SESSION_DAYS),
    })
    response.set_cookie(
        COOKIE_NAME, token, max_age=SESSION_DAYS * 86400, httponly=True,
        samesite="lax", secure=COOKIE_SECURE, path="/",
    )


def current_user(request: Request) -> str:
    ensure_db()
    token = request.cookies.get(COOKIE_NAME)
    if token:
        session = sessions.find_one({"token_hash": token_digest(token)})
        if session and as_utc(session["expires_at"]) > utc_now():
            return session["email"]
    raise HTTPException(status_code=401, detail="Please sign in.")


@app.post("/api/login")
def login(body: LoginBody, response: Response):
    ensure_db()
    email = clean_email(body.email)
    now = utc_now()
    users.update_one(
        {"email": email},
        {"$setOnInsert": {"created_at": now}, "$set": {"last_login": now}},
        upsert=True,
    )
    start_session(response, email)
    return {"email": email}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        try:
            sessions.delete_one({"token_hash": token_digest(token)})
        except PyMongoError:
            pass
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(email: str = Depends(current_user)):
    return {"email": email}


# ---------------------------------------------------------------------------
# Items API  (every query is scoped to the signed-in email)
# ---------------------------------------------------------------------------
@app.get("/api/stats")
def stats(email: str = Depends(current_user)):
    since = utc_now() - timedelta(hours=24)
    return {
        "total": notes.count_documents({"email": email}),
        "images": notes.count_documents({"email": email, "kind": "image"}),
        "text": notes.count_documents({"email": email, "kind": "text"}),
        "new": notes.count_documents({"email": email, "created_at": {"$gte": since}}),
    }


@app.get("/api/items")
def list_items(
    q: str = "",
    start: Optional[str] = None,   # ISO datetime, inclusive
    end: Optional[str] = None,     # ISO datetime, exclusive
    kind: str = "",                # "", "text" or "image"
    order: str = "asc",            # "asc" = oldest first, "desc" = newest first
    email: str = Depends(current_user),
):
    query: dict = {"email": email}

    term = q.strip()
    if term:
        rx = {"$regex": re.escape(term), "$options": "i"}
        query["$or"] = [{"title": rx}, {"text": rx}]

    date_range = {}
    if start:
        date_range["$gte"] = parse_dt(start)
    if end:
        date_range["$lt"] = parse_dt(end)
    if date_range:
        query["created_at"] = date_range

    if kind in ("text", "image"):
        query["kind"] = kind

    direction = DESCENDING if order == "desc" else ASCENDING
    docs = notes.find(query).sort("created_at", direction).limit(1000)
    return {"items": [serialize(d) for d in docs]}


@app.post("/api/items")
def create_item(
    name: str = Form(""),                      # only used by the "Text file" button
    text: str = Form(""),
    created_at: Optional[str] = Form(None),    # sent automatically by the browser
    image: Optional[UploadFile] = File(None),
    email: str = Depends(current_user),
):
    name = name.strip()[:150]
    text = text.strip()
    if len(text) > MAX_TEXT_CHARS:
        raise HTTPException(status_code=400, detail=f"Text is too long (max {MAX_TEXT_CHARS} characters).")

    now = browser_time_or_now(created_at)
    doc = {"email": email, "title": name, "text": text, "kind": "text", "created_at": now}

    if image is not None and image.filename:
        if not (image.content_type or "").startswith("image/"):
            raise HTTPException(status_code=400, detail="Only image files are allowed.")
        data = image.file.read(MAX_IMAGE_BYTES + 1)
        if len(data) > MAX_IMAGE_BYTES:
            raise HTTPException(status_code=413, detail=f"Image is larger than {MAX_IMAGE_MB} MB.")
        if not data:
            raise HTTPException(status_code=400, detail="The image file is empty.")
        image_id = images.insert_one({
            "email": email,
            "content_type": image.content_type,
            "size": len(data),
            "data": Binary(data),
            "created_at": now,
        }).inserted_id
        doc.update(kind="image", image_id=image_id, content_type=image.content_type)
    elif not text:
        raise HTTPException(status_code=400, detail="Nothing to save. Paste, upload, or write some text.")

    doc["_id"] = notes.insert_one(doc).inserted_id
    return serialize(doc)


@app.get("/api/items/{item_id}/image")
def get_image(item_id: str, email: str = Depends(current_user)):
    item = notes.find_one({"_id": to_object_id(item_id), "email": email})
    if not item or not item.get("image_id"):
        raise HTTPException(status_code=404, detail="Image not found.")
    img = images.find_one({"_id": item["image_id"], "email": email})
    if not img:
        raise HTTPException(status_code=404, detail="Image not found.")
    return Response(
        content=bytes(img["data"]),
        media_type=img.get("content_type") or "application/octet-stream",
        headers={"Cache-Control": "private, max-age=86400"},
    )


@app.delete("/api/items/{item_id}")
def delete_item(item_id: str, email: str = Depends(current_user)):
    # Matches _id AND the signed-in email, so another email can never delete it.
    item = notes.find_one_and_delete({"_id": to_object_id(item_id), "email": email})
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    if item.get("image_id"):
        images.delete_one({"_id": item["image_id"], "email": email})
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Frontend (PAGE must be defined before the route that returns it)
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Saved Library</title>
<style>
  :root {
    --bg:#f3f5f9; --card:#ffffff; --text:#0f172a; --muted:#64748b; --line:#e2e8f0;
    --accent:#2563eb; --accent-dark:#1d4ed8; --accent-soft:rgba(37,99,235,.10); --accent-text:#ffffff;
    --nav:#0b1b3a; --new:#ea580c; --danger:#dc2626;
    --shadow:0 1px 2px rgba(15,23,42,.06), 0 4px 14px rgba(15,23,42,.05);
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0b1220; --card:#111a2e; --text:#e5e9f2; --muted:#94a3b8; --line:#1f2a44;
            --accent:#4f8bff; --accent-dark:#3b7bff; --accent-soft:rgba(79,139,255,.14); --accent-text:#ffffff;
            --nav:#070d1b; --new:#fb923c; --danger:#f87171; --shadow:0 1px 2px rgba(0,0,0,.4); }
  }
  * { box-sizing:border-box; }
  [hidden] { display:none !important; }
  html { -webkit-text-size-adjust:100%; }
  body { margin:0; background:var(--bg); color:var(--text);
         font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  input, textarea, select, button { font:inherit; color:inherit; }
  input, textarea, select { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:10px 12px; width:100%; min-height:42px; }
  input:focus, textarea:focus, select:focus, .drop:focus-visible, button:focus-visible { outline:2px solid var(--accent); outline-offset:1px; }
  textarea { resize:vertical; min-height:120px; }
  button { cursor:pointer; border:1px solid var(--line); background:var(--card); border-radius:10px; padding:9px 16px; min-height:40px; font-weight:500; transition:background .15s, border-color .15s; }
  button:hover { border-color:var(--accent); }
  button.primary { background:var(--accent); color:var(--accent-text); border-color:var(--accent); font-weight:600; }
  button.primary:hover { background:var(--accent-dark); }
  button:disabled { opacity:.5; cursor:default; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:14px; box-shadow:var(--shadow); }
  h2.sec { font-size:13px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); margin:0 0 12px; font-weight:700; }

  /* ===== First page ===== */
  .login { min-height:100vh; display:grid; grid-template-columns:1.15fr 1fr; }
  .hero { background:linear-gradient(145deg,#0b1b3a 0%,#12306b 55%,#1d4ed8 120%); color:#eaf0ff; padding:56px clamp(24px,6vw,84px);
          display:flex; flex-direction:column; justify-content:center; }
  .brand { display:flex; align-items:center; gap:10px; font-weight:700; font-size:18px; }
  .logo { width:34px; height:34px; border-radius:9px; background:#fff; color:#1d4ed8; display:grid; place-items:center; font-weight:800; font-size:14px; }
  .hero h1 { font-size:clamp(28px,4vw,42px); line-height:1.15; margin:34px 0 14px; letter-spacing:-.02em; }
  .hero p.lead { color:#c3d2f5; font-size:16.5px; margin:0 0 26px; max-width:560px; }
  .features { list-style:none; padding:0; margin:0; display:grid; gap:14px; max-width:560px; }
  .features li { padding-left:32px; position:relative; color:#dbe5ff; }
  .features li::before { content:"\2713"; position:absolute; left:0; top:1px; width:22px; height:22px; border-radius:50%;
                         background:rgba(255,255,255,.14); display:grid; place-items:center; font-size:12px; color:#fff; font-weight:700; }
  .features b { color:#fff; font-weight:600; }
  .signin { display:flex; align-items:center; justify-content:center; padding:32px 20px; }
  .signin .card { width:100%; max-width:400px; padding:32px; }
  .signin h2 { margin:0 0 6px; font-size:24px; letter-spacing:-.01em; }
  .signin p { margin:0 0 20px; color:var(--muted); }
  .signin .stack { display:grid; gap:12px; }
  .signin .note { font-size:12.5px; color:var(--muted); margin:16px 0 0; text-align:center; }
  @media (max-width:880px) {
    .login { grid-template-columns:1fr; }
    .hero { padding:32px 22px 30px; }
    .hero h1 { margin-top:22px; }
    .signin { padding:24px 16px 40px; }
  }

  /* ===== Dashboard ===== */
  .nav { position:sticky; top:0; z-index:40; background:var(--nav); color:#fff; }
  .nav-in { max-width:1240px; margin:0 auto; padding:10px 18px; display:flex; align-items:center; justify-content:space-between; gap:12px; }
  .nav .brand { font-size:17px; }
  .who { display:flex; align-items:center; gap:10px; min-width:0; }
  .avatar { width:34px; height:34px; border-radius:50%; background:var(--accent); color:#fff; display:grid; place-items:center; font-weight:700; flex:none; }
  #whoEmail { color:#c9d6f5; font-size:14px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:260px; }
  .nav button { background:rgba(255,255,255,.1); border-color:rgba(255,255,255,.2); color:#fff; min-height:36px; padding:6px 14px; }
  .nav button:hover { background:rgba(255,255,255,.2); }
  @media (max-width:640px) { #whoEmail { display:none; } }

  .shell { max-width:1240px; margin:0 auto; padding:20px 18px 80px; }
  .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:20px; }
  .stat { padding:16px 18px; }
  .stat .n { font-size:28px; font-weight:700; line-height:1.1; letter-spacing:-.02em; }
  .stat .l { color:var(--muted); font-size:13px; margin-top:4px; }
  .stat.hl .n { color:var(--new); }
  @media (max-width:760px) { .stats { grid-template-columns:repeat(2,1fr); gap:10px; } .stat .n { font-size:24px; } }

  .layout { display:grid; grid-template-columns:360px minmax(0,1fr); gap:20px; align-items:start; }
  .side { position:sticky; top:74px; padding:18px; }
  @media (max-width:980px) { .layout { grid-template-columns:1fr; } .side { position:static; } }

  .drop { border:2px dashed var(--line); border-radius:12px; padding:28px 14px; text-align:center; color:var(--muted); cursor:pointer; transition:.15s; }
  .drop:hover, .drop.over { border-color:var(--accent); background:var(--accent-soft); }
  .drop .ic { width:44px; height:44px; margin:0 auto 10px; border-radius:12px; background:var(--accent-soft); color:var(--accent); display:grid; place-items:center; font-size:22px; font-weight:700; }
  .drop strong { color:var(--text); display:block; }
  .drop small { display:block; margin-top:4px; }
  .staged { display:grid; grid-template-columns:repeat(auto-fill,minmax(96px,1fr)); gap:10px; margin-top:12px; }
  .chip { position:relative; border:1px solid var(--line); border-radius:10px; overflow:hidden; background:var(--bg); aspect-ratio:1; }
  .chip img { width:100%; height:100%; object-fit:cover; display:block; }
  .chip .snip { padding:8px; font-size:12px; color:var(--muted); height:100%; overflow:hidden; white-space:pre-wrap; word-break:break-word; }
  .chip .x { position:absolute; top:4px; right:4px; width:24px; height:24px; min-height:0; padding:0; border-radius:50%; line-height:1; background:rgba(0,0,0,.65); color:#fff; border:none; }
  .actions-row { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:14px; }
  .textfile { margin-top:16px; border-top:1px solid var(--line); padding-top:16px; display:grid; gap:10px; }
  .textfile .row { display:grid; grid-template-columns:1fr 1fr; gap:10px; }

  .main { min-width:0; }
  .toolbar { padding:14px; margin-bottom:6px; display:grid; grid-template-columns:2fr 1fr 1fr 1fr 1fr auto; gap:10px; align-items:end; }
  .toolbar label { font-size:12px; color:var(--muted); display:block; margin-bottom:4px; font-weight:600; }
  @media (max-width:1180px) { .toolbar { grid-template-columns:repeat(4,1fr); } .toolbar .wide { grid-column:1 / -1; } .toolbar #clearBtn { grid-column:span 1; } }
  @media (max-width:560px) { .toolbar { grid-template-columns:1fr 1fr; } }

  .day { margin-top:24px; }
  .day h3 { font-size:14px; margin:0 0 12px; padding-bottom:8px; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; align-items:center; font-weight:700; }
  .day h3 span { color:var(--muted); font-weight:500; font-size:13px; background:var(--card); border:1px solid var(--line); padding:1px 10px; border-radius:999px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(min(230px,100%),1fr)); gap:14px; }
  .grid > * { min-width:0; }
  .item { position:relative; background:var(--card); border:1px solid var(--line); border-radius:14px; cursor:pointer; box-shadow:var(--shadow);
          display:flex; flex-direction:column; overflow:hidden; min-width:0; max-width:100%; transition:transform .15s, border-color .15s; }
  .item:hover { border-color:var(--accent); transform:translateY(-2px); }
  .item .pic { width:100%; aspect-ratio:4/3; object-fit:cover; display:block; background:var(--bg); }
  .item .in { padding:14px; display:flex; flex-direction:column; gap:8px; flex:1; min-width:0; }
  .item h4 { margin:0; font-size:15px; padding-right:44px; word-break:break-word; }
  .item .body { white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word; tab-size:4; min-width:0; max-width:100%;
                display:-webkit-box; -webkit-box-orient:vertical; -webkit-line-clamp:7; line-clamp:7; overflow:hidden; color:var(--text); }
  .badge { position:absolute; top:10px; right:10px; background:var(--new); color:#fff; font-size:10.5px; font-weight:800; letter-spacing:.07em; padding:3px 9px; border-radius:999px; z-index:1; }
  .actions { display:flex; gap:6px; flex-wrap:wrap; justify-content:flex-end; margin-top:auto; padding-top:4px; }
  .actions button { padding:3px 10px; min-height:30px; font-size:12.5px; }
  .actions .del { color:var(--danger); }
  .empty { text-align:center; color:var(--muted); padding:64px 16px; }
  .empty .big { font-size:40px; margin-bottom:6px; }
  .toast { position:fixed; left:50%; bottom:24px; transform:translateX(-50%); background:#0f172a; color:#fff; z-index:200;
           padding:11px 18px; border-radius:10px; opacity:0; pointer-events:none; transition:opacity .2s; max-width:90vw; box-shadow:0 8px 24px rgba(0,0,0,.3); }
  .toast.show { opacity:1; }
  .toast.err { background:#b91c1c; }

  /* ===== Same-page viewer / slideshow ===== */
  .viewer { position:fixed; inset:0; z-index:100; background:rgba(6,9,16,.95); color:#f1f5f9; display:flex; flex-direction:column; }
  .v-top { display:flex; justify-content:space-between; align-items:center; padding:12px 16px; gap:10px; }
  .v-top .grp { display:flex; gap:8px; align-items:center; }
  .v-top button { background:rgba(255,255,255,.1); border:1px solid rgba(255,255,255,.2); color:#fff; }
  .v-top .v-x { font-size:24px; line-height:1; width:42px; height:42px; padding:0; border-radius:50%; }
  .v-mid { flex:1; min-height:0; display:flex; align-items:center; gap:8px; padding:0 10px; }
  .v-nav { flex:none; width:46px; height:46px; min-height:0; border-radius:50%; font-size:30px; line-height:1; padding:0 0 4px;
           background:rgba(255,255,255,.1); border:1px solid rgba(255,255,255,.2); color:#fff; }
  .v-stage { flex:1; min-width:0; height:100%; display:flex; align-items:center; justify-content:center; }
  .v-stage img { max-width:100%; max-height:100%; object-fit:contain; border-radius:8px; }
  .v-text { width:min(780px,100%); min-width:0; max-height:100%; overflow:auto; background:var(--card); color:var(--text);
            border-radius:14px; padding:24px; display:grid; gap:14px; }
  .v-text h2 { margin:0; font-size:21px; word-break:break-word; }
  .v-text .v-body { white-space:pre-wrap; overflow-wrap:anywhere; tab-size:4; font-size:16px; }
  .v-text button { justify-self:start; }
  .v-thumbs { display:flex; gap:8px; overflow-x:auto; padding:12px 16px 18px; }
  .thumb { flex:none; width:78px; height:58px; padding:0; min-height:0; border-radius:9px; overflow:hidden; border:2px solid transparent;
           background:rgba(255,255,255,.08); opacity:.55; }
  .thumb.active { border-color:var(--accent); opacity:1; }
  .thumb img { width:100%; height:100%; object-fit:cover; display:block; }
  .thumb span { display:block; padding:5px; font-size:10px; line-height:1.2; color:#d8dee9; text-align:left; overflow:hidden; height:100%; word-break:break-word; }
  @media (max-width:600px) { .v-nav { width:36px; height:36px; font-size:24px; } }
</style>
</head>
<body>

<!-- ===== PAGE 1: product description + email login ===== -->
<div id="loginView" class="login" hidden>
  <section class="hero">
    <div class="brand"><span class="logo">SL</span> Saved Library</div>
    <h1>Your private vault for notes and images.</h1>
    <p class="lead">Paste a screenshot, upload a picture or write a quick note, then find it again in seconds. Every email address gets its own isolated library, so what you save stays yours.</p>
    <ul class="features">
      <li><b>Save in one click.</b> Paste with Ctrl+V, drag &amp; drop or upload, then press Save. Nothing to name.</li>
      <li><b>Text files.</b> Give a file a name, write the text, keep it and download it any time.</li>
      <li><b>Organised by date.</b> Date and time are recorded automatically and grouped day by day.</li>
      <li><b>Find anything fast.</b> Search, filter by date range or type, and spot fresh items with the NEW tag.</li>
      <li><b>Gallery viewer.</b> Open items on the same page and flip through them with next and previous.</li>
      <li><b>Isolated by email.</b> Each email sees only its own data and can delete only its own items.</li>
    </ul>
  </section>

  <section class="signin">
    <div class="card">
      <h2>Sign in</h2>
      <p>Enter your email to open your library.</p>
      <div class="stack">
        <input id="email" type="email" placeholder="you@company.com" autocomplete="email" inputmode="email">
        <button id="authBtn" class="primary">Continue</button>
      </div>
      <p class="note">No password needed. Each email has its own separate library.</p>
    </div>
  </section>
</div>

<!-- ===== PAGE 2: dashboard ===== -->
<div id="app" hidden>
  <nav class="nav">
    <div class="nav-in">
      <div class="brand"><span class="logo">SL</span> Saved Library</div>
      <div class="who">
        <span id="avatar" class="avatar"></span>
        <span id="whoEmail"></span>
        <button id="signOutBtn">Sign out</button>
      </div>
    </div>
  </nav>

  <div class="shell">
    <section class="stats">
      <div class="card stat"><div class="n" id="sTotal">0</div><div class="l">Total items</div></div>
      <div class="card stat"><div class="n" id="sImages">0</div><div class="l">Images</div></div>
      <div class="card stat"><div class="n" id="sText">0</div><div class="l">Text items</div></div>
      <div class="card stat hl"><div class="n" id="sNew">0</div><div class="l">New in last 24 hours</div></div>
    </section>

    <div class="layout">
      <aside class="card side">
        <h2 class="sec">Add to library</h2>
        <div id="drop" class="drop" tabindex="0">
          <div class="ic">+</div>
          <strong>Paste, drop or click to upload</strong>
          <small>Use Ctrl+V to paste images or text</small>
        </div>
        <input id="file" type="file" accept="image/*" multiple hidden>

        <div id="staged" class="staged" hidden></div>

        <div class="actions-row">
          <button id="saveBtn" class="primary" disabled>Save</button>
          <button id="textBtn">Text file</button>
        </div>

        <div id="textfile" class="textfile" hidden>
          <input id="tfName" placeholder="File name" maxlength="150">
          <textarea id="tfText" placeholder="Write your text here..."></textarea>
          <div class="row">
            <button id="tfSave" class="primary">Save file</button>
            <button id="tfCancel">Cancel</button>
          </div>
        </div>
      </aside>

      <section class="main">
        <div class="card toolbar">
          <div class="wide">
            <label for="q">Search</label>
            <input id="q" type="search" placeholder="Search saved text and file names...">
          </div>
          <div><label for="from">From date</label><input id="from" type="date"></div>
          <div><label for="to">To date</label><input id="to" type="date"></div>
          <div>
            <label for="kind">Type</label>
            <select id="kind"><option value="">All</option><option value="text">Text</option><option value="image">Images</option></select>
          </div>
          <div>
            <label for="order">Order</label>
            <select id="order"><option value="asc">Oldest first</option><option value="desc">Newest first</option></select>
          </div>
          <button id="clearBtn">Clear</button>
        </div>
        <div id="list"></div>
      </section>
    </div>
  </div>
</div>

<!-- ===== Same-page viewer ===== -->
<div id="viewer" class="viewer" hidden>
  <div class="v-top">
    <span id="vCount"></span>
    <div class="grp">
      <button id="vClose" class="v-x" aria-label="Close" title="Close (Esc)">&times;</button>
    </div>
  </div>
  <div class="v-mid">
    <button id="vPrev" class="v-nav" aria-label="Previous" title="Previous">&lsaquo;</button>
    <div id="vStage" class="v-stage"></div>
    <button id="vNext" class="v-nav" aria-label="Next" title="Next">&rsaquo;</button>
  </div>
  <div id="vThumbs" class="v-thumbs"></div>
</div>

<div id="toast" class="toast"></div>

<script>
const $ = (s) => document.querySelector(s);
let email = "";
let items = [];
let staged = [];      // pasted / dropped / chosen things waiting for the Save button
let timer = null;
let uid = 0;

function toast(msg, isErr) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show" + (isErr ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = "toast"), isErr ? 5000 : 2800);
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = "Request failed (" + r.status + ")";
    try {
      const d = (await r.json()).detail;
      msg = Array.isArray(d) ? d.map((x) => x.msg).join(", ") : d || msg;
    } catch (e) {}
    if (r.status === 401 && !path.startsWith("/api/login") && !path.startsWith("/api/me")) sessionEnded();
    const err = new Error(msg);
    err.status = r.status;
    throw err;
  }
  return r.json();
}

function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  Object.assign(n, props || {});
  kids.forEach((k) => k != null && n.append(k));
  return n;
}

/* ---------- pages ---------- */
function showLogin() {
  closeViewer();
  $("#app").hidden = true;
  $("#loginView").hidden = false;
  $("#email").focus();
}

function showApp() {
  $("#loginView").hidden = true;
  $("#app").hidden = false;
  $("#whoEmail").textContent = email;
  $("#avatar").textContent = (email[0] || "?").toUpperCase();
  load();
}

function sessionEnded() {
  if ($("#app").hidden) return;
  email = ""; items = [];
  clearStaged();
  showLogin();
  toast("Your session ended. Please sign in again.", true);
}

/* ---------- email login ---------- */
async function submitLogin() {
  const e = $("#email").value.trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(e)) return toast("Enter a valid email address", true);
  const btn = $("#authBtn");
  btn.disabled = true;
  try {
    const r = await api("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: e }),
    });
    email = r.email;
    showApp();
  } catch (err) { toast(err.message, true); }
  btn.disabled = false;
}
$("#authBtn").onclick = submitLogin;
$("#email").addEventListener("keydown", (e) => { if (e.key === "Enter") submitLogin(); });

$("#signOutBtn").onclick = async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (e) {}
  email = ""; items = [];
  clearStaged();
  $("#email").value = "";
  showLogin();
};

/* ---------- listing ---------- */
function imgUrl(id) { return "/api/items/" + id + "/image"; }
function isNew(it) { return Date.now() - new Date(it.created_at).getTime() < 24 * 3600 * 1000; }
function dayKey(d) { return d.toLocaleDateString("en-CA"); }
function dayLabel(d) {
  const today = new Date(), yest = new Date();
  yest.setDate(today.getDate() - 1);
  if (dayKey(d) === dayKey(today)) return "Today";
  if (dayKey(d) === dayKey(yest)) return "Yesterday";
  return d.toLocaleDateString(undefined, { weekday: "long", year: "numeric", month: "long", day: "numeric" });
}

async function loadStats() {
  try {
    const s = await api("/api/stats");
    $("#sTotal").textContent = s.total;
    $("#sImages").textContent = s.images;
    $("#sText").textContent = s.text;
    $("#sNew").textContent = s.new;
  } catch (e) {}
}

async function load() {
  const p = new URLSearchParams({ order: $("#order").value });
  const q = $("#q").value.trim();
  if (q) p.set("q", q);
  if ($("#kind").value) p.set("kind", $("#kind").value);
  if ($("#from").value) p.set("start", new Date($("#from").value + "T00:00:00").toISOString());
  if ($("#to").value) {
    const e = new Date($("#to").value + "T00:00:00");
    e.setDate(e.getDate() + 1);
    p.set("end", e.toISOString());
  }
  loadStats();
  try {
    items = (await api("/api/items?" + p)).items;
    render();
  } catch (err) { if (!$("#app").hidden) toast(err.message, true); }
}

function render() {
  const root = $("#list");
  root.replaceChildren();
  if (!items.length) {
    root.append(el("div", { className: "empty" },
      el("div", { className: "big", textContent: "\ud83d\udcc2" }),
      el("div", { textContent: "Nothing here yet. Paste, upload, or create a text file." })));
    return;
  }
  const groups = new Map();
  items.forEach((it) => {
    const d = new Date(it.created_at), k = dayKey(d);
    if (!groups.has(k)) groups.set(k, { label: dayLabel(d), list: [] });
    groups.get(k).list.push(it);
  });
  groups.forEach((g) => {
    const grid = el("div", { className: "grid" });
    g.list.forEach((it) => grid.append(card(it)));
    root.append(el("section", { className: "day" },
      el("h3", {}, el("div", { textContent: g.label }),
        el("span", { textContent: g.list.length + (g.list.length === 1 ? " item" : " items") })),
      grid));
  });
}

function downloadText(it) {
  const base = (it.name || "note").replace(/[\\/:*?"<>|]+/g, "_");
  const a = el("a", { href: URL.createObjectURL(new Blob([it.text], { type: "text/plain" })), download: base + ".txt" });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); } catch (e) { toast("Copy failed", true); }
}

function card(it) {
  const c = el("article", { className: "item" });
  c.onclick = () => openViewer(items.indexOf(it));
  if (isNew(it)) c.append(el("div", { className: "badge", textContent: "NEW" }));
  if (it.has_image) c.append(el("img", { className: "pic", src: imgUrl(it.id), alt: "saved image", loading: "lazy" }));

  const inner = el("div", { className: "in" });
  if (it.name) inner.append(el("h4", { textContent: it.name }));
  if (it.text) inner.append(el("div", { className: "body", textContent: it.text }));

  const actions = el("div", { className: "actions" });
  actions.onclick = (e) => e.stopPropagation();
  const open = el("button", { textContent: "Open" });
  open.onclick = () => openViewer(items.indexOf(it));
  actions.append(open);
  if (it.text) {
    const copy = el("button", { textContent: "Copy" });
    copy.onclick = () => copyText(it.text);
    actions.append(copy);
    if (it.name) {
      const dl = el("button", { textContent: "Download" });
      dl.onclick = () => downloadText(it);
      actions.append(dl);
    }
  }
  const del = el("button", { className: "del", textContent: "Delete" });
  del.onclick = async () => {
    if (!confirm("Delete this item?")) return;
    try { await api("/api/items/" + it.id, { method: "DELETE" }); load(); }
    catch (err) { toast(err.message, true); }
  };
  actions.append(del);
  inner.append(actions);
  c.append(inner);
  return c;
}

/* ---------- same-page viewer with slideshow ---------- */
let vIndex = -1, touchX = null;

function openViewer(i) {
  if (i < 0 || !items.length) return;
  vIndex = i;
  $("#viewer").hidden = false;
  document.body.style.overflow = "hidden";
  buildThumbs();
  showSlide();
}

function closeViewer() {
  if ($("#viewer").hidden) return;
  $("#viewer").hidden = true;
  document.body.style.overflow = "";
  $("#vStage").replaceChildren();
  vIndex = -1;
}

function step(d) {
  if (!items.length) return;
  vIndex = (vIndex + d + items.length) % items.length;
  showSlide();
}

function buildThumbs() {
  const box = $("#vThumbs");
  box.replaceChildren();
  items.forEach((it, i) => {
    const b = el("button", { className: "thumb", title: it.name || "" });
    b.append(it.has_image
      ? el("img", { src: imgUrl(it.id), alt: "", loading: "lazy" })
      : el("span", { textContent: (it.name || it.text).slice(0, 40) }));
    b.onclick = () => { vIndex = i; showSlide(); };
    box.append(b);
  });
}

function showSlide() {
  const it = items[vIndex];
  if (!it) return;
  $("#vCount").textContent = (vIndex + 1) + " / " + items.length;
  const stage = $("#vStage");
  stage.replaceChildren();
  if (it.has_image) {
    stage.append(el("img", { src: imgUrl(it.id), alt: "saved image" }));
  } else {
    const box = el("div", { className: "v-text" });
    if (it.name) box.append(el("h2", { textContent: it.name }));
    box.append(el("div", { className: "v-body", textContent: it.text }));
    const cp = el("button", { textContent: "Copy" });
    cp.onclick = () => copyText(it.text);
    box.append(cp);
    stage.append(box);
  }
  [...$("#vThumbs").children].forEach((t, i) => {
    t.classList.toggle("active", i === vIndex);
    if (i === vIndex) t.scrollIntoView({ inline: "center", block: "nearest", behavior: "smooth" });
  });
}

$("#vClose").onclick = closeViewer;
$("#vPrev").onclick = () => step(-1);
$("#vNext").onclick = () => step(1);
$("#vStage").onclick = (e) => { if (e.target === e.currentTarget) closeViewer(); };
$("#vStage").addEventListener("touchstart", (e) => { touchX = e.touches[0].clientX; }, { passive: true });
$("#vStage").addEventListener("touchend", (e) => {
  if (touchX === null) return;
  const dx = e.changedTouches[0].clientX - touchX;
  touchX = null;
  if (Math.abs(dx) > 50) step(dx < 0 ? 1 : -1);
});
document.addEventListener("keydown", (e) => {
  if ($("#viewer").hidden) return;
  if (e.key === "Escape") closeViewer();
  else if (e.key === "ArrowLeft") step(-1);
  else if (e.key === "ArrowRight") step(1);
});

/* ---------- staging area (paste / drop / upload, then Save) ---------- */
function stageImage(file) {
  staged.push({ id: ++uid, type: "image", file, url: URL.createObjectURL(file) });
  renderStaged();
}
function stageText(text) {
  staged.push({ id: ++uid, type: "text", text });
  renderStaged();
}
function clearStaged() {
  staged.forEach((s) => s.url && URL.revokeObjectURL(s.url));
  staged = [];
  renderStaged();
}
function renderStaged() {
  const box = $("#staged");
  box.replaceChildren();
  box.hidden = staged.length === 0;
  $("#saveBtn").disabled = staged.length === 0;
  staged.forEach((s) => {
    const chip = el("div", { className: "chip" });
    chip.append(s.type === "image" ? el("img", { src: s.url, alt: "" }) : el("div", { className: "snip", textContent: s.text.slice(0, 160) }));
    const x = el("button", { className: "x", textContent: "\u00d7", title: "Remove" });
    x.onclick = () => {
      if (s.url) URL.revokeObjectURL(s.url);
      staged = staged.filter((o) => o.id !== s.id);
      renderStaged();
    };
    chip.append(x);
    box.append(chip);
  });
}

async function postItem({ name = "", text = "", file = null }) {
  const fd = new FormData();
  fd.append("name", name);
  fd.append("text", text);
  fd.append("created_at", new Date().toISOString());   // date & time come from the browser
  if (file) fd.append("image", file, file.name || "image.png");
  return api("/api/items", { method: "POST", body: fd });
}

$("#saveBtn").onclick = async () => {
  const btn = $("#saveBtn");
  btn.disabled = true;
  let saved = 0;
  for (const s of [...staged]) {
    try {
      await postItem(s.type === "image" ? { file: s.file } : { text: s.text });
      if (s.url) URL.revokeObjectURL(s.url);
      staged = staged.filter((o) => o.id !== s.id);
      saved++;
    } catch (err) { toast(err.message, true); break; }
  }
  renderStaged();
  if (saved) { toast(saved === 1 ? "Saved" : saved + " items saved"); load(); }
};

/* ---------- drop zone ---------- */
const drop = $("#drop");
drop.onclick = () => $("#file").click();
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#file").click(); } });
$("#file").onchange = (e) => { [...e.target.files].forEach(stageImage); e.target.value = ""; };

["dragenter", "dragover"].forEach((ev) => window.addEventListener(ev, (e) => { e.preventDefault(); if (!$("#app").hidden) drop.classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => window.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
window.addEventListener("drop", (e) => {
  if ($("#app").hidden || !$("#viewer").hidden) return;
  const dt = e.dataTransfer;
  if (!dt) return;
  const imgs = [...dt.files].filter((f) => f.type.startsWith("image/"));
  if (imgs.length) { imgs.forEach(stageImage); return; }
  const t = dt.getData("text");
  if (t && t.trim()) stageText(t);
});

document.addEventListener("paste", (e) => {
  if ($("#app").hidden || !$("#viewer").hidden) return;
  const cd = e.clipboardData;
  if (!cd) return;
  const imgs = [...cd.files].filter((f) => f.type.startsWith("image/"));
  if (imgs.length) { e.preventDefault(); imgs.forEach(stageImage); return; }
  const tag = document.activeElement && document.activeElement.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA") return;   // normal typing/pasting inside fields
  const t = cd.getData("text");
  if (t && t.trim()) { e.preventDefault(); stageText(t); }
});

/* ---------- "Text file" button ---------- */
$("#textBtn").onclick = () => {
  const box = $("#textfile");
  box.hidden = !box.hidden;
  if (!box.hidden) $("#tfName").focus();
};
$("#tfCancel").onclick = () => { $("#textfile").hidden = true; $("#tfName").value = ""; $("#tfText").value = ""; };
$("#tfSave").onclick = async () => {
  const name = $("#tfName").value.trim(), text = $("#tfText").value.trim();
  if (!name) return toast("Give the file a name", true);
  if (!text) return toast("Write some text first", true);
  const btn = $("#tfSave");
  btn.disabled = true;
  try {
    await postItem({ name, text });
    toast("Text file saved");
    $("#tfCancel").click();
    load();
  } catch (err) { toast(err.message, true); }
  btn.disabled = false;
};

/* ---------- filters ---------- */
$("#q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 250); });
["#from", "#to", "#kind", "#order"].forEach((s) => $(s).addEventListener("change", load));
$("#clearBtn").onclick = () => { $("#q").value = ""; $("#from").value = ""; $("#to").value = ""; $("#kind").value = ""; load(); };

// Re-check the NEW badge every minute so it disappears after 24 hours
setInterval(() => { if (!$("#app").hidden && $("#viewer").hidden && items.length) { render(); loadStats(); } }, 60000);

/* ---------- start: already signed in? ---------- */
(async () => {
  try { email = (await api("/api/me")).email; showApp(); }
  catch (e) {
    showLogin();
    if (e.status === 503) toast(e.message, true);   // show database problems instead of hiding them
  }
})();
</script>
</body>
</html>
"""


# HEAD is allowed so Render / uptime checks get 200 instead of 405
@app.api_route("/healthz", methods=["GET", "HEAD"])
def healthz():
    try:
        ensure_db()
    except HTTPException:
        pass
    return {
        "status": "ok",
        "database": "connected" if _db_ready else "unreachable",
        "hint": "" if _db_ready else _explain(_db_error),
        "error": "" if _db_ready else _db_error,
    }


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def home():
    return HTMLResponse(PAGE)


if __name__ == "__main__":
    print(f"Starting on http://{HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT)
