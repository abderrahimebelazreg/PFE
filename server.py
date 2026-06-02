from __future__ import annotations

import cgi
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import smtplib
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "bibio.db"
ENV_PATH = BASE_DIR / ".env"

ROLE_LEVELS = {"student": 1, "teacher": 2, "librarian": 3, "admin": 4}
PUBLIC_SIGNUP_ROLES = {"student", "teacher"}
VERIFICATION_TTL_MINUTES = 10
SESSION_TTL_DAYS = 7


def load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def getenv(key: str, default: str = "") -> str:
    env_file = load_env_file(ENV_PATH)
    return os.environ.get(key, env_file.get(key, default))


CONFIG = {
    "host": getenv("APP_HOST", "127.0.0.1"),
    "port": int(getenv("APP_PORT", "8000")),
    "gmail_email": getenv("GMAIL_EMAIL", ""),
    "gmail_app_password": getenv("GMAIL_APP_PASSWORD", ""),
    "default_admin_username": getenv("DEFAULT_ADMIN_USERNAME", "admin"),
    "default_admin_password": getenv("DEFAULT_ADMIN_PASSWORD", "Admin123!"),
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def iso_in(minutes: int = 0, days: int = 0) -> str:
    return (now_utc() + timedelta(minutes=minutes, days=days)).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def role_level(role: str | None) -> int:
    return ROLE_LEVELS.get((role or "").lower(), 0)


def normalize_role(role: str | None) -> str:
    value = (role or "student").strip().lower()
    aliases = {"user": "student", "guest": "teacher"}
    value = aliases.get(value, value)
    return value if value in ROLE_LEVELS else "student"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return hmac.compare_digest(actual, expected)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_paths() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    UPLOADS_DIR.mkdir(exist_ok=True)


def init_db() -> None:
    ensure_paths()
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                email_verified INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verification_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                isbn TEXT,
                category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                year INTEGER,
                total_copies INTEGER NOT NULL DEFAULT 1,
                language TEXT DEFAULT 'fr',
                publisher TEXT,
                description TEXT,
                section TEXT,
                shelf TEXT,
                position TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS loans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                book_id INTEGER NOT NULL REFERENCES books(id) ON DELETE CASCADE,
                loan_date TEXT NOT NULL,
                due_date TEXT NOT NULL,
                return_date TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT,
                category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                language TEXT DEFAULT 'fr',
                file_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL DEFAULT 0,
                page_count INTEGER,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        seed_data(conn)


def seed_data(conn: sqlite3.Connection) -> None:
    admin = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (CONFIG["default_admin_username"],),
    ).fetchone()
    if not admin:
        conn.execute(
            """
            INSERT INTO users (username, email, full_name, password_hash, role, is_active, email_verified, created_at)
            VALUES (?, ?, ?, ?, 'admin', 1, 1, ?)
            """,
            (
                CONFIG["default_admin_username"],
                f"{CONFIG['default_admin_username']}@bibio.local",
                "System Administrator",
                hash_password(CONFIG["default_admin_password"]),
                iso_now(),
            ),
        )
        conn.execute(
            "INSERT INTO activity_log (event_type, message, created_at) VALUES (?, ?, ?)",
            ("new_user", "تم إنشاء حساب المدير الافتراضي", iso_now()),
        )

    if conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO categories (name, description) VALUES (?, ?)",
            [
                ("Computer Science", "الخوارزميات والبرمجة"),
                ("Literature", "الروايات والنصوص الأدبية"),
                ("History", "المراجع التاريخية"),
            ],
        )

    if conn.execute("SELECT COUNT(*) FROM books").fetchone()[0] == 0:
        categories = {
            row["name"]: row["id"]
            for row in conn.execute("SELECT id, name FROM categories").fetchall()
        }
        books = [
            (
                "Introduction to Algorithms",
                "Cormen",
                "9780262046305",
                categories["Computer Science"],
                2022,
                4,
                "en",
                "MIT Press",
                "مرجع أساسي للخوارزميات",
                "A",
                "3",
                "12",
            ),
            (
                "Clean Code",
                "Robert C. Martin",
                "9780132350884",
                categories["Computer Science"],
                2008,
                3,
                "en",
                "Prentice Hall",
                "أفضل ممارسات كتابة الكود",
                "A",
                "4",
                "2",
            ),
            (
                "Les Miserables",
                "Victor Hugo",
                None,
                categories["Literature"],
                1862,
                2,
                "fr",
                "A. Lacroix",
                "رواية فرنسية كلاسيكية",
                "B",
                "1",
                "7",
            ),
            (
                "History of North Africa",
                "Abdeljelil Temimi",
                None,
                categories["History"],
                2018,
                2,
                "ar",
                "Academic Press",
                "مرجع إقليمي",
                "C",
                "2",
                "5",
            ),
        ]
        conn.executemany(
            """
            INSERT INTO books
            (title, author, isbn, category_id, year, total_copies, language, publisher, description, section, shelf, position, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(*book, iso_now()) for book in books],
        )
        conn.execute(
            "INSERT INTO activity_log (event_type, message, created_at) VALUES (?, ?, ?)",
            ("new_book", "تمت إضافة الكتب الافتراضية للمكتبة", iso_now()),
        )

    conn.commit()


def log_activity(conn: sqlite3.Connection, event_type: str, message: str) -> None:
    conn.execute(
        "INSERT INTO activity_log (event_type, message, created_at) VALUES (?, ?, ?)",
        (event_type, message, iso_now()),
    )


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (token, user_id, iso_in(days=SESSION_TTL_DAYS), iso_now()),
    )
    conn.commit()
    return token


def get_user_by_token(conn: sqlite3.Connection, token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    return conn.execute(
        """
        SELECT u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
        """,
        (token, iso_now()),
    ).fetchone()


def compute_available_copies(
    conn: sqlite3.Connection, book_id: int, total_copies: int | None = None
) -> int:
    if total_copies is None:
        row = conn.execute(
            "SELECT total_copies FROM books WHERE id = ?",
            (book_id,),
        ).fetchone()
        total_copies = int(row["total_copies"]) if row else 0
    active_loans = conn.execute(
        "SELECT COUNT(*) FROM loans WHERE book_id = ? AND return_date IS NULL",
        (book_id,),
    ).fetchone()[0]
    return max(int(total_copies) - int(active_loans), 0)


def page_count_for_pdf(path: Path) -> int | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    matches = len(re.findall(br"/Type\s*/Page\b", data))
    return matches or None


def send_verification_email(target_email: str, code: str) -> None:
    sender = CONFIG["gmail_email"]
    password = CONFIG["gmail_app_password"].replace(" ", "")
    if not sender or not password:
        raise RuntimeError("Gmail configuration is missing in .env")

    message = EmailMessage()
    message["Subject"] = "Bibio verification code"
    message["From"] = sender
    message["To"] = target_email
    message.set_content(
        "\n".join(
            [
                "Your Bibio verification code is:",
                code,
                "",
                f"This code expires in {VERIFICATION_TTL_MINUTES} minutes.",
                "If you did not request it, you can ignore this email.",
            ]
        )
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
        smtp.login(sender, password)
        smtp.send_message(message)


def json_response(handler: "BibioHandler", status: int, payload: Any) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def empty_response(handler: "BibioHandler", status: int = 204) -> None:
    handler.send_response(status)
    handler.end_headers()


def error_response(handler: "BibioHandler", status: int, detail: str) -> None:
    json_response(handler, status, {"detail": detail})


def parse_json_request(handler: "BibioHandler") -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def parse_form_request(handler: "BibioHandler") -> cgi.FieldStorage:
    environ = {
        "REQUEST_METHOD": handler.command,
        "CONTENT_TYPE": handler.headers.get("Content-Type", ""),
        "CONTENT_LENGTH": handler.headers.get("Content-Length", "0"),
    }
    return cgi.FieldStorage(
        fp=handler.rfile,
        headers=handler.headers,
        environ=environ,
        keep_blank_values=True,
    )


def field_value(form: cgi.FieldStorage, name: str, default: str = "") -> str:
    if name not in form:
        return default
    value = form[name]
    if isinstance(value, list):
        value = value[0]
    return value.value.strip() if getattr(value, "value", None) else default


def save_upload(file_item: cgi.FieldStorage) -> tuple[str, str, Path, int]:
    original_name = Path(file_item.filename or "upload.pdf").name
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", original_name)
    stored_name = f"{secrets.token_hex(8)}_{safe_name}"
    target = UPLOADS_DIR / stored_name
    with target.open("wb") as out:
        shutil.copyfileobj(file_item.file, out)
    return original_name, stored_name, target, target.stat().st_size


def serialize_book(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    total = int(row["total_copies"] or 0)
    return {
        "id": row["id"],
        "title": row["title"],
        "author": row["author"],
        "isbn": row["isbn"],
        "category_id": row["category_id"],
        "category_name": row["category_name"],
        "year": row["year"],
        "total_copies": total,
        "available_copies": compute_available_copies(conn, row["id"], total),
        "language": row["language"],
        "publisher": row["publisher"],
        "description": row["description"],
        "section": row["section"],
        "shelf": row["shelf"],
        "position": row["position"],
        "created_at": row["created_at"],
    }


def serialize_loan(row: sqlite3.Row) -> dict[str, Any]:
    due = parse_iso(row["due_date"])
    returned = parse_iso(row["return_date"])
    today = now_utc()
    days_remaining = 0
    is_overdue = False
    if due and not returned:
        days_remaining = (due.date() - today.date()).days
        is_overdue = days_remaining < 0
    return {
        "id": row["id"],
        "username": row["username"],
        "book_title": row["book_title"],
        "book_author": row["book_author"],
        "loan_date": row["loan_date"],
        "due_date": row["due_date"],
        "return_date": row["return_date"],
        "is_overdue": is_overdue,
        "days_remaining": days_remaining,
    }


class BibioHandler(BaseHTTPRequestHandler):
    server_version = "BibioHTTP/1.0"

    def do_GET(self) -> None:
        self.dispatch()

    def do_POST(self) -> None:
        self.dispatch()

    def do_PUT(self) -> None:
        self.dispatch()

    def do_PATCH(self) -> None:
        self.dispatch()

    def do_DELETE(self) -> None:
        self.dispatch()

    def log_message(self, format: str, *args: Any) -> None:
        sys.stdout.write(
            "%s - - [%s] %s\n"
            % (self.client_address[0], self.log_date_time_string(), format % args)
        )

    def dispatch(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        self.parsed_path = parsed
        self.query = query

        try:
            if path.startswith("/auth/"):
                self.handle_auth(path, query)
                return
            if path.startswith("/catalog/"):
                self.handle_catalog(path, query)
                return
            if path.startswith("/dashboard/"):
                self.handle_dashboard(path, query)
                return
            if path.startswith("/loans/"):
                self.handle_loans(path, query)
                return
            if path.startswith("/pdfs/") or path == "/pdfs":
                self.handle_pdfs(path, query)
                return
            if path.startswith("/recommendations/"):
                self.handle_recommendations(path, query)
                return
            if path == "/stats":
                self.handle_stats()
                return
            self.serve_static(path)
        except json.JSONDecodeError:
            error_response(self, 400, "Invalid JSON body")
        except PermissionError as exc:
            message = str(exc) or "Unauthorized"
            status = 401 if message in {"Unauthorized", "Invalid credentials", "Email is not verified"} else 403
            error_response(self, status, message)
        except FileNotFoundError:
            error_response(self, 404, "Resource not found")
        except ValueError as exc:
            error_response(self, 400, str(exc))
        except Exception as exc:
            error_response(self, 500, str(exc))

    def current_user(self, allow_query_token: bool = False) -> sqlite3.Row | None:
        header = self.headers.get("Authorization", "")
        token = None
        if header.lower().startswith("bearer "):
            token = header.split(" ", 1)[1].strip()
        elif allow_query_token:
            token = (self.query.get("token") or [None])[0]
        with get_db() as conn:
            return get_user_by_token(conn, token)

    def require_auth(self, allow_query_token: bool = False) -> sqlite3.Row:
        user = self.current_user(allow_query_token=allow_query_token)
        if not user:
            raise PermissionError("Unauthorized")
        if not user["is_active"]:
            raise PermissionError("Account is inactive")
        return user

    def require_role(self, minimum: str) -> sqlite3.Row:
        user = self.require_auth()
        if role_level(user["role"]) < role_level(minimum):
            raise PermissionError("Insufficient permissions")
        return user

    def serve_static(self, path: str) -> None:
        rel = "index.html" if path in {"/", ""} else path.lstrip("/")
        target = (BASE_DIR / rel).resolve()
        if BASE_DIR not in target.parents and target != BASE_DIR:
            raise PermissionError("Invalid path")
        if not target.exists() or not target.is_file():
            raise FileNotFoundError
        mime, _ = mimetypes.guess_type(target.name)
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_auth(self, path: str, query: dict[str, list[str]]) -> None:
        if self.command == "POST" and path == "/auth/login":
            form = parse_form_request(self)
            username = field_value(form, "username")
            password = field_value(form, "password")
            if not username or not password:
                raise ValueError("Username and password are required")
            with get_db() as conn:
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
                if not user or not verify_password(password, user["password_hash"]):
                    raise PermissionError("Invalid credentials")
                if not user["is_active"]:
                    raise PermissionError("Account is inactive")
                if not user["email_verified"]:
                    raise PermissionError("Email is not verified")
                token = create_session(conn, user["id"])
            json_response(self, 200, {"access_token": token, "token_type": "bearer"})
            return

        if self.command == "GET" and path == "/auth/me":
            user = self.require_auth()
            json_response(
                self,
                200,
                {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "full_name": user["full_name"],
                    "role": user["role"],
                    "is_active": bool(user["is_active"]),
                },
            )
            return

        if self.command == "POST" and path == "/auth/request-verification-code":
            body = parse_json_request(self)
            username = (body.get("username") or "").strip()
            email = (body.get("email") or "").strip().lower()
            password = body.get("password") or ""
            full_name = (body.get("full_name") or "").strip() or None
            role = normalize_role(body.get("role"))
            if role not in PUBLIC_SIGNUP_ROLES:
                raise ValueError("Public signup only supports student or teacher")
            if not username or not email or len(password) < 6:
                raise ValueError("Username, email, and password are required")
            with get_db() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM users WHERE username = ? OR email = ?",
                    (username, email),
                ).fetchone()
                if exists:
                    raise ValueError("Username or email already exists")
                code = f"{secrets.randbelow(1000000):06d}"
                payload = {
                    "username": username,
                    "email": email,
                    "password": password,
                    "full_name": full_name,
                    "role": role,
                }
                conn.execute("DELETE FROM verification_codes WHERE email = ?", (email,))
                conn.execute(
                    """
                    INSERT INTO verification_codes (email, code, payload_json, expires_at, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        email,
                        code,
                        json.dumps(payload),
                        iso_in(minutes=VERIFICATION_TTL_MINUTES),
                        iso_now(),
                    ),
                )
                conn.commit()
            send_verification_email(email, code)
            json_response(self, 200, {"message": "Verification code sent"})
            return

        if self.command == "POST" and path == "/auth/verify-signup":
            body = parse_json_request(self)
            email = (body.get("email") or "").strip().lower()
            code = (body.get("code") or "").strip()
            if not email or not code:
                raise ValueError("Email and code are required")
            with get_db() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM verification_codes
                    WHERE email = ? AND code = ? AND used_at IS NULL
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (email, code),
                ).fetchone()
                if not row:
                    raise ValueError("Invalid verification code")
                if parse_iso(row["expires_at"]) <= now_utc():
                    raise ValueError("Verification code expired")
                payload = json.loads(row["payload_json"])
                dup = conn.execute(
                    "SELECT 1 FROM users WHERE username = ? OR email = ?",
                    (payload["username"], email),
                ).fetchone()
                if dup:
                    raise ValueError("Username or email already exists")
                conn.execute(
                    """
                    INSERT INTO users (username, email, full_name, password_hash, role, is_active, email_verified, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, 1, ?)
                    """,
                    (
                        payload["username"],
                        email,
                        payload.get("full_name"),
                        hash_password(payload["password"]),
                        normalize_role(payload.get("role")),
                        iso_now(),
                    ),
                )
                conn.execute(
                    "UPDATE verification_codes SET used_at = ? WHERE id = ?",
                    (iso_now(), row["id"]),
                )
                log_activity(conn, "new_user", f"تم إنشاء المستخدم {payload['username']}")
                conn.commit()
            json_response(self, 201, {"message": "Signup completed"})
            return

        if self.command == "POST" and path == "/auth/register":
            actor = self.require_role("librarian")
            body = parse_json_request(self)
            username = (body.get("username") or "").strip()
            email = (body.get("email") or "").strip().lower()
            password = body.get("password") or ""
            full_name = (body.get("full_name") or "").strip() or None
            role = normalize_role(body.get("role"))
            if not username or not email or len(password) < 6:
                raise ValueError("Username, email, and password are required")
            if role_level(actor["role"]) < role_level("admin") and role == "admin":
                raise PermissionError("Only admins can create admins")
            with get_db() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM users WHERE username = ? OR email = ?",
                    (username, email),
                ).fetchone()
                if exists:
                    raise ValueError("Username or email already exists")
                conn.execute(
                    """
                    INSERT INTO users (username, email, full_name, password_hash, role, is_active, email_verified, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, 1, ?)
                    """,
                    (username, email, full_name, hash_password(password), role, iso_now()),
                )
                log_activity(conn, "new_user", f"تم إنشاء المستخدم {username}")
                conn.commit()
            json_response(self, 201, {"message": "User created"})
            return

        if self.command == "GET" and path == "/auth/users":
            self.require_role("librarian")
            with get_db() as conn:
                users = conn.execute(
                    """
                    SELECT id, username, email, full_name, role, is_active, email_verified, created_at
                    FROM users
                    ORDER BY created_at DESC
                    """
                ).fetchall()
            json_response(
                self,
                200,
                [
                    {
                        "id": u["id"],
                        "username": u["username"],
                        "email": u["email"],
                        "full_name": u["full_name"],
                        "role": u["role"],
                        "is_active": bool(u["is_active"]),
                        "email_verified": bool(u["email_verified"]),
                        "created_at": u["created_at"],
                    }
                    for u in users
                ],
            )
            return

        role_match = re.fullmatch(r"/auth/users/([^/]+)/role", path)
        if self.command == "PATCH" and role_match:
            actor = self.require_role("admin")
            username = role_match.group(1)
            new_role = normalize_role((query.get("new_role") or [""])[0])
            if username == actor["username"] and new_role != "admin":
                raise ValueError("You cannot demote yourself")
            with get_db() as conn:
                cur = conn.execute(
                    "UPDATE users SET role = ? WHERE username = ?",
                    (new_role, username),
                )
                if cur.rowcount == 0:
                    raise FileNotFoundError
                conn.commit()
            empty_response(self)
            return

        deactivate_match = re.fullmatch(r"/auth/users/([^/]+)/deactivate", path)
        if self.command == "PATCH" and deactivate_match:
            actor = self.require_role("admin")
            username = deactivate_match.group(1)
            if username == actor["username"]:
                raise ValueError("You cannot deactivate yourself")
            with get_db() as conn:
                cur = conn.execute(
                    "UPDATE users SET is_active = 0 WHERE username = ?",
                    (username,),
                )
                if cur.rowcount == 0:
                    raise FileNotFoundError
                conn.commit()
            empty_response(self)
            return

        raise FileNotFoundError

    def handle_catalog(self, path: str, query: dict[str, list[str]]) -> None:
        if self.command == "GET" and path == "/catalog/categories":
            self.require_auth()
            with get_db() as conn:
                rows = conn.execute(
                    "SELECT id, name, description FROM categories ORDER BY name"
                ).fetchall()
            json_response(self, 200, [dict(row) for row in rows])
            return

        if self.command == "GET" and path == "/catalog/stats":
            self.require_auth()
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT c.name, COUNT(b.id) AS total
                    FROM categories c
                    LEFT JOIN books b ON b.category_id = c.id
                    GROUP BY c.id, c.name
                    ORDER BY c.name
                    """
                ).fetchall()
            json_response(self, 200, {"by_category": [dict(row) for row in rows]})
            return

        if self.command == "POST" and path == "/catalog/categories":
            self.require_role("librarian")
            body = parse_json_request(self)
            name = (body.get("name") or "").strip()
            description = (body.get("description") or "").strip() or None
            if not name:
                raise ValueError("Category name is required")
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO categories (name, description) VALUES (?, ?)",
                    (name, description),
                )
                conn.commit()
            json_response(self, 201, {"message": "Category created"})
            return

        category_match = re.fullmatch(r"/catalog/categories/(\d+)", path)
        if category_match:
            category_id = int(category_match.group(1))
            if self.command == "PUT":
                self.require_role("librarian")
                body = parse_json_request(self)
                name = (body.get("name") or "").strip()
                description = (body.get("description") or "").strip() or None
                if not name:
                    raise ValueError("Category name is required")
                with get_db() as conn:
                    cur = conn.execute(
                        "UPDATE categories SET name = ?, description = ? WHERE id = ?",
                        (name, description, category_id),
                    )
                    if cur.rowcount == 0:
                        raise FileNotFoundError
                    conn.commit()
                empty_response(self)
                return
            if self.command == "DELETE":
                self.require_role("admin")
                with get_db() as conn:
                    cur = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
                    if cur.rowcount == 0:
                        raise FileNotFoundError
                    conn.commit()
                empty_response(self)
                return

        if self.command == "GET" and path == "/catalog/books":
            self.require_auth()
            page = max(int((query.get("page") or ["1"])[0]), 1)
            page_size = max(min(int((query.get("page_size") or ["15"])[0]), 100), 1)
            q = (query.get("q") or [""])[0].strip().lower()
            category_id = (query.get("category_id") or [""])[0].strip()
            language = (query.get("language") or [""])[0].strip().lower()
            available_only = ((query.get("available_only") or ["false"])[0].lower() == "true")

            where = []
            params: list[Any] = []
            if q:
                where.append(
                    "(LOWER(b.title) LIKE ? OR LOWER(b.author) LIKE ? OR LOWER(COALESCE(b.isbn, '')) LIKE ?)"
                )
                like = f"%{q}%"
                params.extend([like, like, like])
            if category_id:
                where.append("b.category_id = ?")
                params.append(int(category_id))
            if language:
                where.append("LOWER(COALESCE(b.language, '')) = ?")
                params.append(language)
            clause = f"WHERE {' AND '.join(where)}" if where else ""

            with get_db() as conn:
                rows = conn.execute(
                    f"""
                    SELECT b.*, c.name AS category_name
                    FROM books b
                    LEFT JOIN categories c ON c.id = b.category_id
                    {clause}
                    ORDER BY b.created_at DESC, b.id DESC
                    """,
                    params,
                ).fetchall()
                books = [serialize_book(conn, row) for row in rows]

            if available_only:
                books = [book for book in books if book["available_copies"] > 0]

            total = len(books)
            start = (page - 1) * page_size
            end = start + page_size
            json_response(self, 200, {"total": total, "results": books[start:end]})
            return

        if self.command == "POST" and path == "/catalog/books":
            self.require_role("librarian")
            body = parse_json_request(self)
            title = (body.get("title") or "").strip()
            author = (body.get("author") or "").strip()
            if not title or not author:
                raise ValueError("Title and author are required")
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO books
                    (title, author, isbn, category_id, year, total_copies, language, publisher, description, section, shelf, position, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        title,
                        author,
                        (body.get("isbn") or "").strip() or None,
                        body.get("category_id"),
                        body.get("year"),
                        max(int(body.get("total_copies") or 1), 1),
                        (body.get("language") or "fr").strip().lower(),
                        (body.get("publisher") or "").strip() or None,
                        (body.get("description") or "").strip() or None,
                        (body.get("section") or "").strip() or None,
                        (body.get("shelf") or "").strip() or None,
                        (body.get("position") or "").strip() or None,
                        iso_now(),
                    ),
                )
                log_activity(conn, "new_book", f"تمت إضافة الكتاب {title}")
                conn.commit()
            json_response(self, 201, {"message": "Book created"})
            return

        book_match = re.fullmatch(r"/catalog/books/(\d+)", path)
        if book_match:
            book_id = int(book_match.group(1))
            if self.command == "GET":
                self.require_auth()
                with get_db() as conn:
                    row = conn.execute(
                        """
                        SELECT b.*, c.name AS category_name
                        FROM books b
                        LEFT JOIN categories c ON c.id = b.category_id
                        WHERE b.id = ?
                        """,
                        (book_id,),
                    ).fetchone()
                    if not row:
                        raise FileNotFoundError
                    json_response(self, 200, serialize_book(conn, row))
                return
            if self.command == "PUT":
                self.require_role("librarian")
                body = parse_json_request(self)
                title = (body.get("title") or "").strip()
                author = (body.get("author") or "").strip()
                if not title or not author:
                    raise ValueError("Title and author are required")
                with get_db() as conn:
                    cur = conn.execute(
                        """
                        UPDATE books
                        SET title = ?, author = ?, isbn = ?, category_id = ?, year = ?, total_copies = ?, language = ?, publisher = ?, description = ?
                        WHERE id = ?
                        """,
                        (
                            title,
                            author,
                            (body.get("isbn") or "").strip() or None,
                            body.get("category_id"),
                            body.get("year"),
                            max(int(body.get("total_copies") or 1), 1),
                            (body.get("language") or "fr").strip().lower(),
                            (body.get("publisher") or "").strip() or None,
                            (body.get("description") or "").strip() or None,
                            book_id,
                        ),
                    )
                    if cur.rowcount == 0:
                        raise FileNotFoundError
                    conn.commit()
                empty_response(self)
                return
            if self.command == "DELETE":
                self.require_role("admin")
                force = ((query.get("force") or ["false"])[0].lower() == "true")
                with get_db() as conn:
                    active = conn.execute(
                        "SELECT COUNT(*) FROM loans WHERE book_id = ? AND return_date IS NULL",
                        (book_id,),
                    ).fetchone()[0]
                    if active and not force:
                        raise ValueError("This book has active loan records")
                    if active and force:
                        conn.execute(
                            "UPDATE loans SET return_date = ? WHERE book_id = ? AND return_date IS NULL",
                            (iso_now(), book_id),
                        )
                    cur = conn.execute("DELETE FROM books WHERE id = ?", (book_id,))
                    if cur.rowcount == 0:
                        raise FileNotFoundError
                    conn.commit()
                empty_response(self)
                return

        raise FileNotFoundError

    def handle_stats(self) -> None:
        self.require_auth()
        with get_db() as conn:
            total_books = conn.execute("SELECT COUNT(*) FROM books").fetchone()[0]
            total_pdfs = conn.execute("SELECT COUNT(*) FROM pdfs").fetchone()[0]
            total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            active_loans = conn.execute(
                "SELECT COUNT(*) FROM loans WHERE return_date IS NULL"
            ).fetchone()[0]
            overdue_loans = conn.execute(
                "SELECT COUNT(*) FROM loans WHERE return_date IS NULL AND due_date < ?",
                (iso_now(),),
            ).fetchone()[0]
            available_books = 0
            for row in conn.execute("SELECT id, total_copies FROM books").fetchall():
                available_books += compute_available_copies(
                    conn, row["id"], row["total_copies"]
                )
        json_response(
            self,
            200,
            {
                "total_books": total_books,
                "available_books": available_books,
                "active_loans": active_loans,
                "overdue_loans": overdue_loans,
                "total_pdfs": total_pdfs,
                "total_users": total_users,
            },
        )

    def handle_dashboard(self, path: str, query: dict[str, list[str]]) -> None:
        self.require_auth()
        if path == "/dashboard/top-books" and self.command == "GET":
            limit = max(min(int((query.get("limit") or ["6"])[0]), 50), 1)
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT b.title, b.author, COUNT(l.id) AS borrow_count
                    FROM books b
                    LEFT JOIN loans l ON l.book_id = b.id
                    GROUP BY b.id
                    ORDER BY borrow_count DESC, b.title ASC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            json_response(self, 200, {"books": [dict(row) for row in rows]})
            return

        if path == "/dashboard/activity" and self.command == "GET":
            limit = max(min(int((query.get("limit") or ["10"])[0]), 50), 1)
            with get_db() as conn:
                rows = conn.execute(
                    "SELECT event_type AS type, message, created_at AS timestamp FROM activity_log ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            json_response(self, 200, {"events": [dict(row) for row in rows]})
            return

        if path == "/dashboard/overdue-summary" and self.command == "GET":
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT l.id, b.title, u.username, l.due_date
                    FROM loans l
                    JOIN books b ON b.id = l.book_id
                    JOIN users u ON u.id = l.user_id
                    WHERE l.return_date IS NULL AND l.due_date < ?
                    ORDER BY l.due_date ASC
                    """,
                    (iso_now(),),
                ).fetchall()
            loans = []
            for row in rows:
                due = parse_iso(row["due_date"])
                days = max((now_utc().date() - due.date()).days, 0) if due else 0
                loans.append(
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "username": row["username"],
                        "due_date": row["due_date"],
                        "days_overdue": days,
                    }
                )
            json_response(
                self,
                200,
                {"total_overdue": len(loans), "buckets": {"overdue": {"loans": loans}}},
            )
            return

        raise FileNotFoundError

    def handle_loans(self, path: str, query: dict[str, list[str]]) -> None:
        user = self.require_auth()

        if self.command == "POST" and path == "/loans/borrow":
            body = parse_json_request(self)
            book_id = int(body.get("book_id") or 0)
            if not book_id:
                raise ValueError("book_id is required")
            with get_db() as conn:
                book = conn.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
                if not book:
                    raise FileNotFoundError
                if compute_available_copies(conn, book_id, book["total_copies"]) <= 0:
                    raise ValueError("No copies available")
                due_days = {
                    "student": 14,
                    "teacher": 30,
                    "librarian": 60,
                    "admin": 365,
                }.get(user["role"], 14)
                conn.execute(
                    """
                    INSERT INTO loans (user_id, book_id, loan_date, due_date, return_date, created_at)
                    VALUES (?, ?, ?, ?, NULL, ?)
                    """,
                    (user["id"], book_id, iso_now(), iso_in(days=due_days), iso_now()),
                )
                log_activity(conn, "loan", f"{user['username']} استعار {book['title']}")
                conn.commit()
            json_response(self, 201, {"message": "Loan created"})
            return

        if self.command == "GET" and path == "/loans/all":
            self.require_role("librarian")
            page_size = max(min(int((query.get("page_size") or ["50"])[0]), 200), 1)
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT l.*, u.username, b.title AS book_title, b.author AS book_author
                    FROM loans l
                    JOIN users u ON u.id = l.user_id
                    JOIN books b ON b.id = l.book_id
                    ORDER BY l.created_at DESC
                    LIMIT ?
                    """,
                    (page_size,),
                ).fetchall()
            results = [serialize_loan(row) for row in rows]
            json_response(self, 200, {"total": len(results), "results": results})
            return

        if self.command == "GET" and path == "/loans/my":
            active_only = ((query.get("active_only") or ["false"])[0].lower() == "true")
            with get_db() as conn:
                sql = """
                    SELECT l.*, u.username, b.title AS book_title, b.author AS book_author
                    FROM loans l
                    JOIN users u ON u.id = l.user_id
                    JOIN books b ON b.id = l.book_id
                    WHERE l.user_id = ?
                """
                if active_only:
                    sql += " AND l.return_date IS NULL"
                sql += " ORDER BY l.created_at DESC"
                rows = conn.execute(sql, (user["id"],)).fetchall()
            json_response(self, 200, [serialize_loan(row) for row in rows])
            return

        if self.command == "GET" and path == "/loans/notifications":
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT l.id, b.title AS book_title, l.due_date
                    FROM loans l
                    JOIN books b ON b.id = l.book_id
                    WHERE l.user_id = ? AND l.return_date IS NULL AND l.due_date < ?
                    ORDER BY l.due_date ASC
                    """,
                    (user["id"], iso_now()),
                ).fetchall()
            alerts = []
            for row in rows:
                due = parse_iso(row["due_date"])
                days = max((now_utc().date() - due.date()).days, 0) if due else 0
                alerts.append(
                    {
                        "id": row["id"],
                        "alert_type": "overdue",
                        "alert_message": f"هذا الكتاب متأخر {days} يوم",
                        "book_title": row["book_title"],
                    }
                )
            json_response(self, 200, {"alerts": alerts})
            return

        return_match = re.fullmatch(r"/loans/return/(\d+)", path)
        if self.command == "POST" and return_match:
            loan_id = int(return_match.group(1))
            with get_db() as conn:
                loan = conn.execute(
                    """
                    SELECT l.*, b.title AS book_title
                    FROM loans l
                    JOIN books b ON b.id = l.book_id
                    WHERE l.id = ?
                    """,
                    (loan_id,),
                ).fetchone()
                if not loan:
                    raise FileNotFoundError
                if loan["user_id"] != user["id"] and role_level(user["role"]) < role_level("librarian"):
                    raise PermissionError("You cannot return this loan")
                conn.execute(
                    "UPDATE loans SET return_date = ? WHERE id = ? AND return_date IS NULL",
                    (iso_now(), loan_id),
                )
                log_activity(conn, "return", f"{user['username']} أعاد {loan['book_title']}")
                conn.commit()
            empty_response(self)
            return

        raise FileNotFoundError

    def handle_pdfs(self, path: str, query: dict[str, list[str]]) -> None:
        if self.command == "GET" and path in {"/pdfs", "/pdfs/"}:
            self.require_auth()
            page = max(int((query.get("page") or ["1"])[0]), 1)
            page_size = max(min(int((query.get("page_size") or ["15"])[0]), 100), 1)
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT p.*, c.name AS category_name
                    FROM pdfs p
                    LEFT JOIN categories c ON c.id = p.category_id
                    ORDER BY p.created_at DESC
                    """
                ).fetchall()
            total = len(rows)
            start = (page - 1) * page_size
            end = start + page_size
            json_response(self, 200, {"total": total, "results": [dict(row) for row in rows[start:end]]})
            return

        if self.command == "POST" and path == "/pdfs/upload":
            self.require_role("librarian")
            form = parse_form_request(self)
            if "file" not in form:
                raise ValueError("PDF file is required")
            file_item = form["file"]
            original_name, stored_name, saved_path, file_size = save_upload(file_item)
            title = field_value(form, "title") or Path(original_name).stem
            author = field_value(form, "author") or None
            category_raw = field_value(form, "category_id")
            category_id = int(category_raw) if category_raw else None
            language = field_value(form, "language", "fr").lower()
            page_count = page_count_for_pdf(saved_path)
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO pdfs
                    (title, author, category_id, language, file_name, stored_name, file_path, file_size, page_count, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        title,
                        author,
                        category_id,
                        language,
                        original_name,
                        stored_name,
                        str(saved_path),
                        file_size,
                        page_count,
                        iso_now(),
                    ),
                )
                conn.commit()
            json_response(self, 201, {"message": "PDF uploaded"})
            return

        if self.command == "GET" and path == "/pdfs/search":
            self.require_auth()
            q = (query.get("q") or [""])[0].strip().lower()
            limit = max(min(int((query.get("limit") or ["8"])[0]), 50), 1)
            if not q:
                json_response(self, 200, {"results": []})
                return
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT id, title, author
                    FROM pdfs
                    WHERE LOWER(title) LIKE ? OR LOWER(COALESCE(author, '')) LIKE ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (f"%{q}%", f"%{q}%", limit),
                ).fetchall()
            json_response(
                self,
                200,
                {
                    "results": [
                        {
                            "id": row["id"],
                            "title": row["title"],
                            "author": row["author"],
                            "snippet": f"Matched title or author for '{q}'.",
                        }
                        for row in rows
                    ]
                },
            )
            return

        pdf_match = re.fullmatch(r"/pdfs/(\d+)", path)
        if pdf_match:
            pdf_id = int(pdf_match.group(1))
            if self.command == "GET":
                self.require_auth()
                with get_db() as conn:
                    row = conn.execute("SELECT * FROM pdfs WHERE id = ?", (pdf_id,)).fetchone()
                    if not row:
                        raise FileNotFoundError
                json_response(self, 200, dict(row))
                return
            if self.command == "PUT":
                self.require_role("librarian")
                form = parse_form_request(self)
                title = field_value(form, "title")
                if not title:
                    raise ValueError("Title is required")
                author = field_value(form, "author") or None
                category_raw = field_value(form, "category_id")
                category_id = int(category_raw) if category_raw else None
                language = field_value(form, "language", "fr").lower()
                with get_db() as conn:
                    row = conn.execute("SELECT * FROM pdfs WHERE id = ?", (pdf_id,)).fetchone()
                    if not row:
                        raise FileNotFoundError
                    file_name = row["file_name"]
                    stored_name = row["stored_name"]
                    file_path = row["file_path"]
                    file_size = row["file_size"]
                    page_count = row["page_count"]
                    if "file" in form and getattr(form["file"], "filename", None):
                        file_item = form["file"]
                        old_path = Path(file_path)
                        original_name, stored_name, saved_path, file_size = save_upload(file_item)
                        file_name = original_name
                        file_path = str(saved_path)
                        page_count = page_count_for_pdf(saved_path)
                        old_path.unlink(missing_ok=True)
                    conn.execute(
                        """
                        UPDATE pdfs
                        SET title = ?, author = ?, category_id = ?, language = ?, file_name = ?, stored_name = ?, file_path = ?, file_size = ?, page_count = ?
                        WHERE id = ?
                        """,
                        (
                            title,
                            author,
                            category_id,
                            language,
                            file_name,
                            stored_name,
                            file_path,
                            file_size,
                            page_count,
                            pdf_id,
                        ),
                    )
                    conn.commit()
                empty_response(self)
                return
            if self.command == "DELETE":
                self.require_role("admin")
                with get_db() as conn:
                    row = conn.execute("SELECT file_path FROM pdfs WHERE id = ?", (pdf_id,)).fetchone()
                    if not row:
                        raise FileNotFoundError
                    conn.execute("DELETE FROM pdfs WHERE id = ?", (pdf_id,))
                    conn.commit()
                Path(row["file_path"]).unlink(missing_ok=True)
                empty_response(self)
                return

        file_match = re.fullmatch(r"/pdfs/(\d+)/(view|download)", path)
        if file_match and self.command == "GET":
            self.require_auth(allow_query_token=True)
            pdf_id = int(file_match.group(1))
            mode = file_match.group(2)
            with get_db() as conn:
                row = conn.execute(
                    "SELECT file_name, file_path FROM pdfs WHERE id = ?",
                    (pdf_id,),
                ).fetchone()
                if not row:
                    raise FileNotFoundError
            pdf_path = Path(row["file_path"])
            if not pdf_path.exists():
                raise FileNotFoundError
            data = pdf_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            disposition = "inline" if mode == "view" else "attachment"
            self.send_header(
                "Content-Disposition",
                f'{disposition}; filename="{row["file_name"]}"',
            )
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        raise FileNotFoundError

    def handle_recommendations(self, path: str, query: dict[str, list[str]]) -> None:
        user = self.require_auth()
        if self.command == "GET" and path == "/recommendations/me":
            limit = max(min(int((query.get("limit") or ["12"])[0]), 50), 1)
            with get_db() as conn:
                category_rows = conn.execute(
                    """
                    SELECT b.category_id, COUNT(*) AS total
                    FROM loans l
                    JOIN books b ON b.id = l.book_id
                    WHERE l.user_id = ? AND b.category_id IS NOT NULL
                    GROUP BY b.category_id
                    ORDER BY total DESC
                    """,
                    (user["id"],),
                ).fetchall()
                preferred = [row["category_id"] for row in category_rows]
                if preferred:
                    placeholders = ",".join(["?"] * len(preferred))
                    rows = conn.execute(
                        f"""
                        SELECT b.*, c.name AS category_name
                        FROM books b
                        LEFT JOIN categories c ON c.id = b.category_id
                        WHERE b.category_id IN ({placeholders})
                        ORDER BY b.created_at DESC
                        LIMIT ?
                        """,
                        (*preferred, limit),
                    ).fetchall()
                    strategy = ["history", "category"]
                else:
                    rows = conn.execute(
                        """
                        SELECT b.*, c.name AS category_name
                        FROM books b
                        LEFT JOIN categories c ON c.id = b.category_id
                        ORDER BY b.created_at DESC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
                    strategy = ["fresh-catalog"]
                recommendations = [serialize_book(conn, row) for row in rows]
            json_response(
                self,
                200,
                {
                    "strategies_used": strategy,
                    "recommendations": recommendations[:limit],
                },
            )
            return

        raise FileNotFoundError


def run() -> None:
    init_db()
    server = ThreadingHTTPServer((CONFIG["host"], CONFIG["port"]), BibioHandler)
    print(f"Bibio server running on http://{CONFIG['host']}:{CONFIG['port']}")
    print(
        "Default admin: "
        f"{CONFIG['default_admin_username']} / {CONFIG['default_admin_password']}"
    )
    server.serve_forever()


if __name__ == "__main__":
    run()
