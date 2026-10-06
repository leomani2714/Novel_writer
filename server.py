#!/usr/bin/env python3
"""Small SQLite-backed server for the Novel Writer app."""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("NOVEL_WRITER_DB", ROOT / "novel_writer.sqlite3"))
SESSION_SECONDS = 30 * 24 * 60 * 60
PASSWORD_ROUNDS = 310_000
MAX_BODY = 2 * 1024 * 1024


def connect_db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash BLOB NOT NULL,
                password_salt BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS manuscripts (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                data TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ROUNDS)


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).digest()


class Handler(BaseHTTPRequestHandler):
    server_version = "NovelWriter/1.0"

    def send_json(self, status, value, headers=None):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, content in (headers or {}).items():
            self.send_header(name, content)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid request body") from None
        if length < 1 or length > MAX_BODY:
            raise ValueError("Request body is empty or too large")
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Invalid JSON") from None
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object")
        return value

    def current_user(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie["session"].value
        except (KeyError, CookieError):
            return None
        with connect_db() as connection:
            row = connection.execute(
                "SELECT users.id, users.username FROM sessions "
                "JOIN users ON users.id = sessions.user_id "
                "WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
                (token_digest(token), int(time.time())),
            ).fetchone()
        return row

    def make_session(self, user_id):
        token = secrets.token_urlsafe(32)
        with connect_db() as connection:
            connection.execute(
                "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_digest(token), user_id, int(time.time()) + SESSION_SECONDS),
            )
        return "session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}".format(token, SESSION_SECONDS)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/session":
            user = self.current_user()
            if not user:
                self.send_json(401, {"error": "Please log in"})
                return
            self.send_json(200, {"user": {"username": user["username"]}})
            return
        if path == "/api/data":
            user = self.current_user()
            if not user:
                self.send_json(401, {"error": "Please log in"})
                return
            with connect_db() as connection:
                row = connection.execute(
                    "SELECT data FROM manuscripts WHERE user_id = ?", (user["id"],)
                ).fetchone()
            self.send_json(200, {"data": json.loads(row["data"]) if row else None})
            return
        if path == "/" or path == "/index.html":
            body = (ROOT / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/logout":
            user = self.current_user()
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            if "session" in cookie:
                with connect_db() as connection:
                    connection.execute(
                        "DELETE FROM sessions WHERE token_hash = ?",
                        (token_digest(cookie["session"].value),),
                    )
            self.send_json(200, {"ok": True}, {"Set-Cookie": "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
            return
        if path not in ("/api/login", "/api/register"):
            self.send_json(404, {"error": "Not found"})
            return
        try:
            body = self.read_json()
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_-]{3,24}", username):
            self.send_json(400, {"error": "Username must be 3-24 letters, numbers, underscores, or hyphens"})
            return
        if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
            self.send_json(400, {"error": "Password must be at least 8 characters"})
            return

        with connect_db() as connection:
            user = connection.execute(
                "SELECT id, username, password_hash, password_salt FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if path == "/api/register":
                if user:
                    self.send_json(409, {"error": "That username is already registered"})
                    return
                salt = secrets.token_bytes(16)
                password_hash = hash_password(password, salt)
                try:
                    cursor = connection.execute(
                        "INSERT INTO users(username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)",
                        (username, password_hash, salt, int(time.time())),
                    )
                except sqlite3.IntegrityError:
                    self.send_json(409, {"error": "That username is already registered"})
                    return
                user_id = cursor.lastrowid
                account_name = username
            else:
                if not user or not hmac.compare_digest(
                    user["password_hash"], hash_password(password, user["password_salt"])
                ):
                    self.send_json(401, {"error": "Incorrect username or password"})
                    return
                user_id = user["id"]
                account_name = user["username"]
        cookie_header = self.make_session(user_id)
        self.send_json(200, {"user": {"username": account_name}}, {"Set-Cookie": cookie_header})

    def do_PUT(self):
        if urlparse(self.path).path != "/api/data":
            self.send_json(404, {"error": "Not found"})
            return
        user = self.current_user()
        if not user:
            self.send_json(401, {"error": "Please log in"})
            return
        try:
            data = self.read_json()
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        chapters = data.get("chapters")
        if not isinstance(chapters, list) or not chapters or len(chapters) > 1000:
            self.send_json(400, {"error": "A manuscript must contain 1-1000 chapters"})
            return
        if any(not isinstance(chapter, dict) for chapter in chapters):
            self.send_json(400, {"error": "Invalid chapter data"})
            return
        encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        with connect_db() as connection:
            connection.execute(
                "INSERT INTO manuscripts(user_id, data, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
                (user["id"], encoded, int(time.time())),
            )
        self.send_json(200, {"ok": True})

    def log_message(self, format_string, *args):
        if not urlparse(self.path).path.startswith("/api/"):
            super().log_message(format_string, *args)


try:
    from http.cookies import CookieError
except ImportError:  # pragma: no cover
    CookieError = ValueError


if __name__ == "__main__":
    initialize_db()
   host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    print("Novel Writer running at http://{}:{}/".format(host, port), flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
