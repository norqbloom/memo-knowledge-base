import csv
import hashlib
import io
import json
import math
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

import bleach
import markdown
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


ROLES = ("viewer", "editor", "admin")
ROLE_LEVELS = {"viewer": 10, "editor": 20, "admin": 30}
ROLE_LABELS = {"viewer": "閲覧者", "editor": "編集者", "admin": "管理者"}
REVISION_ACTION_LABELS = {
    "create": "作成",
    "update": "更新",
    "restore": "履歴から復元",
    "trash": "ゴミ箱へ移動",
    "trash_restore": "ゴミ箱から復元",
    "import_create": "CSV作成",
    "import_update": "CSV更新",
}
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
JST = timezone(timedelta(hours=9), "JST")
ARTICLES_PER_PAGE = 20
CSV_FORMAT = "kb-csv-v2"
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 10 * 60
LOGIN_BLOCK_SECONDS = 15 * 60
FTS_VERSION = "trigram-v1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE
        CHECK (length(username) BETWEEN 3 AND 50),
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'admin')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S+09:00', 'now', 'localtime'))
);

CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 150),
    summary TEXT NOT NULL DEFAULT '' CHECK (length(summary) <= 300),
    content_md TEXT NOT NULL CHECK (length(content_md) BETWEEN 1 AND 50000),
    lock_version INTEGER NOT NULL DEFAULT 1,
    deleted_at TEXT,
    deleted_by TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S+09:00', 'now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S+09:00', 'now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_articles_updated_id
ON articles (updated_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_articles_active_updated_id
ON articles (updated_at DESC, id DESC)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_articles_deleted_at_id
ON articles (deleted_at DESC, id DESC)
WHERE deleted_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE
        CHECK (length(name) BETWEEN 1 AND 30),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S+09:00', 'now', 'localtime'))
);

CREATE TABLE IF NOT EXISTS article_tags (
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (article_id, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_article_tags_tag_id
ON article_tags (tag_id, article_id);

CREATE TABLE IF NOT EXISTS article_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    version_no INTEGER NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    content_md TEXT NOT NULL,
    tags_json TEXT NOT NULL DEFAULT '[]',
    changed_by TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'update',
    restored_from_revision_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S+09:00', 'now', 'localtime')),
    UNIQUE (article_id, version_no)
);

CREATE INDEX IF NOT EXISTS idx_article_revisions_article_version
ON article_revisions (article_id, version_no DESC);

CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_key TEXT PRIMARY KEY,
    failed_count INTEGER NOT NULL,
    window_started_at INTEGER NOT NULL,
    blocked_until INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_updated_at
ON login_attempts (updated_at);

CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts USING fts5(
    title,
    content_md,
    content='articles',
    content_rowid='id',
    tokenize='trigram'
);

CREATE TRIGGER IF NOT EXISTS articles_fts_insert
AFTER INSERT ON articles BEGIN
    INSERT INTO articles_fts(rowid, title, content_md)
    VALUES (new.id, new.title, new.content_md);
END;

CREATE TRIGGER IF NOT EXISTS articles_fts_delete
AFTER DELETE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, content_md)
    VALUES ('delete', old.id, old.title, old.content_md);
END;

CREATE TRIGGER IF NOT EXISTS articles_fts_update
AFTER UPDATE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, content_md)
    VALUES ('delete', old.id, old.title, old.content_md);
    INSERT INTO articles_fts(rowid, title, content_md)
    VALUES (new.id, new.title, new.content_md);
END;
"""

ALLOWED_TAGS = {
    "a", "blockquote", "br", "code", "del", "em", "h1", "h2", "h3",
    "h4", "h5", "h6", "hr", "li", "ol", "p", "pre", "strong", "table",
    "tbody", "td", "th", "thead", "tr", "ul",
}
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "code": ["class"],
    "td": ["align"],
    "th": ["align"],
}


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "local-development-key"),
        DATABASE=os.environ.get("DATABASE_PATH", "/data/memo.db"),
        ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD", "change-me"),
        TIMEZONE="Asia/Tokyo",
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )

    if test_config:
        app.config.update(test_config)

    # ApacheだけがFlaskへ接続する構成のため、直前のプロキシが付けた実IPだけを信頼する。
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    dummy_password_hash = generate_password_hash("login-timing-placeholder")

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(
                app.config["DATABASE"],
                timeout=5,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
            g.db.execute("PRAGMA busy_timeout = 5000")
            g.db.execute("PRAGMA synchronous = NORMAL")
        return g.db

    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        journal_mode = db.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if journal_mode.lower() != "wal":
            raise RuntimeError("SQLite WAL mode could not be enabled.")
        db.execute("PRAGMA synchronous = NORMAL")

        article_table = db.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'articles'"
        ).fetchone()
        if article_table is not None:
            article_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(articles)").fetchall()
            }
            if "lock_version" not in article_columns:
                db.execute(
                    "ALTER TABLE articles ADD COLUMN lock_version INTEGER NOT NULL DEFAULT 1"
                )
            if "deleted_at" not in article_columns:
                db.execute("ALTER TABLE articles ADD COLUMN deleted_at TEXT")
            if "deleted_by" not in article_columns:
                db.execute("ALTER TABLE articles ADD COLUMN deleted_by TEXT")

        revision_table = db.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'article_revisions'"
        ).fetchone()
        if revision_table is not None:
            revision_columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(article_revisions)").fetchall()
            }
            if "action" not in revision_columns:
                db.execute(
                    "ALTER TABLE article_revisions ADD COLUMN action TEXT NOT NULL DEFAULT 'update'"
                )

        fts_schema = db.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'articles_fts'"
        ).fetchone()
        needs_fts_rebuild = fts_schema is None or "trigram" not in fts_schema[0].lower()
        if fts_schema is not None and needs_fts_rebuild:
            db.executescript(
                """
                DROP TRIGGER IF EXISTS articles_fts_insert;
                DROP TRIGGER IF EXISTS articles_fts_delete;
                DROP TRIGGER IF EXISTS articles_fts_update;
                DROP TABLE articles_fts;
                """
            )
        db.executescript(SCHEMA)
        stored_fts_version = db.execute(
            "SELECT value FROM app_meta WHERE key = 'fts_version'"
        ).fetchone()
        if needs_fts_rebuild or stored_fts_version is None or stored_fts_version["value"] != FTS_VERSION:
            db.execute("INSERT INTO articles_fts(articles_fts) VALUES ('rebuild')")
            db.execute(
                """
                INSERT INTO app_meta (key, value) VALUES ('fts_version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (FTS_VERSION,),
            )
        if db.execute("SELECT count(*) FROM users").fetchone()[0] == 0:
            db.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                (
                    app.config["ADMIN_USERNAME"],
                    generate_password_hash(app.config["ADMIN_PASSWORD"]),
                    jst_now(),
                ),
            )
        for table_name, column_name in (
            ("users", "created_at"),
            ("articles", "created_at"),
            ("articles", "updated_at"),
            ("tags", "created_at"),
            ("article_revisions", "created_at"),
        ):
            db.execute(
                f"""
                UPDATE {table_name}
                SET {column_name} = strftime('%Y-%m-%dT%H:%M:%S+09:00', {column_name}, '+9 hours')
                WHERE substr({column_name}, -1) = 'Z'
                """
            )
        changed_by = db.execute(
            "SELECT username FROM users WHERE role = 'admin' ORDER BY id LIMIT 1"
        ).fetchone()[0]
        db.execute(
            """
            INSERT INTO article_revisions
                (article_id, version_no, title, summary, content_md, tags_json,
                 changed_by, action, created_at)
            SELECT a.id, 1, a.title, a.summary, a.content_md, '[]', ?, 'create', a.updated_at
            FROM articles a
            WHERE NOT EXISTS (
                SELECT 1 FROM article_revisions r WHERE r.article_id = a.id
            )
            """,
            (changed_by,),
        )
        db.execute(
            "DELETE FROM tags WHERE NOT EXISTS (SELECT 1 FROM article_tags at WHERE at.tag_id = tags.id)"
        )
        db.execute(
            "DELETE FROM login_attempts WHERE updated_at < ?",
            (int(time.time()) - 7 * 24 * 60 * 60,),
        )
        db.execute("PRAGMA optimize")
        db.commit()

    def render_markdown(value):
        rendered = markdown.markdown(
            value or "",
            extensions=["fenced_code", "sane_lists", "tables"],
        )
        cleaned = bleach.clean(
            rendered,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            protocols={"http", "https", "mailto"},
            strip=True,
        )
        return Markup(cleaned)

    def jst_now():
        return datetime.now(JST).isoformat(timespec="seconds")

    def requested_page():
        try:
            return max(1, int(request.args.get("page", "1")))
        except ValueError:
            return 1

    def pagination_for(total_count, page):
        total_pages = max(1, math.ceil(total_count / ARTICLES_PER_PAGE))
        page = min(page, total_pages)
        return {
            "page": page,
            "per_page": ARTICLES_PER_PAGE,
            "total_count": total_count,
            "total_pages": total_pages,
            "has_previous": page > 1,
            "has_next": page < total_pages,
        }

    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    def is_safe_next_url(target):
        if not target:
            return False
        parts = urlsplit(target)
        return not parts.scheme and not parts.netloc and target.startswith("/")

    def role_required(required_role):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if g.user is None:
                    return redirect(url_for("login", next=request.path))
                if ROLE_LEVELS[g.user["role"]] < ROLE_LEVELS[required_role]:
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

    def article_from_form():
        return {
            "title": request.form.get("title", "").strip(),
            "content_md": request.form.get("content_md", "").strip(),
        }

    def validate_article(article):
        if not article["title"]:
            return "タイトルを入力してください。"
        if len(article["title"]) > 150:
            return "タイトルは150文字以内で入力してください。"
        if not article["content_md"]:
            return "Markdown本文を入力してください。"
        if len(article["content_md"]) > 50000:
            return "Markdown本文は50,000文字以内で入力してください。"
        return None

    def parse_tags(raw_value):
        try:
            values = json.loads(raw_value or "[]")
        except json.JSONDecodeError:
            return [], "タグの形式が正しくありません。"
        if not isinstance(values, list):
            return [], "タグの形式が正しくありません。"

        tags = []
        seen = set()
        for value in values:
            name = re.sub(r"\s+", " ", str(value)).strip()
            if not name:
                continue
            if len(name) > 30 or "," in name:
                return tags, "タグはカンマを含めず、30文字以内で入力してください。"
            key = name.casefold()
            if key not in seen:
                tags.append(name)
                seen.add(key)
        if len(tags) > 10:
            return tags, "タグは10個まで設定できます。"
        return tags, None

    def set_article_tags(db, article_id, tag_names):
        db.execute("DELETE FROM article_tags WHERE article_id = ?", (article_id,))
        for name in tag_names:
            db.execute(
                "INSERT OR IGNORE INTO tags (name, created_at) VALUES (?, ?)",
                (name, jst_now()),
            )
            tag_id = db.execute("SELECT id FROM tags WHERE name = ?", (name,)).fetchone()[0]
            db.execute(
                "INSERT INTO article_tags (article_id, tag_id) VALUES (?, ?)",
                (article_id, tag_id),
            )
        db.execute(
            "DELETE FROM tags WHERE NOT EXISTS (SELECT 1 FROM article_tags at WHERE at.tag_id = tags.id)"
        )

    def get_article_tags(db, article_id):
        return [
            row["name"]
            for row in db.execute(
                """
                SELECT t.name
                FROM tags t
                JOIN article_tags at ON at.tag_id = t.id
                WHERE at.article_id = ?
                ORDER BY t.name COLLATE NOCASE
                """,
                (article_id,),
            ).fetchall()
        ]

    def save_revision(
        db,
        article_id,
        article,
        tag_names,
        changed_by,
        restored_from=None,
        action="update",
    ):
        version_no = db.execute(
            "SELECT COALESCE(MAX(version_no), 0) + 1 FROM article_revisions WHERE article_id = ?",
            (article_id,),
        ).fetchone()[0]
        db.execute(
            """
            INSERT INTO article_revisions
                (article_id, version_no, title, summary, content_md, tags_json,
                 changed_by, action, restored_from_revision_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                article_id,
                version_no,
                article["title"],
                article.get("summary", ""),
                article["content_md"],
                json.dumps(tag_names, ensure_ascii=False),
                changed_by,
                action,
                restored_from,
                jst_now(),
            ),
        )
        return version_no

    def make_fts_query(search_text):
        terms = [term for term in re.split(r"\s+", search_text.strip()) if term]
        if not terms:
            return None
        return " AND ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)

    def make_like_search(search_text):
        terms = [term for term in re.split(r"\s+", search_text.strip()) if term]
        conditions = []
        params = []
        for term in terms:
            escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            value = f"%{escaped}%"
            conditions.append(
                "(a.title LIKE ? ESCAPE '\\' OR a.content_md LIKE ? ESCAPE '\\')"
            )
            params.extend((value, value))
        return " AND ".join(conditions), params

    def csv_safe_value(value):
        value = str(value or "")
        first = value.lstrip(" \t\r\n")[:1]
        return f"'{value}" if first in {"=", "+", "-", "@"} else value

    def csv_restore_value(value, row_format):
        value = str(value or "")
        if row_format == CSV_FORMAT and value.startswith("'"):
            candidate = value[1:]
            if candidate.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"}:
                return candidate
        return value

    def login_attempt_key(username):
        client_ip = request.remote_addr or "unknown"
        normalized_username = username.casefold()
        return hashlib.sha256(
            f"{client_ip}\0{normalized_username}".encode("utf-8")
        ).hexdigest()

    def login_retry_after(db, attempt_key):
        now = int(time.time())
        row = db.execute(
            "SELECT blocked_until FROM login_attempts WHERE attempt_key = ?",
            (attempt_key,),
        ).fetchone()
        return max(0, row["blocked_until"] - now) if row else 0

    def record_login_failure(db, attempt_key):
        now = int(time.time())
        row = db.execute(
            """
            SELECT failed_count, window_started_at, blocked_until
            FROM login_attempts WHERE attempt_key = ?
            """,
            (attempt_key,),
        ).fetchone()
        if row is None or now - row["window_started_at"] >= LOGIN_WINDOW_SECONDS:
            failed_count = 1
            window_started_at = now
            blocked_until = 0
        else:
            failed_count = row["failed_count"] + 1
            window_started_at = row["window_started_at"]
            blocked_until = row["blocked_until"]
        if failed_count >= LOGIN_MAX_FAILURES:
            blocked_until = max(blocked_until, now + LOGIN_BLOCK_SECONDS)
        db.execute(
            """
            INSERT INTO login_attempts
                (attempt_key, failed_count, window_started_at, blocked_until, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(attempt_key) DO UPDATE SET
                failed_count = excluded.failed_count,
                window_started_at = excluded.window_started_at,
                blocked_until = excluded.blocked_until,
                updated_at = excluded.updated_at
            """,
            (attempt_key, failed_count, window_started_at, blocked_until, now),
        )
        db.commit()
        return max(0, blocked_until - now)

    def parse_article_csv(file_storage):
        if not file_storage or not file_storage.filename:
            raise ValueError("CSVファイルを選択してください。")
        if not file_storage.filename.lower().endswith(".csv"):
            raise ValueError("CSVファイルを選択してください。")
        try:
            text = file_storage.read().decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError("CSVはUTF-8で保存してください。") from error

        reader = csv.DictReader(io.StringIO(text, newline=""))
        if reader.fieldnames is None:
            raise ValueError("CSVヘッダーがありません。")
        reader.fieldnames = [field.strip() if field else field for field in reader.fieldnames]
        nonempty_fieldnames = [field for field in reader.fieldnames if field]
        if len(nonempty_fieldnames) != len(set(nonempty_fieldnames)):
            raise ValueError("CSVヘッダーに重複した列があります。")
        fieldnames = {field for field in reader.fieldnames if field}
        missing = {"title", "content_md"} - fieldnames
        if missing:
            raise ValueError("CSVにはtitle列とcontent_md列が必要です。")
        tags_provided = "tags" in fieldnames

        parsed_rows = []
        errors = []
        seen_ids = set()
        for line_number, row in enumerate(reader, start=2):
            if None in row:
                errors.append(f"{line_number}行目: 列数が正しくありません。")
                continue
            if not any((value or "").strip() for value in row.values()):
                continue
            if len(parsed_rows) >= 1000:
                errors.append("一度にインポートできる記事は1,000件までです。")
                break

            raw_id = (row.get("id") or "").strip()
            article_id = None
            if raw_id:
                try:
                    article_id = int(raw_id)
                    if article_id <= 0:
                        raise ValueError
                except ValueError:
                    errors.append(f"{line_number}行目: idは正の整数で入力してください。")
                    continue
                if article_id in seen_ids:
                    errors.append(f"{line_number}行目: 同じidがCSV内で重複しています。")
                    continue
                seen_ids.add(article_id)

            row_format = (row.get("_format") or "").strip()
            article = {
                "title": csv_restore_value(row.get("title"), row_format).strip(),
                "content_md": csv_restore_value(row.get("content_md"), row_format).strip(),
            }
            error = validate_article(article)
            tag_values = (
                [
                    csv_restore_value(tag, row_format).strip()
                    for tag in (row.get("tags") or "").split(",")
                ]
                if tags_provided
                else []
            )
            tag_names, tag_error = parse_tags(json.dumps(tag_values, ensure_ascii=False))
            error = error or tag_error
            if error:
                errors.append(f"{line_number}行目: {error}")
                continue
            parsed_rows.append(
                {
                    "id": article_id,
                    "article": article,
                    "tags": tag_names,
                    "tags_provided": tags_provided,
                }
            )

        if errors:
            shown_errors = errors[:5]
            if len(errors) > 5:
                shown_errors.append(f"ほか{len(errors) - 5}件のエラーがあります。")
            raise ValueError(" / ".join(shown_errors))
        if not parsed_rows:
            raise ValueError("インポート対象の記事がありません。")
        return parsed_rows

    def user_from_form(require_password):
        user = {
            "username": request.form.get("username", "").strip(),
            "role": request.form.get("role", ""),
            "password": request.form.get("password", ""),
        }
        if not USERNAME_PATTERN.fullmatch(user["username"]):
            return user, "ユーザ名は英数字と . _ - を使い、3〜50文字で入力してください。"
        if user["role"] not in ROLES:
            return user, "有効なロールを選択してください。"
        if require_password and not user["password"]:
            return user, "パスワードを入力してください。"
        if user["password"] and len(user["password"]) < 8:
            return user, "パスワードは8文字以上で入力してください。"
        return user, None

    def admin_count(db):
        return db.execute("SELECT count(*) FROM users WHERE role = 'admin'").fetchone()[0]

    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

    @app.before_request
    def load_logged_in_user_and_check_csrf():
        user_id = session.get("user_id")
        g.user = (
            get_db().execute(
                "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if user_id is not None
            else None
        )
        if user_id is not None and g.user is None:
            session.clear()
        if request.method == "POST":
            expected = session.get("csrf_token", "")
            received = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not expected or not received or not secrets.compare_digest(expected, received):
                abort(400, "CSRF token is invalid.")

    @app.context_processor
    def inject_helpers():
        return {
            "csrf_token": csrf_token,
            "has_role": lambda role: g.user is not None
            and ROLE_LEVELS[g.user["role"]] >= ROLE_LEVELS[role],
            "role_labels": ROLE_LABELS,
        }

    app.add_template_filter(render_markdown, "markdown")

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'"
        )
        if g.user is not None or request.endpoint == "login":
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user is not None:
            return redirect(url_for("index"))
        next_url = request.args.get("next", "") if request.method == "GET" else request.form.get("next", "")
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            attempt_key = login_attempt_key(username)
            retry_after = login_retry_after(db, attempt_key)
            if retry_after:
                flash("ログイン試行が多すぎます。しばらく待ってから再試行してください。", "error")
                response = app.make_response(
                    (render_template("login.html", next_url=next_url if is_safe_next_url(next_url) else ""), 429)
                )
                response.headers["Retry-After"] = str(retry_after)
                return response

            user = db.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            password_is_valid = check_password_hash(
                user["password_hash"] if user is not None else dummy_password_hash,
                password,
            )
            if user is None or not password_is_valid:
                retry_after = record_login_failure(db, attempt_key)
                flash("ユーザ名またはパスワードが正しくありません。", "error")
                if retry_after:
                    response = app.make_response(
                        (render_template("login.html", next_url=next_url if is_safe_next_url(next_url) else ""), 429)
                    )
                    response.headers["Retry-After"] = str(retry_after)
                    return response
            else:
                db.execute("DELETE FROM login_attempts WHERE attempt_key = ?", (attempt_key,))
                db.commit()
                session.clear()
                session["user_id"] = user["id"]
                session.permanent = True
                return redirect(next_url if is_safe_next_url(next_url) else url_for("index"))
        return render_template("login.html", next_url=next_url if is_safe_next_url(next_url) else "")

    @app.post("/logout")
    @role_required("viewer")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @role_required("viewer")
    def index():
        db = get_db()
        search_text = request.args.get("q", "").strip()
        selected_tag = request.args.get("tag", "").strip()
        page = requested_page()
        fields = """
            a.id, a.title, a.updated_at,
            COALESCE((
                SELECT group_concat(t.name, ',')
                FROM tags t JOIN article_tags at ON at.tag_id = t.id
                WHERE at.article_id = a.id
            ), '') AS tag_names
        """
        tag_params = []
        tag_condition = ""
        if selected_tag:
            tag_condition = """
                AND EXISTS (
                    SELECT 1 FROM article_tags at2
                    JOIN tags t2 ON t2.id = at2.tag_id
                    WHERE at2.article_id = a.id AND t2.name = ?
                )
            """
            tag_params.append(selected_tag)

        fts_query = make_fts_query(search_text)
        search_terms = [term for term in re.split(r"\s+", search_text) if term]
        if fts_query and all(len(term) >= 3 for term in search_terms):
            query_params = [fts_query, *tag_params]
            total_count = db.execute(
                f"""
                SELECT count(*)
                FROM articles_fts
                JOIN articles a ON a.id = articles_fts.rowid
                WHERE articles_fts MATCH ?
                  AND a.deleted_at IS NULL {tag_condition}
                """,
                query_params,
            ).fetchone()[0]
            pagination = pagination_for(total_count, page)
            articles = db.execute(
                f"""
                SELECT {fields}
                FROM articles_fts
                JOIN articles a ON a.id = articles_fts.rowid
                WHERE articles_fts MATCH ?
                  AND a.deleted_at IS NULL {tag_condition}
                ORDER BY bm25(articles_fts), a.updated_at DESC, a.id DESC
                LIMIT ? OFFSET ?
                """,
                [
                    *query_params,
                    ARTICLES_PER_PAGE,
                    (pagination["page"] - 1) * ARTICLES_PER_PAGE,
                ],
            ).fetchall()
        elif search_terms:
            like_condition, like_params = make_like_search(search_text)
            query_params = [*like_params, *tag_params]
            total_count = db.execute(
                f"""
                SELECT count(*) FROM articles a
                WHERE a.deleted_at IS NULL AND {like_condition} {tag_condition}
                """,
                query_params,
            ).fetchone()[0]
            pagination = pagination_for(total_count, page)
            articles = db.execute(
                f"""
                SELECT {fields}
                FROM articles a
                WHERE a.deleted_at IS NULL AND {like_condition} {tag_condition}
                ORDER BY a.updated_at DESC, a.id DESC
                LIMIT ? OFFSET ?
                """,
                [
                    *query_params,
                    ARTICLES_PER_PAGE,
                    (pagination["page"] - 1) * ARTICLES_PER_PAGE,
                ],
            ).fetchall()
        else:
            total_count = db.execute(
                f"""
                SELECT count(*) FROM articles a
                WHERE a.deleted_at IS NULL {tag_condition}
                """,
                tag_params,
            ).fetchone()[0]
            pagination = pagination_for(total_count, page)
            articles = db.execute(
                f"""
                SELECT {fields}
                FROM articles a
                WHERE a.deleted_at IS NULL {tag_condition}
                ORDER BY a.updated_at DESC, a.id DESC
                LIMIT ? OFFSET ?
                """,
                [
                    *tag_params,
                    ARTICLES_PER_PAGE,
                    (pagination["page"] - 1) * ARTICLES_PER_PAGE,
                ],
            ).fetchall()
        tags = db.execute(
            """
            SELECT t.name, count(a.id) AS article_count
            FROM tags t
            LEFT JOIN article_tags at ON at.tag_id = t.id
            LEFT JOIN articles a ON a.id = at.article_id AND a.deleted_at IS NULL
            GROUP BY t.id
            HAVING count(a.id) > 0
            ORDER BY t.name COLLATE NOCASE
            """
        ).fetchall()
        return render_template(
            "index.html",
            articles=articles,
            tags=tags,
            search_text=search_text,
            selected_tag=selected_tag,
            pagination=pagination,
        )

    @app.get("/articles/<int:article_id>")
    @role_required("viewer")
    def article_detail(article_id):
        db = get_db()
        article = db.execute(
            """
            SELECT id, title, content_md, created_at, updated_at
            FROM articles WHERE id = ? AND deleted_at IS NULL
            """,
            (article_id,),
        ).fetchone()
        if article is None:
            abort(404)
        return render_template(
            "article.html", article=article, article_tags=get_article_tags(db, article_id)
        )

    @app.route("/articles/new", methods=["GET", "POST"])
    @role_required("editor")
    def create_article():
        article = {"title": "", "content_md": ""}
        article_tags = []
        if request.method == "POST":
            article = article_from_form()
            article_tags, tag_error = parse_tags(request.form.get("tags_json", "[]"))
            error = validate_article(article) or tag_error
            if error:
                flash(error, "error")
            else:
                db = get_db()
                timestamp = jst_now()
                cursor = db.execute(
                    """
                    INSERT INTO articles
                        (title, summary, content_md, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (article["title"], "", article["content_md"], timestamp, timestamp),
                )
                article_id = cursor.lastrowid
                set_article_tags(db, article_id, article_tags)
                save_revision(
                    db,
                    article_id,
                    article,
                    article_tags,
                    g.user["username"],
                    action="create",
                )
                db.commit()
                flash("ナレッジを作成しました。", "success")
                return redirect(url_for("article_detail", article_id=article_id))
        return render_template(
            "article_form.html", article=article, article_tags=article_tags, mode="create"
        )

    @app.route("/articles/<int:article_id>/edit", methods=["GET", "POST"])
    @role_required("editor")
    def edit_article(article_id):
        db = get_db()
        stored_article = db.execute(
            """
            SELECT id, title, content_md, lock_version
            FROM articles WHERE id = ? AND deleted_at IS NULL
            """,
            (article_id,),
        ).fetchone()
        if stored_article is None:
            abort(404)
        article = dict(stored_article)
        article_tags = get_article_tags(db, article_id)
        conflict = False
        if request.method == "POST":
            article.update(article_from_form())
            article_tags, tag_error = parse_tags(request.form.get("tags_json", "[]"))
            error = validate_article(article) or tag_error
            try:
                submitted_lock_version = int(request.form.get("lock_version", ""))
                if submitted_lock_version <= 0:
                    raise ValueError
            except ValueError:
                submitted_lock_version = stored_article["lock_version"]
                error = error or "編集バージョンが正しくありません。画面を再読み込みしてください。"
            if error:
                flash(error, "error")
            else:
                db.execute("BEGIN IMMEDIATE")
                cursor = db.execute(
                    """
                    UPDATE articles
                    SET title = ?, content_md = ?, updated_at = ?,
                        lock_version = lock_version + 1
                    WHERE id = ? AND deleted_at IS NULL AND lock_version = ?
                    """,
                    (
                        article["title"],
                        article["content_md"],
                        jst_now(),
                        article_id,
                        submitted_lock_version,
                    ),
                )
                if cursor.rowcount == 0:
                    db.rollback()
                    current = db.execute(
                        "SELECT lock_version FROM articles WHERE id = ? AND deleted_at IS NULL",
                        (article_id,),
                    ).fetchone()
                    if current is None:
                        abort(404)
                    article["lock_version"] = current["lock_version"]
                    conflict = True
                    flash(
                        "ほかのユーザが先に更新しました。入力内容を確認して、必要ならもう一度更新してください。",
                        "error",
                    )
                else:
                    set_article_tags(db, article_id, article_tags)
                    save_revision(
                        db,
                        article_id,
                        article,
                        article_tags,
                        g.user["username"],
                        action="update",
                    )
                    db.commit()
                    flash("ナレッジを更新しました。", "success")
                    return redirect(url_for("article_detail", article_id=article_id))
        return render_template(
            "article_form.html",
            article=article,
            article_tags=article_tags,
            mode="edit",
            conflict=conflict,
        )

    @app.post("/articles/<int:article_id>/delete")
    @role_required("editor")
    def delete_article(article_id):
        db = get_db()
        article = db.execute(
            "SELECT id, title, content_md FROM articles WHERE id = ? AND deleted_at IS NULL",
            (article_id,),
        ).fetchone()
        if article is None:
            flash("対象が見つかりません。", "error")
            return redirect(url_for("index"))
        article_tags = get_article_tags(db, article_id)
        timestamp = jst_now()
        db.execute(
            """
            UPDATE articles
            SET deleted_at = ?, deleted_by = ?, updated_at = ?,
                lock_version = lock_version + 1
            WHERE id = ? AND deleted_at IS NULL
            """,
            (timestamp, g.user["username"], timestamp, article_id),
        )
        save_revision(
            db,
            article_id,
            dict(article),
            article_tags,
            g.user["username"],
            action="trash",
        )
        db.commit()
        flash("ナレッジをゴミ箱へ移動しました。", "success")
        return redirect(url_for("index"))

    @app.get("/articles/trash")
    @role_required("editor")
    def article_trash():
        db = get_db()
        page = requested_page()
        total_count = db.execute(
            "SELECT count(*) FROM articles WHERE deleted_at IS NOT NULL"
        ).fetchone()[0]
        pagination = pagination_for(total_count, page)
        articles = db.execute(
            """
            SELECT id, title, deleted_at, deleted_by
            FROM articles
            WHERE deleted_at IS NOT NULL
            ORDER BY deleted_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (
                ARTICLES_PER_PAGE,
                (pagination["page"] - 1) * ARTICLES_PER_PAGE,
            ),
        ).fetchall()
        return render_template(
            "trash.html", articles=articles, pagination=pagination
        )

    @app.post("/articles/<int:article_id>/trash/restore")
    @role_required("editor")
    def restore_trashed_article(article_id):
        db = get_db()
        article = db.execute(
            """
            SELECT id, title, content_md
            FROM articles WHERE id = ? AND deleted_at IS NOT NULL
            """,
            (article_id,),
        ).fetchone()
        if article is None:
            abort(404)
        article_tags = get_article_tags(db, article_id)
        db.execute(
            """
            UPDATE articles
            SET deleted_at = NULL, deleted_by = NULL, updated_at = ?,
                lock_version = lock_version + 1
            WHERE id = ? AND deleted_at IS NOT NULL
            """,
            (jst_now(), article_id),
        )
        save_revision(
            db,
            article_id,
            dict(article),
            article_tags,
            g.user["username"],
            action="trash_restore",
        )
        db.commit()
        flash("ナレッジをゴミ箱から復元しました。", "success")
        return redirect(url_for("article_detail", article_id=article_id))

    @app.get("/articles/<int:article_id>/history")
    @role_required("viewer")
    def article_history(article_id):
        db = get_db()
        article = db.execute(
            "SELECT id, title, deleted_at FROM articles WHERE id = ?", (article_id,)
        ).fetchone()
        if article is None:
            abort(404)
        if article["deleted_at"] is not None and ROLE_LEVELS[g.user["role"]] < ROLE_LEVELS["editor"]:
            abort(404)
        page = requested_page()
        total_count = db.execute(
            "SELECT count(*) FROM article_revisions WHERE article_id = ?",
            (article_id,),
        ).fetchone()[0]
        pagination = pagination_for(total_count, page)
        revisions = db.execute(
            """
            SELECT id, version_no, title, changed_by, action,
                   restored_from_revision_id, created_at
            FROM article_revisions
            WHERE article_id = ?
            ORDER BY version_no DESC
            LIMIT ? OFFSET ?
            """,
            (
                article_id,
                ARTICLES_PER_PAGE,
                (pagination["page"] - 1) * ARTICLES_PER_PAGE,
            ),
        ).fetchall()
        return render_template(
            "history.html",
            article=article,
            revisions=revisions,
            pagination=pagination,
            action_labels=REVISION_ACTION_LABELS,
        )

    @app.get("/articles/<int:article_id>/history/<int:revision_id>")
    @role_required("viewer")
    def revision_detail(article_id, revision_id):
        revision = get_db().execute(
            """
            SELECT r.id, r.article_id, r.version_no, r.title, r.summary,
                   r.content_md, r.tags_json, r.changed_by, r.action,
                   r.restored_from_revision_id, r.created_at, a.deleted_at
            FROM article_revisions r
            JOIN articles a ON a.id = r.article_id
            WHERE r.id = ? AND r.article_id = ?
            """,
            (revision_id, article_id),
        ).fetchone()
        if revision is None:
            abort(404)
        if revision["deleted_at"] is not None and ROLE_LEVELS[g.user["role"]] < ROLE_LEVELS["editor"]:
            abort(404)
        return render_template(
            "revision.html",
            revision=revision,
            revision_tags=json.loads(revision["tags_json"]),
            action_labels=REVISION_ACTION_LABELS,
        )

    @app.post("/articles/<int:article_id>/restore/<int:revision_id>")
    @role_required("editor")
    def restore_revision(article_id, revision_id):
        db = get_db()
        revision = db.execute(
            """
            SELECT r.id, r.version_no, r.title, r.summary, r.content_md, r.tags_json
            FROM article_revisions r
            JOIN articles a ON a.id = r.article_id
            WHERE r.id = ? AND r.article_id = ? AND a.deleted_at IS NULL
            """,
            (revision_id, article_id),
        ).fetchone()
        if revision is None:
            abort(404)
        article = {
            "title": revision["title"],
            "content_md": revision["content_md"],
        }
        article_tags = json.loads(revision["tags_json"])
        db.execute(
            """
            UPDATE articles
            SET title = ?, content_md = ?, updated_at = ?,
                lock_version = lock_version + 1
            WHERE id = ?
            """,
            (article["title"], article["content_md"], jst_now(), article_id),
        )
        set_article_tags(db, article_id, article_tags)
        save_revision(
            db,
            article_id,
            article,
            article_tags,
            g.user["username"],
            restored_from=revision_id,
            action="restore",
        )
        db.commit()
        flash(f"バージョン{revision['version_no']}の内容を復元しました。", "success")
        return redirect(url_for("article_detail", article_id=article_id))

    @app.post("/editor/preview")
    @role_required("editor")
    def preview_markdown():
        data = request.get_json(silent=True) or {}
        content_md = str(data.get("content_md", ""))
        if len(content_md) > 50000:
            return jsonify(error="本文が長すぎます。"), 400
        return jsonify(html=str(render_markdown(content_md)))

    @app.get("/api/tags")
    @role_required("editor")
    def search_tags():
        query = request.args.get("q", "").strip()
        rows = get_db().execute(
            "SELECT name FROM tags WHERE name LIKE ? ORDER BY name COLLATE NOCASE LIMIT 10",
            (f"%{query}%",),
        ).fetchall()
        return jsonify(tags=[row["name"] for row in rows])

    @app.get("/admin/articles/import-export")
    @role_required("admin")
    def article_import_export():
        return render_template("import_export.html")

    @app.get("/admin/articles/export.csv")
    @role_required("admin")
    def export_articles_csv():
        def generate_csv():
            articles = get_db().execute(
                """
                SELECT a.id, a.title, a.content_md, a.created_at, a.updated_at,
                       COALESCE(group_concat(ordered_tags.name, ','), '') AS tag_names
                FROM articles a
                LEFT JOIN (
                    SELECT at.article_id, t.name
                    FROM article_tags at
                    JOIN tags t ON t.id = at.tag_id
                    ORDER BY t.name COLLATE NOCASE
                ) AS ordered_tags ON ordered_tags.article_id = a.id
                WHERE a.deleted_at IS NULL
                GROUP BY a.id
                ORDER BY a.id
                """
            )
            output = io.StringIO(newline="")
            writer = csv.DictWriter(
                output,
                fieldnames=[
                    "_format",
                    "id",
                    "title",
                    "content_md",
                    "tags",
                    "created_at",
                    "updated_at",
                ],
                lineterminator="\n",
            )
            output.write("\ufeff")
            writer.writeheader()
            yield output.getvalue()
            for article in articles:
                output.seek(0)
                output.truncate(0)
                writer.writerow(
                    {
                        "_format": CSV_FORMAT,
                        "id": article["id"],
                        "title": csv_safe_value(article["title"]),
                        "content_md": csv_safe_value(article["content_md"]),
                        "tags": csv_safe_value(article["tag_names"]),
                        "created_at": article["created_at"],
                        "updated_at": article["updated_at"],
                    }
                )
                yield output.getvalue()

        response = app.response_class(
            stream_with_context(generate_csv()), mimetype="text/csv"
        )
        filename = f"knowledge-{datetime.now(JST).strftime('%Y%m%d-%H%M%S')}-JST.csv"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/admin/articles/import")
    @role_required("admin")
    def import_articles_csv():
        try:
            rows = parse_article_csv(request.files.get("csv_file"))
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("article_import_export"))

        db = get_db()
        created_count = 0
        updated_count = 0
        skipped_count = 0
        try:
            db.execute("BEGIN IMMEDIATE")
            for row in rows:
                article_id = row["id"]
                article = row["article"]
                tag_names = row["tags"]
                existing = (
                    db.execute(
                        "SELECT id, title, content_md, deleted_at FROM articles WHERE id = ?",
                        (article_id,),
                    ).fetchone()
                    if article_id is not None
                    else None
                )

                if existing is not None:
                    if existing["deleted_at"] is not None:
                        raise ValueError(
                            f"id {article_id} はゴミ箱にあります。復元してからインポートしてください。"
                        )
                    current_tags = get_article_tags(db, article_id)
                    if not row["tags_provided"]:
                        tag_names = current_tags
                    unchanged = (
                        existing["title"] == article["title"]
                        and existing["content_md"] == article["content_md"]
                        and {tag.casefold() for tag in current_tags}
                        == {tag.casefold() for tag in tag_names}
                    )
                    if unchanged:
                        skipped_count += 1
                        continue
                    db.execute(
                        """
                        UPDATE articles
                        SET title = ?, content_md = ?, updated_at = ?,
                            lock_version = lock_version + 1
                        WHERE id = ?
                        """,
                        (article["title"], article["content_md"], jst_now(), article_id),
                    )
                    set_article_tags(db, article_id, tag_names)
                    save_revision(
                        db,
                        article_id,
                        article,
                        tag_names,
                        g.user["username"],
                        action="import_update",
                    )
                    updated_count += 1
                    continue

                timestamp = jst_now()
                if article_id is None:
                    cursor = db.execute(
                        """
                        INSERT INTO articles
                            (title, summary, content_md, created_at, updated_at)
                        VALUES (?, '', ?, ?, ?)
                        """,
                        (article["title"], article["content_md"], timestamp, timestamp),
                    )
                    article_id = cursor.lastrowid
                else:
                    db.execute(
                        """
                        INSERT INTO articles
                            (id, title, summary, content_md, created_at, updated_at)
                        VALUES (?, ?, '', ?, ?, ?)
                        """,
                        (article_id, article["title"], article["content_md"], timestamp, timestamp),
                    )
                set_article_tags(db, article_id, tag_names)
                save_revision(
                    db,
                    article_id,
                    article,
                    tag_names,
                    g.user["username"],
                    action="import_create",
                )
                created_count += 1
            db.commit()
        except ValueError as error:
            db.rollback()
            flash(str(error), "error")
            return redirect(url_for("article_import_export"))
        except Exception:
            db.rollback()
            app.logger.exception("CSV article import failed")
            flash("CSVのインポートに失敗しました。データは変更されていません。", "error")
            return redirect(url_for("article_import_export"))

        flash(
            f"インポート完了: 新規{created_count}件、更新{updated_count}件、変更なし{skipped_count}件",
            "success",
        )
        return redirect(url_for("article_import_export"))

    @app.get("/admin")
    @role_required("admin")
    def admin():
        return redirect(url_for("manage_users"))

    @app.get("/admin/users")
    @role_required("admin")
    def manage_users():
        users = get_db().execute(
            "SELECT id, username, role, created_at FROM users ORDER BY username COLLATE NOCASE"
        ).fetchall()
        return render_template("users.html", users=users)

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @role_required("admin")
    def create_user():
        user = {"username": "", "role": "viewer", "password": ""}
        if request.method == "POST":
            user, error = user_from_form(require_password=True)
            if error:
                flash(error, "error")
            else:
                try:
                    db = get_db()
                    db.execute(
                        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                        (user["username"], generate_password_hash(user["password"]), user["role"], jst_now()),
                    )
                    db.commit()
                except sqlite3.IntegrityError:
                    flash("同じユーザ名が既に登録されています。", "error")
                else:
                    flash("ユーザを作成しました。", "success")
                    return redirect(url_for("manage_users"))
        return render_template("user_form.html", user=user, mode="create", roles=ROLES)

    @app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
    @role_required("admin")
    def edit_user(user_id):
        db = get_db()
        stored_user = db.execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if stored_user is None:
            abort(404)
        user = dict(stored_user)
        user["password"] = ""
        if request.method == "POST":
            submitted, error = user_from_form(require_password=False)
            user.update(submitted)
            if stored_user["role"] == "admin" and user["role"] != "admin" and admin_count(db) <= 1:
                error = "最後の管理者は他のロールへ変更できません。"
            if error:
                flash(error, "error")
            else:
                try:
                    if user["password"]:
                        db.execute(
                            "UPDATE users SET username = ?, role = ?, password_hash = ? WHERE id = ?",
                            (user["username"], user["role"], generate_password_hash(user["password"]), user_id),
                        )
                    else:
                        db.execute(
                            "UPDATE users SET username = ?, role = ? WHERE id = ?",
                            (user["username"], user["role"], user_id),
                        )
                    db.commit()
                except sqlite3.IntegrityError:
                    flash("同じユーザ名が既に登録されています。", "error")
                else:
                    flash("ユーザを更新しました。", "success")
                    return redirect(url_for("manage_users"))
        return render_template("user_form.html", user=user, mode="edit", roles=ROLES)

    @app.post("/admin/users/<int:user_id>/delete")
    @role_required("admin")
    def delete_user(user_id):
        db = get_db()
        user = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            abort(404)
        if user["id"] == g.user["id"]:
            flash("ログイン中の自分自身は削除できません。", "error")
        elif user["role"] == "admin" and admin_count(db) <= 1:
            flash("最後の管理者は削除できません。", "error")
        else:
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            flash("ユーザを削除しました。", "success")
        return redirect(url_for("manage_users"))

    @app.get("/health")
    def health():
        db = get_db()
        db.execute("SELECT 1").fetchone()
        journal_mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        return jsonify(
            status="ok",
            database="connected",
            journal_mode=journal_mode,
            timezone=app.config["TIMEZONE"],
        )

    return app
