import csv
import io
import json
import re
import sqlite3

import pytest
from werkzeug.security import generate_password_hash

from memo import create_app


CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
LOCK_VERSION_PATTERN = re.compile(r'name="lock_version" value="(\d+)"')


@pytest.fixture()
def app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-key",
            "DATABASE": str(tmp_path / "test.db"),
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin-password",
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_from(response):
    match = CSRF_PATTERN.search(response.get_data(as_text=True))
    assert match is not None
    return match.group(1)


def lock_version_from(response):
    match = LOCK_VERSION_PATTERN.search(response.get_data(as_text=True))
    assert match is not None
    return match.group(1)


def login(client, username, password, next_url=""):
    token = csrf_from(client.get(f"/login?next={next_url}"))
    return client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": username,
            "password": password,
            "next": next_url,
        },
        follow_redirects=True,
    )


def add_user(app, username, password, role):
    with sqlite3.connect(app.config["DATABASE"]) as db:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        return cursor.lastrowid


def clear_session(client):
    with client.session_transaction() as session:
        session.clear()


def test_login_is_shared_and_health_is_public(client):
    health = client.get("/health")
    assert health.status_code == 200
    assert health.get_json()["journal_mode"] == "wal"
    assert health.get_json()["timezone"] == "Asia/Tokyo"
    assert client.get("/").status_code == 302
    assert client.get("/login").headers["Cache-Control"] == "no-store"

    response = login(client, "admin", "wrong-password")
    assert "正しくありません".encode() in response.data

    response = login(client, "admin", "admin-password")
    assert response.status_code == 200
    assert "ナレッジ一覧".encode() in response.data
    assert "管理者".encode() in response.data
    assert response.data.count(b'href="/articles/new"') == 1
    assert response.headers["Cache-Control"] == "no-store"


def test_viewer_can_read_but_cannot_edit_or_manage_users(client, app):
    add_user(app, "viewer1", "viewer-password", "viewer")
    with sqlite3.connect(app.config["DATABASE"]) as db:
        article_id = db.execute(
            "INSERT INTO articles (title, summary, content_md) VALUES (?, ?, ?)",
            ("閲覧テスト", "unsearchable-secret", "# 本文"),
        ).lastrowid

    login(client, "viewer1", "viewer-password")
    assert client.get("/").status_code == 200
    article_page = client.get(f"/articles/{article_id}")
    assert article_page.status_code == 200
    assert b"unsearchable-secret" not in article_page.data
    assert "閲覧テスト".encode() not in client.get("/?q=unsearchable-secret").data
    assert client.get("/articles/new").status_code == 403
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/articles/import-export").status_code == 403
    assert client.get("/admin/articles/export.csv").status_code == 403
    assert client.get("/articles/trash").status_code == 403


def test_editor_can_crud_and_preview_but_cannot_manage_users(client, app):
    add_user(app, "editor1", "editor-password", "editor")
    login(client, "editor1", "editor-password")

    form_page = client.get("/articles/new")
    assert b'name="summary"' not in form_page.data
    assert b'data-editor-tab="preview"' in form_page.data
    token = csrf_from(form_page)
    preview = client.post(
        "/editor/preview",
        json={"content_md": "## Preview\n\n<script>alert(1)</script>"},
        headers={"X-CSRF-Token": token},
    )
    assert preview.status_code == 200
    assert "<h2>Preview</h2>" in preview.get_json()["html"]
    assert "<script>" not in preview.get_json()["html"]

    response = client.post(
        "/articles/new",
        data={
            "csrf_token": token,
            "title": "編集者の記事",
            "content_md": "# 作成済み",
        },
        follow_redirects=True,
    )
    assert "編集者の記事".encode() in response.data

    with sqlite3.connect(app.config["DATABASE"]) as db:
        article_id = db.execute("SELECT id FROM articles").fetchone()[0]

    edit_page = client.get(f"/articles/{article_id}/edit")
    token = csrf_from(edit_page)
    lock_version = lock_version_from(edit_page)
    response = client.post(
        f"/articles/{article_id}/edit",
        data={
            "csrf_token": token,
            "lock_version": lock_version,
            "title": "更新済みの記事",
            "content_md": "## 更新",
        },
        follow_redirects=True,
    )
    assert "更新済みの記事".encode() in response.data

    token = csrf_from(client.get(f"/articles/{article_id}/edit"))
    response = client.post(
        f"/articles/{article_id}/delete",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert "ナレッジをゴミ箱へ移動しました".encode() in response.data
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/articles/import-export").status_code == 403
    assert client.get("/admin/articles/export.csv").status_code == 403
    assert client.get("/articles/trash").status_code == 200


def test_admin_can_create_update_and_delete_users(client, app):
    login(client, "admin", "admin-password")

    new_page = client.get("/admin/users/new")
    token = csrf_from(new_page)
    response = client.post(
        "/admin/users/new",
        data={
            "csrf_token": token,
            "username": "writer1",
            "password": "writer-password",
            "role": "viewer",
        },
        follow_redirects=True,
    )
    assert "writer1".encode() in response.data

    with sqlite3.connect(app.config["DATABASE"]) as db:
        user_id = db.execute("SELECT id FROM users WHERE username = 'writer1'").fetchone()[0]

    edit_page = client.get(f"/admin/users/{user_id}/edit")
    token = csrf_from(edit_page)
    response = client.post(
        f"/admin/users/{user_id}/edit",
        data={"csrf_token": token, "username": "writer1", "password": "", "role": "editor"},
        follow_redirects=True,
    )
    assert "編集者".encode() in response.data

    token = csrf_from(response)
    response = client.post(
        f"/admin/users/{user_id}/delete",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert "ユーザを削除しました".encode() in response.data


def test_last_admin_and_csrf_are_protected(client, app):
    login(client, "admin", "admin-password")
    with sqlite3.connect(app.config["DATABASE"]) as db:
        admin_id = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[0]

    assert client.post("/articles/new", data={}).status_code == 400
    edit_page = client.get(f"/admin/users/{admin_id}/edit")
    token = csrf_from(edit_page)
    response = client.post(
        f"/admin/users/{admin_id}/edit",
        data={"csrf_token": token, "username": "admin", "password": "", "role": "viewer"},
        follow_redirects=True,
    )
    assert "最後の管理者".encode() in response.data


def test_tags_full_text_search_history_and_restore(client, app):
    add_user(app, "history-editor", "editor-password", "editor")
    login(client, "history-editor", "editor-password")

    token = csrf_from(client.get("/articles/new"))
    response = client.post(
        "/articles/new",
        data={
            "csrf_token": token,
            "title": "Docker永続化ガイド",
            "content_md": "# Volume\n\ncompose volume の運用手順",
            "tags_json": json.dumps(["Docker", "SQLite"]),
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with sqlite3.connect(app.config["DATABASE"]) as db:
        article_id = db.execute(
            "SELECT id FROM articles WHERE title = 'Docker永続化ガイド'"
        ).fetchone()[0]
        revision_one = db.execute(
            "SELECT id FROM article_revisions WHERE article_id = ? AND version_no = 1",
            (article_id,),
        ).fetchone()[0]
        timestamps = db.execute(
            "SELECT created_at, updated_at FROM articles WHERE id = ?", (article_id,)
        ).fetchone()
        assert timestamps[0].endswith("+09:00")
        assert timestamps[1].endswith("+09:00")

    search = client.get("/?q=compose")
    assert "Docker永続化ガイド".encode() in search.data
    tag_filter = client.get("/?tag=SQLite")
    assert "Docker永続化ガイド".encode() in tag_filter.data
    tag_api = client.get("/api/tags?q=Dock")
    assert tag_api.get_json() == {"tags": ["Docker"]}

    edit_page = client.get(f"/articles/{article_id}/edit")
    token = csrf_from(edit_page)
    lock_version = lock_version_from(edit_page)
    client.post(
        f"/articles/{article_id}/edit",
        data={
            "csrf_token": token,
            "lock_version": lock_version,
            "title": "Apache更新版",
            "content_md": "# Apache\n\nreverse proxy",
            "tags_json": json.dumps(["Apache"]),
        },
    )
    history = client.get(f"/articles/{article_id}/history")
    assert "バージョン 2".encode() in history.data
    assert "バージョン 1".encode() in history.data

    revision_page = client.get(f"/articles/{article_id}/history/{revision_one}")
    token = csrf_from(revision_page)
    restored = client.post(
        f"/articles/{article_id}/restore/{revision_one}",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert "Docker永続化ガイド".encode() in restored.data
    assert "SQLite".encode() in restored.data

    with sqlite3.connect(app.config["DATABASE"]) as db:
        assert db.execute(
            "SELECT count(*) FROM article_revisions WHERE article_id = ?", (article_id,)
        ).fetchone()[0] == 3
        assert db.execute(
            "SELECT restored_from_revision_id FROM article_revisions WHERE article_id = ? AND version_no = 3",
            (article_id,),
        ).fetchone()[0] == revision_one

    assert "Docker永続化ガイド".encode() in client.get("/?q=compose").data


def test_legacy_utc_timestamp_is_migrated_to_jst(app):
    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.execute(
            "UPDATE users SET created_at = '2026-01-01T00:00:00Z' WHERE username = 'admin'"
        )

    create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-key",
            "DATABASE": app.config["DATABASE"],
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin-password",
        }
    )

    with sqlite3.connect(app.config["DATABASE"]) as db:
        created_at = db.execute(
            "SELECT created_at FROM users WHERE username = 'admin'"
        ).fetchone()[0]
    assert created_at == "2026-01-01T09:00:00+09:00"


def test_admin_csv_export_import_and_atomic_validation(client, app):
    login(client, "admin", "admin-password")

    token = csrf_from(client.get("/articles/new"))
    client.post(
        "/articles/new",
        data={
            "csrf_token": token,
            "title": "CSV元記事",
            "content_md": "# Original\n\n複数行本文",
            "tags_json": json.dumps(["ExportTag"]),
        },
    )
    with sqlite3.connect(app.config["DATABASE"]) as db:
        article_id = db.execute(
            "SELECT id FROM articles WHERE title = 'CSV元記事'"
        ).fetchone()[0]

    exported = client.get("/admin/articles/export.csv")
    assert exported.status_code == 200
    assert exported.mimetype == "text/csv"
    assert "attachment" in exported.headers["Content-Disposition"]
    exported_rows = list(
        csv.DictReader(io.StringIO(exported.data.decode("utf-8-sig"), newline=""))
    )
    assert exported_rows[0]["title"] == "CSV元記事"
    assert exported_rows[0]["tags"] == "ExportTag"
    assert "複数行本文" in exported_rows[0]["content_md"]

    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=["id", "title", "content_md", "tags", "created_at", "updated_at"],
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerow(
        {
            "id": article_id,
            "title": "CSV更新記事",
            "content_md": "# Updated\n\n更新済み",
            "tags": "Alpha,Beta",
            "created_at": "",
            "updated_at": "",
        }
    )
    writer.writerow(
        {
            "id": "",
            "title": "CSV新規記事",
            "content_md": "# Imported\n\n検索対象語 importmarker",
            "tags": "Gamma",
            "created_at": "",
            "updated_at": "",
        }
    )
    transfer_page = client.get("/admin/articles/import-export")
    token = csrf_from(transfer_page)
    imported = client.post(
        "/admin/articles/import",
        data={
            "csrf_token": token,
            "csv_file": (
                io.BytesIO(csv_buffer.getvalue().encode("utf-8-sig")),
                "articles.csv",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "新規1件、更新1件".encode() in imported.data

    with sqlite3.connect(app.config["DATABASE"]) as db:
        assert db.execute("SELECT count(*) FROM articles").fetchone()[0] == 2
        assert db.execute(
            "SELECT count(*) FROM article_revisions WHERE article_id = ?", (article_id,)
        ).fetchone()[0] == 2
        tags = {
            row[0]
            for row in db.execute(
                """
                SELECT t.name FROM tags t
                JOIN article_tags at ON at.tag_id = t.id
                WHERE at.article_id = ?
                """,
                (article_id,),
            )
        }
        assert tags == {"Alpha", "Beta"}
    assert "CSV新規記事".encode() in client.get("/?q=importmarker").data

    no_tag_column_csv = (
        f"id,title,content_md\n{article_id},CSVタグ維持,# Keep existing tags\n"
    )
    token = csrf_from(client.get("/admin/articles/import-export"))
    client.post(
        "/admin/articles/import",
        data={
            "csrf_token": token,
            "csv_file": (
                io.BytesIO(no_tag_column_csv.encode("utf-8")),
                "without-tags.csv",
            ),
        },
        content_type="multipart/form-data",
    )
    with sqlite3.connect(app.config["DATABASE"]) as db:
        retained_tags = {
            row[0]
            for row in db.execute(
                """
                SELECT t.name FROM tags t
                JOIN article_tags at ON at.tag_id = t.id
                WHERE at.article_id = ?
                """,
                (article_id,),
            )
        }
    assert retained_tags == {"Alpha", "Beta"}

    invalid_csv = "id,title,content_md,tags\n,Valid before error,# body,Tag\n,,# missing title,Tag\n"
    token = csrf_from(client.get("/admin/articles/import-export"))
    rejected = client.post(
        "/admin/articles/import",
        data={
            "csrf_token": token,
            "csv_file": (io.BytesIO(invalid_csv.encode("utf-8")), "invalid.csv"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "タイトルを入力してください".encode() in rejected.data
    with sqlite3.connect(app.config["DATABASE"]) as db:
        assert db.execute("SELECT count(*) FROM articles").fetchone()[0] == 2


def test_japanese_search_and_article_pagination(client, app):
    login(client, "admin", "admin-password")
    with sqlite3.connect(app.config["DATABASE"]) as db:
        for number in range(1, 22):
            db.execute(
                "INSERT INTO articles (title, content_md) VALUES (?, ?)",
                (
                    f"日本語全文検索の対象記事{number:02d}",
                    f"空白なしの日本語文章から検索できます番号{number:02d}",
                ),
            )

    long_query = client.get("/?q=全文検索")
    assert long_query.status_code == 200
    assert long_query.data.count(b'class="article-row"') == 20
    assert "次へ".encode() in long_query.data

    second_page = client.get("/?q=全文検索&page=2")
    assert second_page.data.count(b'class="article-row"') == 1
    assert "日本語全文検索の対象記事01".encode() in second_page.data

    short_query = client.get("/?q=検索")
    assert short_query.status_code == 200
    assert "日本語全文検索の対象記事".encode() in short_query.data

    with sqlite3.connect(app.config["DATABASE"]) as db:
        fts_sql = db.execute(
            "SELECT sql FROM sqlite_schema WHERE name = 'articles_fts'"
        ).fetchone()[0]
        fts_version = db.execute(
            "SELECT value FROM app_meta WHERE key = 'fts_version'"
        ).fetchone()[0]
    assert "trigram" in fts_sql
    assert fts_version == "trigram-v1"


def test_trash_restore_preserves_history_and_history_is_paginated(client, app):
    login(client, "admin", "admin-password")
    token = csrf_from(client.get("/articles/new"))
    client.post(
        "/articles/new",
        data={
            "csrf_token": token,
            "title": "ゴミ箱テスト",
            "content_md": "# 復元対象",
            "tags_json": json.dumps(["PreservedTag"]),
        },
    )
    with sqlite3.connect(app.config["DATABASE"]) as db:
        article_id = db.execute(
            "SELECT id FROM articles WHERE title = 'ゴミ箱テスト'"
        ).fetchone()[0]
        for version in range(2, 23):
            db.execute(
                """
                INSERT INTO article_revisions
                    (article_id, version_no, title, content_md, tags_json, changed_by, action)
                VALUES (?, ?, 'ゴミ箱テスト', '# 復元対象', '[\"PreservedTag\"]', 'admin', 'update')
                """,
                (article_id, version),
            )

    history_page = client.get(f"/articles/{article_id}/history")
    assert history_page.data.count("バージョン ".encode()) == 20
    assert "次へ".encode() in history_page.data
    assert "バージョン 1".encode() in client.get(
        f"/articles/{article_id}/history?page=2"
    ).data

    edit_page = client.get(f"/articles/{article_id}/edit")
    token = csrf_from(edit_page)
    client.post(
        f"/articles/{article_id}/delete",
        data={"csrf_token": token},
    )
    assert client.get(f"/articles/{article_id}").status_code == 404
    trash_page = client.get("/articles/trash")
    assert "ゴミ箱テスト".encode() in trash_page.data
    assert "PreservedTag".encode() not in client.get("/").data

    token = csrf_from(trash_page)
    restored = client.post(
        f"/articles/{article_id}/trash/restore",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert "ゴミ箱から復元しました".encode() in restored.data
    assert "PreservedTag".encode() in restored.data
    with sqlite3.connect(app.config["DATABASE"]) as db:
        actions = [
            row[0]
            for row in db.execute(
                "SELECT action FROM article_revisions WHERE article_id = ? ORDER BY version_no DESC LIMIT 2",
                (article_id,),
            )
        ]
    assert actions == ["trash_restore", "trash"]


def test_optimistic_lock_rejects_stale_edit(app):
    first_client = app.test_client()
    second_client = app.test_client()
    login(first_client, "admin", "admin-password")
    login(second_client, "admin", "admin-password")

    token = csrf_from(first_client.get("/articles/new"))
    first_client.post(
        "/articles/new",
        data={"csrf_token": token, "title": "競合前", "content_md": "# 元本文"},
    )
    with sqlite3.connect(app.config["DATABASE"]) as db:
        article_id = db.execute("SELECT id FROM articles").fetchone()[0]

    first_form = first_client.get(f"/articles/{article_id}/edit")
    second_form = second_client.get(f"/articles/{article_id}/edit")
    first_client.post(
        f"/articles/{article_id}/edit",
        data={
            "csrf_token": csrf_from(first_form),
            "lock_version": lock_version_from(first_form),
            "title": "先に保存",
            "content_md": "# 先の本文",
        },
    )
    conflicted = second_client.post(
        f"/articles/{article_id}/edit",
        data={
            "csrf_token": csrf_from(second_form),
            "lock_version": lock_version_from(second_form),
            "title": "後から保存",
            "content_md": "# 後の本文",
        },
        follow_redirects=True,
    )
    assert "ほかのユーザが先に更新しました".encode() in conflicted.data
    assert "後から保存".encode() in conflicted.data
    with sqlite3.connect(app.config["DATABASE"]) as db:
        article = db.execute(
            "SELECT title, lock_version FROM articles WHERE id = ?", (article_id,)
        ).fetchone()
        revision_count = db.execute(
            "SELECT count(*) FROM article_revisions WHERE article_id = ?", (article_id,)
        ).fetchone()[0]
    assert article == ("先に保存", 2)
    assert revision_count == 2


def test_login_rate_limit_blocks_fifth_failure(client):
    for _ in range(4):
        assert login(client, "admin", "wrong-password").status_code == 200
    blocked = login(client, "admin", "wrong-password")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    correct_but_blocked = login(client, "admin", "admin-password")
    assert correct_but_blocked.status_code == 429


def test_csv_formula_cells_are_safe_and_round_trip(client, app):
    login(client, "admin", "admin-password")
    token = csrf_from(client.get("/articles/new"))
    client.post(
        "/articles/new",
        data={
            "csrf_token": token,
            "title": "=1+1",
            "content_md": "- Markdown list",
            "tags_json": json.dumps(["@danger"]),
        },
    )

    exported = client.get("/admin/articles/export.csv")
    rows = list(csv.DictReader(io.StringIO(exported.data.decode("utf-8-sig"), newline="")))
    assert rows[0]["_format"] == "kb-csv-v2"
    assert rows[0]["title"] == "'=1+1"
    assert rows[0]["content_md"] == "'- Markdown list"
    assert rows[0]["tags"] == "'@danger"

    token = csrf_from(client.get("/admin/articles/import-export"))
    imported = client.post(
        "/admin/articles/import",
        data={
            "csrf_token": token,
            "csv_file": (io.BytesIO(exported.data), "safe-export.csv"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "変更なし1件".encode() in imported.data
    with sqlite3.connect(app.config["DATABASE"]) as db:
        stored = db.execute(
            "SELECT title, content_md FROM articles"
        ).fetchone()
    assert stored == ("=1+1", "- Markdown list")
