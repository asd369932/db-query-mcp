"""db-query-mcp 的安全边界测试。"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from db_query_mcp.server import _resolve_db_path, _validate_sql, query, schema  # noqa: E402
from db_query_mcp.server import QueryError  # noqa: E402


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """造一个测试库,并把允许根目录设为 tmp_path。"""
    monkeypatch.setenv("DB_QUERY_MCP_ROOT", str(tmp_path))
    p = tmp_path / "test.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    con.executemany(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        [("alice", "a@example.com"), ("bob", "b@example.com")],
    )
    con.commit()
    con.close()
    return p


class TestSqlValidation:
    def test_select_allowed(self) -> None:
        assert _validate_sql("SELECT * FROM users") == "SELECT * FROM users"

    def test_with_allowed(self) -> None:
        _validate_sql("WITH t AS (SELECT 1) SELECT * FROM t")

    def test_pragma_allowed(self) -> None:
        _validate_sql("PRAGMA table_info(users)")

    def test_trailing_semicolon_ok(self) -> None:
        assert _validate_sql("SELECT 1;") == "SELECT 1"

    def test_update_rejected(self) -> None:
        with pytest.raises(QueryError, match="只读"):
            _validate_sql("UPDATE users SET name='x'")

    def test_drop_rejected(self) -> None:
        with pytest.raises(QueryError, match="只读"):
            _validate_sql("DROP TABLE users")

    def test_multi_statement_rejected(self) -> None:
        with pytest.raises(QueryError, match="单条"):
            _validate_sql("SELECT 1; DELETE FROM users")

    def test_delete_hidden_in_select_rejected(self) -> None:
        # 多语句在分号检查就被拦(先于关键字黑名单);两条防线都要求拒绝
        with pytest.raises(QueryError, match="单条"):
            _validate_sql("SELECT * FROM users WHERE 1=1; DELETE FROM users")

    def test_insert_hidden_rejected(self) -> None:
        # 单句内藏写操作关键字(无分号)由黑名单拦
        with pytest.raises(QueryError, match="只读"):
            _validate_sql("WITH x AS (SELECT 1) INSERT INTO users VALUES (9)")

    def test_writable_schema_pragma_rejected(self) -> None:
        with pytest.raises(QueryError, match="只读"):
            _validate_sql("PRAGMA writable_schema=ON")

    def test_column_named_like_keyword_ok(self) -> None:
        # update_time / created_at 这类列名不能被词边界误杀
        _validate_sql("SELECT update_time, created_at, deleted_flag FROM t")

    def test_empty_rejected(self) -> None:
        with pytest.raises(QueryError):
            _validate_sql("   ")


class TestPathValidation:
    def test_inside_root_ok(self, db: Path) -> None:
        assert _resolve_db_path(str(db)) == db.resolve()

    def test_outside_root_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_QUERY_MCP_ROOT", str(tmp_path / "allowed"))
        (tmp_path / "allowed").mkdir()
        outside = tmp_path / "secret.db"
        with pytest.raises(QueryError, match="根目录"):
            _resolve_db_path(str(outside))

    def test_traversal_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_QUERY_MCP_ROOT", str(tmp_path / "sub"))
        (tmp_path / "sub").mkdir()
        with pytest.raises(QueryError, match="根目录"):
            _resolve_db_path(str(tmp_path / "sub" / ".." / "escaped.db"))

    def test_missing_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_QUERY_MCP_ROOT", str(tmp_path))
        with pytest.raises(QueryError, match="不存在"):
            _resolve_db_path(str(tmp_path / "nope.db"))


class TestQueryExecution:
    def test_select_rows(self, db: Path) -> None:
        import json
        out = json.loads(query(str(db), "SELECT name, email FROM users ORDER BY id"))
        assert out["row_count"] == 2
        assert out["columns"] == ["name", "email"]
        assert out["rows"][0] == ["alice", "a@example.com"]
        assert out["truncated"] is False

    def test_max_rows_capped(self, db: Path) -> None:
        import json
        out = json.loads(query(str(db), "SELECT * FROM users", max_rows=1))
        assert out["row_count"] == 1
        assert out["truncated"] is True

    def test_write_denied_via_query(self, db: Path) -> None:
        out = query(str(db), "DELETE FROM users")
        assert out.startswith("[拒绝]")

    def test_schema_lists_tables(self, db: Path) -> None:
        import json
        out = json.loads(schema(str(db)))
        assert any(t["name"] == "users" for t in out["tables"])

    def test_schema_columns(self, db: Path) -> None:
        import json
        out = json.loads(schema(str(db), table="users"))
        names = [c["name"] for c in out["columns"]]
        assert names == ["id", "name", "email"]
        assert out["ddl"].startswith("CREATE TABLE")

    def test_schema_missing_table(self, db: Path) -> None:
        assert "[未找到]" in schema(str(db), table="nope")

    def test_bad_sql_returns_error(self, db: Path) -> None:
        out = query(str(db), "SELECT * FROM no_such_table")
        assert out.startswith("[SQL 错误]")

    def test_blob_handled(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json
        monkeypatch.setenv("DB_QUERY_MCP_ROOT", str(tmp_path))
        p = tmp_path / "b.db"
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE blobs (data BLOB)")
        con.execute("INSERT INTO blobs VALUES (?)", (b"\x00\x01\x02\x03",))
        con.commit()
        con.close()
        out = json.loads(query(str(p), "SELECT data FROM blobs"))
        assert out["rows"][0][0] == "<blob 4 bytes>"
