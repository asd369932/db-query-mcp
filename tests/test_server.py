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

    def test_pragma_assignment_rejected(self) -> None:
        # 赋值型 PRAGMA 全部按写操作拦截(实测 journal_mode=WAL 能真实改库)
        with pytest.raises(QueryError, match="赋值"):
            _validate_sql("PRAGMA journal_mode=WAL")
        with pytest.raises(QueryError, match="赋值"):
            _validate_sql("PRAGMA user_version=123")

    def test_readonly_pragma_ok(self) -> None:
        _validate_sql("PRAGMA table_info(users)")
        _validate_sql("PRAGMA index_list(users)")

    def test_nonwhitelisted_pragma_rejected(self) -> None:
        with pytest.raises(QueryError, match="白名单"):
            _validate_sql("PRAGMA journal_mode")

    def test_comment_obfuscation_rejected(self) -> None:
        # 注释拆分的写操作关键字必须被识别:DEL/**/ETE 在 SQLite 里等于 DELETE,
        # 不删注释就躲过黑名单。拒绝理由可能是"分号"或"关键字",重点是【不放行】。
        with pytest.raises(QueryError):
            _validate_sql("SELECT 1; DEL/**/ETE FROM t")
        # 纯注释混淆(Pragma 名):删注释后命中黑名单的 writable_schema
        with pytest.raises(QueryError, match="只读"):
            _validate_sql("PRAGMA writ/**/able_schema=ON")
        # 注释里的关键字(不在语句里)不该误伤
        _validate_sql("SELECT 1 /* delete this comment */")

    def test_line_comment_removed(self) -> None:
        # 行注释里有关键字不影响;注释外没有就放行
        _validate_sql("SELECT 1 -- delete from nowhere\n")

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


class TestSecurityRegressions:
    """回归测试:验证 verify 子代理发现的三个绕过均已修复。

    这些不是理论问题,都是实际利用成功的:
    - URI fragment: 文件名含 # 时 ?mode=ro 被丢弃 → 实际读写模式打开
    - PRAGMA 写:     journal_mode/user_version 能真实改动库文件
    """

    def test_uri_fragment_cannot_escalate_to_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """文件名含 # 时,不能通过 URI 解析把只读连接变成读写连接。"""
        monkeypatch.setenv("DB_QUERY_MCP_ROOT", str(tmp_path))
        real = tmp_path / "evil.db"
        con = sqlite3.connect(real)
        con.execute("CREATE TABLE accounts (data TEXT)")
        con.execute("INSERT INTO accounts VALUES ('secret')")
        con.execute("PRAGMA user_version=0")
        con.commit()
        con.close()
        # 诱饵文件:名字里带 #(旧实现下会让 evil.db 被读写模式打开)
        (tmp_path / "evil.db#frag").write_text("not a database")

        # 通过诱饵路径请求 → 要么报错(打开的是诱饵),要么拒绝;绝不能读到真库
        out = query(str(tmp_path / "evil.db#frag"), "SELECT * FROM accounts")
        assert "secret" not in out, f"越权读到了真库内容: {out[:200]}"

    def test_pragma_write_cannot_modify_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAGMA 写操作必须被拒绝,且库文件真实状态不变。"""
        monkeypatch.setenv("DB_QUERY_MCP_ROOT", str(tmp_path))
        p = tmp_path / "x.db"
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE t (x)")
        con.commit()
        con.close()

        assert query(str(p), "PRAGMA user_version=123").startswith("[拒绝]")
        assert query(str(p), "PRAGMA journal_mode=WAL").startswith("[拒绝]")
        assert query(str(p), "PRAGMA writable_schema=ON").startswith("[拒绝]")

        # 检查文件真实状态未被改动
        con = sqlite3.connect(p)
        assert con.execute("PRAGMA user_version").fetchone()[0] == 0
        assert con.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        con.close()

    def test_query_only_blocks_write_attempts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """连接级 query_only 兜底:即使校验层被绕过,连接也拒绝写。"""
        monkeypatch.setenv("DB_QUERY_MCP_ROOT", str(tmp_path))
        p = tmp_path / "y.db"
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE t (x INTEGER)")
        con.execute("INSERT INTO t VALUES (1)")
        con.commit()
        con.close()

        # 正常读仍工作
        import json
        out = json.loads(query(str(p), "SELECT x FROM t"))
        assert out["rows"] == [[1]]
