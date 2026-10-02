"""db-query-mcp — 让 AI 安全查询数据库的 MCP Server。

设计三条安全边界(本地文件访问工具的必要防线):
1. 只读:连接以 ro URI 打开,并在 SQL 层拒绝任何写操作关键字。
2. 限流:结果集硬上限 N 行、单列超长截断,防止几百万行灌爆对话上下文。
3. 防目录穿越:库文件路径必须位于允许的根目录内(默认当前工作目录)。

配套两个工具:
- query:  执行只读 SQL,返回 rows + columns。
- schema: 列出表/视图与列定义,让模型先看结构再写 SQL。
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

server = MCPServer(
    name="db-query-mcp",
    title="Database Query",
    version="0.1.0",
    instructions=(
        "Read-only SQL access to SQLite databases. "
        "Always inspect the schema (schema tool) before writing a query. "
        "Results are capped; narrow with WHERE/LIMIT instead of pulling whole tables."
    ),
)

# ---------------------------------------------------------------------------
# 安全边界
# ---------------------------------------------------------------------------

MAX_ROWS = 500
MAX_CELL_CHARS = 2000

# 只允许以这些关键字开头的语句(单条、只读)
_ALLOWED_LEADING = re.compile(r"^\s*(SELECT|WITH|PRAGMA|EXPLAIN)\b", re.IGNORECASE)

# 任何位置出现写操作/DDL/挂载,直接拒绝
_FORBIDDEN = re.compile(
    r"("
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|REPLACE|TRUNCATE|"
    r"ATTACH|DETACH|REINDEX|VACUUM|GRANT|BEGIN|COMMIT|ROLLBACK|SAVEPOINT)\b"
    r"|writable_schema"
    r")",
    re.IGNORECASE,
)

# 允许的库根目录:环境变量 DB_QUERY_MCP_ROOT 覆盖,默认当前工作目录
def _allowed_roots() -> list[Path]:
    roots = []
    env = os.environ.get("DB_QUERY_MCP_ROOT", "")
    for part in env.split(os.pathsep):
        if part.strip():
            roots.append(Path(part).expanduser().resolve())
    if not roots:
        roots.append(Path.cwd().resolve())
    return roots


class QueryError(Exception):
    """校验失败或执行失败,统一转成可读文本返回给模型。"""


def _resolve_db_path(db_path: str) -> Path:
    """把用户给的路径解析成真实文件路径,并确认在允许根目录内。"""
    p = Path(db_path).expanduser()
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    else:
        p = p.resolve()

    roots = _allowed_roots()
    if not any(p == r or r in p.parents for r in roots):
        allowed = ", ".join(str(r) for r in roots)
        raise QueryError(f"路径不在允许的根目录内。允许: {allowed}")

    if not p.exists():
        raise QueryError(f"文件不存在: {p}")
    if not p.is_file():
        raise QueryError(f"不是普通文件: {p}")
    return p


def _validate_sql(sql: str) -> str:
    """把 SQL 收紧到"单条只读查询"。返回去掉首尾空白后的语句。"""
    s = sql.strip().rstrip(";").strip()
    if not s:
        raise QueryError("SQL 为空")

    # 拒绝多语句(分号后还有非空内容)
    body = s[:-1] if s.endswith(";") else s
    if ";" in body:
        raise QueryError("只允许单条语句,检测到多个分号")

    if not _ALLOWED_LEADING.match(s):
        raise QueryError("只允许 SELECT / WITH / PRAGMA / EXPLAIN 开头的只读查询")

    hit = _FORBIDDEN.search(s)
    if hit:
        raise QueryError(f"检测到写操作关键字: {hit.group(0).upper()}(本服务只读)")
    return s


def _to_jsonable(value: Any) -> Any:
    """SQLite 可能返回 bytes/blob,转成占位字符串,并截断超长单元格。"""
    if isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        return f"<blob {len(b)} bytes>"
    if isinstance(value, str) and len(value) > MAX_CELL_CHARS:
        return value[:MAX_CELL_CHARS] + f"…<截断,共 {len(value)} 字符>"
    return value


def _run_query(db_file: Path, sql: str, max_rows: int) -> dict[str, Any]:
    # ro URI:即使 SQL 漏过校验,数据库层也是只读的(双保险)
    uri = f"file:{db_file.as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=10)
    try:
        con.row_factory = sqlite3.Row
        cur = con.execute(sql)
        rows = cur.fetchmany(max_rows)
        columns = [d[0] for d in (cur.description or [])]
        truncated = cur.fetchone() is not None
        return {
            "columns": columns,
            "rows": [[_to_jsonable(r[c]) for c in columns] for r in rows],
            "row_count": len(rows),
            "truncated": truncated,
            "max_rows": max_rows,
        }
    finally:
        con.close()


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

@server.tool(
    description=(
        "执行只读 SQL 查询(SELECT/WITH/PRAGMA/EXPLAIN)。"
        "返回 {columns, rows, row_count, truncated}。结果默认最多 500 行。"
    )
)
def query(db_path: str, sql: str, max_rows: int = 200) -> str:
    """对 SQLite 数据库执行一条只读查询。"""
    try:
        db_file = _resolve_db_path(db_path)
        clean_sql = _validate_sql(sql)
        limit = max(1, min(int(max_rows), MAX_ROWS))
        result = _run_query(db_file, clean_sql, limit)
        return json.dumps(result, ensure_ascii=False, indent=2)
    except QueryError as e:
        return f"[拒绝] {e}"
    except sqlite3.Error as e:
        return f"[SQL 错误] {e}"


@server.tool(
    description="列出数据库中的表和视图(schema 工具的一部分)。"
)
def schema(db_path: str, table: str = "") -> str:
    """不传 table 时列出全部表/视图;传了则返回该表的列定义与建表语句。"""
    try:
        db_file = _resolve_db_path(db_path)
    except QueryError as e:
        return f"[拒绝] {e}"

    uri = f"file:{db_file.as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=10)
    try:
        con.row_factory = sqlite3.Row
        if not table:
            cur = con.execute(
                "SELECT name, type FROM sqlite_master "
                "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
            items = [{"name": r["name"], "type": r["type"]} for r in cur.fetchall()]
            return json.dumps({"tables": items}, ensure_ascii=False, indent=2)

        cur = con.execute("SELECT name FROM sqlite_master WHERE name = ?", (table,))
        if cur.fetchone() is None:
            return f"[未找到] 表/视图不存在: {table}"

        info = con.execute(f'PRAGMA table_info("{table}")').fetchall()
        columns = [
            {
                "name": r["name"],
                "type": r["type"] or "ANY",
                "notnull": bool(r["notnull"]),
                "default": r["dflt_value"],
                "pk": bool(r["pk"]),
            }
            for r in info
        ]
        ddl_row = con.execute(
            "SELECT sql FROM sqlite_master WHERE name = ?", (table,)
        ).fetchone()
        return json.dumps(
            {"table": table, "columns": columns, "ddl": ddl_row["sql"] if ddl_row else None},
            ensure_ascii=False,
            indent=2,
        )
    except sqlite3.Error as e:
        return f"[SQL 错误] {e}"
    finally:
        con.close()


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
