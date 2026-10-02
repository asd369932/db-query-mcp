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
from urllib.parse import quote

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

# PRAGMA 白名单:只放行纯读取的。写类(如 journal_mode=WAL、user_version=123)
# 不在名单里,直接拒绝 —— 它们能真实改动库文件。
_READONLY_PRAGMAS = {
    "table_info",
    "table_list",
    "table_xinfo",
    "index_info",
    "index_list",
    "index_xinfo",
    "foreign_key_list",
    "database_list",
    "collation_list",
    "compile_options",
    "function_list",
    "pragma_list",
    "module_list",
    "integrity_check",
    "quick_check",
    "user_version",   # 读取版本号;带 = 赋值会被 SQL 校验的引号/赋值检测另行拦截
    "schema_version",
    "page_count",
    "page_size",
    "encoding",
    "freelist_count",
    "application_id",
}

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


# SQLite 的 URI 文件名有保留字符(& ? # % 等)。不转义时,文件名里的 '#frag'
# 会被解析成 URI fragment,把后半段(含 ?mode=ro)整段丢弃 —— 连接于是以默认
# 读写模式打开,只读防线静默失效。所有拼 URI 的地方必须走这个函数。
def _readonly_uri(db_file: Path) -> str:
    return f"file:{quote(db_file.as_posix())}?mode=ro"


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
    """把 SQL 收紧到"单条只读查询"。返回去掉首尾空白后的语句。

    校验前先删掉注释 —— 否则 `INS/**/ERT` 这类写法能躲过关键字黑名单
    (SQLite 把块注释当空白,拼接后仍是完整关键字)。
    """
    s = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)  # 块注释
    s = re.sub(r"--[^\n]*", "", s)                        # 行注释
    s = s.strip().rstrip(";").strip()
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

    # PRAGMA 校验两条:
    # 1. 带赋值(=)的一律拒绝 —— 赋值型 PRAGMA 全是写操作(user_version=123、
    #    journal_mode=WAL、writable_schema=ON 都算),没有例外;
    # 2. 无赋值的也要在只读白名单内 —— 挡住那些不带 = 但同样改库的 pragma。
    if s.upper().startswith("PRAGMA"):
        if "=" in s:
            raise QueryError("PRAGMA 赋值属于写操作,本服务只读")
        pragma_name = re.sub(r"^PRAGMA\s+(\w+).*$", r"\1", s, flags=re.IGNORECASE | re.DOTALL)
        if pragma_name.lower() not in _READONLY_PRAGMAS:
            raise QueryError(
                f"PRAGMA {pragma_name} 未在只读白名单内。"
                f"允许的: {', '.join(sorted(_READONLY_PRAGMAS))}"
            )
    return s


def _to_jsonable(value: Any) -> Any:
    """SQLite 可能返回 bytes/blob,转成占位字符串,并截断超长单元格。"""
    if isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        return f"<blob {len(b)} bytes>"
    if isinstance(value, str) and len(value) > MAX_CELL_CHARS:
        return value[:MAX_CELL_CHARS] + f"…<截断,共 {len(value)} 字符>"
    return value


def _open_readonly(db_file: Path) -> sqlite3.Connection:
    """以只读方式打开数据库。三层保障:

    1. URI 转义 —— 文件名里的 # ? & 不会被当 URI 元字符,?mode=ro 不会被吞;
    2. mode=ro —— 数据库层只读;
    3. PRAGMA query_only —— 连接级只读开关。实测:mode=ro 单独拦不住
       `PRAGMA journal_mode=WAL`(会把库文件改成 WAL 模式),加上
       query_only 才能把 PRAGMA 类写操作也拒掉。
    """
    con = sqlite3.connect(_readonly_uri(db_file), uri=True, timeout=10)
    con.execute("PRAGMA query_only=ON")
    return con


def _run_query(db_file: Path, sql: str, max_rows: int) -> dict[str, Any]:
    con = _open_readonly(db_file)
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

    uri = _readonly_uri(db_file)
    con = sqlite3.connect(uri, uri=True, timeout=10)
    con.execute("PRAGMA query_only=ON")
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

        info = con.execute('PRAGMA table_info("' + table.replace('"', '""') + '")').fetchall()
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
