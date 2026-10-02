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

# PRAGMA 白名单分两类:
# - 无参数读取型:出现等号/括号一律拒绝
# - 名字参数型:允许 `name(表名)` 形式(如 table_info(users));这些 pragma
#   的参数语义是"对象名查找",不是赋值,无法借此写库
_READONLY_PRAGMAS = {
    "user_version",   # 只放行无参读取;= 与 () 形式都会被赋值/参数检查拦下
    "schema_version",
    "page_count",
    "page_size",
    "encoding",
    "freelist_count",
    "application_id",
    "database_list",
    "collation_list",
    "compile_options",
    "function_list",
    "pragma_list",
    "module_list",
    "integrity_check",
    "quick_check",
}

_NAME_ARG_PRAGMAS = {
    "table_info",
    "table_xinfo",
    "table_list",
    "index_info",
    "index_list",
    "index_xinfo",
    "foreign_key_list",
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


def _scan_sql(sql: str) -> tuple[str, str]:
    """扫描 SQL,返回 (cleaned, code_only)。

    cleaned   —— 删注释、保留字符串字面量;交给 SQLite 执行。
    code_only —— 删注释、并把字符串内容遮蔽;给关键字/分号/PRAGMA 检查用。

    两个必须点:
    1. 注释删除必须引号感知 —— 字符串里的 '--' 或 '/*' 不是注释。
       正则直接剥会破坏合法查询(`WHERE msg='--x--'` 变语法错误,
       `'/* x */'` 被剥后语义静默改变)。
    2. 校验要用 code_only —— 否则字符串内容里的 'DELETE' 或 ';'
       会把合法查询误判成写操作/多语句(`WHERE action='DELETE'`)。
       字符串是数据,永远不可执行,遮蔽它们不会放过真攻击。
    """
    cleaned: list[str] = []
    code: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in ("'", '"', "`"):
            # 引号段:双写引号是转义,不算结束
            j = i + 1
            while j < n:
                if sql[j] == ch:
                    if j + 1 < n and sql[j + 1] == ch:
                        j += 2
                        continue
                    break
                j += 1
            end = min(j + 1, n)
            cleaned.append(sql[i:end])
            code.append(ch * 2)          # 空字面量占位
            i = end
        elif ch == "[":
            j = sql.find("]", i + 1)
            end = n if j == -1 else j + 1
            cleaned.append(sql[i:end])
            code.append("[]")
            i = end
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            cleaned.append(" ")
            code.append(" ")
            i = n if j == -1 else j + 2
        elif sql.startswith("--", i):
            j = sql.find("\n", i + 2)
            cleaned.append(" ")
            code.append(" ")
            i = n if j == -1 else j
        else:
            cleaned.append(ch)
            code.append(ch)
            i += 1
    return "".join(cleaned), "".join(code)


def _validate_sql(sql: str) -> str:
    """把 SQL 收紧到"单条只读查询"。返回清洗后的语句(供执行)。

    所有检查跑在 code_only 上(注释已删、字符串内容已遮蔽);
    返回的则是 cleaned(字符串完整保留)。
    """
    cleaned, code = _scan_sql(sql)
    code = code.strip().rstrip(";").strip()
    if not code:
        raise QueryError("SQL 为空")

    # 拒绝多语句(分号后还有非空内容)
    body = code[:-1] if code.endswith(";") else code
    if ";" in body:
        raise QueryError("只允许单条语句,检测到多个分号")

    if not _ALLOWED_LEADING.match(code):
        raise QueryError("只允许 SELECT / WITH / PRAGMA / EXPLAIN 开头的只读查询")

    hit = _FORBIDDEN.search(code)
    if hit:
        raise QueryError(f"检测到写操作关键字: {hit.group(0).upper()}(本服务只读)")

    # PRAGMA 校验三条(三种写形式全部要堵):
    # 1. 等号赋值 `PRAGMA name=value` → 拒绝
    # 2. 括号传值 `PRAGMA name(value)` → 只有"名字参数"类 pragma
    #    才允许(如 table_info(表名));其余带括号一律拒绝
    #    (实测 PRAGMA user_version(123) 会触发写,但等号检查拦不住它)
    # 3. "名字参数"类 pragma 的参数里不能有等号(防混入赋值)
    if code.upper().startswith("PRAGMA"):
        m = re.match(r"^PRAGMA\s+(\w+)\s*(.*)$", code, re.IGNORECASE | re.DOTALL)
        if not m:
            raise QueryError("PRAGMA 语法无法解析")
        pragma_name, rest = m.group(1).lower(), m.group(2).strip()

        if rest.startswith("="):
            raise QueryError("PRAGMA 赋值属于写操作,本服务只读")
        if rest.startswith("("):
            if pragma_name not in _NAME_ARG_PRAGMAS:
                raise QueryError(
                    f"PRAGMA {pragma_name} 不接受参数(带参数形式可能触发写操作),本服务只读"
                )
            if "=" in rest:
                raise QueryError("PRAGMA 参数含赋值,拒绝")
        if pragma_name not in _READONLY_PRAGMAS and pragma_name not in _NAME_ARG_PRAGMAS:
            allowed = ", ".join(sorted(_READONLY_PRAGMAS | _NAME_ARG_PRAGMAS))
            raise QueryError(f"PRAGMA {pragma_name} 未在只读白名单内。允许的: {allowed}")
    return cleaned.strip().rstrip(";").strip()


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

    1. URI 转义 —— 文件名里的 # ? & 不会被当 URI 元字符,?mode=ro 不会被吞
       (不转义时 '#frag' 后的 ?mode=ro 被当 fragment 丢弃,连接静默变读写);
    2. mode=ro —— 数据库层只读。实测能拦 journal_mode=WAL、user_version、
       INSERT 等所有写路径(每写尝试报 "attempt to write a readonly database");
    3. PRAGMA query_only —— 连接级兜底。注意它单独【拦不住 journal_mode=WAL】
       (会把文件真实切到 WAL,属 SQLite 该 pragma 的特殊行为),但能拦住
       user_version/INSERT 类;两层叠加后所有写路径均被拒。
       (这几条都是逐层隔离实测的结论,实验脚本见 tests 里的回归用例。)
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
