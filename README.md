# db-query-mcp

让 AI 助手安全查询 SQLite 数据库的 MCP Server —— 只读强制、SQL 校验、结果封顶。

## 为什么做这个

给 AI 接数据库,最大的风险不是"查不到",而是三件事:

1. **误写** —— 模型把 `SELECT` 写成 `UPDATE`,或者 `DROP TABLE` 出现在"顺手清理"里
2. **灌爆上下文** —— 一句 `SELECT * FROM orders` 拉回 200 万行,对话直接崩
3. **读到不该读的** —— 路径没限制,`db_path: ../../etc/passwd` 之类的穿越

这个服务把这三条做成设计约束,而不是"提示词里提醒一句"。

## 三条安全边界

| 边界 | 实现 | 绕过尝试的结果 |
|------|------|----------------|
| 只读 | ① SQL 白名单前缀(SELECT/WITH/PRAGMA/EXPLAIN)② 写操作关键字黑名单(先剥注释,防 `DEL/**/ETE` 混淆)③ PRAGMA 白名单 + 拒绝赋值 ④ 路径 URI 转义 + `mode=ro` ⑤ `PRAGMA query_only=ON` | 拒绝并返回原因,不执行 |
| 结果封顶 | 硬上限 500 行 + 单元格超 2000 字符截断 | 返回 `truncated: true` |
| 路径限制 | 库文件必须位于 `DB_QUERY_MCP_ROOT`(默认当前目录)内 | 拒绝并列出允许目录 |

只读为什么需要这么多层 —— 对抗性测试中的真实教训:

- **URI 注入**:不转义直接拼 `f"file:{path}?mode=ro"` 时,文件名里的 `#`
  会被解析成 fragment,把 `?mode=ro` 整段丢弃 → 连接偷偷变成读写模式。
  必须 `quote()` 转义路径。
- **PRAGMA 写**:`mode=ro` 单独拦不住 `PRAGMA journal_mode=WAL`(会真实
  改写库文件头)。`query_only` 连接级开关才能把 PRAGMA 类写操作也拒掉。
- **注释混淆**:`DEL/**/ETE` 在 SQLite 里等于 `DELETE`,校验前必须先剥注释。

这三点都是先被实际绕过、修复后才写进这段文档的(见 git 历史里的
`fix(security)` 提交和 `TestSecurityRegressions` 回归测试)。

## 安装

```bash
pip install -e .
```

## 配置(以 Claude Desktop 为例)

```json
{
  "mcpServers": {
    "db-query": {
      "command": "db-query-mcp",
      "env": {
        "DB_QUERY_MCP_ROOT": "/path/to/your/databases"
      }
    }
  }
}
```

`DB_QUERY_MCP_ROOT` 支持多个目录,用 `:` 分隔(Linux/macOS)或 `;`(Windows)。

## 工具

### `query`

```json
{
  "db_path": "data/app.db",
  "sql": "SELECT id, email FROM users WHERE created_at > '2026-01-01' LIMIT 50",
  "max_rows": 50
}
```

返回:

```json
{
  "columns": ["id", "email"],
  "rows": [[1, "a@example.com"]],
  "row_count": 1,
  "truncated": false,
  "max_rows": 50
}
```

### `schema`

不传 `table`:列出全部表和视图。
传 `table`:返回列定义(类型/非空/默认值/主键)和建表 SQL。

推荐工作流:先 `schema` 看结构,再写 `query` —— 这也是给模型的 instructions 里写明的。

## 会拒绝什么

```
[拒绝] 只允许 SELECT / WITH / PRAGMA / EXPLAIN 开头的只读查询     # UPDATE ...
[拒绝] 检测到写操作关键字: DROP(本服务只读)                       # SELECT 1; DROP TABLE x
[拒绝] 只允许单条语句,检测到多个分号
[拒绝] 路径不在允许的根目录内。允许: /home/me/data
```

## 测试

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
