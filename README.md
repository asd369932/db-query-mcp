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
| 只读 | ① SQL 白名单前缀(SELECT/WITH/PRAGMA/EXPLAIN) ② 写操作关键字黑名单 ③ `mode=ro` URI 打开 | 拒绝并返回原因,不执行 |
| 结果封顶 | 硬上限 500 行 + 单元格超 2000 字符截断 | 返回 `truncated: true` |
| 路径限制 | 库文件必须位于 `DB_QUERY_MCP_ROOT`(默认当前目录)内 | 拒绝并列出允许目录 |

只读是三层防御:即使某个新 SQL 方言绕过前两层,`mode=ro` 的连接层也会兜底。

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
