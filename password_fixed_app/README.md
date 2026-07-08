# Flask 用户管理系统（密码与 SQL 注入修复版）

本项目是课程实践用的 Flask 用户信息管理平台，包含登录、注册和用户搜索功能。

已完成的安全修复：

1. 使用 Werkzeug Scrypt 哈希保存和校验密码。
2. 注册与搜索全部使用 SQLite 参数化查询，避免 SQL 注入。
3. 搜索结果只读取页面需要的公开字段。
4. 数据库文件、虚拟环境、缓存和日志不纳入版本控制。

## 运行

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

启动后访问 `http://127.0.0.1:5001`。

> 该项目仍使用 Flask 开发服务器和固定开发密钥，仅适合本地课程实验。
