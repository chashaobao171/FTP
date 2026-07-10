# FTP 安全传输系统 — Web 控制面板

> 基于 FTP 协议设计的文件安全传输系统。从零自实现 TCP/UDP 协议栈，集成 BLP 四级访问控制、DES-CBC 加密传输、断点续传、UDP 服务发现，并提供现代化 Web 管理界面。

![Python](https://img.shields.io/badge/Python-3.9+-blue) ![Flask](https://img.shields.io/badge/Flask-3.0+-green) ![License](https://img.shields.io/badge/License-MIT-blue) ![Status](https://img.shields.io/badge/Status-教学项目-yellow)

---

## 🎯 给 AI 助手 / 接手开发者 的一分钟导读

> **如果你（一个 AI Agent 或新开发者）通过 URL 看到这份代码，请按下面顺序理解：**

1. **架构一句话**：浏览器访问 `http://127.0.0.1:5000`，由 `launch.py` 同时托管 Flask API + 静态 HTML；后台启动 3 个端口：8888（TCP 指令）、8000（TCP 数据流）、9999（UDP 广播）。
2. **代码地图**（你应该依次读）：
   - `ftp_project/encrypt.py`（102 行）— DES-CBC 加解密，固定 KEY `b'FTP2025!'`，确定性 IV 派生
   - `ftp_project/user_store.py`（109 行）— JSON 持久化用户
   - `ftp_project/server.py`（913 行）— Socket 服务端 + 21 条命令字
   - `ftp_project/client.py`（959 行）— 命令行客户端（与 Web 共享协议）
   - `launch.py`（1175 行）— Flask 主入口，30+ RESTful API
   - `landing.html` / `login.html` / `admin.html` / `home.html` / `uploads_page.html` — 5 个页面
3. **关键约定**：
   - 默认管理员账号：`admin / admin123 / admin1234`（已硬编码在 `admin.cfg`）
   - 注册用户写入 `users.json` 默认 `status="pending"`，必须由管理员审批
   - 密码走 SHA-256 哈希；明文用 DES-CBC 加密后存 `cipher_pw` 字段
4. **读完立即知道在哪改什么**：
   - 想换加密算法？→ 改 `ftp_project/encrypt.py:41` 的 `KEY`
   - 想加新命令？→ 改 `server.py:client_thread()` 的分发表
   - 想加新页面？→ 在 `launch.py` 加 `@app.route('/xxx')` 并返回 `send_from_directory('.', 'xxx.html')`

---

## 🚀 快速开始

### 安装依赖
```bash
pip install flask flask-cors pycryptodome
```

### 一键启动
```bash
cd ftp_gui_project
python launch.py
```

控制台输出（启动成功后）：
```
 * Running on http://127.0.0.1:5000
 * Socket CMD listening on 8888
 * Socket DATA listening on 8000
 * UDP Broadcast ready on 9999
```

### 访问 Web 界面
打开浏览器 → http://127.0.0.1:5000

### 首次使用流程
1. 点击"管理员登录" → 用 `admin / admin123` + 验证密码 `admin1234` 登录
2. 进入管理后台 →"服务控制" → 启动 Socket 服务
3. 返回登录页 → 客户端注册新用户
4. 管理员后台审批 → 用户可登录客户端工作台

---

## 🏗️ 系统架构

### 三层 C/S 架构

```
┌────────────────────────────────────────────────────────────────┐
│                  表示层 (Browser @ :5000)                        │
│  landing.html → login.html → admin.html / home.html / upload   │
└────────────────────────────────────────────────────────────────┘
                              │ HTTP (RESTful API)
┌────────────────────────────────────────────────────────────────┐
│                  业务层 (Flask + Socket)                         │
│  launch.py (1175 行, 30+ API)  ──→  ftp_project/server.py       │
│                                     ├ CMD @ :8888 (JSON+8B 前缀) │
│                                     ├ DATA @ :8000 (二进制流)      │
│                                     └ UDP @ :9999 (服务广播)       │
└────────────────────────────────────────────────────────────────┘
                              │ TCP / UDP
┌────────────────────────────────────────────────────────────────┐
│                  数据层                                            │
│  users.json  admin.cfg  ftp_root/  .encrypted/  .decrypted/     │
└────────────────────────────────────────────────────────────────┘
```

### 双通道 Socket 协议

**指令通道（TCP :8888）**：JSON 帧，每帧前 8 字节大端长度前缀

```python
# 发送
length_prefix = len(payload_bytes).to_bytes(8, 'big')
sock.sendall(length_prefix + payload_bytes)

# 接收
def recv_all(sock, size):
    buf = b''
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk: raise ConnectionError()
        buf += chunk
    return buf
```

**数据通道（TCP :8000）**：一次性 token 模式

```python
# 客户端申请
response = send_cmd({'cmd': 'upload', 'filename': 'demo.txt', ...})
data_token = response['data_token']  # secrets.token_hex(32)

# 凭 token 连接数据端口
data_sock.connect(('127.0.0.1', 8000))
data_sock.send(data_token.encode())

# 服务端验证后弹出 session，pop 即销毁
```

### DES-CBC 加密

| 维度 | 值 |
|------|---|
| 主密钥 | `b'FTP2025!'` (8B，硬编码，**教学用不可生产**) |
| IV 派生 | `md5(KEY) XOR IV_BASE` (确定性，便于单测) |
| 分块大小 | 1000B (PKCS#7 填充到 8B 倍数) |
| 文件格式 | `[4B 块长][8B IV][密文块]...` |
| 文本格式 | `Base64(IV || 密文)` |
| 密码哈希 | `hashlib.sha256() → 64位十六进制` |

### BLP 四级权限模型

| 级别 | 中文名 | 可访问目录 | 操作 |
|------|--------|-----------|------|
| 1 | 公开 | 公开 | 浏览 |
| 2 | 一般 | 公开+一般 | + 上传 |
| 3 | 高级 | + 高级 | + 下载/删除 |
| 4 | 特殊 | 全部 | + 管理员 |

判定：`user_level >= target_level`（向下包含），实现 BLP 的"no read up"原则。

---

## 📂 项目结构

```
ftp_gui_project/
├── launch.py               # Flask 主入口 + 30+ RESTful API (≈1175 行)
├── README.md               # 本文件
├── requirements.txt        # Python 依赖
├── .gitignore              # git 排除规则
│
├── ftp_project/            # 核心 Python 模块
│   ├── server.py           # Socket 服务端 (≈913 行, 21 命令字)
│   ├── client.py           # 命令行客户端 (≈959 行, 保留功能)
│   ├── encrypt.py          # DES-CBC + SHA-256 工具 (≈102 行)
│   ├── user_store.py       # 用户 JSON 持久化 (≈109 行)
│   ├── test_run.py         # 离线测试脚本 (≈280 行)
│   ├── users.json          # 注册用户数据
│   ├── admin.cfg           # 管理员凭据
│   └── ftp_root/           # 文件存储根目录
│       ├── 公开/             # BLP Lv1 目录
│       ├── 一般/             # BLP Lv2
│       ├── 高级/             # BLP Lv3
│       ├── 特殊/             # BLP Lv4
│       ├── .encrypted/     # 密文存储
│       └── .decrypted/     # 解密副本（演示用）
│
├── uploads/                # Web 上传的工作目录
│   └── demo_plain.txt      # 演示文件 (416B)
│
├── landing.html            # 着陆页 (335 行)
├── login.html              # 登录/注册 (333 行)
├── admin.html              # 管理员控制台 (≈860 行, 5 个 tab)
├── home.html               # 客户端工作台 (≈982 行, 5 个 tab)
└── uploads_page.html       # 加密演示三栏 (≈510 行)
```

---

## 🔌 API 速查

> 完整 30+ API 清单见 `launch.py` 各 `@app.route` 注解。下面是 12 个最常用的：

| 方法 | 路径 | 用途 | 鉴权 |
|------|------|------|------|
| GET | `/` | 着陆页 | — |
| GET | `/login` | 登录页 | — |
| GET | `/admin` | 管理员控制台 | — |
| GET | `/home` | 客户端工作台 | — |
| GET | `/upload` | 加密演示页 | — |
| GET | `/api/status` | 查询服务状态 | — |
| POST | `/api/service/start` | 启动 Socket 服务 | — |
| POST | `/api/admin/login` | 管理员登录（含二次验证） | — |
| POST | `/api/client/register` | 用户注册 | — |
| POST | `/api/client/login` | 用户登录 | — |
| GET | `/api/users` | 列出所有用户 | 需管理员 |
| POST | `/api/upload` | Web 上传（multipart） | — |

完整 21 条 Socket 命令字见 `ftp_project/server.py:client_thread()` 的 `if cmd == "xxx"` 分发表。

---

## 🧪 测试

### 离线自测
```bash
cd ftp_project
python test_run.py
```

### 端到端测试
参考以下 7 个测试用例（全部已通过）：

| # | 用例 | 验证 |
|---|------|------|
| 1 | 着陆页 | GET / 返回 200 + 玻璃风 HTML |
| 2 | 管理员登录 | POST /api/admin/login 返回 level=4 |
| 3 | 注册审批闭环 | register → approve → login 拿到 level |
| 4 | 加密一致性 | 上传 → 加密 → 解密 SHA-256 比对一致 |
| 5 | 演示页实时加解密 | 三栏对比逐字一致 |
| 6 | 权限提升 | 申请 → 管理员处理 → 级别生效 |
| 7 | 服务监听 | GET /api/status 返回 running=true |

---

## 🛠️ 扩展指引

### 想换加密算法？
1. 仅改 `ftp_project/encrypt.py` 一个文件
2. `KEY` 常量改 AES-256
3. `pad_pkcs7` / `unpad_pkcs7` 保留
4. 调用方完全不变

### 想加新的 Socket 命令？
1. 在 `ftp_project/server.py:client_thread()` 的分发表加 `if cmd == "your_cmd"`
2. 实现 `handle_your_cmd(data)` 函数
3. 在 `ftp_project/client.py` 加对应调用

### 想加新的 API？
1. 在 `launch.py` 加 `@app.route('/api/xxx', methods=['GET','POST'])`
2. 返回 `jsonify({...})`

### 想加新的 HTML 页面？
1. 在 `ftp_gui_project/` 放 `yourpage.html`
2. 在 `launch.py` 加：
   ```python
   @app.route('/yourpath')
   def yourpage():
       return send_from_directory('.', 'yourpage.html')
   ```

---

## 🌐 端口说明

| 端口 | 用途 | 协议 |
|------|------|------|
| 5000 | Web 控制面板 | TCP (HTTP) |
| 8888 | Socket 指令通道 | TCP (JSON + 8B 长度前缀) |
| 8000 | Socket 数据通道 | TCP (一次性 token 二进制流) |
| 9999 | 服务发现广播 | UDP (SO_BROADCAST) |

---

## 🔄 实时同步 GitHub 工作流（已配好）

仓库已绑定到 `https://github.com/chashaobao171/FTP` 并配置了凭据缓存。**改完代码后**，在项目根目录跑一个命令即可同步：

### 最常用：`git sync "改了什么"`
```bash
git sync "feat: 加了 AES 支持"
# 等价于：add . → commit → pull --rebase → push
```

### 三个内置 alias（一次性脚本，已写入 .git/config）

| Alias | 作用 |
|-------|------|
| `git sync "描述"` | 自动 add + commit + pull + push，推送到 GitHub |
| `git pp` | 仅 pull + push（不 commit，适合同步远端别人的改动） |
| `git st` | 单行状态（已设置简化输出） |

**离线情况下**，手动版 4 步：
```bash
git add .
git commit -m "改了 X"
git pull --rebase origin main
git push origin main
```

### 第一次跨设备克隆

```bash
git clone https://github.com/chashaobao171/FTP.git
cd FTP
pip install -r requirements.txt
python launch.py
```

> 协作前需要在 GitHub 设置 Personal Access Token，仓库凭据不通过密码认证。

---

## 🌐 远程仓库信息

- **GitHub**: https://github.com/chashaobao171/FTP
- **默认分支**: main
- **首次提交**: `fa59c12` (initial public release)
- **认证方式**: PAT + Git Credential Manager（推不再弹登录框）

---

## 🤖 AI 助手协作约定

> 当你（一个 AI Agent）被要求**修改或扩展**这个项目时，请遵循：

1. **先读 `launch.py` 顶部导入和路由清单**（看到所有 API 一目了然）
2. **改前端**：直接编辑对应 `.html` 文件中的 CSS/JS
3. **改后端**：
   - 小改：在 `launch.py` 找最近的 `@app.route`
   - 大改：进入 `ftp_project/server.py` 的命令分发
4. **改加密**：`ftp_project/encrypt.py` 是**唯一**加密入口，改一处即影响全局
5. **数据迁移**：修改 `users.json` 结构时需保留所有现有字段，否则旧账号将无法登录

---

## 📜 已知限制（教学 vs 生产）

| 项 | 当前实现 | 生产建议 |
|----|---------|---------|
| DES 密钥 | 8B 硬编码 | AES-256-GCM + KMS |
| 密码哈希 | SHA-256 单次 | bcrypt / Argon2id + 盐 |
| 传输层 | JSON 明文 | TLS 1.3 全链路 |
| 持久化 | JSON 文件 | SQLite/PostgreSQL + 事务 |
| 并发 | threading.Lock | asyncio + 数据库事务 |

详见 `/server` 目录中的报告章节"局限与未来工作"。

---

## 📄 License

教学项目，欢迎学习与修改。
