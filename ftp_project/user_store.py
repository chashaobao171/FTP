"""
user_store.py - 用户与管理员信息 JSON 持久化
=============================================

【老师可能问的 Q&A 清单】
 Q1. 为什么用 JSON 文件而不是 SQLite/MySQL？
 A1. 教学项目优先"看得见摸得着"——JSON 文件可以直接用记事本打开看结构。
     生产环境应该用数据库，因为 JSON 没有索引、并发写会冲突、无事务保证。

 Q2. 如果两个用户同时注册会怎样？
 A2. 两个 load_users() 各自读到旧字典，save_users() 后写入，**后写者覆盖前者**——后注册的会丢失。
     生产方案：文件锁（fcntl/msvcrt）或数据库事务。本项目仅演示，可接受的不完美。

 Q3. 为什么管理员信息单独一个 admin.cfg 文件？
 A3. 把"管理员登录凭据"和"普通用户数据"物理隔离，
     一旦普通用户数据泄露不会同时泄露管理员口令。
"""

import json
import os
from typing import Optional


# ---------------------------------------------------------------------------
# 文件路径
# ---------------------------------------------------------------------------

# 【路径小技巧】
# os.path.dirname(__file__) = 当前文件所在目录（ftp_project/）
# os.path.abspath(__file__) = 当前文件的绝对路径
# '..' 上一级目录 = ftp_gui_project/
USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'users.json')
ADMIN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'admin.cfg')


# ---------------------------------------------------------------------------
# 用户数据操作
# ---------------------------------------------------------------------------

def load_users() -> dict:
    """
    加载所有用户信息（从 users.json 反序列化）。

    【Q4. 异常处理为什么这么宽松？】
    A4. JSON 解析失败或文件 IO 错误时直接返回空字典 {}，保证服务不崩溃。
         实战中应记录日志、上报告警，方便运维追溯问题。
    """
    if not os.path.exists(USERS_FILE):           # 文件不存在 → 空字典（首次启动）
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):      # JSON 解析失败 / IO 错误 → 不崩溃
        return {}


def save_users(users: dict):
    """
    保存所有用户信息。

    【Q5. ensure_ascii=False 是什么意思？】
    A5. JSON 默认把所有非 ASCII 字符转义成 \\uXXXX，关闭后可保留中文等 UTF-8 字符可读。
         indent=2 让文件人类可读（缩进 2 空格）。
         注意：写入时是全量覆盖（open 'w'），不是 append。
    """
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def get_user(username: str) -> Optional[dict]:
    """
    获取指定用户的信息（dict 或 None）。
    """
    users = load_users()
    return users.get(username)


def add_user(username: str, user_data: dict):
    """
    添加新用户（首次注册时调用）。

    【Q6. 为什么不检查用户是否存在？】
    A6. 调用方（server.handle_register）已经检查过了；这里保持单一职责（Single Responsibility）。
         本模块只管 JSON 读写，业务校验应在业务层。
    """
    users = load_users()
    users[username] = user_data                  # dict[key] = value 把用户名当 key
    save_users(users)


def update_user(username: str, updates: dict) -> bool:
    """
    更新用户信息（增量更新）。
    dict.update({k: v, ...})：只改传入的字段，其他字段保留不变。

    【Q7. 增量更新 vs 全量替换的区别？】
    A7. 全量替换会丢失没传的字段；增量更新只改目标字段，其他保留。
         比如 update_user('alice', {'level': 3}) 只改 level，password/email/status 都保留。
    """
    users = load_users()
    if username in users:                        # 用户不存在就不更新，避免误创建
        users[username].update(updates)
        save_users(users)
        return True
    return False


def user_exists(username: str) -> bool:
    """检查用户名是否已存在。"""
    return get_user(username) is not None


# ---------------------------------------------------------------------------
# 管理员配置操作
# ---------------------------------------------------------------------------

def load_admin_config() -> dict:
    """加载管理员配置（admin.cfg 内容）。"""
    if not os.path.exists(ADMIN_FILE):
        return {}
    try:
        with open(ADMIN_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_admin_config(config: dict):
    """保存管理员配置。"""
    with open(ADMIN_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def get_admin_password() -> str:
    """
    获取管理员登录密码哈希。

    【Q8. 为什么返回哈希而不是明文？】
    A8. 整个项目从不保存明文密码，包括管理员。
         连"看自己密码"这个功能都不提供——保护用户，强制记忆或用密码管理器。
    """
    cfg = load_admin_config()
    return cfg.get('password', '')


def get_admin_username() -> str:
    """获取管理员用户名。"""
    cfg = load_admin_config()
    return cfg.get('username', '')


def get_admin_verify_password() -> str:
    """
    获取管理员验证密码哈希。

    【Q9. 验证密码和登录密码有什么区别？】
    A9. 登录密码：登录时输入一次，进入账号。
        验证密码：登录后**敏感操作前**再次输入（如删除用户、改权限）。
        这叫"二次验证"或"step-up authentication"，防止登录密码被窃取后攻击者立刻能搞破坏。
        两个密码独立存储、互不相关，可以是不同长度、不同字符。
    """
    cfg = load_admin_config()
    return cfg.get('verify_password', '')


def set_admin_password(password_hash: str):
    """
    设置管理员登录密码哈希。

    【Q10. 为什么用 set_admin_password 而不是 add_user？】
    A10. 管理员信息存在 admin.cfg，用户存在 users.json——两套存储、两套 API。
          不能用 add_user 是因为存储位置不同（物理隔离）。
          这种"按存储位置划分"的设计让数据泄露风险降低。
    """
    cfg = load_admin_config()
    cfg['password'] = password_hash
    save_admin_config(cfg)


def set_admin_verify_password(verify_hash: str):
    """设置管理员验证密码哈希。"""
    cfg = load_admin_config()
    cfg['verify_password'] = verify_hash
    save_admin_config(cfg)


def set_admin_username(username: str):
    """设置管理员用户名。"""
    cfg = load_admin_config()
    cfg['username'] = username
    save_admin_config(cfg)


def is_admin_configured() -> bool:
    """
    检查管理员是否已配置。
    用于 launch.py 启动时判断：未配置时自动写入默认管理员凭据。
    """
    cfg = load_admin_config()
    return bool(cfg.get('password'))
