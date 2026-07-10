"""
server.py - FTP 服务端主程序
=============================

【老师可能问的 Q&A 清单】
 Q1. 为什么分三个端口 8888/8000/9999？
 A1. 这是经典 FTP 协议的"控制-数据分离"思想：
     - 8888 (TCP)：指令通道。所有 JSON 命令（注册/登录/列表...）
     - 8000 (TCP)：数据通道。文件二进制流传输
     - 9999 (UDP)：服务发现广播。客户端启动时监听，收到就知道服务端在哪
     控制和数据分离的好处：① 大文件传输不会卡住控制命令 ② 多种传输模式可灵活切换

 Q2. 双通道 Socket 是怎么关联的？
 A2. 通过一次性 token：
     1. 客户端发 `cmd=upload` 到 8888 拿 data_token
     2. 客户端凭 token 连接到 8000 数据通道
     3. 服务端用 pop_data_session 验证 token 并销毁它
     4. 后续数据传输与控制无关，可中途断开重连
     一次性 token 防止重放攻击——拿到一次请求的 token 无法复用第二次。

 Q3. BLP 模型是怎么体现的？
 A3. can_access() 函数检查 user_level >= target_level。
     比如 Lv2 用户只能访问公开/一般目录（range(1, 3) = [1, 2]），不能访问高级/特殊。
     这对应 BLP 的"不上读不下写"原则（机密性）。
"""

import json
import os
import platform
import secrets       # 密码学强随机数（用于 token）
import socket
import threading     # 多客户端并发：每连接一个线程
import time

import encrypt
import user_store
from typing import Optional


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

# 0.0.0.0 表示绑定本机所有网卡；监听端口 8888（指令）/ 8000（数据）
HOST, PORT, DATA_PORT = '0.0.0.0', 8888, 8000
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ftp_root')
CHUNK_SIZE = 1000        # 文件分块大小（与 encrypt.py 同名常量一致）

# 【Q4. 为什么用中文名映射？】
# A4. 权限级别本身是数字（1-4），但业务上要给用户看到"公开/一般/高级/特殊"这样的友好名。
#     LEVEL_NAMES 数字→中文，LEVEL_MAP 中文→数字。两套互逆映射，是 Python 项目的常见模式。
LEVEL_NAMES = {1: '公开', 2: '一般', 3: '高级', 4: '特殊'}
LEVEL_MAP = {'公开': 1, '一般': 2, '高级': 3, '特殊': 4}

# 数据通道会话池: token -> session_info
# 用 dict 存，使用 threading.Lock 保证线程安全
_data_sessions = {}
_data_lock = threading.Lock()         # 解释：原子操作；不加锁会出现并发覆盖


# ---------------------------------------------------------------------------
# 目录工具
# ---------------------------------------------------------------------------

def ensure_dirs():
    """
    确保四级目录存在（公开/一般/高级/特殊）。

    【Q5. exist_ok=True 是什么意思？】
    A5. os.makedirs(..., exist_ok=True) 如果目录已存在不报错；不存在则创建（含父目录）。
        这样无论首次启动还是重启都不会异常。
    """
    for name in LEVEL_NAMES.values():
        os.makedirs(os.path.join(BASE_DIR, name), exist_ok=True)


def get_level_dir(level_name: str) -> str:
    """获取级别目录的完整路径（中文名 → 绝对路径）。"""
    return os.path.join(BASE_DIR, level_name)


def get_user_level(username: str) -> int:
    """
    获取用户的权限级别（数字 1-4）；不存在用户视作 Lv1（最低权限）。

    【Q6. 为什么不存在的用户默为 Lv1？】
    A6. 防御性默认：即便不存在的用户访问资源，也让他只能访问最低级别（公开目录）。
         这是 fail-safe 原则——出错时给最小权限，不给最大权限。
    """
    user = user_store.get_user(username)
    return user.get('level', 1) if user else 1


def can_access(username: str, level_name: str) -> bool:
    """
    检查用户是否有权限访问指定级别目录。

    【Q7. 不允许下读还是不允许上写？】
    A7. can_access() 是 "user_level >= target_level"——允许**下读**（Lv3 可看 Lv3/Lv2/Lv1）。
         不允许上读（Lv2 不能看 Lv3）。
         这符合 BLP 的 "*-property"（no read up）：低权限不能读高权限。
         但本项目允许"下读"，意味着 Lv3 用户可以看到所有低于自己的目录文件。
    """
    user_level = get_user_level(username)
    target_level = LEVEL_MAP.get(level_name, 1)        # 中文名 → 数字
    return user_level >= target_level


# ---------------------------------------------------------------------------
# 数据通道会话管理
# ---------------------------------------------------------------------------

def create_data_session(session_info: dict) -> str:
    """
    创建数据通道会话，返回一次性 token。

    【Q8. token_hex(32) 是 256 位随机？为什么？】
    A8. secrets.token_hex(32) 生成 32 字节的密码学强随机数（256 位）。
        256 位的随机空间（2^256）暴力枚举完全不可能。
        hex 编码后是 64 字符的字符串。

    【Q9. 为什么存到全局 dict + 加锁？】
    A9. 因为 8000 数据通道是独立线程（或另一个进程）处理的，要共享给主线程用。
        threading.Lock 确保多线程下不会出现"两个客户端同时创建 token 但字典被覆盖"的问题。
    """
    token = secrets.token_hex(32)        # 256 位密码学强随机 token
    with _data_lock:                      # 上锁保护 _data_sessions 字典读写原子性
        _data_sessions[token] = session_info
    return token


def pop_data_session(token: str) -> Optional[dict]:
    """
    消费（取出并删除）数据通道会话。
    pop 而不是 get：消费即销毁，防止 token 被重复利用（防重放）。

    【Q10. 为什么用 pop 而不是 del _data_sessions[token]？】
    A10. dict.pop(key, default) 在 key 不存在时返回默认值，不会抛 KeyError。
         防御性编程：客户端发来伪造 token 时优雅失败。
    """
    with _data_lock:
        return _data_sessions.pop(token, None)


# ---------------------------------------------------------------------------
# 网络工具
# ---------------------------------------------------------------------------

def send_json(sock, data: dict):
    """
    发送 JSON 数据（8 字节大端长度前缀 + JSON 正文）。

    【Q11. 为什么要加长度前缀？】
    A11. TCP 是字节流协议，没有"消息边界"概念。
         客户端分两次发送"Hello"+"World"，服务端可能一次读到 "HelloWorld"（粘包）。
         加长度前缀后，服务端先读 8 字节得到本条消息长度，再读那么多字节，天然切分。
         这就是"长度前缀法"，HTTP/2、gRPC 等协议都在用类似思路。

    【Q12. 为什么用大端字节序？】
    A12. 网络字节序（network byte order）= 大端（high byte first）。
         把 0x1234 写成 \\x12\\x34 而不是 \\x34\\x12。
         这是 TCP/IP 协议栈的统一约定，确保不同字节序的机器互通。
    """
    try:
        raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
        sock.sendall(len(raw).to_bytes(8, 'big') + raw)
    except (BrokenPipeError, OSError):
        pass      # 客户端断开等情况静默忽略


def recv_all(sock, size: int) -> bytes:
    """
    精确接收指定字节数的数据。

    【Q13. 为什么用 while 而不是 recv(size) 一次拿够？】
    A13. TCP 的 recv() 不保证一次返回 size 字节，可能只返回部分。
         比如你请求 1000 字节，实际只收到 800，另一部分在下一批到达。
         必须反复 recv 直到收够 size，否则下游解析会出错。
    """
    buf = b''
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:                  # 连接关闭（客户端断开）
            break
        buf += chunk
    return buf


def recv_json(sock) -> Optional[dict]:
    """
    接收 JSON 数据。先读 8 字节长度，再读相应字节。

    【Q14. 三个 if len(...) < size 都是在做什么？】
    A14. 防御性检查：连接中断可能让 recv_all 收到的字节少于期望值。
         一旦少于期望值，说明 JSON 不完整，不能 json.loads() 解析，
         直接返回 None 让调用方知道"客户端走了"。
    """
    raw_len = recv_all(sock, 8)
    if len(raw_len) < 8:           # 读不到 8 字节 → 客户端断开
        return None
    length = int.from_bytes(raw_len, 'big')    # 大端 8 字节转整数
    if length == 0:                  # 长度 0 → 空白消息
        return None
    data = recv_all(sock, length)
    if len(data) < length:           # JSON 体不完整
        return None
    try:
        return json.loads(data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# UDP 广播
# ---------------------------------------------------------------------------

def udp_broadcast():
    """
    广播服务器信息（客户端登录时同步调用一次）。

    【Q15. SO_BROADCAST 套接字选项是什么？】
    A15. 默认情况下 UDP socket 不能发广播包（受网络协议栈限制）。
         setsockopt(SOL_SOCKET, SO_BROADCAST, 1) 开启广播权限。
         "<broadcast>" 是特殊目标地址，会发到当前子网所有主机。

    【Q16. 为什么同时向 127.0.0.1 发？】
    A16. <broadcast> 在某些网络配置下不传给自己。
         同机自测时向 127.0.0.1 也发一份，确保客户端在本机测试时也能收到。

    【Q17. 为什么不阻塞？UDP sendto 默认就是非阻塞吗？】
    A17. UDP 是无连接的，sendto 直接把数据放进发送缓冲区就返回；
         若对方端口关闭数据报丢失是正常的——反正广播包本来就是 best-effort 通知。
    """
    bc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            # UDP
    bc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)          # 允许广播
    hostname = platform.node()                                              # 本机主机名（如 PC-UserName）
    ip = '127.0.0.1'
    msg = json.dumps({'type': 'ftp_server', 'name': 'FTP-Secure-Server',
                      'host': ip, 'port': PORT}, ensure_ascii=False)
    try:
        bc_sock.sendto(msg.encode('utf-8'), ('<broadcast>', 9999))          # 子网广播
        bc_sock.sendto(msg.encode('utf-8'), ('127.0.0.1', 9999))           # 本机备份
    except OSError:
        pass                                                                 # 失败静默
    bc_sock.close()
    return ip, hostname


# ---------------------------------------------------------------------------
# 文件列表
# ---------------------------------------------------------------------------

def list_files(username: str) -> list:
    """
    列出用户可访问的所有文件（按可访问的级别扫描对应目录）。

    【Q18. range(1, user_level + 1) 为什么是 user_level + 1？】
    A18. Python range 左闭右开：range(1, 4) = [1, 2, 3]。
         Lv3 用户能访问 Lv1/Lv2/Lv3 三个目录，所以 range(1, 4)。
         这里巧用了"级别数字 = 目录级别"的设计——Lv3 数字大对应高级目录。
    """
    result = []
    user_level = get_user_level(username)
    for lvl in range(1, user_level + 1):                  # 从 1 扫到 user_level
        d = get_level_dir(LEVEL_NAMES[lvl])                # 中文名 → 绝对路径
        if os.path.isdir(d):
            for fn in sorted(os.listdir(d)):               # sorted 字母序，便于展示
                fp = os.path.join(d, fn)
                if os.path.isfile(fp):                     # 跳过子目录
                    result.append({'name': fn, 'level': LEVEL_NAMES[lvl],
                                   'size': os.path.getsize(fp)})
    return result


def list_all_files() -> list:
    """
    管理员用：列出所有文件（不分权限，扫描所有四级目录）。
    """
    result = []
    for lvl in range(1, 5):                                # 1, 2, 3, 4
        d = get_level_dir(LEVEL_NAMES[lvl])
        if os.path.isdir(d):
            for fn in sorted(os.listdir(d)):
                fp = os.path.join(d, fn)
                if os.path.isfile(fp):
                    result.append({'name': fn, 'level': LEVEL_NAMES[lvl],
                                   'size': os.path.getsize(fp)})
    return result


# ---------------------------------------------------------------------------
# 命令处理器
# ---------------------------------------------------------------------------

def handle_register(data: dict, sock) -> dict:
    """
    处理注册请求。

    【Q19. status='pending' 是什么意思？】
    A19. 注册后账号处于"待审核"状态，handle_login 检测到 pending 会返回 403 拒绝登录。
         这是"注册申请审核"流程，没有这一步就会变成"自由注册"——安全漏洞。
    """
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    cipher_pw = data.get('cipher_pw', '')

    if not username or not password or not email:                  # 三项必填
        send_json(sock, {'code': 400, 'msg': '用户名、密码、邮箱均不能为空'})
        sock.close()
        return None

    if user_store.user_exists(username):                            # 用户名冲突
        send_json(sock, {'code': 409, 'msg': '用户名已存在'})
        sock.close()
        return None

    user_store.add_user(username, {
        'username': username,
        'password': encrypt.hash_password(password),               # SHA-256 哈希存储
        'email': email,
        'level': 1,                                                # 默认 Lv1 公开
        'status': 'pending',                                       # 待审核
        'apply_time': time.strftime('%Y-%m-%d %H:%M:%S'),          # 申请时间
        # cipher_pw 是 DES-CBC 加密的明文密码，用于断点续传等需要还原明文的场景
        'cipher_pw': cipher_pw or encrypt.encrypt_text(password),
    })
    return {'code': 200, 'msg': '注册成功，请等待管理员审核'}


def handle_login(data: dict) -> dict:
    """
    处理登录请求。

    【Q20. 为什么登录成功还要 udp_broadcast()？】
    A20. 用户登录成功说明服务端在运行，趁机向局域网广播一条让客户端发现本服务端的包。
         这样如果有人刚启动服务端，没人知道它的 IP，登录动作会"顺手"广播它的存在。

    【Q21. 登录失败的 4 种 code 怎么用？】
    A21. 401 (Unauthorized) = 用户名或密码错误
         403 (Forbidden)    = 账号状态异常（待审/拒绝/删除）
         404 (Not Found)    = 用户不存在（隐含）
         200 (OK)           = 登录成功
         标准 HTTP 风格，客户端可以直接根据 code 区分原因。
    """
    username = data.get('username', '').strip()
    password = data.get('password', '')
    user = user_store.get_user(username)

    if not user:
        return {'code': 401, 'msg': '用户不存在'}
    if user['status'] == 'pending':
        return {'code': 403, 'msg': '账号待审核，请等待管理员批准'}
    if user['status'] == 'rejected':
        return {'code': 403, 'msg': '账号审核未通过'}
    if user['status'] == 'deleted':
        return {'code': 403, 'msg': '账号已被删除'}
    if user['password'] != encrypt.hash_password(password):       # 哈希比对（不存明文）
        return {'code': 401, 'msg': '密码错误'}

    # 登录成功，广播服务器信息
    udp_broadcast()

    return {'code': 200, 'msg': '登录成功', 'level': user.get('level', 1),
            'username': username, 'email': user.get('email', '')}


def handle_admin_verify(data: dict) -> dict:
    """
    处理管理员二次验证。

    【Q22. 二次验证为什么放在独立 handle？】
    A22. 因为它的发起时机不固定：登录成功后立即发起、也可能在敏感操作前再次发起。
         独立成一个命令让客户端主动控制调用时机。
         这里返回 200 表示"验证通过"，配合客户端的 is_admin 标志位决定权限。
    """
    pwd = data.get('password', '')
    admin_verify_pw = user_store.get_admin_verify_password()
    if not admin_verify_pw:
        return {'code': 403, 'msg': '管理员未设置验证密码'}
    if encrypt.hash_password(pwd) == admin_verify_pw:
        return {'code': 200, 'msg': '验证通过'}
    return {'code': 403, 'msg': '验证密码错误'}


def handle_list(data: dict) -> dict:
    """处理文件列表请求：返回用户名可访问的所有文件。"""
    username = data.get('username', '')
    files = list_files(username)
    return {'code': 200, 'files': files}


def handle_list_dirs(data: dict) -> dict:
    """处理可访问目录列表请求：给客户端展示"你能下哪些目录"。"""
    username = data.get('username', '')
    user_level = get_user_level(username)
    dirs = [LEVEL_NAMES[l] for l in range(1, user_level + 1)]
    return {'code': 200, 'dirs': dirs}


def handle_upload(data: dict) -> dict:
    """
    处理上传请求：创建数据通道会话并返回 token。

    【Q23. 为什么不在指令通道就传输文件？】
    A23. 大文件传输可能要几分钟，期间阻塞指令通道会让其他用户注册/登录卡住。
         把控制和数据分离是 FTP 协议的经典架构。

    【Q24. iv_bytes 有什么用？】
    A24. 客户端发来的初始 IV，CBC 模式第一个块用它；之后每块用前一密文块作为 IV。
         由客户端生成保证两端用同一个 IV。
    """
    username = data.get('username', '')
    filename = data.get('filename', '')
    level_name = data.get('level', '公开')
    total = data.get('total', 0)
    iv_hex = data.get('iv', '')

    if not can_access(username, level_name):                      # 权限检查
        return {'code': 403, 'msg': '权限不足，无法上传到该目录'}

    iv_bytes = bytes.fromhex(iv_hex) if isinstance(iv_hex, str) else iv_hex
    save_path = os.path.join(BASE_DIR, level_name, filename + '.enc')

    token = create_data_session({
        'action': 'upload',
        'username': username,
        'save_path': save_path,
        'total': total,
        'iv_bytes': iv_bytes,
    })
    return {'code': 200, 'data_token': token, 'data_port': DATA_PORT,
            'total': total, 'iv': iv_hex}


def handle_download(data: dict) -> dict:
    """
    处理下载请求：创建数据通道会话并返回 token。

    【Q25. 为什么要先解密到 .tmp 再传送？】
    A25. .enc 是自定义多块格式（[chunk_len][IV][密文]），不能直接发送给客户端。
         先用 encrypt.decrypt_file() 解密到 .tmp（明文临时文件），
         然后 data_channel_thread 再对这个明文重新按块加密发送。
         客户端拿到的是新的密文块流（因为重新加密 IV 不同）。
         重点：磁盘上持久化是密文（.enc），传输中也是密文，只有客户端收到后才能解密。
    """
    username = data.get('username', '')
    filename = data.get('filename', '')
    level_name = data.get('level', '公开')

    if not can_access(username, level_name):
        return {'code': 403, 'msg': '权限不足，无法下载该文件'}

    enc_path = os.path.join(BASE_DIR, level_name, filename)         # 服务端存的是 .enc
    if not os.path.isfile(enc_path):
        return {'code': 404, 'msg': '文件不存在'}

    # 解密 .enc 到临时文件 .tmp，然后用新 IV 重新分块加密传输
    tmp_path = enc_path + '.tmp'
    try:
        encrypt.decrypt_file(enc_path, tmp_path)
    except Exception as e:
        return {'code': 500, 'msg': f'文件解密失败: {e}'}

    total = os.path.getsize(tmp_path)
    iv_bytes = encrypt._derive_iv()

    token = create_data_session({
        'action': 'download',
        'username': username,
        'read_path': tmp_path,                                       # 临时明文，传输后立即删除
        'total': total,
        'iv_bytes': iv_bytes,
    })
    return {'code': 200, 'data_token': token, 'data_port': DATA_PORT,
            'total': total, 'iv': iv_bytes.hex()}


def handle_download_resume(data: dict) -> dict:
    """
    处理断点续传下载请求（同上，但带 offset 偏移）。
    """
    username = data.get('username', '')
    filename = data.get('filename', '')
    level_name = data.get('level', '公开')
    offset = data.get('offset', 0)

    if not can_access(username, level_name):
        return {'code': 403, 'msg': '权限不足'}

    enc_path = os.path.join(BASE_DIR, level_name, filename)
    if not os.path.isfile(enc_path):
        return {'code': 404, 'msg': '文件不存在'}

    tmp_path = enc_path + '.tmp'
    try:
        encrypt.decrypt_file(enc_path, tmp_path)
    except Exception as e:
        return {'code': 500, 'msg': f'文件解密失败: {e}'}

    total = os.path.getsize(tmp_path)
    iv_bytes = encrypt._derive_iv()

    token = create_data_session({
        'action': 'download',
        'username': username,
        'read_path': tmp_path,
        'total': total,
        'iv_bytes': iv_bytes,
        'offset': offset,                                            # 从这里继续读
    })
    return {'code': 200, 'data_token': token, 'data_port': DATA_PORT,
            'total': total, 'iv': iv_bytes.hex(), 'offset': offset}


def handle_delete(data: dict) -> dict:
    """
    处理删除文件请求。
    """
    username = data.get('username', '')
    filename = data.get('filename', '')
    level_name = data.get('level', '公开')

    if not can_access(username, level_name):
        return {'code': 403, 'msg': '权限不足'}

    enc_path = os.path.join(BASE_DIR, level_name, filename)
    if not os.path.isfile(enc_path):
        return {'code': 404, 'msg': '文件不存在'}

    try:
        os.remove(enc_path)
        # 清理临时文件（可能因上次下载遗留）
        tmp_path = enc_path + '.tmp'
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return {'code': 200, 'msg': f'文件 {filename} 已删除'}
    except OSError as e:
        return {'code': 500, 'msg': f'删除失败: {e}'}


def handle_chpw(data: dict) -> dict:
    """
    处理修改密码请求。

    【Q26. 为什么要求传 old_password？】
    A26. 防 CSRF：如果只传 new_password，恶意代码拿到你的会话就能改密码。
         二次校验（输入当前密码）确保是本人操作。
    """
    username = data.get('username', '')
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    new_cipher_pw = data.get('new_cipher_pw', '')

    user = user_store.get_user(username)
    if not user:
        return {'code': 404, 'msg': '用户不存在'}
    if user['password'] != encrypt.hash_password(old_password):
        return {'code': 401, 'msg': '旧密码错误'}

    updates = {'password': encrypt.hash_password(new_password)}
    if new_cipher_pw:                       # 客户端传了就同步更新密文密码
        updates['cipher_pw'] = new_cipher_pw
    user_store.update_user(username, updates)
    return {'code': 200, 'msg': '密码修改成功'}


def handle_request_level_up(data: dict) -> dict:
    """
    处理权限提升申请。

    【Q27. 为什么不直接改 level，而是写到 level_up_request 子对象？】
    A27. 权限提升需要管理员审批，不能由用户自增。
         把"申请中"状态独立成一个子对象（status=pending），
         管理员批了再覆盖 level 字段、申请 status 改成 approved。
    """
    username = data.get('username', '')
    target_level = data.get('target_level', 2)
    reason = data.get('reason', '')

    user = user_store.get_user(username)
    if not user:
        return {'code': 404, 'msg': '用户不存在'}

    # 保存申请到用户记录中
    user_store.update_user(username, {
        'level_up_request': {
            'target_level': target_level,
            'reason': reason,
            'request_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'pending'                              # 等待管理员处理
        }
    })
    return {'code': 200, 'msg': f'权限提升申请已提交，目标等级: {target_level}'}


# ---- 管理员命令 ----

def handle_admin_list_users(data: dict) -> dict:
    """管理员：列出所有用户（不含 password 字段，安全考虑）。"""
    users = user_store.load_users()
    user_list = []
    for u, info in users.items():
        user_list.append({
            'username': u,
            'email': info.get('email', ''),
            'level': info.get('level', 1),
            'status': info.get('status', ''),
            'apply_time': info.get('apply_time', ''),
        })
    return {'code': 200, 'users': user_list}


def handle_admin_approve(data: dict) -> dict:
    """
    管理员：审核注册申请。
    action='approve' 设 approved + level；action='reject' 设 rejected。
    """
    username = data.get('target_user', '')
    action = data.get('action', '')                       # 'approve' or 'reject'
    new_level = data.get('level', 1)

    user = user_store.get_user(username)
    if not user:
        return {'code': 404, 'msg': '用户不存在'}

    if action == 'approve':
        user_store.update_user(username, {'status': 'approved', 'level': new_level})
        return {'code': 200, 'msg': f'已批准用户 {username}，权限等级: {new_level}'}
    elif action == 'reject':
        user_store.update_user(username, {'status': 'rejected'})
        return {'code': 200, 'msg': f'已拒绝用户 {username}'}
    return {'code': 400, 'msg': '未知操作'}


def handle_admin_set_level(data: dict) -> dict:
    """管理员：直接修改用户权限等级（绕过审批流程）。"""
    username = data.get('target_user', '')
    new_level = data.get('level', 1)

    user = user_store.get_user(username)
    if not user:
        return {'code': 404, 'msg': '用户不存在'}

    user_store.update_user(username, {'level': new_level})
    return {'code': 200, 'msg': f'用户 {username} 权限已修改为 {new_level}'}


def handle_admin_del_user(data: dict) -> dict:
    """
    管理员：删除用户（标记为 deleted，软删除）。

    【Q28. 为什么不真删而是用 soft delete？】
    A28. 软删除（status='deleted'）保留审计线索——谁曾经存在过、什么时候删的。
         如果将来需要恢复，直接把 status 改回 'approved' 即可。
         实战中 GDPR 要求"被遗忘权"，那就只能硬删；这里为了教学演示软删。
    """
    username = data.get('target_user', '')

    user = user_store.get_user(username)
    if not user:
        return {'code': 404, 'msg': '用户不存在'}

    user_store.update_user(username, {'status': 'deleted'})
    return {'code': 200, 'msg': f'用户 {username} 已删除'}


def handle_admin_list_all_files(data: dict) -> dict:
    """管理员：列出所有文件（无视权限）。"""
    files = list_all_files()
    return {'code': 200, 'files': files}


def handle_admin_del_file(data: dict) -> dict:
    """管理员：删除指定文件（磁盘删除，不是软删除）。"""
    filename = data.get('filename', '')
    level_name = data.get('level', '公开')

    enc_path = os.path.join(BASE_DIR, level_name, filename)
    if not os.path.isfile(enc_path):
        return {'code': 404, 'msg': '文件不存在'}

    try:
        os.remove(enc_path)
        tmp_path = enc_path + '.tmp'
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return {'code': 200, 'msg': f'文件 {filename} 已删除'}
    except OSError as e:
        return {'code': 500, 'msg': f'删除失败: {e}'}


def handle_admin_move_file(data: dict) -> dict:
    """管理员：移动文件到新的目录（os.rename 跨目录移动）。"""
    filename = data.get('filename', '')
    level_name = data.get('level', '公开')
    new_level_name = data.get('new_level', '公开')

    src = os.path.join(BASE_DIR, level_name, filename)
    dst = os.path.join(BASE_DIR, new_level_name, filename)

    if not os.path.isfile(src):
        return {'code': 404, 'msg': '源文件不存在'}

    try:
        os.rename(src, dst)
        return {'code': 200, 'msg': f'文件已移动到 {new_level_name}'}
    except OSError as e:
        return {'code': 500, 'msg': f'移动失败: {e}'}


def handle_admin_set_file_level(data: dict) -> dict:
    """
    管理员：设置文件权限级别（原地修改所属目录）。
    本质和 move 一样，但语义不同——这个表示"修改文件密级"，move 表示"移动位置"。
    """
    filename = data.get('filename', '')
    level_name = data.get('level', '公开')
    new_level_name = data.get('new_level', '公开')

    src = os.path.join(BASE_DIR, level_name, filename)
    dst = os.path.join(BASE_DIR, new_level_name, filename)

    if not os.path.isfile(src):
        return {'code': 404, 'msg': '文件不存在'}

    if level_name == new_level_name:                          # 同目录是合法 no-op
        return {'code': 200, 'msg': '文件已在目标目录中'}

    try:
        os.rename(src, dst)
        return {'code': 200, 'msg': f'文件权限已修改为 {new_level_name}'}
    except OSError as e:
        return {'code': 500, 'msg': f'修改失败: {e}'}


def handle_admin_list_level_requests(data: dict) -> dict:
    """
    管理员：列出所有权限提升申请（待处理）。
    扫描每个用户的 level_up_request 子对象，过滤 status=pending 的。
    """
    users = user_store.load_users()
    requests = []
    for u, info in users.items():
        req = info.get('level_up_request')
        if req and req.get('status') == 'pending':
            requests.append({
                'username': u,
                'target_level': req.get('target_level', 2),
                'reason': req.get('reason', ''),
                'request_time': req.get('request_time', ''),
                'current_level': info.get('level', 1),
            })
    return {'code': 200, 'requests': requests}


def handle_admin_process_level_request(data: dict) -> dict:
    """
    管理员：处理权限提升申请。
    action='approve' 按申请目标级别通过；
    action='reject'  拒绝但不改正 level；
    action='modify'  修改级别到指定值（不同于申请目标）。

    【Q29. 为什么要分 approve 和 modify？】
    A29. approve 让管理员"完全同意用户申请"；
         modify 让管理员可以"调到中间级别"（比如申请 Lv4 但只给 Lv3），
         既给了部分权限又保留管理员的最终裁量权。
    """
    username = data.get('target_user', '')
    action = data.get('action', '')
    new_level = data.get('level', None)

    user = user_store.get_user(username)
    if not user:
        return {'code': 404, 'msg': '用户不存在'}

    req = user.get('level_up_request')
    if not req or req.get('status') != 'pending':
        return {'code': 400, 'msg': '没有待处理的申请'}

    if action == 'approve':
        final_level = new_level if new_level is not None else req.get('target_level', 2)
        user_store.update_user(username, {
            'level': final_level,
            'level_up_request': {**req, 'status': 'approved'}    # {**req, ...} 解包并覆盖
        })
        return {'code': 200, 'msg': f'已批准 {username} 的权限提升，新等级: {final_level}'}
    elif action == 'reject':
        user_store.update_user(username, {
            'level_up_request': {**req, 'status': 'rejected'}
        })
        return {'code': 200, 'msg': f'已拒绝 {username} 的权限提升申请'}
    elif action == 'modify':
        if new_level is None:
            return {'code': 400, 'msg': '请指定修改后的权限等级'}
        user_store.update_user(username, {
            'level': new_level,
            'level_up_request': {**req, 'status': 'approved'}
        })
        return {'code': 200, 'msg': f'已修改并批准 {username} 的权限为 {new_level}'}
    return {'code': 400, 'msg': '未知操作'}


def handle_enc_info(data: dict) -> dict:
    """
    返回加密信息（教学展示用）。
    Web 端的"加密算法"tab 和客户端 CLI 的加密信息命令都调这个。
    """
    return {
        'code': 200,
        'algorithm': 'DES-CBC',
        'key_length': 64,                                            # bits（含 8 位奇偶校验）
        'iv_derivation': 'md5(KEY) XOR IV_BASE',
        'padding': 'PKCS#7',
        'chunk_size': CHUNK_SIZE,
        'hash_algorithm': 'SHA-256',
    }


# ---------------------------------------------------------------------------
# 指令通道客户端线程
# ---------------------------------------------------------------------------

def client_thread(sock, addr):
    """
    处理单个客户端的连接（指令通道）。
    每来一个连接拉一个线程，避免阻塞其他客户端。

    【Q30. 为什么不直接 while 串行处理而要用多线程？】
    A30. 串行的话，客户端 A 正在上传 1GB 文件，客户端 B 永远进不来。
         多线程让每个客户端的请求处理互不干扰。

    【Q31. daemon=True 是什么意思？】
    A31. daemon 线程在主程序退出时自动终止。
         服务端进程退出时所有 daemon 客户端线程会被强制回收，不会"僵尸"。
    """
    print(f'[+] 新连接 from {addr}')
    try:
        while True:                                                  # 长连接循环
            data = recv_json(sock)
            if data is None:
                break                                                  # 客户端断开

            cmd = data.get('cmd', '')                                # 命令字
            username = data.get('username', '')

            # 大型 if-elif 命令分发（教科书式 router）
            if cmd == 'register':
                resp = handle_register(data, sock)
            elif cmd == 'login':
                resp = handle_login(data)
            elif cmd == 'admin_verify':
                resp = handle_admin_verify(data)
            elif cmd == 'list':
                resp = handle_list(data)
            elif cmd == 'list_dirs':
                resp = handle_list_dirs(data)
            elif cmd == 'upload':
                resp = handle_upload(data)
            elif cmd == 'download':
                resp = handle_download(data)
            elif cmd == 'download_resume':
                resp = handle_download_resume(data)
            elif cmd == 'delete':
                resp = handle_delete(data)
            elif cmd == 'chpw':
                resp = handle_chpw(data)
            elif cmd == 'request_level_up':
                resp = handle_request_level_up(data)
            elif cmd == 'admin_list_users':
                resp = handle_admin_list_users(data)
            elif cmd == 'admin_approve':
                resp = handle_admin_approve(data)
            elif cmd == 'admin_set_level':
                resp = handle_admin_set_level(data)
            elif cmd == 'admin_del_user':
                resp = handle_admin_del_user(data)
            elif cmd == 'admin_list_all_files':
                resp = handle_admin_list_all_files(data)
            elif cmd == 'admin_del_file':
                resp = handle_admin_del_file(data)
            elif cmd == 'admin_move_file':
                resp = handle_admin_move_file(data)
            elif cmd == 'admin_set_file_level':
                resp = handle_admin_set_file_level(data)
            elif cmd == 'admin_list_level_requests':
                resp = handle_admin_list_level_requests(data)
            elif cmd == 'admin_process_level_request':
                resp = handle_admin_process_level_request(data)
            elif cmd == 'enc_info':
                resp = handle_enc_info(data)
            else:
                resp = {'code': 400, 'msg': f'未知命令: {cmd}'}

            if resp:
                send_json(sock, resp)

            # register 失败特殊处理：用户名已存在等服务端主动断开连接
            if cmd in ('register',) and resp and resp.get('code') != 200:
                break

    except (ConnectionResetError, BrokenPipeError):
        pass                                                          # 客户端异常断开静默
    finally:
        print(f'[-] 连接断开 {addr}')
        try:
            sock.close()                                              # 释放 fd
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 数据通道
# ---------------------------------------------------------------------------

def data_channel_server():
    """
    数据通道服务器（独立线程，常驻监听 8000 端口）。
    每来一个客户端连接拉一个线程。

    【Q32. 为什么 SO_REUSEADDR？】
    A32. 避免 TIME_WAIT 状态下重启服务时报 "Address already in use"。
         允许操作系统把处于 TIME_WAIT 的端口立即分配给新进程。
    """
    ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ds.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)         # 允许端口复用
    ds.bind((HOST, DATA_PORT))
    ds.listen(50)                                                     # backlog 队列长度
    print(f'[*] 数据通道监听 {DATA_PORT}')

    while True:
        try:
            cs, ca = ds.accept()
            threading.Thread(target=data_channel_thread, args=(cs, ca),
                             daemon=True).start()                       # 每连接一线程
        except OSError:
            break                                                      # 服务关闭


def data_channel_thread(sock, addr):
    """
    处理数据通道连接。

    【Q33. 为什么数据通道也要 pop_data_session？】
    A33. 数据通道是"先发 token 才能传数据"的模式：
         ① 指令通道：拿 token
         ② 数据通道：拿 token 来"开箱"
         一次性 token 设计：每次上传/下载都是独立的 token，用完即焚。
         这样即使有恶意客户端猜到了别人的 token，最多能下载完那一段就无法继续——几乎没用。
    """
    print(f'[DATA CH] connection from {addr}')
    try:
        # 接收元数据帧：客户端连接后第一时间发 token
        meta = recv_json(sock)
        if not meta:
            send_json(sock, {'code': 400, 'msg': '元数据格式错误'})
            return

        token = meta.get('token', '')
        session = pop_data_session(token)                             # 一次性消费 token
        if not session:
            send_json(sock, {'code': 404, 'msg': '数据会话不存在或已过期'})
            return

        action = meta.get('action', session.get('action', ''))

        if action == 'upload':
            # 接收加密文件流并写入 .enc（使用标准 encrypt_file 格式）
            save_path = session.get('save_path')
            total = session.get('total', 0)
            iv_bytes = session.get('iv_bytes')

            with open(save_path, 'wb') as f:
                # 写入文件头: total
                f.write(total.to_bytes(8, 'big'))

                prev_iv = iv_bytes
                received = 0
                buffer = b''

                # 自定义协议：[4B chunk_len][8B IV][密文] 循环
                while received < total:
                    remaining = total - received
                    current_plain = min(CHUNK_SIZE, remaining)
                    # PKCS#7 填充
                    pad = 8 - (current_plain % 8)
                    if pad == 0:
                        pad = 8
                    current_cipher = current_plain + pad

                    # TCP 是流式协议，需要循环接收直到凑够 current_cipher 字节
                    while len(buffer) < current_cipher:
                        data = sock.recv(current_cipher - len(buffer) + 64)
                        if not data:
                            break
                        buffer += data

                    if len(buffer) < current_cipher:
                        break

                    ct_block = buffer[:current_cipher]
                    buffer = buffer[current_cipher:]

                    # 写入标准格式: [4B chunk_len][8B IV][密文]
                    f.write(len(ct_block).to_bytes(4, 'big'))
                    f.write(prev_iv)
                    f.write(ct_block)

                    prev_iv = ct_block[-8:]                           # CBC 链式 IV 更新
                    received += current_plain

            send_json(sock, {'code': 200, 'msg': '数据通道上传完成',
                             'received': received})

        elif action == 'download':
            # 发送加密文件流
            read_path = session.get('read_path')
            total = session.get('total', 0)
            iv_bytes = session.get('iv_bytes')
            offset = session.get('offset', 0)

            # 发送 IV 和总大小（让客户端知道本会话的 IV 用于接收）
            sock.sendall(iv_bytes)
            sock.sendall(total.to_bytes(8, 'big'))

            with open(read_path, 'rb') as f:
                if offset:
                    f.seek(offset)                                    # 跳到断点
                prev_iv = iv_bytes
                sent = 0
                target = total - offset                               # 断点续传：少发 offset

                while sent < target:
                    chunk = f.read(min(CHUNK_SIZE, target - sent))
                    if not chunk:
                        break
                    padded = encrypt.pad_pkcs7(chunk)
                    c = encrypt.DES.new(encrypt.KEY, encrypt.DES.MODE_CBC, prev_iv)
                    ct = c.encrypt(padded)
                    sock.sendall(ct)
                    prev_iv = ct[-8:]                                  # CBC 链更新
                    sent += len(chunk)

            # 清理临时文件（重要：tmp 含明文，泄露危险）
            try:
                if os.path.exists(read_path):
                    os.remove(read_path)
            except OSError:
                pass

            send_json(sock, {'code': 200, 'msg': '数据通道下载完成'})

    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        # 【Q34. 为什么这里只捕获不抛？】
        # A34. 数据通道独立线程，异常若不捕获会向上抛到 Thread.run，造成线程静默死亡。
        #     用 try/except 包住后，至少 print 出来让运维感知。
        print(f'[DATA CH] 错误: {e}')
        try:
            send_json(sock, {'code': 500, 'msg': f'数据通道错误: {e}'})
        except OSError:
            pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 管理员控制台菜单（CLI 模式，Web 启动时不走这里）
# ---------------------------------------------------------------------------

def print_menu():
    print('\n===== FTP 安全传输系统 服务端 =====')
    print('1. 启动服务')
    print('2. 查看所有用户')
    print('3. 审核注册申请')
    print('4. 修改用户权限')
    print('5. 启用/设置管理员')
    print('6. 审批权限提升申请')
    print('7. 发送 UDP 广播')
    print('0. 退出')
    print('===================================')


def menu_approve_users():
    """审核注册申请。"""
    users = user_store.load_users()
    pending = {u: info for u, info in users.items()
               if info.get('status') == 'pending'}

    if not pending:
        print('  没有待审核的注册申请')
        return

    print(f'\n--- 待审核用户 ({len(pending)}) ---')
    for u, info in pending.items():
        print(f'  用户名: {u}, 邮箱: {info.get("email", "")}, '
              f'申请时间: {info.get("apply_time", "")}')

    username = input('输入要审核的用户名(留空返回): ').strip()
    if not username:
        return
    if username not in pending:
        print('  用户不在待审核列表中')
        return

    print('  1. 批准')
    print('  2. 拒绝')
    choice = input('选择: ').strip()

    if choice == '1':
        level = input('设置权限等级(1-公开,2-一般,3-高级,4-特殊,默认1): ').strip() or '1'
        level_map = {'1': 1, '2': 2, '3': 3, '4': 4}
        new_level = level_map.get(level, 1)
        user_store.update_user(username, {'status': 'approved', 'level': new_level})
        print(f'  已批准用户 {username}，权限等级: {LEVEL_NAMES[new_level]}')
    elif choice == '2':
        user_store.update_user(username, {'status': 'rejected'})
        print(f'  已拒绝用户 {username}')


def menu_set_level():
    """修改用户权限。"""
    username = input('输入用户名: ').strip()
    if not user_store.user_exists(username):
        print('  用户不存在')
        return
    print('  1. 公开  2. 一般  3. 高级  4. 特殊')
    level = input('新权限等级: ').strip()
    level_map = {'1': 1, '2': 2, '3': 3, '4': 4}
    new_level = level_map.get(level, 1)
    user_store.update_user(username, {'level': new_level})
    print(f'  权限已修改为 {LEVEL_NAMES[new_level]}')


def menu_setup_admin():
    """设置/重置管理员密码。"""
    import getpass
    print('\n--- 设置管理员 ---')
    password = getpass.getpass('输入管理员登录密码: ').strip()
    if len(password) < 6:
        print('  密码长度不得低于6位')
        return
    confirm = getpass.getpass('确认密码: ').strip()
    if password != confirm:
        print('  两次密码不一致')
        return

    verify_pw = getpass.getpass('输入管理员验证密码(二次验证用): ').strip()
    if len(verify_pw) < 6:
        print('  验证密码长度不得低于6位')
        return
    verify_confirm = getpass.getpass('确认验证密码: ').strip()
    if verify_pw != verify_confirm:
        print('  两次验证密码不一致')
        return

    user_store.set_admin_password(encrypt.hash_password(password))
    user_store.set_admin_verify_password(encrypt.hash_password(verify_pw))
    print('  管理员密码设置成功')


def menu_list_users():
    """查看所有用户。"""
    users = user_store.load_users()
    if not users:
        print('  暂无用户')
        return
    print(f'\n--- 用户列表 ({len(users)}) ---')
    print(f'{"用户名":<15} {"邮箱":<20} {"权限":<6} {"状态":<10} {"申请时间":<20}')
    print('-' * 75)
    for u, info in users.items():
        level_name = LEVEL_NAMES.get(info.get('level', 1), '未知')
        print(f"{u:<15} {info.get('email', ''):<20} {level_name:<6} "
              f"{info.get('status', ''):<10} {info.get('apply_time', ''):<20}")


def menu_level_requests():
    """审批权限提升申请。"""
    users = user_store.load_users()
    pending = {}
    for u, info in users.items():
        req = info.get('level_up_request')
        if req and req.get('status') == 'pending':
            pending[u] = info

    if not pending:
        print('  没有待处理的权限提升申请')
        return

    print(f'\n--- 权限提升申请 ({len(pending)}) ---')
    for u, info in pending.items():
        req = info['level_up_request']
        print(f'  用户: {u}, 当前等级: {LEVEL_NAMES.get(info.get("level", 1), "?")}, '
              f'目标等级: {LEVEL_NAMES.get(req.get("target_level", 2), "?")}, '
              f'理由: {req.get("reason", "")}')

    username = input('输入要处理的用户名(留空返回): ').strip()
    if not username or username not in pending:
        return

    print('  1. 批准')
    print('  2. 拒绝')
    print('  3. 修改权限后批准')
    choice = input('选择: ').strip()

    if choice == '1':
        req = pending[username]['level_up_request']
        user_store.update_user(username, {
            'level': req.get('target_level', 2),
            'level_up_request': {**req, 'status': 'approved'}
        })
        print(f'  已批准 {username}')
    elif choice == '2':
        req = pending[username]['level_up_request']
        user_store.update_user(username, {
            'level_up_request': {**req, 'status': 'rejected'}
        })
        print(f'  已拒绝 {username}')
    elif choice == '3':
        level = input('新权限等级(1-4): ').strip()
        level_map = {'1': 1, '2': 2, '3': 3, '4': 4}
        new_level = level_map.get(level, 2)
        req = pending[username]['level_up_request']
        user_store.update_user(username, {
            'level': new_level,
            'level_up_request': {**req, 'status': 'approved'}
        })
        print(f'  已修改并批准 {username} 的权限为 {LEVEL_NAMES[new_level]}')


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def main():
    ensure_dirs()
    print('=' * 40)
    print('  FTP 安全传输系统 服务端')
    print('=' * 40)

    while True:
        print_menu()
        choice = input('选择: ').strip()

        if choice == '1':
            # 启动服务
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((HOST, PORT))
            sock.listen(50)
            print(f'[*] 指令通道监听 {PORT}')

            # 启动数据通道
            threading.Thread(target=data_channel_server, daemon=True).start()

            print('[*] 服务已启动，等待客户端连接...')
            print('    (按 Ctrl+C 停止服务)')
            try:
                while True:
                    cs, ca = sock.accept()
                    threading.Thread(target=client_thread, args=(cs, ca),
                                     daemon=True).start()
            except KeyboardInterrupt:                             # Ctrl+C 优雅退出
                print('\n[*] 服务停止')
                sock.close()

        elif choice == '2':
            menu_list_users()

        elif choice == '3':
            menu_approve_users()

        elif choice == '4':
            menu_set_level()

        elif choice == '5':
            menu_setup_admin()

        elif choice == '6':
            menu_level_requests()

        elif choice == '7':
            ip, hostname = udp_broadcast()
            print(f'  UDP 广播已发送: IP={ip}, 主机名={hostname}')

        elif choice == '0':
            print('再见!')
            break


if __name__ == '__main__':
    main()
