"""
client.py - FTP 客户端主程序
=============================

【老师可能问的 Q&A 清单】
 Q1. 客户端为什么也有文件加解密？
 A1. 客户端加密后再上传，服务端拿到的是密文。
     在 8000 数据通道传输时，整个管道都是密文（CBC 流式加密）。
     离开服务端落盘前，已经在数据通道被加密一次；磁盘持久化在 encrypt_file 自定义格式中。
     客户端在 DATA CHANNEL 读到的流即时解密到本地文件。

 Q2. 客户端的"记住密码"为什么用 DES-CBC 而不是明文存？
 A2. 防止 login_history.json 被读时直接泄露密码。
     但用户机器上的 KDF/明文密码本身已经能登账号，所以这里是"防偷窥"而非"防入侵"。

 Q3. 断点续传的状态为什么也加密？
 A3. 一样，防文件被读出时泄露下载进度（用户/文件名）。
"""

import getpass
import json
import os
import socket
import struct
import sys
import threading
import time

import encrypt
from typing import Optional


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

HOST, PORT, DATA_PORT = '127.0.0.1', 8888, 8000       # 默认连本机
SERVER_NAME = 'FTP-Secure-Server'
CHUNK_SIZE = 1000
HISTORY_FILE = 'login_history.json'

LEVEL_NAMES = {1: '公开', 2: '一般', 3: '高级', 4: '特殊'}


# ---------------------------------------------------------------------------
# 网络工具（和服务端几乎对称，实现相同的帧协议）
# ---------------------------------------------------------------------------

def send_json(sock, data: dict):
    """
    发送 JSON 数据（8 字节大端长度前缀 + JSON 正文）。
    与服务端 send_json 协议完全对称，确保互通。
    """
    raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
    sock.sendall(len(raw).to_bytes(8, 'big') + raw)


def recv_all(sock, size: int) -> bytes:
    """
    精确接收指定字节数的数据（应对 TCP 粘包）。

    【Q1. 为什么 recv(size) 不能保证一次收够 size？】
    A1. TCP 是字节流协议，send 1MB 可能被拆成多段，recv 一次可能只拿到部分。
         网络栈完全可能分成好几次 deliver。
    """
    buf = b''
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def recv_json(sock) -> Optional[dict]:
    """接收 JSON 数据：先读 8 字节长度，再读 JSON 体。"""
    raw_len = recv_all(sock, 8)
    if len(raw_len) < 8:
        return None
    length = int.from_bytes(raw_len, 'big')
    if length == 0:
        return None
    data = recv_all(sock, length)
    if len(data) < length:
        return None
    try:
        return json.loads(data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# UDP 广播监听（客户端启动后，服务端的广播会被收到）
# ---------------------------------------------------------------------------

def _udp_listen(stop_event, callback):
    """
    UDP 监听线程函数。

    【Q2. 为什么客户端监听 9999？】
    A2. 服务端在登录成功后会向 9999 端口发广播。
       客户端启动监听这个端口，收到就回调显示 "FTP-Secure-Server found"。

    【Q3. us.settimeout(1.0) 是做什么？】
    A3. recvfrom() 默认是阻塞的，没广播时永远不会回来。
       设置 1 秒超时，配合 stop_event 让线程能响应退出信号。
       每秒检查 stop_event.is_set()，是则退出循环。
    """
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        us.bind(('', 9999))                                  # 监听所有网卡 9999
    except OSError:                                          # 端口被占（多客户端）
        try:
            us.bind(('127.0.0.1', 9999))                      # 退而求其次
        except OSError:
            return
    us.settimeout(1.0)
    while not stop_event.is_set():                           # 优雅退出条件
        try:
            data, addr = us.recvfrom(4096)
            msg = json.loads(data.decode('utf-8'))
            if msg.get('type') == 'ftp_server':              # 只关心 ftp_server 类型
                callback(msg)
        except (socket.timeout, json.JSONDecodeError, UnicodeDecodeError):
            continue                                         # 超时或脏数据继续等
        except OSError:
            break                                            # socket 出错退出
    us.close()


def start_udp_listener():
    """启动 UDP 监听线程，返回 stop_event、线程、状态容器。"""
    stop = threading.Event()
    state = {'ip': '', 'hostname': ''}                        # 用 dict 方便回调中修改外部可见
    def cb(msg):
        state['ip'] = msg.get('host', '')
        state['hostname'] = msg.get('name', '')
        print(f'  [UDP] 收到服务器广播: IP={state["ip"]}, 名称={state["hostname"]}')
    t = threading.Thread(target=_udp_listen, args=(stop, cb), daemon=True)
    t.start()
    return stop, t, state


# ---------------------------------------------------------------------------
# 登录历史（"记住密码"功能）
# ---------------------------------------------------------------------------

def save_history(username: str, password: str, remember: bool):
    """
    保存登录历史。

    【Q4. 为什么用 DES 加密后存密码？】
    A4. login_history.json 一般人可以读到，如果存明文就能直接看到密码。
       即使是同机用户或临时文件窃取者，都只能得到 Base64 密文。
       必须知道 DES 的 KEY 才能解出（KEY 在 encrypt.py 里硬编码）。

    【Q5. 但 KEY 也是在本机，这安全吗？】
    A5. 任何"用户机器上的本地存储"都不是真安全——攻击者拿到这台机器的代码就能看到 KEY。
       真实的"记住密码"应该用操作系统的凭据管理（Windows Credential Manager、
       macOS Keychain、Linux Secret Service）。
       这里的加密只是"挡住随手查看"这一层。
    """
    data = {'username': username, 'remember': remember}
    if remember:
        data['cipher_pw'] = encrypt.encrypt_text(password)
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_history() -> dict:
    """加载登录历史。"""
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def get_saved_credentials():
    """
    获取保存的凭据。

    返回 (username, password, remember)。
    如果没勾记住或文件损坏，password 返回 ''。
    """
    hist = load_history()
    username = hist.get('username', '')
    remember = hist.get('remember', False)
    password = ''
    if remember and 'cipher_pw' in hist:
        try:
            password = encrypt.decrypt_text(hist['cipher_pw'])
        except Exception:
            password = ''
    return username, password, remember


# ---------------------------------------------------------------------------
# 注册校验
# ---------------------------------------------------------------------------

def validate_username(username: str) -> Optional[str]:
    """返回错误字符串（None = 通过）。"""
    if not username:
        return '用户名不能为空'
    if len(username) < 3:
        return '用户名长度不得低于3位'
    return None


def validate_email(email: str) -> Optional[str]:
    """极简邮箱校验：必须有 @ 字符；复杂校验可加正则。"""
    if not email:
        return '邮箱不能为空'
    if '@' not in email:
        return '邮箱账号必须包含"@"字符'
    return None


def validate_password(password: str) -> Optional[str]:
    """密码≥6 位即可。"""
    if not password:
        return '密码不能为空'
    if len(password) < 6:
        return '密码长度不得低于6位'
    return None


def password_strength(password: str):
    """
    根据长度/大小写/数字/特殊符号综合打分，返回 (等级, 提示)。

    【Q6. 这就是传说中密码熵估算吗？】
    A6. 简化版本，扫一遍字符看哪些特征命中：
       - 长度≥6 / ≥10
       - 含大小写字母
       - 含数字
       - 含特殊符号
       命中 0-1 个 = 弱，2-3 个 = 中，4-5 个 = 强。
       真实密码强度计（如 zxcvbn 库）会考虑字符位置、常见组合（qwerty/12345）、字典词。
    """
    score = 0
    if len(password) >= 6:
        score += 1
    if len(password) >= 10:
        score += 1
    if any('a' <= c <= 'z' for c in password) and any('A' <= c <= 'Z' for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        score += 1
    if score <= 1:
        return '弱', '[*] 密码强度: 弱 — 建议增加大小写字母、数字、特殊符号'
    elif score <= 3:
        return '中', '[**] 密码强度: 中 — 建议增加特殊符号或增加长度'
    else:
        return '强', '[***] 密码强度: 强'


def show_register_info():
    print('\n--- 注册说明 ---')
    print('  1. 用户名长度不得低于3位')
    print('  2. 邮箱账号必须包含"@"字符')
    print('  3. 密码长度不得低于6位')
    print('  4. 确认密码必须与输入密码一致')
    print('----------------')


# ---------------------------------------------------------------------------
# 断点续传（state 文件也是密的）
# ---------------------------------------------------------------------------

def save_resume_state(filepath: str, total: int, offset: int,
                      username: str, filename: str, mode: str):
    """
    保存断点续传状态（DES 加密 JSON）。

    【Q7. 断点文件为什么叫 .xc？】
    A7. 是"X Continue"的意思，便于和真实文件 .enc 区分。
       filename.txt.xc 是该文件的断点状态文件。
    """
    plain = json.dumps({
        'total': total,
        'offset': offset,
        'username': username,
        'filename': filename,
        'mode': mode,
    }, ensure_ascii=False)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(encrypt.encrypt_text(plain))               # 同样加密防偷窥


def load_resume_state(filepath: str) -> dict:
    """加载断点续传状态。"""
    with open(filepath, 'r', encoding='utf-8') as f:
        cipher = f.read()
    plain = encrypt.decrypt_text(cipher)
    return json.loads(plain)


def delete_resume_state(filepath: str):
    """删除断点续传状态文件。"""
    if os.path.exists(filepath):
        os.remove(filepath)


# ---------------------------------------------------------------------------
# 数据通道
# ---------------------------------------------------------------------------

def data_channel_send(token: str, action: str, payload_meta: dict) -> dict:
    """
    通过数据通道发送/接收文件。

    【Q8. 为什么这里也要负责解密？】
    A8. 上传：客户端先加密流再发，服务端解密写入磁盘。
       下载：客户端收的是密文流，要即时解密。
       整条管道都是密文——不加密只在两端密文。
    """
    ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ds.connect((HOST, DATA_PORT))                                  # 主动连服务端 8000
    send_json(ds, {'token': token, 'action': action, **payload_meta})

    if action == 'upload':
        offset = payload_meta.get('offset', 0)
        total = payload_meta['total']
        local_path = payload_meta['local_path']
        iv_hex = payload_meta['iv']
        iv_bytes = bytes.fromhex(iv_hex) if isinstance(iv_hex, str) else iv_hex

        with open(local_path, 'rb') as fin:
            if offset:
                fin.seek(offset)                                   # 跳到断点
            prev_iv = iv_bytes
            sent = offset
            target = total

            # 流式加密上传（一边读一边加密一边发）
            while sent < target:
                chunk = fin.read(min(CHUNK_SIZE, target - sent))
                if not chunk:
                    break
                pad = 8 - (len(chunk) % 8)
                pad = 8 if pad == 0 else pad                       # 8 倍数时仍补 8 字节
                c = encrypt.DES.new(encrypt.KEY, encrypt.DES.MODE_CBC, prev_iv)
                ct = c.encrypt(chunk + bytes([pad]) * pad)           # 自实现 PKCS#7 填充
                ds.sendall(ct)
                prev_iv = ct[-8:]                                   # CBC 链更新
                sent += len(chunk)

                pct = sent / total * 100 if total else 0
                print(f'\r  上传进度: {pct:.1f}%', end='', flush=True)

        print()
        ds.shutdown(socket.SHUT_WR)                                 # 半关闭：通知服务端发送完毕

    elif action == 'download':
        # 接收 IV 和总大小（与服务端发送顺序一致）
        iv_bytes = recv_all(ds, 8)
        total = int.from_bytes(recv_all(ds, 8), 'big')
        local_path = payload_meta['local_path']
        offset = payload_meta.get('offset', 0)
        resume_file = payload_meta.get('resume_file')
        username = payload_meta.get('username', '')
        filename = payload_meta.get('filename', '')

        # 【Q9. 断点续传时 mode 为什么是 'ab'？】
        # A9. 正常首次下载用 'wb'（覆盖）；断点用 'ab'（追加）。两种模式由 offset>0 区分。
        mode = 'ab' if offset else 'wb'
        received = offset

        with open(local_path, mode) as fout:
            prev_iv = iv_bytes
            while received < total:
                ct = ds.recv(CHUNK_SIZE + 16)                      # 多读 16 字节适应 PKCS#7
                if not ct:
                    break
                c = encrypt.DES.new(encrypt.KEY, encrypt.DES.MODE_CBC, prev_iv)
                padded = c.decrypt(ct)
                chunk = encrypt.unpad_pkcs7(padded)
                fout.write(chunk)
                prev_iv = ct[-8:]
                received += len(chunk)

                # 边下载边保存断点（断电/崩溃后下次能继续）
                if resume_file:
                    save_resume_state(resume_file, total, received,
                                      username, filename, 'download')

                pct = received / total * 100 if total else 0
                print(f'\r  下载进度: {pct:.1f}%', end='', flush=True)

        print()
        if resume_file and os.path.exists(resume_file):
            delete_resume_state(resume_file)                       # 完成 → 删断点文件

    return recv_json(ds) or {'code': 500, 'msg': '数据通道无响应'}


# ---------------------------------------------------------------------------
# FTPClient 类
# ---------------------------------------------------------------------------

class FTPClient:
    def __init__(self):
        self.sock = None
        self.username = ''
        self.level = 1
        self.is_admin = False                                       # Lv4 = True
        self.logged_in = False
        self.udp_stop = None                                        # UDP 停止信号
        self.udp_thread = None
        self.udp_state = None

    def connect(self) -> bool:
        """连接到服务端（指令通道 8888）。"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            return True
        except ConnectionRefusedError:
            print(f'[!] 无法连接到服务器 {HOST}:{PORT}，请确认服务端是否已启动')
            return False

    def disconnect(self):
        """断开连接。"""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self.logged_in = False
        if self.udp_stop:
            self.udp_stop.set()                                    # 关 UDP 监听线程

    def _show_connection_info(self):
        """显示连接信息（登录成功后展示）。"""
        dirs = self._fetch_accessible_dirs()                        # 拉一次 list_dirs
        level_name = LEVEL_NAMES.get(self.level, '未知')
        print('\n--- 连接信息 ---')
        print(f'  服务器名称: {SERVER_NAME}')
        print(f'  服务器地址: {HOST}:{PORT}')
        print(f'  数据端口:   {DATA_PORT}')
        print(f'  当前用户:   {self.username}')
        print(f'  用户权限:   {self.level} ({level_name})')
        print(f'  可下载目录: {", ".join(dirs) if dirs else "(无)"}')
        print('----------------')

    def _fetch_accessible_dirs(self) -> list:
        """获取可访问的目录列表。"""
        send_json(self.sock, {'cmd': 'list_dirs', 'username': self.username})
        resp = recv_json(self.sock)
        return resp.get('dirs', []) if resp and resp.get('code') == 200 else []

    # ---- 注册 ----

    def register(self):
        """注册流程。"""
        show_register_info()

        # 输入用户名（循环到合法）
        while True:
            username = input('用户名: ').strip()
            err = validate_username(username)
            if not err:
                break
            print(f'  [!] {err}')

        # 输入密码（循环到合法 + 两次一致）
        while True:
            password = getpass.getpass('密码: ').strip()
            err = validate_password(password)
            if err:
                print(f'  [!] {err}')
                continue
            strength, tip = password_strength(password)
            print(f'  {tip}')
            confirm = getpass.getpass('确认密码: ').strip()
            if password != confirm:
                print('  [!] 两次密码不一致')
                continue
            break

        # 输入邮箱（循环到合法）
        while True:
            email = input('邮箱: ').strip()
            err = validate_email(email)
            if not err:
                break
            print(f'  [!] {err}')

        # cipher_pw = 加密后的密码（用于服务端存档，后续仍可还原明文）
        cipher_pw = encrypt.encrypt_text(password)
        send_json(self.sock, {
            'cmd': 'register',
            'username': username,
            'password': password,
            'email': email,
            'cipher_pw': cipher_pw,
        })
        resp = recv_json(self.sock)
        if resp:
            print(f'  {resp.get("msg", "")}')
        if resp and resp.get('code') != 200:
            self.disconnect()
        else:
            print('  请等待管理员审核通过后登录')

    # ---- 登录 ----

    def login(self):
        """
        登录流程（含管理员二次验证）。

        【Q10. 为什么"管理员"单独一套流程？】
        A10. is_admin (Lv4) 用户登录后必须输入验证密码，作为二次身份验证 (Two-Factor Auth)。
            普通用户 (Lv1-3) 跳过这步。
            三次试错后降级为普通用户（保留登录但失去管理员权限），
            避免无限次重试。
        """
        saved_user, saved_pw, saved_remember = get_saved_credentials()

        username = input('用户名: ').strip() or saved_user                     # 空白回车用上次
        if saved_remember and saved_user == username and saved_pw:
            password = saved_pw
            print('  密码: ******** (已从历史记录自动填充)')
        else:
            password = getpass.getpass('密码: ').strip()

        remember = input('记住密码?(y/n, 默认n): ').strip().lower() == 'y'

        send_json(self.sock, {'cmd': 'login', 'username': username, 'password': password})
        resp = recv_json(self.sock)

        if not resp:
            print('  [!] 登录失败: 服务器无响应')
            return

        if resp.get('code') == 200:
            self.username = username
            self.level = resp.get('level', 1)
            self.is_admin = (self.level == 4)                       # Lv4 → 管理员

            # 管理员二次验证
            if self.is_admin:
                verified = False
                for tries in range(3, 0, -1):
                    admin_pw = getpass.getpass(f'请输入管理员验证密码(剩余{tries}次): ').strip()
                    send_json(self.sock, {'cmd': 'admin_verify', 'password': admin_pw})
                    vresp = recv_json(self.sock)
                    if vresp and vresp.get('code') == 200:
                        print('  管理员验证通过')
                        verified = True
                        break
                    print(f'  验证失败: {vresp.get("msg", "")} (剩余{tries - 1}次)')
                if not verified:
                    print('  [!] 管理员验证失败，降级为普通用户')
                    self.is_admin = False

            save_history(username, password, remember)
            self.logged_in = True

            # 启动 UDP 监听（让服务端能反向发现本客户端）
            self.udp_stop, self.udp_thread, self.udp_state = start_udp_listener()

            self._show_connection_info()
            return

        # 失败提示
        code = resp.get('code', 0)
        if code == 401:
            print(f'  [!] {resp.get("msg", "用户名或密码错误")}')
        elif code == 403:
            print(f'  [!] {resp.get("msg", "账号异常")}')
        else:
            print(f'  [!] 登录失败: {resp.get("msg", "未知错误")}')

    # ---- 文件列表 ----

    def list_files(self):
        """列出可下载文件。"""
        send_json(self.sock, {'cmd': 'list', 'username': self.username})
        resp = recv_json(self.sock)
        if not resp or resp.get('code') != 200:
            print(f'  [!] 获取文件列表失败: {resp.get("msg", "") if resp else ""}')
            return
        files = resp.get('files', [])
        if not files:
            print('  暂无文件')
            return
        print(f'\n  {"文件名":<35} {"目录":<8} {"大小":>12}')
        print('  ' + '-' * 57)
        for f in files:
            s = f['size']
            if s > 1024 * 1024:
                s_str = f'{s / (1024 * 1024):.1f} MB'
            elif s > 1024:
                s_str = f'{s / 1024:.1f} KB'
            else:
                s_str = f'{s} B'
            print(f"  {f['name']:<35} {f['level']:<8} {s_str:>12}")

    # ---- 上传 ----

    def upload(self):
        """上传文件（含断点续传）。"""
        local_path = input('本地文件路径: ').strip()
        if not os.path.isfile(local_path):
            print('  [!] 文件不存在')
            return

        fname = os.path.basename(local_path)
        print('  1. 公开  2. 一般  3. 高级  4. 特殊')
        lvl = input('上传到目录(1-4, 默认1): ').strip() or '1'
        level_name = LEVEL_NAMES.get(int(lvl) if lvl.isdigit() else 1, '公开')

        # 检查断点续传
        resume_file = fname + '.xc'
        offset = 0
        if os.path.exists(resume_file):
            if input('检测到未完成的传输记录，是否断点续传?(y/n): ').lower().strip() == 'y':
                try:
                    state = load_resume_state(resume_file)
                    offset = state.get('offset', 0)
                    print(f'  从偏移 {offset} 继续传输')
                except Exception as e:
                    print(f'  [!] 读取断点记录失败: {e}')
                    offset = 0

        total = os.path.getsize(local_path)
        iv_bytes = encrypt._derive_iv()
        iv_hex = iv_bytes.hex()

        # 保存断点状态（先存再传，传完再删）
        save_resume_state(resume_file, total, offset, self.username, fname, 'upload')

        send_json(self.sock, {
            'cmd': 'upload', 'username': self.username,
            'filename': fname, 'level': level_name,
            'total': total, 'iv': iv_hex, 'data_channel': True,
        })
        resp = recv_json(self.sock)
        if not resp or resp.get('code') != 200:
            print(f'  [!] 上传请求失败: {resp.get("msg", "") if resp else ""}')
            return

        token = resp.get('data_token')
        print(f'  开始上传 {fname} ({total} bytes) -> {level_name}')
        result = data_channel_send(token, 'upload', {
            'save_path': os.path.join('ftp_root', level_name, fname + '.enc'),
            'local_path': local_path, 'total': total,
            'iv': iv_hex, 'offset': offset,
        })
        print(f'  {result.get("msg", "")}')

        # 成功则删除断点文件
        if result and result.get('code') == 200:
            delete_resume_state(resume_file)

    # ---- 下载 ----

    def download(self):
        """下载文件（含断点续传）。"""
        # 先列出可下载文件
        self.list_files()

        filename = input('\n要下载的文件名: ').strip()
        if not filename:
            return

        level_name = input('文件所在目录(1-公开,2-一般,3-高级,4-特殊,默认1): ').strip() or '1'
        level_map = {'1': '公开', '2': '一般', '3': '高级', '4': '特殊'}
        level_name = level_map.get(level_name, '公开')

        save_path = input('保存到本地路径(默认./文件名): ').strip()
        if not save_path:
            save_path = filename.replace('.enc', '')

        # 检查断点续传
        resume_file = filename.replace('.enc', '') + '.xc'
        offset = 0
        if os.path.exists(resume_file):
            if input('检测到未完成的下载记录，是否断点续传?(y/n): ').lower().strip() == 'y':
                try:
                    state = load_resume_state(resume_file)
                    offset = state.get('offset', 0)
                    print(f'  从偏移 {offset} 继续下载')
                except Exception as e:
                    print(f'  [!] 读取断点记录失败: {e}')
                    offset = 0

        # 断点续传需要发送 resume 命令
        if offset > 0:
            send_json(self.sock, {
                'cmd': 'download_resume', 'username': self.username,
                'filename': filename, 'level': level_name, 'offset': offset,
            })
        else:
            send_json(self.sock, {
                'cmd': 'download', 'username': self.username,
                'filename': filename, 'level': level_name,
            })
        resp = recv_json(self.sock)
        if not resp or resp.get('code') != 200:
            print(f'  [!] 下载请求失败: {resp.get("msg", "") if resp else ""}')
            return

        token = resp.get('data_token')
        total = resp.get('total', 0)
        print(f'  开始下载 {filename} ({total} bytes)')
        result = data_channel_send(token, 'download', {
            'local_path': save_path, 'total': total,
            'offset': offset, 'resume_file': resume_file,
            'username': self.username, 'filename': filename,
        })
        print(f'  {result.get("msg", "")}')

        if result and result.get('code') == 200:
            print(f'  文件已保存到: {os.path.abspath(save_path)}')

    # ---- 删除 ----

    def delete_file(self):
        """删除文件（需要确认）。"""
        self.list_files()
        filename = input('\n要删除的文件名: ').strip()
        if not filename:
            return

        level_name = input('文件所在目录(1-公开,2-一般,3-高级,4-特殊,默认1): ').strip() or '1'
        level_map = {'1': '公开', '2': '一般', '3': '高级', '4': '特殊'}
        level_name = level_map.get(level_name, '公开')

        confirm = input(f'确认删除 {filename}? (y/n): ').strip().lower()
        if confirm != 'y':
            return

        send_json(self.sock, {
            'cmd': 'delete', 'username': self.username,
            'filename': filename, 'level': level_name,
        })
        resp = recv_json(self.sock)
        if resp:
            print(f'  {resp.get("msg", "")}')

    # ---- 密码修改 ----

    def change_password(self):
        """修改密码。"""
        old_pw = getpass.getpass('旧密码: ').strip()
        new_pw = getpass.getpass('新密码: ').strip()

        err = validate_password(new_pw)
        if err:
            print(f'  [!] {err}')
            return

        strength, tip = password_strength(new_pw)
        print(f'  {tip}')

        confirm = getpass.getpass('确认新密码: ').strip()
        if new_pw != confirm:
            print('  [!] 两次密码不一致')
            return

        new_cipher_pw = encrypt.encrypt_text(new_pw)
        send_json(self.sock, {
            'cmd': 'chpw', 'username': self.username,
            'old_password': old_pw, 'new_password': new_pw,
            'new_cipher_pw': new_cipher_pw,
        })
        resp = recv_json(self.sock)
        if resp:
            print(f'  {resp.get("msg", "")}')

    # ---- 权限提升申请 ----

    def request_level_up(self):
        """申请权限提升。"""
        print('  1. 公开  2. 一般  3. 高级  4. 特殊')
        lvl = input('目标权限等级(1-4): ').strip()
        level_map = {'1': 1, '2': 2, '3': 3, '4': 4}
        target_level = level_map.get(lvl, 2)

        reason = input('申请理由(可选): ').strip()

        send_json(self.sock, {
            'cmd': 'request_level_up', 'username': self.username,
            'target_level': target_level, 'reason': reason,
        })
        resp = recv_json(self.sock)
        if resp:
            print(f'  {resp.get("msg", "")}')

    # ---- 管理员: 用户管理 ----

    def _admin_user_menu(self):
        """管理员子菜单：用户管理。"""
        while True:
            print('\n--- 用户管理 ---')
            print('1. 查看所有用户')
            print('2. 审核注册申请')
            print('3. 修改用户权限')
            print('4. 删除用户')
            print('5. 审批权限提升申请')
            print('0. 返回上级菜单')

            sub = input('选择: ').strip()

            if sub == '1':
                send_json(self.sock, {'cmd': 'admin_list_users'})
                resp = recv_json(self.sock)
                if resp and resp.get('code') == 200:
                    users = resp.get('users', [])
                    print(f'\n  {"用户名":<15} {"邮箱":<20} {"权限":<6} {"状态":<10} {"申请时间":<20}')
                    print('  ' + '-' * 75)
                    for u in users:
                        ln = LEVEL_NAMES.get(u.get('level', 1), '?')
                        print(f"  {u['username']:<15} {u.get('email', ''):<20} "
                              f"{ln:<6} {u.get('status', ''):<10} {u.get('apply_time', ''):<20}")

            elif sub == '2':
                self._admin_approve_menu()

            elif sub == '3':
                target = input('用户名: ').strip()
                print('  1. 公开  2. 一般  3. 高级  4. 特殊')
                lvl = input('新权限等级: ').strip()
                level_map = {'1': 1, '2': 2, '3': 3, '4': 4}
                new_level = level_map.get(lvl, 1)
                send_json(self.sock, {
                    'cmd': 'admin_set_level', 'target_user': target, 'level': new_level,
                })
                resp = recv_json(self.sock)
                if resp:
                    print(f'  {resp.get("msg", "")}')

            elif sub == '4':
                target = input('要删除的用户名: ').strip()
                confirm = input(f'确认删除用户 {target}? (y/n): ').strip().lower()
                if confirm == 'y':
                    send_json(self.sock, {
                        'cmd': 'admin_del_user', 'target_user': target,
                    })
                    resp = recv_json(self.sock)
                    if resp:
                        print(f'  {resp.get("msg", "")}')

            elif sub == '5':
                self._admin_level_requests_menu()

            elif sub == '0':
                break

    def _admin_approve_menu(self):
        """管理员审核注册。"""
        send_json(self.sock, {'cmd': 'admin_list_users'})
        resp = recv_json(self.sock)
        if not resp or resp.get('code') != 200:
            return
        users = resp.get('users', [])
        pending = [u for u in users if u.get('status') == 'pending']

        if not pending:
            print('  没有待审核的注册申请')
            return

        print(f'\n  --- 待审核用户 ({len(pending)}) ---')
        for u in pending:
            print(f"  {u['username']:<15} {u.get('email', ''):<20} {u.get('apply_time', '')}")

        username = input('输入要审核的用户名(留空返回): ').strip()
        if not username:
            return
        if not any(u['username'] == username for u in pending):
            print('  用户不在待审核列表中')
            return

        print('  1. 批准')
        print('  2. 拒绝')
        choice = input('选择: ').strip()
        if choice == '1':
            lvl = input('设置权限等级(1-4,默认1): ').strip() or '1'
            level_map = {'1': 1, '2': 2, '3': 3, '4': 4}
            new_level = level_map.get(lvl, 1)
            send_json(self.sock, {
                'cmd': 'admin_approve', 'target_user': username,
                'action': 'approve', 'level': new_level,
            })
        elif choice == '2':
            send_json(self.sock, {
                'cmd': 'admin_approve', 'target_user': username,
                'action': 'reject',
            })
        resp = recv_json(self.sock)
        if resp:
            print(f'  {resp.get("msg", "")}')

    def _admin_level_requests_menu(self):
        """管理员审批权限提升申请。"""
        send_json(self.sock, {'cmd': 'admin_list_level_requests'})
        resp = recv_json(self.sock)
        if not resp or resp.get('code') != 200:
            print('  获取申请列表失败')
            return

        requests = resp.get('requests', [])
        if not requests:
            print('  没有待处理的权限提升申请')
            return

        print(f'\n  --- 权限提升申请 ({len(requests)}) ---')
        for r in requests:
            print(f"  {r['username']:<15} 目标: {LEVEL_NAMES.get(r.get('target_level', 2), '?'):<6} "
                  f"理由: {r.get('reason', '')}")

        username = input('输入要处理的用户名(留空返回): ').strip()
        if not username:
            return

        print('  1. 批准')
        print('  2. 拒绝')
        print('  3. 修改权限后批准')
        choice = input('选择: ').strip()

        if choice == '1':
            send_json(self.sock, {
                'cmd': 'admin_process_level_request',
                'target_user': username, 'action': 'approve',
            })
        elif choice == '2':
            send_json(self.sock, {
                'cmd': 'admin_process_level_request',
                'target_user': username, 'action': 'reject',
            })
        elif choice == '3':
            lvl = input('新权限等级(1-4): ').strip()
            level_map = {'1': 1, '2': 2, '3': 3, '4': 4}
            new_level = level_map.get(lvl, 2)
            send_json(self.sock, {
                'cmd': 'admin_process_level_request',
                'target_user': username, 'action': 'modify', 'level': new_level,
            })

        resp = recv_json(self.sock)
        if resp:
            print(f'  {resp.get("msg", "")}')

    # ---- 管理员: 文件管理 ----

    def _admin_file_menu(self):
        """管理员子菜单：文件管理。"""
        while True:
            print('\n--- 文件管理 ---')
            print('1. 添加文件到目录')
            print('2. 查看所有文件')
            print('3. 删除文件')
            print('4. 修改文件')
            print('5. 设置文件权限(移动目录)')
            print('6. 修改文件级别')
            print('0. 返回上级菜单')

            sub = input('选择: ').strip()

            if sub == '1':
                self._admin_add_file()

            elif sub == '2':
                send_json(self.sock, {'cmd': 'admin_list_all_files'})
                resp = recv_json(self.sock)
                if resp and resp.get('code') == 200:
                    files = resp.get('files', [])
                    print(f'\n  {"文件名":<35} {"目录":<8} {"大小":>12}')
                    print('  ' + '-' * 57)
                    for f in files:
                        s = f['size']
                        if s > 1024 * 1024:
                            s_str = f'{s / (1024 * 1024):.1f} MB'
                        elif s > 1024:
                            s_str = f'{s / 1024:.1f} KB'
                        else:
                            s_str = f'{s} B'
                        print(f"  {f['name']:<35} {f['level']:<8} {s_str:>12}")

            elif sub == '3':
                fname = input('要删除的文件名: ').strip()
                lvl = input('所在目录(1-公开,2-一般,3-高级,4-特殊,默认1): ').strip() or '1'
                level_map = {'1': '公开', '2': '一般', '3': '高级', '4': '特殊'}
                level_name = level_map.get(lvl, '公开')
                send_json(self.sock, {
                    'cmd': 'admin_del_file', 'filename': fname, 'level': level_name,
                })
                resp = recv_json(self.sock)
                if resp:
                    print(f'  {resp.get("msg", "")}')

            elif sub == '4':
                # 修改文件 - 占位实现：重新上传覆盖
                fname = input('要修改的文件名: ').strip()
                if not fname:
                    continue
                local_path = input('新文件本地路径: ').strip()
                if not os.path.isfile(local_path):
                    print('  [!] 文件不存在')
                    continue
                level_name = input('文件所在目录(1-公开,2-一般,3-高级,4-特殊,默认1): ').strip() or '1'
                level_map = {'1': '公开', '2': '一般', '3': '高级', '4': '特殊'}
                level_name = level_map.get(level_name, '公开')

                confirm = input(f'确认用 {local_path} 覆盖 {fname}? (y/n): ').strip().lower()
                if confirm != 'y':
                    continue

                # 先删除旧文件
                send_json(self.sock, {
                    'cmd': 'admin_del_file', 'filename': fname, 'level': level_name,
                })
                recv_json(self.sock)

                # 再上传新文件
                total = os.path.getsize(local_path)
                iv_bytes = encrypt._derive_iv()
                iv_hex = iv_bytes.hex()
                send_json(self.sock, {
                    'cmd': 'upload', 'username': self.username,
                    'filename': fname, 'level': level_name,
                    'total': total, 'iv': iv_hex, 'data_channel': True,
                })
                resp = recv_json(self.sock)
                if resp and resp.get('code') == 200:
                    token = resp.get('data_token')
                    result = data_channel_send(token, 'upload', {
                        'save_path': os.path.join('ftp_root', level_name, fname + '.enc'),
                        'local_path': local_path, 'total': total,
                        'iv': iv_hex, 'offset': 0,
                    })
                    print(f'  {result.get("msg", "")}')

            elif sub == '5':
                fname = input('文件名: ').strip()
                lvl = input('当前目录(1-4): ').strip()
                level_map = {'1': '公开', '2': '一般', '3': '高级', '4': '特殊'}
                level = level_map.get(lvl, '公开')
                lvl2 = input('新目录(1-4): ').strip()
                new_level = level_map.get(lvl2, '公开')
                send_json(self.sock, {
                    'cmd': 'admin_move_file',
                    'filename': fname, 'level': level, 'new_level': new_level,
                })
                resp = recv_json(self.sock)
                if resp:
                    print(f'  {resp.get("msg", "")}')

            elif sub == '6':
                fname = input('文件名: ').strip()
                lvl = input('当前目录(1-4): ').strip()
                level_map = {'1': '公开', '2': '一般', '3': '高级', '4': '特殊'}
                level = level_map.get(lvl, '公开')
                lvl2 = input('新目录(1-4): ').strip()
                new_level = level_map.get(lvl2, '公开')
                send_json(self.sock, {
                    'cmd': 'admin_set_file_level',
                    'filename': fname, 'level': level, 'new_level': new_level,
                })
                resp = recv_json(self.sock)
                if resp:
                    print(f'  {resp.get("msg", "")}')

            elif sub == '0':
                break

    def _admin_add_file(self):
        """管理员添加文件到服务端目录。"""
        local_path = input('本地文件路径: ').strip()
        if not os.path.isfile(local_path):
            print('  [!] 文件不存在')
            return
        fname = os.path.basename(local_path)
        print('  1. 公开  2. 一般  3. 高级  4. 特殊')
        lvl = input('目标目录(1-4, 默认1): ').strip() or '1'
        level_map = {'1': '公开', '2': '一般', '3': '高级', '4': '特殊'}
        level_name = level_map.get(lvl, '公开')

        total = os.path.getsize(local_path)
        iv_bytes = encrypt._derive_iv()
        iv_hex = iv_bytes.hex()

        send_json(self.sock, {
            'cmd': 'upload', 'username': self.username,
            'filename': fname, 'level': level_name,
            'total': total, 'iv': iv_hex, 'data_channel': True,
        })
        resp = recv_json(self.sock)
        if resp and resp.get('code') == 200:
            token = resp.get('data_token')
            print(f'  正在添加 {fname} -> {level_name}')
            result = data_channel_send(token, 'upload', {
                'save_path': os.path.join('ftp_root', level_name, fname + '.enc'),
                'local_path': local_path, 'total': total,
                'iv': iv_hex, 'offset': 0,
            })
            print(f'  {result.get("msg", "")}')

    # ---- 加密信息 ----

    def show_enc_info(self):
        """显示加密信息（拉服务端 /api/encrypt/info）。"""
        send_json(self.sock, {'cmd': 'enc_info'})
        resp = recv_json(self.sock)
        if resp and resp.get('code') == 200:
            print('\n--- 加密信息 ---')
            print(f"  加密算法: {resp.get('algorithm', 'N/A')}")
            print(f"  密钥长度: {resp.get('key_length', 'N/A')} bits")
            print(f"  IV 派生:  {resp.get('iv_derivation', 'N/A')}")
            print(f"  填充方式: {resp.get('padding', 'N/A')}")
            print(f"  分块大小: {resp.get('chunk_size', 'N/A')} bytes")
            print(f"  哈希算法: {resp.get('hash_algorithm', 'N/A')}")
            print('----------------')

    # ---- 主菜单 ----

    def main_menu(self):
        """登录后主菜单（按角色显示不同选项）。"""
        while self.logged_in:
            print('\n===== FTP 客户端 主菜单 =====')
            print('1. 浏览文件列表')
            print('2. 上传文件')
            print('3. 下载文件')
            print('4. 删除文件')
            print('5. 修改密码')
            print('6. 查看加密信息')
            if not self.is_admin:
                print('7. 申请权限提升')
            if self.is_admin:
                print('8. 用户管理')
                print('9. 文件管理')
            print('0. 退出登录')
            print('=============================')

            choice = input('选择: ').strip()

            if choice == '1':
                self.list_files()
            elif choice == '2':
                self.upload()
            elif choice == '3':
                self.download()
            elif choice == '4':
                self.delete_file()
            elif choice == '5':
                self.change_password()
            elif choice == '6':
                self.show_enc_info()
            elif choice == '7' and not self.is_admin:
                self.request_level_up()
            elif choice == '8' and self.is_admin:
                self._admin_user_menu()
            elif choice == '9' and self.is_admin:
                self._admin_file_menu()
            elif choice == '0':
                self.disconnect()
                print('  已退出登录')
                break


# ---------------------------------------------------------------------------
# 程序入口
# ---------------------------------------------------------------------------

def print_main_menu():
    print('\n===== FTP 安全传输系统 =====')
    print('1. 注册')
    print('2. 登录')
    print('0. 退出')
    print('============================')


def main():
    print('=' * 40)
    print('  欢迎使用 FTP 安全传输系统')
    print('  客户端')
    print('=' * 40)

    while True:
        print_main_menu()
        choice = input('选择: ').strip()

        if choice == '1':
            # 注册是个独立会话（注册完就断开，避免一直占着连接）
            client = FTPClient()
            if client.connect():
                client.register()
                client.disconnect()

        elif choice == '2':
            # 登录才有长连接
            client = FTPClient()
            if client.connect():
                client.login()
                if client.logged_in:
                    client.main_menu()
                else:
                    client.disconnect()

        elif choice == '0':
            print('再见!')
            break


if __name__ == '__main__':
    main()
