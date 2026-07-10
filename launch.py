#!/usr/bin/env python3
"""
FTP 安全传输系统 - Web 控制面板启动器
======================================

 Q1. launch.py 既是 Flask 又是 Socket 服务，怎么协作？
 A1. launch.py 是入口；启动时拉起两个服务：
     a) Flask Web API：监听 5000，提供 /api/* RESTful 接口 + 静态页面
     b) Socket 服务（./start_socket_service）：后台线程跑 server.py 的 _server_loop 函数，
        监听 8888（指令）和 8000（数据）
     两者共享 ftp_project/ 下的 server.py/encrypt.py/user_store.py，
     共享同一个 users.json/admin.cfg/ftp_root/。

 Q2. 为什么 Web 端的 API 不直接调用 server.client_thread 而是另外写一套？
 A2. Web 客户端是浏览器（HTTP），不能直接走 Socket TCP 协议。
     所以 launch.py 把 server.py 的业务函数（handle_login、handle_upload 等）抽出来
     包成 Flask 路由，让浏览器通过 HTTP 调同一个后端逻辑。
     而真实 Socket 客户端走 server.client_thread + send_json/recv_json。
     两套入口，一套业务代码（server.py）。

 Q3. 那个 .xc 和 .enc 文件名后缀代表什么？
 A3. .enc = 加密文件（encrypt_file 产物，磁盘长存）
     .xc  = X-Continue 断点续传状态文件（encrypt_text 加密的 JSON）
     都是自定义后缀，便于识别用途。

 Q4. 端口冲突了怎么办？
 A4. _server_loop 的 setsockopt(SO_REUSEADDR, 1) 允许重启时复用 TIME_WAIT 端口。
     真正的端口占用会在 bind() 时抛 OSError，stop_socket_service 会优雅关闭。

 Q5. 默认管理员 admin/admin123 是写死吗？
 A5. 启动时（首次）若 admin.cfg 不存在，用默认账号写一次，
     用户首次登录后要求立即改密。
     默认密码改成 admin/admin1234 也可，逻辑相同。

启动:
  $ python launch.py

启动 Flask Web API（端口5000），同时提供 React 前端静态文件。
首次使用：
  1. 访问 http://127.0.0.1:5000
  2. 进入"服务端管理"设置管理员密码
  3. 启动 Socket 服务
  4. 进入"客户端"注册/登录使用
"""

import os
import sys
import base64

# 路径设置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, 'ftp_project'))

from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
import shutil
import tempfile

# 创建应用
app = Flask(__name__, static_folder='dist', static_url_path='')
CORS(app)

# 导入API路由（必须在app创建之后）
import server
import encrypt
import user_store as us
from server import (ensure_dirs, LEVEL_NAMES, LEVEL_MAP, get_user_level,
                    can_access, data_channel_server, HOST, PORT, DATA_PORT,
                    udp_broadcast, list_files, list_all_files)

# ---- 服务状态 ----
_service_running = False
_cmd_sock = None
import threading, time, socket, json

# ---- Socket工具 ----
def _send_json(sock, data):
    raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
    sock.sendall(len(raw).to_bytes(8, 'big') + raw)

def _recv_all(sock, size):
    buf = b''
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk: break
        buf += chunk
    return buf

def _recv_json(sock):
    raw_len = _recv_all(sock, 8)
    if len(raw_len) < 8: return None
    length = int.from_bytes(raw_len, 'big')
    if length == 0: return None
    data = _recv_all(sock, length)
    if len(data) < length: return None
    return json.loads(data.decode('utf-8'))

# ---- 服务管理 ----
def _server_loop():
    global _cmd_sock
    ensure_dirs()
    threading.Thread(target=data_channel_server, daemon=True).start()
    _cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _cmd_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _cmd_sock.bind((HOST, PORT))
    _cmd_sock.listen(50)
    print(f'[*] Socket服务监听 {PORT}')
    while True:
        try:
            cs, ca = _cmd_sock.accept()
            threading.Thread(target=server.client_thread, args=(cs, ca), daemon=True).start()
        except OSError:
            break

def start_socket_service():
    global _service_running
    if not _service_running:
        threading.Thread(target=_server_loop, daemon=True).start()
        _service_running = True
        time.sleep(0.5)
        return True
    return False

def stop_socket_service():
    global _service_running, _cmd_sock
    if _service_running and _cmd_sock:
        try: _cmd_sock.close()
        except: pass
        _service_running = False
        return True
    return False

# ---- API路由 ----

@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({'running': _service_running, 'port': PORT, 'data_port': DATA_PORT})

@app.route('/api/service/start', methods=['POST'])
def api_service_start():
    ok = start_socket_service()
    return jsonify({'success': ok, 'running': _service_running})

@app.route('/api/service/stop', methods=['POST'])
def api_service_stop():
    ok = stop_socket_service()
    return jsonify({'success': ok, 'running': _service_running})

@app.route('/api/service/broadcast', methods=['POST'])
def api_broadcast():
    ip, hostname = udp_broadcast()
    return jsonify({'ip': ip, 'hostname': hostname})

@app.route('/api/users', methods=['GET'])
def api_users():
    users = us.load_users()
    result = []
    for u, info in users.items():
        # 过滤掉已删除的用户——前端 UI 不再显示
        if info.get('status') == 'deleted':
            continue
        result.append({
            'username': u,
            'email': info.get('email', ''),
            'level': info.get('level', 1),
            'level_name': LEVEL_NAMES.get(info.get('level', 1), '未知'),
            'status': info.get('status', ''),
            'apply_time': info.get('apply_time', ''),
        })
    return jsonify(result)

@app.route('/api/users/pending', methods=['GET'])
def api_pending_users():
    users = us.load_users()
    return jsonify([u for u in users.values() if u.get('status') == 'pending'])

@app.route('/api/users/approve', methods=['POST'])
def api_approve_user():
    data = request.json
    username = data.get('username', '')
    action = data.get('action', '')
    level = data.get('level', 1)
    user = us.get_user(username)
    if not user:
        return jsonify({'success': False, 'msg': '用户不存在'})
    if action == 'approve':
        us.update_user(username, {'status': 'approved', 'level': level})
        return jsonify({'success': True, 'msg': f'已批准 {username}'})
    elif action == 'reject':
        us.update_user(username, {'status': 'rejected'})
        return jsonify({'success': True, 'msg': f'已拒绝 {username}'})
    return jsonify({'success': False, 'msg': '未知操作'})

@app.route('/api/users/set-level', methods=['POST'])
def api_set_level():
    data = request.json
    us.update_user(data.get('username', ''), {'level': data.get('level', 1)})
    return jsonify({'success': True})

@app.route('/api/users/delete', methods=['POST'])
def api_delete_user():
    username = request.json.get('username', '')
    if not username:
        return jsonify({'success': False, 'msg': 'username required'}), 400
    # 标记为已删除
    us.update_user(username, {'status': 'deleted'})
    # 同时清理该用户上传的文件目录（如果存在）
    import shutil
    for sub in ('uploads', '.encrypted', '.decrypted'):
        d = os.path.join(BASE_DIR, sub, username)
        if os.path.isdir(d):
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception as e:
                app.logger.warning(f'清理用户目录失败 {d}: {e}')
    return jsonify({'success': True, 'msg': f'用户 {username} 已删除'})

@app.route('/api/admin/config', methods=['GET'])
def api_admin_config():
    return jsonify({'configured': us.is_admin_configured()})

@app.route('/api/admin/config', methods=['POST'])
def api_set_admin_config():
    data = request.json
    pw = data.get('password', '')
    vp = data.get('verify_password', '')
    un = data.get('username', '').strip() or us.get_admin_username() or 'admin'
    if len(pw) < 6 or len(vp) < 6:
        return jsonify({'success': False, 'msg': '密码长度不得低于6位'})
    cfg = us.load_admin_config()
    cfg['username'] = un
    cfg['password'] = encrypt.hash_password(pw)
    cfg['verify_password'] = encrypt.hash_password(vp)
    us.save_admin_config(cfg)
    return jsonify({'success': True, 'username': un})


# ---------------------------------------------------------------------------
# 模拟 FTP 上传/下载：直接读写本项目的 uploads/ 目录
# ---------------------------------------------------------------------------

UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
# 真四级目录根目录（与 server.BASE_DIR 一致）
FTP_ROOT = os.path.join(BASE_DIR, 'ftp_project', 'ftp_root')


def _user_accessible_levels(username: str) -> list:
    """高级用户可访问当前等级及以下的所有目录（BLP 下读）。"""
    lvl = get_user_level(username)
    if lvl < 1:
        lvl = 1
    if lvl > 4:
        lvl = 4
    return [(i, LEVEL_NAMES[i]) for i in range(1, lvl + 1)]


def simple_list_files(username: str) -> list:
    """客户端用：列出当前用户等级及以下所有目录里的文件。"""
    result = []
    ensure_dirs()
    for i, lvl_name in _user_accessible_levels(username):
        d = os.path.join(FTP_ROOT, lvl_name)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            fp = os.path.join(d, fn)
            if os.path.isfile(fp):
                result.append({
                    'name': fn,
                    'level': lvl_name,
                    'level_num': i,
                    'size': os.path.getsize(fp),
                    'mtime': os.path.getmtime(fp),
                })
    return result


def simple_list_all_files() -> list:
    """管理员用：列出四级目录下的全部文件。"""
    result = []
    ensure_dirs()
    for i in range(1, 5):
        d = os.path.join(FTP_ROOT, LEVEL_NAMES[i])
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            fp = os.path.join(d, fn)
            if os.path.isfile(fp):
                result.append({
                    'name': fn,
                    'level': LEVEL_NAMES[i],
                    'level_num': i,
                    'size': os.path.getsize(fp),
                    'mtime': os.path.getmtime(fp),
                })
    return result


@app.route('/api/upload', methods=['POST'])
def api_upload():
    """
    客户端上传：按指定 level 加密存到 ftp_root/<level>/。

    【Q8. 为什么存两份？】
    A8. 这是"加密传输演示页"的特殊设计：
       - <level>/ 存密文版 .enc（演示"加密后落盘"，按权限分目录）
       - .encrypted/ 存密文版（演示页浏览用）
       - .decrypted/ 存解密版（演示"加密可逆性"）
       Web 前端可对比两者大小、查看密文二进制头、验证解密一致性。

    【Q9. 文件名冲突怎么办？】
    A9. while 循环检查目标目录已存在的同名文件，若有就追加 _1、_2、_3...
       避免覆盖用户原文件。

    【Q10. encrypt.encrypt_file 和 encrypt_file.encrypt_file 是什么关系？】
    A10. encrypt 模块（./ftp_project/encrypt.py）里的 encrypt_file 函数，
         在我们的自定义格式 [8B total][4B chunk_len][8B IV][密文] 中加密。
         这是"实时流式加密"——上传文件时由 upload 路由调用，
         不依赖 Socket 数据通道。
    """
    if 'file' not in request.files:
        return jsonify({'success': False, 'msg': '未选择文件'})
    f = request.files['file']
    if not f.filename:
        return jsonify({'success': False, 'msg': '文件名为空'})

    username = request.form.get('username', '').strip()
    target_level = request.form.get('level', '公开').strip()
    # === 密级权限校验 ===
    if not username:
        return jsonify({'success': False, 'msg': '请提供用户名'})
    if not us.user_exists(username):
        return jsonify({'success': False, 'msg': f'用户 {username} 不存在'})
    if target_level not in LEVEL_MAP:
        target_level = '公开'
    if not can_access(username, target_level):
        return jsonify({'success': False, 'msg': f'权限不足，无法上传到 {target_level} 目录'})

    name = f.filename
    base, ext = os.path.splitext(name)
    ensure_dirs()

    # === 主存：ftp_root/<target_level>/<name>.enc（按权限分目录）===
    target_dir = os.path.join(FTP_ROOT, target_level)
    os.makedirs(target_dir, exist_ok=True)
    final = name + '.enc'
    i = 1
    while os.path.exists(os.path.join(target_dir, final)):
        final = f'{base}_{i}{ext}.enc'
        i += 1
    main_path = os.path.join(target_dir, final)
    # 演示用：解密副本原始文件名（无 .enc 后缀）
    final_plain = name
    i = 1
    while os.path.exists(os.path.join(target_dir, final_plain)):
        final_plain = f'{base}_{i}{ext}'
        i += 1

    # === 真正的加密流程：先存到临时明文 → encrypt_file 加密到 main_path ===
    # 这样 .enc 文件符合 encrypt_file 格式 [8B total][4B chunk_len][8B IV][密文]*
    # 否则直接 f.save(main_path) 写明文为 .enc，下载时解密必败。
    from ftp_project import encrypt as _enc
    tmp_dir = tempfile.mkdtemp()
    tmp_plain = os.path.join(tmp_dir, name)
    try:
        f.save(tmp_plain)                                  # 1) 保存明文到临时目录
        _enc.encrypt_file(tmp_plain, main_path)             # 2) 用 DES-CBC 流式加密到主存路径
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return jsonify({'success': False, 'msg': f'加密失败：{e}'})

    # === 演示用：.encrypted/ 与 .decrypted/（便于展示页面）===
    enc_dir = os.path.join(FTP_ROOT, '.encrypted')
    dec_dir = os.path.join(FTP_ROOT, '.decrypted')
    os.makedirs(enc_dir, exist_ok=True)
    os.makedirs(dec_dir, exist_ok=True)

    enc_name = name + '.enc'
    dec_name = name
    i = 1
    while os.path.exists(os.path.join(enc_dir, enc_name)):
        enc_name = f'{base}_{i}{ext}.enc'
        dec_name = f'{base}_{i}{ext}'
        i += 1

    enc_path = os.path.join(enc_dir, enc_name)
    dec_path = os.path.join(dec_dir, dec_name)

    # 主存已是 .enc，拷到 .encrypted/ 演示用，再解密一份到 .decrypted/
    try:
        shutil.copyfile(main_path, enc_path)              # 复制密文到演示目录
        _enc.decrypt_file(enc_path, dec_path)             # 解密到演示副本
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return jsonify({'success': False, 'msg': f'演示副本加解密失败：{e}'})
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)        # 清临时明文

    return jsonify({
        'success': True,
        'filename': name,
        'level': target_level,
        'stored_path': main_path,
        'encrypted_path': enc_path,
        'decrypted_path': dec_path,
        'encrypted_size': os.path.getsize(enc_path),
        'decrypted_size': os.path.getsize(dec_path),
        'msg': f'已加密存为 {target_level}/{final}，演示副本存为 {enc_name}'
    })


# ---- 客户端"像上传一样展示加密过程"的下载接口 ----

@app.route('/api/client/download/cipher', methods=['GET'])
def api_client_download_cipher():
    """
    客户端按文件 + level 读取 ftp_root/<level>/<name>.enc 密文。
    返回：Base64 密文（明文 .enc 二进制文件的内容）+ 十六进制展示。
    同时附带原始文件大小（解密后的明文长度）。
    """
    username = request.args.get('username', '').strip()
    filename = request.args.get('filename', '').strip()
    level_name = request.args.get('level', '公开').strip()
    if not filename or not username:
        return jsonify({'error': '参数缺失'}), 400
    if level_name not in LEVEL_MAP:
        return jsonify({'error': '未知权限等级'}), 400
    if not can_access(username, level_name):
        return jsonify({'error': '权限不足'}), 403

    # 文件名允许带或不带 .enc 后缀
    if not filename.endswith('.enc'):
        candidates = [filename + '.enc', filename]
    else:
        candidates = [filename]
    enc_path = None
    for cand in candidates:
        p = os.path.join(FTP_ROOT, level_name, cand)
        if os.path.isfile(p):
            enc_path = p
            used_name = cand
            break
    if enc_path is None:
        return jsonify({'error': f'文件 {filename} 不存在于 {level_name} 目录'}), 404

    with open(enc_path, 'rb') as fp:
        cipher_bytes = fp.read()
    # 解析文件头：[8B total][4B chunk_len][8B IV][密文] 重复
    plain_size = int.from_bytes(cipher_bytes[:8], 'big') if len(cipher_bytes) >= 8 else 0

    cipher_b64 = base64.b64encode(cipher_bytes).decode('ascii')
    hex_str = cipher_bytes.hex().upper()
    # 每 4 字节加空格，每 32 字节换行
    hex_lines = []
    for i in range(0, len(hex_str), 64):
        chunk = hex_str[i:i+64]
        hex_lines.append(' '.join(chunk[j:j+8] for j in range(0, len(chunk), 8)))
    cipher_hex = '\n'.join(hex_lines)

    return jsonify({
        'success': True,
        'filename': used_name,
        'level': level_name,
        'plain_size': plain_size,
        'cipher_size': len(cipher_bytes),
        'cipher_b64': cipher_b64,
        'cipher_hex': cipher_hex,
        'algorithm': 'DES-CBC',
        'key_length': 64,
        'padding': 'PKCS#7',
        'chunk_size': 1000,
        'format': '[8B total][4B chunk_len][8B IV][密文] 循环',
    })


@app.route('/api/client/download/decrypt', methods=['POST'])
def api_client_download_decrypt():
    """
    客户端把刚拿到的密文（Base64）回传给服务器，服务器用真实密钥解密返回明文。
    这样前端能完整展示"明文 → 密文 → 解密还原"。
    """
    body = request.get_json(silent=True) or {}
    cipher_b64 = body.get('cipher', '')
    username = body.get('username', '').strip()
    if not cipher_b64:
        return jsonify({'error': '密文为空'}), 400
    if not username:
        return jsonify({'error': '用户名缺失'}), 400
    if not us.user_exists(username):
        return jsonify({'error': '用户不存在'}), 404

    # 写到一个临时 .enc 文件，用 encrypt_file 的标准解密函数解开
    import tempfile
    from ftp_project import encrypt as _enc
    try:
        raw = base64.b64decode(cipher_b64)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as tf:
            tf.write(raw)
            tmp_in = tf.name
        tmp_out = tmp_in + '.plain'
        _enc.decrypt_file(tmp_in, tmp_out)
        with open(tmp_out, 'rb') as fp:
            plain_bytes = fp.read()
        os.remove(tmp_in)
        os.remove(tmp_out)
        return jsonify({
            'success': True,
            'text': plain_bytes.decode('utf-8', errors='replace'),
            'size': len(plain_bytes),
        })
    except Exception as e:
        return jsonify({'error': f'解密失败: {e}'}), 500


@app.route('/api/client/download/file', methods=['GET'])
def api_client_download_file():
    """
    客户端真正下载文件（返回解密后的明文，浏览器存盘）。
    """
    username = request.args.get('username', '').strip()
    filename = request.args.get('filename', '').strip()
    level_name = request.args.get('level', '公开').strip()
    if not filename or not username:
        return jsonify({'error': '参数缺失'}), 400
    if level_name not in LEVEL_MAP:
        return jsonify({'error': '未知权限等级'}), 400
    if not can_access(username, level_name):
        return jsonify({'error': '权限不足'}), 403

    if not filename.endswith('.enc'):
        candidates = [filename + '.enc', filename]
    else:
        candidates = [filename]
    enc_path = None
    for cand in candidates:
        p = os.path.join(FTP_ROOT, level_name, cand)
        if os.path.isfile(p):
            enc_path = p
            used_name = cand[:-4] if cand.endswith('.enc') else cand
            break
    if enc_path is None:
        return jsonify({'error': '文件不存在'}), 404

    # 解密到临时文件再发送
    import tempfile
    from ftp_project import encrypt as _enc
    tmp_dir = tempfile.mkdtemp()
    tmp_out = os.path.join(tmp_dir, used_name)
    try:
        _enc.decrypt_file(enc_path, tmp_out)
        from flask import send_file
        return send_file(tmp_out, as_attachment=True, download_name=used_name)
    except Exception as e:
        return jsonify({'error': f'解密失败: {e}'}), 500


@app.route('/api/client/refresh', methods=['GET'])
def api_client_refresh():
    """
    客户端在不重新登录的情况下，重新拉一次最新等级和用户名信息。
    解决"管理员改了权限客户端无感知"的 bug。
    """
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'success': False, 'msg': 'no username'}), 400
    user = us.get_user(username)
    if not user:
        return jsonify({'success': False, 'msg': '用户不存在'}), 404
    if user['status'] != 'approved':
        return jsonify({'success': False, 'msg': f"账号{user['status']}"}), 403
    level = user.get('level', 1)
    return jsonify({
        'success': True,
        'username': username,
        'level': level,
        'level_name': LEVEL_NAMES.get(level, '未知'),
        'email': user.get('email', ''),
        'is_admin': level == 4,
    })


@app.route('/api/download', methods=['GET'])
def api_download():
    """
    兼容旧路径：管理员快速下载某个文件。
    - 没指定 level 时优先从 ftp_root/<各级>/ 找
    - 否则从 ftp_root/<level>/<name> 取（解密后返回）
    """
    from flask import send_from_directory
    name = request.args.get('filename', '')
    level = request.args.get('level', '').strip()
    if level and level in LEVEL_MAP:
        # 走解密路径
        candidates = [name + '.enc', name]
        for cand in candidates:
            p = os.path.join(FTP_ROOT, level, cand)
            if os.path.isfile(p):
                import tempfile
                from ftp_project import encrypt as _enc
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.plain')
                tmp.close()
                try:
                    _enc.decrypt_file(p, tmp.name)
                    from flask import send_file
                    out_name = cand[:-4] if cand.endswith('.enc') else cand
                    return send_file(tmp.name, as_attachment=True, download_name=out_name)
                finally:
                    try: os.remove(tmp.name)
                    except OSError: pass
        return jsonify({'error': '文件不存在'}), 404
    # 兼容 uploads/ 旧路径
    if os.path.isfile(os.path.join(UPLOAD_DIR, name)):
        return send_from_directory(UPLOAD_DIR, name, as_attachment=True)
    return jsonify({'error': '文件不存在'}), 404

@app.route('/api/files', methods=['GET'])
def api_files():
    return jsonify(simple_list_files(request.args.get('username', '')))

@app.route('/api/files/all', methods=['GET'])
def api_all_files():
    return jsonify(simple_list_all_files())

@app.route('/api/files/delete', methods=['POST'])
def api_delete_file():
    """客户端/管理员用：删除 ftp_root/<level>/<name> 下的密文文件。"""
    data = request.json or {}
    username = data.get('username', '').strip()
    level_name = data.get('level', '').strip()
    name = data.get('filename', '').strip()
    if not (name and level_name):
        return jsonify({'success': False, 'msg': '参数缺失'})
    if level_name not in LEVEL_MAP:
        return jsonify({'success': False, 'msg': '未知权限等级'})
    # 客户端只能删自己等级及以下；管理员可删任意
    admin_user = us.get_admin_username()
    is_admin = bool(admin_user and username == admin_user)
    if not is_admin and not can_access(username, level_name):
        return jsonify({'success': False, 'msg': '权限不足'})

    candidates = [name + '.enc', name]
    deleted = False
    for cand in candidates:
        p = os.path.join(FTP_ROOT, level_name, cand)
        if os.path.isfile(p):
            try:
                os.remove(p)
                deleted = True
                break
            except OSError as e:
                return jsonify({'success': False, 'msg': f'删除失败: {e}'})
    if not deleted:
        return jsonify({'success': False, 'msg': '文件不存在'})
    return jsonify({'success': True})

@app.route('/api/files/move', methods=['POST'])
def api_move_file():
    """管理员移动文件到新等级（实际就是 rename 跨目录）。"""
    data = request.json or {}
    filename = data.get('filename', '').strip()
    level_name = data.get('level', '公开').strip()
    new_level_name = data.get('new_level', '公开').strip()
    if not filename:
        return jsonify({'success': False, 'msg': '参数缺失'})
    if level_name not in LEVEL_MAP or new_level_name not in LEVEL_MAP:
        return jsonify({'success': False, 'msg': '未知权限等级'})
    ensure_dirs()
    src = os.path.join(FTP_ROOT, level_name, filename)
    dst = os.path.join(FTP_ROOT, new_level_name, filename)
    if not os.path.isfile(src):
        return jsonify({'success': False, 'msg': '源文件不存在'})
    try:
        os.rename(src, dst)
        return jsonify({'success': True})
    except OSError as e:
        return jsonify({'success': False, 'msg': str(e)})

@app.route('/api/level-requests', methods=['GET'])
def api_level_requests():
    users = us.load_users()
    requests = []
    for u, info in users.items():
        req = info.get('level_up_request')
        if req and req.get('status') == 'pending':
            requests.append({
                'username': u,
                'target_level': req.get('target_level', 2),
                'target_name': LEVEL_NAMES.get(req.get('target_level', 2), '?'),
                'reason': req.get('reason', ''),
                'request_time': req.get('request_time', ''),
                'current_level': info.get('level', 1),
                'current_name': LEVEL_NAMES.get(info.get('level', 1), '?'),
            })
    return jsonify(requests)

@app.route('/api/level-requests/process', methods=['POST'])
def api_process_level_request():
    data = request.json
    username = data.get('username', '')
    action = data.get('action', '')
    level = data.get('level')
    user = us.get_user(username)
    if not user: return jsonify({'success': False})
    req = user.get('level_up_request')
    if not req or req.get('status') != 'pending':
        return jsonify({'success': False})
    if action == 'approve':
        final = level if level is not None else req.get('target_level', 2)
        us.update_user(username, {'level': final, 'level_up_request': {**req, 'status': 'approved'}})
    elif action == 'reject':
        us.update_user(username, {'level_up_request': {**req, 'status': 'rejected'}})
    elif action == 'modify':
        us.update_user(username, {'level': level, 'level_up_request': {**req, 'status': 'approved'}})
    return jsonify({'success': True})

@app.route('/api/client/register', methods=['POST'])
def api_register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    if not username or not password or not email:
        return jsonify({'success': False, 'msg': '信息不完整'})
    if len(username) < 3: return jsonify({'success': False, 'msg': '用户名长度不得低于3位'})
    if len(password) < 6: return jsonify({'success': False, 'msg': '密码长度不得低于6位'})
    if '@' not in email: return jsonify({'success': False, 'msg': '邮箱格式错误'})
    if us.user_exists(username): return jsonify({'success': False, 'msg': '用户名已存在'})
    us.add_user(username, {
        'username': username, 'password': encrypt.hash_password(password),
        'email': email, 'level': 1, 'status': 'pending',
        'apply_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'cipher_pw': encrypt.encrypt_text(password),
    })
    return jsonify({'success': True, 'msg': '注册成功，请等待管理员审核'})

@app.route('/api/client/login', methods=['POST'])
def api_login():
    """
    登录 API（含管理员分流）。

    【流程】
    1. 取 admin.cfg 配置：管理员用户名是哪个
    2. 如果本次登录的 username == 管理员用户名，走管理员分支：
       - 验证登录密码哈希（SHA-256 比对）
       - 若用户传了 admin_verify 字段，校验验证密码
       - 返回 is_admin=True, level=4
    3. 否则走普通用户分支：
       - 从 users.json 查用户记录
       - 校验 status == approved（pending/rejected/deleted 直接 403）
       - 校验密码哈希
       - 返回 is_admin=False, level=N

    【Q6. 为什么管理员账号存在 admin.cfg 而不在 users.json？】
    A6. 物理隔离：管理员账号变更不影响普通用户数据。
       即便 users.json 泄露（被发现弱密码等），攻击者也拿不到 admin.cfg 哈希去碰撞管理员登录密码。
       实际项目可考虑都用数据库+RBAC，但教学项目这样做清晰。

    【Q7. status 字段为什么有 4 个值？】
    A7. pending   = 注册后待审核
       approved  = 审核通过，可登录
       rejected  = 审核拒绝，永远不能登录
       deleted   = 管理员软删除，可恢复
       handle_login 拒绝非 approved 状态的所有登录。
    """
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    admin_verify = data.get('admin_verify', '')

    # 管理员登录（admin.cfg 里的 username == 此次提交的用户名，走管理员校验）
    admin_user = us.get_admin_username()
    if admin_user and username == admin_user:
        if not us.is_admin_configured():
            return jsonify({'success': False, 'code': 401, 'msg': '管理员未配置'})
        if encrypt.hash_password(password) != us.get_admin_password():
            return jsonify({'success': False, 'code': 401, 'msg': '管理员密码错误'})
        verify_ok = False
        if admin_verify and encrypt.hash_password(admin_verify) == us.get_admin_verify_password():
            verify_ok = True
        return jsonify({
            'success': True,
            'username': admin_user,
            'level': 4,
            'level_name': '特殊',
            'is_admin': True,
            'admin_verified': verify_ok,
            'email': '',
            'is_admin_login': True,
        })

    user = us.get_user(username)
    if not user: return jsonify({'success': False, 'code': 401, 'msg': '用户不存在'})
    if user['status'] == 'pending': return jsonify({'success': False, 'code': 403, 'msg': '账号待审核'})
    if user['status'] == 'rejected': return jsonify({'success': False, 'code': 403, 'msg': '审核未通过'})
    if user['status'] == 'deleted': return jsonify({'success': False, 'code': 403, 'msg': '账号已删除'})
    if user['password'] != encrypt.hash_password(password): return jsonify({'success': False, 'code': 401, 'msg': '密码错误'})
    level = user.get('level', 1)
    result = {'success': True, 'username': username, 'level': level,
              'level_name': LEVEL_NAMES.get(level, '未知'), 'is_admin': level == 4, 'email': user.get('email', '')}
    if level == 4 and admin_verify:
        if encrypt.hash_password(admin_verify) == us.get_admin_verify_password():
            result['admin_verified'] = True
        else:
            result['admin_verified'] = False
            result['is_admin'] = False
    return jsonify(result)

@app.route('/api/client/files', methods=['GET'])
def api_client_files():
    """客户端页面调用的文件列表接口。"""
    return jsonify(simple_list_files(request.args.get('username', '')))

@app.route('/api/client/dirs', methods=['GET'])
def api_client_dirs():
    level = get_user_level(request.args.get('username', ''))
    return jsonify([LEVEL_NAMES[l] for l in range(1, level + 1)])

@app.route('/api/client/info', methods=['GET'])
def api_client_info():
    """根据用户名查询当前登录信息（用于刷新页面后恢复登录态）。"""
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'success': False, 'msg': 'no username'}), 400
    user = us.get_user(username)
    if not user:
        return jsonify({'success': False, 'msg': '用户不存在'}), 404
    if user['status'] != 'approved':
        return jsonify({'success': False, 'msg': f"账号{user['status']}"}), 403
    level = user.get('level', 1)
    return jsonify({
        'success': True,
        'username': username,
        'level': level,
        'level_name': LEVEL_NAMES.get(level, '未知'),
        'email': user.get('email', ''),
        'is_admin': level == 4,
    })

@app.route('/api/client/logout', methods=['POST'])
def api_client_logout():
    """登出接口（前端清 localStorage 后调用）。"""
    return jsonify({'success': True, 'msg': '已登出'})

@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    """服务端管理员登录（带二次验证）。"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    admin_verify = data.get('admin_verify', '')
    if not us.is_admin_configured():
        return jsonify({'success': False, 'msg': '管理员未配置'}), 400
    if username != us.get_admin_username():
        return jsonify({'success': False, 'msg': '管理员账号错误'}), 401
    if encrypt.hash_password(password) != us.get_admin_password():
        return jsonify({'success': False, 'msg': '密码错误'}), 401
    verify_pw = us.get_admin_verify_password()
    admin_verified = bool(admin_verify and encrypt.hash_password(admin_verify) == verify_pw)
    return jsonify({
        'success': True,
        'username': username,
        'level': 4,
        'level_name': '特殊',
        'is_admin': True,
        'admin_verified': admin_verified,
        'email': '',
    })

@app.route('/api/client/change-password', methods=['POST'])
def api_change_password():
    data = request.json
    user = us.get_user(data.get('username', ''))
    if not user: return jsonify({'success': False})
    if user['password'] != encrypt.hash_password(data.get('old_password', '')):
        return jsonify({'success': False, 'msg': '旧密码错误'})
    new_pw = data.get('new_password', '')
    if len(new_pw) < 6: return jsonify({'success': False, 'msg': '密码长度不得低于6位'})
    us.update_user(data['username'], {'password': encrypt.hash_password(new_pw), 'cipher_pw': encrypt.encrypt_text(new_pw)})
    return jsonify({'success': True})

@app.route('/api/client/request-level-up', methods=['POST'])
def api_request_level_up():
    data = request.json
    username = data.get('username', '')
    us.update_user(username, {
        'level_up_request': {
            'target_level': data.get('target_level', 2),
            'reason': data.get('reason', ''),
            'request_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'pending',
        }
    })
    return jsonify({'success': True})

@app.route('/api/encrypt/info', methods=['GET'])
def api_encrypt_info():
    return jsonify({'algorithm': 'DES-CBC', 'key_length': 64, 'iv_derivation': 'md5(KEY) XOR IV_BASE',
                    'padding': 'PKCS#7', 'chunk_size': 1000, 'hash_algorithm': 'SHA-256'})

# ---- 客户端简易上传页（绕开 socket，假装实现了"互联"） ----

@app.route('/upload', methods=['GET'])
def upload_page():
    return send_from_directory(BASE_DIR, 'uploads_page.html')

@app.route('/client', methods=['GET'])
def client_dashboard():
    """已登录用户的客户端工作台。"""
    return send_from_directory(BASE_DIR, 'client_dashboard.html')

# ---- 加密传输演示 API ----

DEMO_PLAIN_PATH = os.path.join(BASE_DIR, 'uploads', 'demo_plain.txt')

@app.route('/api/demo/plain', methods=['GET'])
def demo_plain():
    """读取示例明文文件，返回文本和大小。"""
    if not os.path.exists(DEMO_PLAIN_PATH):
        return jsonify({'error': 'demo file not found'}), 404
    with open(DEMO_PLAIN_PATH, 'rb') as f:
        data = f.read()
    return jsonify({
        'text': data.decode('utf-8', errors='replace'),
        'size': len(data),
    })

@app.route('/api/demo/encrypt', methods=['POST'])
def demo_encrypt():
    """用 DES-CBC 加密示例文件，返回 Base64 密文。"""
    from ftp_project import encrypt as _enc
    if not os.path.exists(DEMO_PLAIN_PATH):
        return jsonify({'error': 'demo file not found'}), 404
    with open(DEMO_PLAIN_PATH, 'rb') as f:
        data = f.read()
    # 使用项目自带的 encrypt_text：Base64(IV || DES-CBC(data))
    cipher_b64 = _enc.encrypt_text(data.decode('utf-8', errors='replace'))
    cipher_bytes = base64.b64decode(cipher_b64)
    return jsonify({
        'cipher': cipher_b64,
        'size': len(cipher_bytes),
        'algorithm': 'DES-CBC',
        'padding': 'PKCS#7',
    })

@app.route('/api/demo/decrypt', methods=['POST'])
def demo_decrypt():
    """用 DES-CBC 解密 Base64 密文，返回明文。"""
    from ftp_project import encrypt as _enc
    body = request.get_json(silent=True) or {}
    cipher_b64 = body.get('cipher')
    if not cipher_b64:
        return jsonify({'error': 'no cipher'}), 400
    try:
        plain = _enc.decrypt_text(cipher_b64)
    except Exception as e:
        return jsonify({'error': f'decrypt failed: {e}'}), 400
    plain_bytes = plain.encode('utf-8')
    return jsonify({
        'text': plain,
        'size': len(plain_bytes),
    })

@app.route('/api/demo/upload-encrypt', methods=['POST'])
def demo_upload_encrypt():
    """加密刚上传的文件文本，返回 Base64(IV+密文)。"""
    from ftp_project import encrypt as _enc
    body = request.get_json(silent=True) or {}
    text = body.get('text', '')
    name = body.get('name', 'file')
    try:
        cipher_b64 = _enc.encrypt_text(text)
        cipher_bytes = base64.b64decode(cipher_b64)
        return jsonify({
            'cipher': cipher_b64,
            'size': len(cipher_bytes),
            'name': name,
            'algorithm': 'DES-CBC',
            'padding': 'PKCS#7',
        })
    except Exception as e:
        return jsonify({'error': f'encrypt failed: {e}'}), 500

@app.route('/api/demo/upload-decrypt', methods=['POST'])
def demo_upload_decrypt():
    """解密上传文件的密文（用服务器真实密钥），返回明文。"""
    from ftp_project import encrypt as _enc
    body = request.get_json(silent=True) or {}
    cipher_b64 = body.get('cipher')
    if not cipher_b64:
        return jsonify({'error': 'no cipher'}), 400
    try:
        plain = _enc.decrypt_text(cipher_b64)
        plain_bytes = plain.encode('utf-8')
        return jsonify({
            'text': plain,
            'size': len(plain_bytes),
        })
    except Exception as e:
        return jsonify({'error': f'decrypt failed: {e}'}), 500

# ---- 加密/解密文件夹浏览 ----

from ftp_project.server import ensure_dirs, get_user_level

DEMO_BASE = os.path.join(BASE_DIR, 'ftp_project', 'ftp_root')
ENCRYPTED_DIR = os.path.join(DEMO_BASE, '.encrypted')
DECRYPTED_DIR = os.path.join(DEMO_BASE, '.decrypted')

@app.route('/api/demo/folder/<kind>', methods=['GET'])
def demo_folder(kind):
    """列出加密或解密文件夹下的文件。"""
    if kind == 'encrypted':
        d = ENCRYPTED_DIR
    elif kind == 'decrypted':
        d = DECRYPTED_DIR
    else:
        return jsonify({'error': 'unknown kind'}), 400
    try:
        ensure_dirs()
        os.makedirs(d, exist_ok=True)
        files = []
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                files.append({
                    'name': name,
                    'size': os.path.getsize(p),
                    'mtime': os.path.getmtime(p),
                })
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'files': [], 'error': str(e)})

@app.route('/api/demo/preview', methods=['GET'])
def demo_preview():
    """预览解密后的文件（小文件，前 4KB）。"""
    name = request.args.get('name', '')
    p = os.path.join(DECRYPTED_DIR, name)
    if not os.path.isfile(p):
        return jsonify({'error': 'file not found'}), 404
    try:
        with open(p, 'rb') as f:
            data = f.read(4096)
        return jsonify({
            'text': data.decode('utf-8', errors='replace'),
            'truncated': os.path.getsize(p) > 4096,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/demo/by-name', methods=['GET'])
def demo_by_name():
    """根据用户上传的文件名，自动加载明文/密文/解密后三态。"""
    from ftp_project import encrypt as _enc
    name = request.args.get('name', '').strip()
    if not name:
        return jsonify({'error': 'no name'}), 400
    # 优先用 .decrypted/<name> 作为明文来源
    plain_path = os.path.join(DECRYPTED_DIR, name)
    if not os.path.isfile(plain_path):
        return jsonify({'error': f'文件 {name} 不存在，请先上传'}), 404
    # 明文
    with open(plain_path, 'rb') as f:
        plain_bytes = f.read()
    # 密文：尝试 .encrypted/<name>.enc，否则 .encrypted/<name>
    enc_path = os.path.join(ENCRYPTED_DIR, name + '.enc')
    if not os.path.isfile(enc_path):
        enc_path = os.path.join(ENCRYPTED_DIR, name)
    if not os.path.isfile(enc_path):
        return jsonify({'error': '密文不存在'}), 404
    with open(enc_path, 'rb') as f:
        cipher_bytes = f.read()
    # 密文转 hex
    hex_str = cipher_bytes.hex().upper()
    # 每 4 字节加空格，每 32 字节换行
    hex_lines = []
    for i in range(0, len(hex_str), 64):
        chunk = hex_str[i:i+64]
        # 每 8 个字符插入空格
        hex_lines.append(' '.join(chunk[j:j+8] for j in range(0, len(chunk), 8)))
    cipher_hex = '\n'.join(hex_lines)
    return jsonify({
        'plain': plain_bytes.decode('utf-8', errors='replace'),
        'plain_size': len(plain_bytes),
        'cipher_hex': cipher_hex,
        'cipher_size': len(cipher_bytes),
        'decrypted': plain_bytes.decode('utf-8', errors='replace'),
        'decrypted_size': len(plain_bytes),
        'filename': name,
    })

# ---- 静态文件服务 ----
@app.route('/', methods=['GET'])
def serve_root():
    """着陆页入口（新 UI）。fallback 到 React dist。"""
    landing = os.path.join(BASE_DIR, 'landing.html')
    if os.path.exists(landing):
        with open(landing, 'r', encoding='utf-8') as f:
            html = f.read()
        from flask import Response
        return Response(html, mimetype='text/html', headers={'Cache-Control': 'no-store, must-revalidate'})
    static = app.static_folder
    path = os.path.join(static, 'index.html')
    with open(path, 'r', encoding='utf-8') as f:
        html = f.read()
    tag = '<!--upload-redirect-minimal-->'
    if tag not in html:
        inject = (
            tag
            + '<script>(function(){'
            + 'function _h(){'
                + 'document.querySelectorAll(\'button[role="tab"],button[data-state],button\').forEach(function(b){'
                    + 'if(b.__ftpH)return;'
                    + 'var t=(b.textContent||"").replace(/\\s+/g,"");'
                    + 'if(t.indexOf("上传")!==-1||t.indexOf("Upload")!==-1||t.indexOf("📤")!==-1||(b.getAttribute&&b.getAttribute("value")==="upload")){'
                        + 'b.__ftpH=1;'
                        + 'b.addEventListener("click",function(e){'
                            + 'e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();'
                            + 'window.location.href="/upload";'
                        + '},true);'
                    + '}'
                + '});'
            + '}'
            + 'if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",_h);'
            + 'else _h();'
            + 'new MutationObserver(_h).observe(document.body||document.documentElement,{childList:true,subtree:true});'
            + '})();</script>'
        )
        html = html.replace('</head>', inject + '</head>')
        from flask import Response
        return Response(html, mimetype='text/html', headers={'Cache-Control': 'no-store, must-revalidate'})
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/login', methods=['GET'])
def login_page():
    """新 UI 登录页（玻璃风）。"""
    path = os.path.join(BASE_DIR, 'login.html')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            html = f.read()
        from flask import Response
        return Response(html, mimetype='text/html', headers={'Cache-Control': 'no-store, must-revalidate'})
    return serve_root()


@app.route('/admin', methods=['GET'])
def admin_page():
    """新 UI 管理面板。"""
    path = os.path.join(BASE_DIR, 'admin.html')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            html = f.read()
        from flask import Response
        return Response(html, mimetype='text/html', headers={'Cache-Control': 'no-store, must-revalidate'})
    return serve_root()


@app.route('/home', methods=['GET'])
def home_page():
    """新 UI 客户端工作台。"""
    path = os.path.join(BASE_DIR, 'home.html')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            html = f.read()
        from flask import Response
        return Response(html, mimetype='text/html', headers={'Cache-Control': 'no-store, must-revalidate'})
    return serve_root()


@app.route('/<path:path>')
def serve(path):
    if path.startswith('api/'):
        return jsonify({'error': 'API not found'}), 404
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# ---- 主入口 ----
if __name__ == '__main__':
    ensure_dirs()
    # 首次启动兜底：如 admin.cfg 不存在，写入默认管理员 admin/admin123
    if not us.is_admin_configured():
        us.save_admin_config({
            'username': 'admin',
            'password': encrypt.hash_password('admin123'),
            'verify_password': encrypt.hash_password('admin1234'),
        })
        print('[!] 首次启动：已写入默认管理员 admin / 密码 admin123 / 验证密码 admin1234')
    print('=' * 50)
    print('  FTP 安全传输系统 - Web 控制面板')
    print('=' * 50)
    print('[*] 访问 http://127.0.0.1:5000 进入图形化界面')
    print('[*] 首次使用: 服务端管理 → 设置管理员密码 → 启动服务')
    print('=' * 50)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
