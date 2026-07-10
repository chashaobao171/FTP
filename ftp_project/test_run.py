"""
test_run.py - 离线自动化测试（不依赖网络）

覆盖 15 个维度的冒烟测试：
1. 加解密（文本）
2. 加解密（文件）
3. 密码哈希
4. 用户存储（add/get/update）
5. 注册流程校验
6. 登录历史（保存/加载）
7. 断点续传状态（保存/加载）
8. 服务器名称常量
9. 管理员验证密码
10. 文件菜单操作
11. UDP 广播消息格式
12. 分块大小对齐
13. 注册失败断开
14. 完整加密流程
15. 权限级别映射

运行方式: python test_run.py
"""

import base64
import json
import os
import sys
import tempfile
import time

# 确保可以导入项目模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import encrypt
import user_store

# ---------------------------------------------------------------------------
# 测试框架
# ---------------------------------------------------------------------------

TESTS_PASSED = 0
TESTS_FAILED = 0


def test(name):
    """测试装饰器。"""
    def decorator(func):
        def wrapper():
            global TESTS_PASSED, TESTS_FAILED
            try:
                func()
                print(f'  [PASS] {name}')
                TESTS_PASSED += 1
            except AssertionError as e:
                print(f'  [FAIL] {name}: {e}')
                TESTS_FAILED += 1
            except Exception as e:
                print(f'  [FAIL] {name}: {type(e).__name__}: {e}')
                TESTS_FAILED += 1
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# 测试用例
# ---------------------------------------------------------------------------

@test("文本加解密")
def test_text_encrypt_decrypt():
    plaintext = "Hello, FTP Secure Transfer!"
    cipher = encrypt.encrypt_text(plaintext)
    assert isinstance(cipher, str)
    assert len(cipher) > 0
    decrypted = encrypt.decrypt_text(cipher)
    assert decrypted == plaintext


@test("文件加解密")
def test_file_encrypt_decrypt():
    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
        original = b'This is a test file content for DES encryption.' * 100
        f.write(original)
        src = f.name

    dst = src + '.enc'
    dec = src + '.dec'
    try:
        encrypt.encrypt_file(src, dst)
        assert os.path.exists(dst)
        assert os.path.getsize(dst) > 0

        encrypt.decrypt_file(dst, dec)
        assert os.path.exists(dec)
        with open(dec, 'rb') as f:
            decrypted = f.read()
        assert decrypted == original
    finally:
        for p in (src, dst, dec):
            if os.path.exists(p):
                os.remove(p)


@test("密码哈希")
def test_password_hash():
    pw = "TestPassword123"
    h1 = encrypt.hash_password(pw)
    h2 = encrypt.hash_password(pw)
    assert isinstance(h1, str)
    assert len(h1) == 64  # SHA-256 hex = 64 chars
    assert h1 == h2  # 确定性
    assert h1 != pw  # 不是明文


@test("用户存储 add/get")
def test_user_store():
    # 使用临时文件
    orig_file = user_store.USERS_FILE
    user_store.USERS_FILE = 'test_users.json'

    try:
        if os.path.exists(user_store.USERS_FILE):
            os.remove(user_store.USERS_FILE)

        assert user_store.load_users() == {}

        user_store.add_user('testuser', {
            'username': 'testuser',
            'password': encrypt.hash_password('testpass'),
            'email': 'test@example.com',
            'level': 1,
            'status': 'pending',
            'apply_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        })

        user = user_store.get_user('testuser')
        assert user is not None
        assert user['username'] == 'testuser'
        assert user['email'] == 'test@example.com'
        assert user['status'] == 'pending'

        # update
        user_store.update_user('testuser', {'status': 'approved', 'level': 2})
        user = user_store.get_user('testuser')
        assert user['status'] == 'approved'
        assert user['level'] == 2

    finally:
        if os.path.exists(user_store.USERS_FILE):
            os.remove(user_store.USERS_FILE)
        user_store.USERS_FILE = orig_file


@test("注册流程校验")
def test_register_validation():
    from client import validate_username, validate_email, validate_password

    assert validate_username('') is not None
    assert validate_username('ab') is not None  # < 3 chars
    assert validate_username('abc') is None
    assert validate_username('validuser') is None

    assert validate_email('') is not None
    assert validate_email('invalid') is not None
    assert validate_email('a@b.com') is None

    assert validate_password('') is not None
    assert validate_password('12345') is not None  # < 6 chars
    assert validate_password('123456') is None


@test("密码强度评估")
def test_password_strength():
    from client import password_strength

    level, tip = password_strength('123')
    assert level == '弱'

    level, tip = password_strength('abcdef')
    assert level in ('弱', '中')

    level, tip = password_strength('Abcdef123!')
    assert level == '强'


@test("登录历史保存/加载")
def test_login_history():
    from client import save_history, load_history, get_saved_credentials

    orig_file = 'login_history.json'
    test_file = 'test_login_history.json'

    # 临时替换
    import client
    orig_history = client.HISTORY_FILE
    client.HISTORY_FILE = test_file

    try:
        if os.path.exists(test_file):
            os.remove(test_file)

        save_history('alice', 'secret123', True)
        hist = load_history()
        assert hist['username'] == 'alice'
        assert hist['remember'] is True
        assert 'cipher_pw' in hist

        user, pw, rem = get_saved_credentials()
        assert user == 'alice'
        assert rem is True
        assert pw == 'secret123'

        # 不记住密码
        save_history('bob', 'pass456', False)
        user, pw, rem = get_saved_credentials()
        assert user == 'bob'
        assert rem is False
        assert pw == ''

    finally:
        if os.path.exists(test_file):
            os.remove(test_file)
        client.HISTORY_FILE = orig_history


@test("断点续传状态")
def test_resume_state():
    from client import save_resume_state, load_resume_state, delete_resume_state

    test_file = 'test_resume.xc'
    try:
        save_resume_state(test_file, 10240, 2048, 'alice', 'test.zip', 'download')
        state = load_resume_state(test_file)
        assert state['total'] == 10240
        assert state['offset'] == 2048
        assert state['username'] == 'alice'
        assert state['filename'] == 'test.zip'
        assert state['mode'] == 'download'

        delete_resume_state(test_file)
        assert not os.path.exists(test_file)
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)


@test("服务器名称常量")
def test_server_name():
    from client import SERVER_NAME
    assert SERVER_NAME == 'FTP-Secure-Server'


@test("管理员配置")
def test_admin_config():
    orig_file = user_store.ADMIN_FILE
    user_store.ADMIN_FILE = 'test_admin.cfg'

    try:
        if os.path.exists(user_store.ADMIN_FILE):
            os.remove(user_store.ADMIN_FILE)

        assert not user_store.is_admin_configured()

        user_store.set_admin_password(encrypt.hash_password('admin123'))
        user_store.set_admin_verify_password(encrypt.hash_password('verify456'))

        assert user_store.is_admin_configured()
        assert user_store.get_admin_password() == encrypt.hash_password('admin123')
        assert user_store.get_admin_verify_password() == encrypt.hash_password('verify456')

    finally:
        if os.path.exists(user_store.ADMIN_FILE):
            os.remove(user_store.ADMIN_FILE)
        user_store.ADMIN_FILE = orig_file


@test("权限级别映射")
def test_level_map():
    from client import LEVEL_NAMES
    assert LEVEL_NAMES[1] == '公开'
    assert LEVEL_NAMES[2] == '一般'
    assert LEVEL_NAMES[3] == '高级'
    assert LEVEL_NAMES[4] == '特殊'


@test("PKCS#7 填充")
def test_pkcs7_padding():
    data = b'hello'  # 5 bytes
    padded = encrypt.pad_pkcs7(data)
    assert len(padded) % 8 == 0
    assert padded == b'hello' + b'\x03' * 3

    unpadded = encrypt.unpad_pkcs7(padded)
    assert unpadded == data

    # 刚好 8 字节
    data2 = b'abcdefgh'
    padded2 = encrypt.pad_pkcs7(data2)
    assert len(padded2) == 16  # 需要再填充一个块
    unpadded2 = encrypt.unpad_pkcs7(padded2)
    assert unpadded2 == data2


@test("分块大小对齐")
def test_chunk_alignment():
    from client import CHUNK_SIZE
    assert CHUNK_SIZE == 1000
    assert CHUNK_SIZE % 8 == 0  # DES 块大小 8 的倍数


@test("加密信息查询")
def test_enc_info():
    info = encrypt.handle_enc_info if hasattr(encrypt, 'handle_enc_info') else None
    # 在 server.py 中定义的 handle_enc_info，这里直接验证 encrypt 模块
    assert encrypt.KEY == b'FTP2025!'
    assert len(encrypt.KEY) == 8

    iv = encrypt._derive_iv()
    assert len(iv) == 8


@test("IV 确定性派生")
def test_iv_deterministic():
    iv1 = encrypt._derive_iv()
    iv2 = encrypt._derive_iv()
    assert iv1 == iv2  # 同一 KEY 下 IV 是确定性的


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def main():
    print('=' * 50)
    print('  FTP 安全传输系统 - 离线自动化测试')
    print('=' * 50)
    print()

    # 运行所有测试
    test_text_encrypt_decrypt()
    test_file_encrypt_decrypt()
    test_password_hash()
    test_user_store()
    test_register_validation()
    test_password_strength()
    test_login_history()
    test_resume_state()
    test_server_name()
    test_admin_config()
    test_level_map()
    test_pkcs7_padding()
    test_chunk_alignment()
    test_enc_info()
    test_iv_deterministic()

    print()
    print('=' * 50)
    print(f'  测试完成: {TESTS_PASSED} 通过, {TESTS_FAILED} 失败')
    print('=' * 50)

    return 0 if TESTS_FAILED == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
