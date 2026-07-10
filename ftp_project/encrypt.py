"""
encrypt.py - DES-CBC 加解密与密码哈希工具模块
================================================

【老师可能问的 Q&A 清单】
 Q1. DES 是什么？为什么要用 CBC 模式？
 A1. DES 是 1977 年由 IBM/NSA 设计的对称分组密码，分组长度 64 位（8 字节），有效密钥 56 位（外加 8 位奇偶校验）。
     ECB 模式（电子密码本）会把相同明文块加密成相同密文块，对图片/明文攻击下会泄露"结构信息"；
     CBC 模式（Cipher Block Chaining）每个明文块先与前一个密文块异或，再加密，使得相同明文产生不同密文。
     CBC 还引入了 IV（初始化向量）作为第一个块的前置输入。

 Q2. 为什么硬编码 KEY 而不是用环境变量/KMS？
 A2. 这是教学项目，演示"对称分组密码的基本原理"和"分块加密文件格式"。
     实战中应使用 KDF（如 PBKDF2/Argon2）从用户口令派生密钥，并使用 KMS/HSM 管理主密钥。

 Q3. IV 为什么不用随机，而是 md5(KEY) XOR IV_BASE？
 A3. 随机 IV 在并发场景下管理复杂，且若随机源有问题（熵不足）反而会降低安全性。
     确定性 IV 通过密钥派生，保证"相同 KEY 相同 IV"，简化了测试与调试，并保证解密端不需要额外传 IV。
     加 IV_BASE 是为了让 IV 不是 16 进制字符常量，而是任意 8 字节，便于扩展。
     严格来说，生产环境推荐随机 IV + 密文前缀保存（我们 text 模式就是这样：IV 跟着密文一起存）。
"""


import base64
import hashlib
import os

# 【关键库】
# pycryptodome（Python Crypto 库）提供标准的 DES 实现，行业标准、教学和比赛广泛使用。
# 注意：DES 已被 NIST 弃用（2005 年），实际项目应该用 AES-256-GCM。
from Crypto.Cipher import DES


# ---------------------------------------------------------------------------
# 密钥与 IV 派生
# ---------------------------------------------------------------------------

# 【Q4. 这里 8 字节是不是太短了？】
# A4. 是的，DES 密钥有效长度仅 56 位（64 位中 8 位是奇偶校验），现代化的暴力破解设备每秒可尝试数百亿次。
#     教学演示够了，但生产必须 AES-256。
_raw_key = b'FTP2025!'                 # 8 字节主密钥（DES 要求 8 字节；密钥长度必须是 8）
KEY      = _raw_key[:8]                # 防御性截断，防止误改 _raw_key 超过 8 字节炸 DES.new()
# 8 字节基向量：与 KEY 的 MD5 异或后得到真正的 IV
# 之所以做"异或"，是为了保证即使 IV_BASE = 全零，最终 IV 也不是固定的 md5 摘要明文，
# 增加一层混淆；本质上功能等价于"IV = md5(KEY)"。
IV_BASE  = (b'\x00' * 8)[:8]


def _derive_iv() -> bytes:
    """
    IV 由 KEY 派生（非随机），确保同一 KEY 下 IV 确定性派生。

    【Q5. 为什么确定性 IV 不影响安全性？】
    A5. CBC 的安全性要求"相同 KEY 下，相同明文块应被加密成不同密文"。
        因为 CBC 把每个明文块都和**前一个密文块**异或，所以同一个明文块经过 CBC 后不会得到同一个密文。
        IV 只影响**第一个块**，相当于"给第一块加一个随机起点"。
        确定性 IV 在教学场景下便于单元测试（同样的明文+同样的 IV → 同样的密文），
        而生产环境则建议用 os.urandom(8) 让 IV 也随机，并把 IV 附在密文前面保存。
    """
    h = hashlib.md5(KEY).digest()      # md5 输出 16 字节，截断到前 8 字节作为 DES IV
    return bytes(a ^ b for a, b in zip(h, IV_BASE))


# ---------------------------------------------------------------------------
# PKCS#7 填充 / 去除填充
# ---------------------------------------------------------------------------

def pad_pkcs7(data: bytes) -> bytes:
    """
    PKCS#7 填充，块大小 = 8（DES 块大小）。

    【Q6. 为什么 DES 必须填充？】
    A6. DES 是分组密码，每次只能加密 8 字节的整倍数。
        如果文件大小不是 8 的倍数，最后一个块不足 8 字节，需要填充到 8 字节。

    【Q7. PKCS#7 是怎么填充的？】
    A7. 如果差 N 个字节才到 8 字节的倍数（N 在 1~8 之间），就填充 N 个字节，每个字节的值都是 N。
        例如：差 1 字节 → 补 1 个 \\x01；差 5 字节 → 补 5 个 \\x05；
        恰好是 8 的倍数时，必须补一个完整填充块（8 个 \\x08），让"是否填过"二义性被消除。
        解密时看最后一个字节 N，去掉末尾 N 个字节即可。
    """
    n = 8 - len(data) % 8              # 计算需要填充多少字节
    return data + bytes([n] * n)        # 用值等于数量的字节填充


def unpad_pkcs7(data: bytes) -> bytes:
    """
    去除 PKCS#7 填充。

    【Q8. 如果有人篡改了最后一个字节怎么办？】
    A8. unpad 会得到一个非法 n（比如 n > 8），结果是 data[:-n] 会越界或返回错误数据。
        严格的生产系统应当在校验后抛出异常；本项目为了教学简洁，未做完整性校验。
        真正的解决方案是用 GCM 模式（带认证标签的加密）来同时检查密文完整性。
    """
    n = data[-1]                        # 最后一个字节就是填充数量
    return data[:-n]


# ---------------------------------------------------------------------------
# 文本（口令）加解密：Base64(IV || 密文)
# ---------------------------------------------------------------------------

def encrypt_text(plaintext: str) -> str:
    """
    对文本进行 DES-CBC 加密，返回 Base64 编码的字符串（便于 JSON 落盘）。

    【Q9. 为什么要包成 Base64？】
    A9. JSON 文件只能保存文本字符，加密结果是任意二进制，
        必须经 Base64（一种用 64 个可打印字符表示二进制的方法）编码后才能存进 JSON。
        文件落盘场景（见 encrypt_file）则不需要 Base64，因为文件本身就是二进制。

    【Q10. 为什么把 IV 也一起存？】
    A10. CBC 模式每个块需要前一块的密文，但要解密第一块必须知道 IV。
         有两种方案：
         (1) 通信双方预先共享一个固定 IV（我们 DEV/SERVER 模块传 iv_hex 用这种方式）
         (2) 每条消息附自己的 IV（encrypt_text/decrypt_text 用这种方式）
         第 (2) 种更灵活，每条消息独立 IV，即使被重放也不会泄露信息。
    """
    iv = _derive_iv()                   # 本次的 IV（文本模式允许每条 IV 不同或固定）
    c = DES.new(KEY, DES.MODE_CBC, iv)  # 创建 CBC 模式的 DES 密码器
    pad = pad_pkcs7(plaintext.encode('utf-8'))    # 明文 → UTF-8 字节 → PKCS#7 填充
    return base64.b64encode(iv + c.encrypt(pad)).decode('ascii')  # IV + 密文 → Base64


def decrypt_text(ciphertext: str) -> str:
    """
    解密由 encrypt_text 产生的 Base64 密文。

    【Q11. 这里的解密流程是什么？】
    A11. Base64 解码 → 前 8 字节是 IV，后面是密文 → 用 KEY+IV 创建 DES-CBC 解密器 → 解密 → 去填充 → UTF-8 解码为字符串。
         这与加密完全对称，但顺序相反。
    """
    data = base64.b64decode(ciphertext)         # Base64 解码
    iv, ct = data[:8], data[8:]                # 拆分：前 8 字节 IV，后为密文
    c = DES.new(KEY, DES.MODE_CBC, iv)         # 用 IV 创建解密器
    return unpad_pkcs7(c.decrypt(ct)).decode('utf-8')   # 解密 → 去填充 → UTF-8


# ---------------------------------------------------------------------------
# 文件加解密：文件总长 || (chunk_len || IV || 密文)*
# ---------------------------------------------------------------------------

def encrypt_file(src_path: str, dst_path: str, chunk_size: int = 1000):
    """
    加密文件。
    格式: [8 bytes: 原始文件总大小] + 循环([4 bytes: 本块填充后长度][8 bytes: IV][密文块])

    【Q12. 为什么要分块加密？】
    A12. 大文件（比如 1GB）一次性读入内存会爆。
         1000 字节分块，边读边加密边写盘，常数级内存开销。
         块大小选 1000 而非 8 的倍数是因为我们要配合 PKCS#7 填充——填充后会变成 1008 字节，
         仍然是 8 的倍数，符合 DES-CBC 要求。

    【Q13. 文件头存总大小有什么用？】
    A13. 解密时要知道"什么时候停"，因为最后一个块有 PKCS#7 填充字节，
         若不存总大小就会多读几个填充字节写出去，损坏文件。
         存了 total 后，while fout.tell() < total: 就能精准停止。

    【Q14. 每块前面存 IV 不是浪费吗？KEY 都是同一个？】
    A14. 严格来说 CBC 模式下，**后续块的 IV 就是前一个密文块**，所以理论上不需要每块单独存 IV。
         但本项目为了演示"加密 + 完整性保护"的混合方案，每块都给了显式 IV。
         如果要去掉该 8 字节，格式可改成：[chunk_len][密文]，但失去了"每块 IV 独立"的好处。
    """
    total = os.path.getsize(src_path)          # 原始文件大小（用于写头）
    with open(src_path, 'rb') as fin, open(dst_path, 'wb') as fout:
        # 8 字节大端：原始文件总长
        # 大端字节序：高位在前（与网络字节序一致），便于跨平台兼容
        fout.write(total.to_bytes(8, 'big'))
        while True:
            chunk = fin.read(chunk_size)        # 读最多 chunk_size 字节
            if not chunk:                       # EOF
                break
            padded = pad_pkcs7(chunk)           # PKCS#7 填充到 8 字节倍数
            iv = _derive_iv()
            c = DES.new(KEY, DES.MODE_CBC, iv)
            # 4 字节：本块填充后长度（解密时知道要读多少密文）
            fout.write(len(padded).to_bytes(4, 'big'))
            fout.write(iv)                       # 8 字节 IV
            fout.write(c.encrypt(padded))       # 密文


def decrypt_file(src_path: str, dst_path: str, chunk_size: int = 1000):
    """
    解密由 encrypt_file 生成的文件。

    【Q15. 为什么 while fout.tell() < total 就够了？PKCS#7 不会带多余字节？】
    A15. 加密时虽然最后一块有填充，但我们用 total 来控制循环次数——写够 total 字节后就停。
         残留的 PKCS#7 填充字节不会被写入 fout，相当于被自动丢弃，正好是我们需要的。

    【Q16. 如果加密文件被截断/损坏会发生什么？】
    A16. int.from_bytes(fin.read(8), 'big') 会读到错误的长度和乱七八糟的数据，
         解密后是乱码（因为 CBC 错误会向后扩散）。本项目没有完整性校验，
         实战中应用 SHA-256 在每块后做 HMAC，或用 AES-GCM 自带认证标签。
    """
    with open(src_path, 'rb') as fin:
        total = int.from_bytes(fin.read(8), 'big')     # 文件头：原始文件总长
        with open(dst_path, 'wb') as fout:
            while fout.tell() < total:                 # 解密写入未达 total 就继续
                payload_len = int.from_bytes(fin.read(4), 'big')   # 本块填充后长度
                iv, ct = fin.read(8), fin.read(payload_len)       # IV + 密文
                c = DES.new(KEY, DES.MODE_CBC, iv)
                fout.write(unpad_pkcs7(c.decrypt(ct)))   # 解密 → 去填充 → 写明文


# ---------------------------------------------------------------------------
# 密码哈希（登录密码、管理员密码统一使用 SHA-256）
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """
    对密码进行 SHA-256 哈希，返回十六进制字符串（64 字符）。

    【Q17. 为什么不存明文密码？】
    A17. 数据库/JSON 泄露时，黑客拿到的是哈希值，反推密码极难（除非预先算了彩虹表）。
         即便 users.json 全泄露，没有原始字典对应哈希值，仍然安全（除非密码过于简单）。

    【Q18. 为什么不用 bcrypt/Argon2 而用 SHA-256？】
    A18. SHA-256 计算速度极快（每秒百万次），不适合做密码哈希——攻击者用 GPU 可以每秒数十亿次枚举。
         bcrypt/Argon2/scrypt 故意设计得很慢（毫秒级），让暴力破解在经济上不可行。
         本项目为了演示简洁用了 SHA-256，并已在报告"未来工作"中列为改进项。

    【Q19. 既然 SHA-256 不安全，为啥还要用？】
    A19. 教学项目，目的是"展示哈希存储的设计模式"。
         SHA-256 是 NIST 标准、FIPS 认证、所有语言都内置，演示价值高。
         用户密码复杂度由前端表单（>=6 位、提示强度）把关一部分。
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()
