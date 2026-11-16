# Crypto 讲师解题步骤

## 环境与生成

```bash
cd crypto
./generate.sh            # 可重新生成 public/ciphertexts.json 和 leaked_memo.txt
python3 solve.py
```

生成脚本在 `instructor/make_challenge.py`，其中包含教学用密码、nonce 和 flag；
这些内容都不在 `public/` 中。`public/encrypt.py` 只展示构造，不含密码。

## 构造回顾

```text
keystream = SHA256(password || nonce || counter_be32) || ...
C = P xor keystream
```

同一个 nonce 下，两条消息的密钥流完全相同：

```text
C1 = P1 xor KS
C2 = P2 xor KS
C1 xor C2 = P1 xor P2
```

## 步骤 1：消掉密钥流

读取两条密文并 XOR。由于 `C_flag` 较短，只取同样长度：

```python
xored = bytes(a ^ b for a, b in zip(ct_flag, ct_memo))
# C_flag xor C_memo = P_flag xor P_memo
```

这一步之后，密码和 SHA-256 都不再需要。

## 步骤 2：用泄露明文恢复 flag

`leaked_memo.txt` 给出 `P_memo`，因此：

```text
P_flag = (P_flag xor P_memo) xor P_memo
       = xored xor P_memo
```

完整脚本见 `solve.py`，核心只有三行：

```python
ct_flag = base64.b64decode(payload["ciphertext_flag"])
ct_memo = base64.b64decode(payload["ciphertext_memo"])
recovered = bytes(a ^ b ^ c for a, b, c in zip(ct_flag, ct_memo, memo))
```

运行结果：

```text
[1] ciphertext lengths: flag=32, memo=56, nonce reused=Zml4ZWQtbm9uY2UtMDAxIQ==
[2] C_flag xor C_memo = 2b2924333220774e22677f3672223d1d7f20207a7a2c530b3b31527e7523263c
    recovered plaintext: b'flag{n0nc3_r3us3_br34ks_str34ms}'
[+] FLAG: flag{n0nc3_r3us3_br34ks_str34ms}
```

## 为什么这是“教学错误密码构造”

- 直接用 `SHA256(password || nonce || counter)` 作为流密码，缺少慢 KDF、完整性保护，
  且完全依赖 nonce 唯一性。
- 一旦 nonce 复用，得到的是两条明文的 XOR，而不是两条独立密文。
- 正确做法包括：每次加密使用唯一 nonce、使用 AEAD（如 AES-GCM/ChaCha20-Poly1305）、
  用 Argon2/scrypt/PBKDF2 做口令派生，并校验认证标签。

## 修复建议（讲师可讲）

- nonce 必须唯一；随机 96-bit nonce 对 GCM 足够，但要有碰撞监控。
- 不要把裸 SHA-256 当 KDF 或 MAC。
- 加密必须带认证，解密前先验 tag。
- 迁移脚本应在每次加密时生成新 nonce，并把 nonce 与密文一起存储。
