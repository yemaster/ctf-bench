# Reverse 讲师解题步骤

## 环境与构建

```bash
cd reverse
./build.sh              # 重新生成 instructor/src/secret.h 并编译 public/checker
python3 solve.py
```

`build.py` 读取 `instructor/flag.txt`，生成许可证数据块，写入
`instructor/src/secret.h`，再用 `gcc ... -s` 编译并去除符号。`public/` 中不含明文
key 或 flag。

## 步骤 1：确认二进制已去符号

```bash
file public/checker
# ... stripped
nm public/checker
# nm: public/checker: no symbols
readelf -SW public/checker | grep -E '\.(text|rodata)'
objdump -d -M intel public/checker | sed -n '1,160p'
```

程序仍然是 `-no-pie` 的普通 ELF，`.rodata` 可读。虽然函数名被去掉，检查循环和
数据引用仍然保留。

## 步骤 2：定位 `.rodata` 中的许可证数据块

`readelf -SW` 给出 `.rodata` 的文件偏移和大小。在这段数据中搜索 4 字节标记
`4c 33 56 52`（小端 `0x5256334c`），可以得到数据块起始位置。结构体布局为：

```c
typedef struct {
    unsigned int magic;          /* 0x5256334c */
    unsigned int key_len;        /* 固定长度，构建时写入 */
    unsigned int flag_len;
    unsigned char perm[KEYLEN];  /* 第一层：字节置换 */
    unsigned char target[KEYLEN];/* 第二层：链式异或目标 */
    unsigned char flag_enc[FLAGLEN];
} license_blob_t;
```

在本题构建产物中，数据块位于 `.rodata` 的文件偏移 `0x2020`，`key_len = 20`，
`flag_len = 25`：

```text
perm:   0b 03 12 00 0f 07 01 13 09 0c 04 10 06 02 0e 08 11 05 0d 0a
target: 5d 3b 07 ed c7 9b bf ec 79 4a 34 12 cd a8 e0 e6 6e 21 60 5c
```

`solve.py` 不读取 `secret.h` 或 `flag.txt`，而是用 `readelf` 找到 `.rodata`，
扫描标记，按 `key_len`/`flag_len` 切片，因此 flag 或 key 改变后仍可使用。

## 步骤 3：理解两层校验

第一层是字节置换：

```c
p[i] = key[perm[i]];
```

第二层是相邻字节链，`prev` 初始为 `0x5a`：

```c
v = p[i] ^ prev ^ ((i * 0x1d + 0x33) & 0xff);
if (v != target[i]) reject();
prev = p[i];
```

因此正向是“先置换、再链式异或”，两层都是可逆的。

## 步骤 4：逆向恢复 key

逆变换顺序与正向相反。

先由 `target` 反推 `p`：

```text
p[i] = target[i] ^ prev ^ ((i*0x1d + 0x33) & 0xff)
prev = p[i]
```

再对置换求逆：

```text
key[perm[i]] = p[i]
```

Python 核心代码：

```python
p = bytearray()
prev = 0x5A
for i, t in enumerate(target):
    v = (t ^ prev ^ ((i * 0x1D + 0x33) & 0xFF)) & 0xFF
    p.append(v)
    prev = v

key = bytearray(len(perm))
for i, dst in enumerate(perm):
    key[dst] = p[i]
```

恢复结果：

```text
R3v_P3rm_Ch41n_2025!
```

## 步骤 5：让程序解码 flag

```bash
printf 'R3v_P3rm_Ch41n_2025!\n' | ./public/checker
```

输出：

```text
license key: access granted
flag{r3v3rs3_th3_ch3ck3r}
```

`solve.py` 还会从 `flag_enc` 独立解码一次，并与 checker 的输出比较：

```bash
python3 solve.py
```

示例输出：

```text
[1] found license blob at file offset 0x2020 (key_len=20, flag_len=25)
    perm:   0b0312000f070113090c041006020e0811050d0a
    target: 5d3b07edc79bbfec794a3412cda8e0e66e21605c
[2] recovered key: 'R3v_P3rm_Ch41n_2025!'
[3] flag decoded from blob: 'flag{r3v3rs3_th3_ch3ck3r}'
[4] checker output:
license key: access granted
flag{r3v3rs3_th3_ch3ck3r}
[+] FLAG: flag{r3v3rs3_th3_ch3ck3r}
```

## 修复建议（讲师可讲）

- 不要用“置换 + 异或链”这类离线可逆校验作为许可证；应使用签名或服务端校验。
- 去符号只能增加定位成本，不能阻止静态分析；常量最终仍在 `.rodata` 中。
- 客户端二进制中的 flag 最终一定可以被有决心的分析者提取，敏感数据应放在服务端。
- 若要提高强度，可结合密钥派生、完整性校验和运行时反调试，但仍不能替代服务端授权。
