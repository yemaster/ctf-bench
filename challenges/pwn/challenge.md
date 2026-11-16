# Pwn — 双门本地覆盖：cookie 与 admin

- **方向**：Pwn
- **难度**：中等偏难
- **分值**：140
- **预计时间**：35–50 分钟
- **知识点**：随机 challenge、32 位混合运算、栈布局、缓冲区溢出、双字段覆盖、小端序

## 背景

`pwnme` 是一个本地玩具程序。它先给出一个随机 `challenge`，要求你计算并输入对应的
`cookie`；通过第一道门后，再读取一段原始字节作为溢出载荷。只有载荷同时满足两个字段
约束，程序才会调用 `win()` 并打印 flag。

程序没有生成 shell、没有执行命令、没有网络功能；`win()` 只负责解码并打印 flag。

## 目标

让 `public/pwnme` 打印形如 `flag{...}` 的内容，并说明两道门分别是怎么通过的。

## 程序行为

1. 打印 `challenge=<8 位十六进制>`；
2. 等待一行 `cookie` 输入；错误则直接退出；
3. 通过后打印 `gate 1 passed`，并等待一段原始溢出载荷；
4. 载荷写入一个栈上的 `name[32]` 缓冲区，但读取长度是 96；
5. 结构体中另有 `admin` 与 `auth` 两个 32 位字段。只有
   `admin == 0x1337` 且 `auth == cookie` 时，才打印 flag。

## 学员材料

- `public/pwnme`：x86_64 Linux ELF 可执行文件

## 运行方式

```bash
chmod +x public/pwnme
./public/pwnme
```

程序是交互式的，建议用 Python `subprocess` 的管道分阶段读写，而不是一次性把
cookie 和二进制载荷全部灌进去。

## 规则与边界

- 仅限本地 `pwnme` 进程；不生成 shell、不反弹连接、不攻击网络服务。
- 不允许修改题目文件或系统配置。
- 允许 `objdump`、`gdb`、Python 标准库（`subprocess`、`struct`）等。
- flag 经过编码，直接 `strings` 不会得到明文。

## 提示

1. `challenge` 每次运行都不同，不能写死 cookie。先反汇编 `mix_challenge`，把它的
   32 位运算（异或、循环左移、乘法、逻辑右移）按无符号回绕复现出来。
2. 用 `objdump -d -M intel --disassemble=main public/pwnme` 观察 `name`、`admin`、
   `auth` 的 `[rbp-...]` 偏移，以及 `read()` 的长度。
3. `name` 与 `admin` 之间有 32 字节填充；`auth` 紧挨着 `admin`。两个值都要按
   x86_64 小端序写入。
4. 第二道门复用了第一道门算出的 cookie，所以两段逻辑是关联的；这不是覆盖返回地址。
5. 目标只是调用题内 `win()` 打印 flag，不需要也无法获得 shell。

## 交付

提交 flag，并给出：

- 从 challenge 计算 cookie 的方法；
- 溢出载荷的完整结构（填充长度、`admin` 的值、`auth` 的值及其来源）。
