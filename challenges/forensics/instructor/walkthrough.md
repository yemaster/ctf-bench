# Forensics 讲师解题步骤

## 环境与生成

```bash
cd forensics
./generate.sh           # 重新生成 public/capture.pcap
python3 solve.py
```

`instructor/make_pcap.py` 只用 Python 标准库合成 Ethernet/IPv4/UDP/DNS 数据包。
flag 在 `instructor/flag.txt`；PCAP 中只有 XOR + 十六进制后的碎片，没有明文 flag。

## 步骤 1：过滤 DNS 并找 TXT 密钥

如果安装了 Wireshark/tshark：

```bash
tshark -r public/capture.pcap -Y dns -T fields -e dns.qry.name
tshark -r public/capture.pcap -Y 'dns.txt' -T fields -e dns.qry.name -e dns.txt
```

会看到：

```text
www.training.test
mail.training.test
vpn.training.test
key.exfil.training.test    s3cr3tK3y!
notes.training.test        maintenance window
c04-...
c02-...
...
```

`key.exfil.training.test` 的 TXT 答案是 XOR 密钥 `s3cr3tK3y!`；`notes...` 是干扰项。

没有 tshark 也可以用 Python 直接读 PCAP（`solve.py` 就是这样做）：

```text
PCAP 全局头 24 字节
每条记录 16 字节（ts_sec, ts_usec, incl_len, orig_len）
Ethernet 14 字节 -> IPv4（IHL 可变）-> UDP 8 字节 -> DNS
```

## 步骤 2：收集并排序碎片

查询名形如：

```text
c01-<12 hex chars>.exfil.training.test
c02-<12 hex chars>.exfil.training.test
...
```

正则：

```python
r"^c(\d+)-([0-9a-f]+)\.exfil\.training\.test$"
```

把每个 `NN` 对应的 hex 片段按数字排序后拼接，得到完整的十六进制串。

## 步骤 3：重复密钥 XOR

将 hex 解码为字节，再用 `s3cr3tK3y!` 循环 XOR：

```python
plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
```

得到：

```text
b'flag{dns_3xf1l_1n_pl41n_s1ght}'
```

运行 `python3 solve.py` 的完整输出：

```text
[1] parsed 12 DNS packets; TXT names: ['key.exfil.training.test', 'notes.training.test']
[2] XOR key from TXT record: b's3cr3tK3y!'
[3] reassembled 5 chunks (30 bytes)
    plaintext: b'flag{dns_3xf1l_1n_pl41n_s1ght}'
[+] FLAG: flag{dns_3xf1l_1n_pl41n_s1ght}
```

## 检测与修复建议（讲师可讲）

- DNS 查询名长度、熵、标签数量异常；对长随机子域做告警。
- 监控 TXT 记录和罕见的 `*.exfil.*` 域名。
- 出站 DNS 只允许经过受控解析器，限制直接外部解析。
- 对高风险环境启用 DNS over HTTPS/TLS 并做域名信誉与长度基线。
- 本题只用于教学，所有域名和 IP 均为保留/虚构地址。
