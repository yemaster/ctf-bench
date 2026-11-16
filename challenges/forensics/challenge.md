# Forensics — DNS 隧道里的碎片

- **方向**：Forensics
- **难度**：中等偏难
- **分值**：120
- **预计时间**：30–45 分钟
- **知识点**：PCAP 结构、Ethernet/IPv4/UDP 解析、DNS 资源记录、数据外带与重组

## 背景

培训网络的一台主机被怀疑通过 DNS 查询向外传送数据。传感器只保存了一段很短的
`capture.pcap`。流量中混有正常的 DNS 查询，但某个子域看起来不太对劲。

## 目标

分析 `capture.pcap`，恢复被外带的 `flag{...}`。

## 学员材料

- `public/capture.pcap`：本地合成的 DNS 流量抓包

## 规则与边界

- 只分析本地合成 PCAP，不连接抓包中的任何域名或 IP。
- 允许 Wireshark/tshark、`tcpdump`、Python 标准库等；即使没有第三方库也能完成。
- 不要尝试访问 `exfil.training.test` 或修改系统 DNS 配置。

## 提示

1. 先按 UDP 53 过滤，观察 DNS 查询名和 TXT 记录。
2. 有一条 TXT 记录看起来像密钥；注意区分它和普通的维护通知。
3. 查询名中的 `cNN-<hex>` 片段顺序是乱的，需要按 `NN` 重排。
4. 对重排后的十六进制数据做“密钥重复 XOR”即可得到明文。

## 交付

提交 flag，并说明 key 来自哪条 DNS 记录、数据如何排序。
