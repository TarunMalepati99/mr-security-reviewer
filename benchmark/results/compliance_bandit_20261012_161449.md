# compliance benchmark: bandit (bandit)

```
Suite: compliance -- 32 MRs (20 vulnerable, 12 clean), 26 labeled issues
Analyzer: bandit (bandit)
Recall 46% (12/26)   Precision 63% (7 false alarms)   F1 0.53
Right rule family when found: 100%
Vulnerable MRs flagged 10/20   Clean MRs wrongly flagged 2/12   Findings on deleted lines 0
Per category: injection 5/7, hardcoded_secret 2/5, sensitive_logging 0/3, weak_crypto 3/4, insecure_transport 2/3, broken_access_control 0/4
```

## Misses

- **v01** `payments/lookup.py:13` (sensitive_logging): `logger.info("charged pan=%s amount=%s", pan, amount)`
- **v04** `config/settings.py:3` (hardcoded_secret): `DATABASE_URL = "postgresql://admin:Sup3rS3cret!@prod-db.internal:5432/payments"`
- **v05** `auth/tokens.py:4` (hardcoded_secret): `JWT_SIGNING_KEY = "my-very-secret-signing-key-2024"`
- **v06** `auth/reset.py:9` (sensitive_logging): `log.info(f"reset token for {user.email}: {token}")`
- **v08** `api/refunds.py:9` (broken_access_control): `order = Order.query.get(order_id)`
- **v09** `api/admin.py:4` (broken_access_control): `@app.route("/admin/users/delete", methods=["POST"])`
- **v10** `api/export.py:5` (broken_access_control): `if request.headers.get("X-User-Role") != "admin":`
- **v13** `vault/cards.py:7` (weak_crypto): `cipher = AES.new(KEY, AES.MODE_ECB)`
- **v14** `src/orders.js:3` (hardcoded_secret): `const stripe = require("stripe")("sk_live_4eC39HqLyjWDarjtT1zdp7dc");`
- **v14** `src/orders.js:8` (injection): `const result = await pool.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);`
- **v15** `src/main/java/com/shop/MerchantDao.java:12` (injection): `return stmt.executeQuery("SELECT * FROM merchants WHERE name = '" + name + "'");`
- **v16** `middleware/logging.py:11` (sensitive_logging): `logger.debug("request %s auth=%s", environ.get("PATH_INFO"), auth)`
- **v18** `webhooks/settlement.py:5` (insecure_transport): `CALLBACK = "http://partner-bank.example.com/settlements"`
- **v20** `api/statements.py:4` (broken_access_control): `@app.route("/accounts/<account_id>/statements")`

## False alarms

- **c08** `reports/export.py` BANDIT-B404: `import subprocess`
- **c08** `reports/export.py` BANDIT-B607: `subprocess.run(["tar", "-czf", "/tmp/export.tgz", f"/data/reports/{name}"], check=True)`
- **c08** `reports/export.py` BANDIT-B603: `subprocess.run(["tar", "-czf", "/tmp/export.tgz", f"/data/reports/{name}"], check=True)`
- **c08** `reports/export.py` BANDIT-B108: `subprocess.run(["tar", "-czf", "/tmp/export.tgz", f"/data/reports/{name}"], check=True)`
- **c11** `scripts/healthcheck.py` BANDIT-B310: `urllib.request.urlopen("http://localhost:8080/healthz", timeout=2)`
- **v13** `vault/cards.py` BANDIT-B413: `from Crypto.Cipher import AES`
- **v18** `webhooks/settlement.py` BANDIT-B404: `import subprocess`
