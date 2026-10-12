# compliance benchmark: gemini (gemini-3.5-flash-lite, prompt v2, check on)

```
Suite: compliance -- 32 MRs (20 vulnerable, 12 clean), 26 labeled issues
Analyzer: gemini (gemini-3.5-flash-lite, prompt v2, check on)
Recall 73% (19/26)   Precision 100% (0 false alarms)   F1 0.84
Right rule family when found: 100%
Vulnerable MRs flagged 17/20   Clean MRs wrongly flagged 0/12   Findings on deleted lines 0
Hallucination check: dropped 0 of 21 candidate findings
Per category: injection 7/7, hardcoded_secret 2/5, sensitive_logging 2/3, weak_crypto 4/4, insecure_transport 1/3, broken_access_control 3/4
API usage this run: 8 request(s) -- 34 new file reviews, 19 new exploitability checks; 53 answers reused from cache
```

## Misses

- **v04** `config/settings.py:2` (hardcoded_secret): `AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
- **v04** `config/settings.py:3` (hardcoded_secret): `DATABASE_URL = "postgresql://admin:Sup3rS3cret!@prod-db.internal:5432/payments"`
- **v05** `auth/tokens.py:4` (hardcoded_secret): `JWT_SIGNING_KEY = "my-very-secret-signing-key-2024"`
- **v06** `auth/reset.py:9` (sensitive_logging): `log.info(f"reset token for {user.email}: {token}")`
- **v18** `webhooks/settlement.py:5` (insecure_transport): `CALLBACK = "http://partner-bank.example.com/settlements"`
- **v19** `jobs/upload.py:8` (insecure_transport): `with FTP(FTP_HOST) as ftp:`
- **v20** `api/statements.py:4` (broken_access_control): `@app.route("/accounts/<account_id>/statements")`

## False alarms

