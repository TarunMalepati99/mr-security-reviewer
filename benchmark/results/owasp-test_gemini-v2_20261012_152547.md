# owasp benchmark: gemini (gemini-3.5-flash-lite, prompt v2, check off)

```
Suite: OWASP Benchmark for Python v0.1 -- 136 cases (67 real vulnerabilities, 69 safe look-alikes)
Analyzer: gemini (gemini-3.5-flash-lite, prompt v2, check off)
Benchmark score (avg TPR - FPR): +0.50  (95% CI +0.31 to +0.52)   [avg true-positive rate 96%, avg false-positive rate 45%]
Precision 67%   Recall 96%   F1 0.79   Accuracy 75%
Confusion: TP 64  FP 31  TN 38  FN 3
Hallucination check: dropped 0 of 95 candidate findings

Category                    TP  FN  FP  TN    TPR    FPR   Score
Path traversal               5   0   5   0   100%   100%   +0.00
Command injection            5   0   3   1   100%    75%   +0.25
Code injection               5   0   4   1   100%    80%   +0.20
Insecure deserialization     5   0   4   1   100%    80%   +0.20
Weak hashing                 5   0   3   2   100%    60%   +0.40
LDAP injection               5   0   2   3   100%    40%   +0.60
Open redirect                5   0   1   4   100%    20%   +0.80
Insecure cookie              5   0   0   5   100%     0%   +1.00
SQL injection                2   0   0   5   100%     0%   +1.00
Trust boundary               5   0   4   1   100%    80%   +0.20
Weak randomness              5   0   0   5   100%     0%   +1.00
XPath injection              5   0   3   2   100%    60%   +0.40
Cross-site scripting         2   3   0   5    40%     0%   +0.40
XML external entities        5   0   2   3   100%    40%   +0.60
API usage this run: 0 request(s) -- 0 new file reviews, 0 new exploitability checks; 136 answers reused from cache

Same cases, Bandit baseline: score +0.14 (95% CI +0.03 to +0.20), precision 58%, recall 45%, F1 0.50
```

## Missed real vulnerabilities

- owasp-00189 (BenchmarkTest00189) Cross-site scripting
- owasp-00366 (BenchmarkTest00366) Cross-site scripting
- owasp-00839 (BenchmarkTest00839) Cross-site scripting

## False alarms on safe code

- owasp-00071 (BenchmarkTest00071) Trust boundary
- owasp-00261 (BenchmarkTest00261) Trust boundary
- owasp-00339 (BenchmarkTest00339) Trust boundary
- owasp-00350 (BenchmarkTest00350) Command injection
- owasp-00411 (BenchmarkTest00411) Weak hashing
- owasp-00435 (BenchmarkTest00435) Insecure deserialization
- owasp-00441 (BenchmarkTest00441) Path traversal
- owasp-00461 (BenchmarkTest00461) XML external entities
- owasp-00508 (BenchmarkTest00508) Insecure deserialization
- owasp-00521 (BenchmarkTest00521) Path traversal
- owasp-00544 (BenchmarkTest00544) XPath injection
- owasp-00658 (BenchmarkTest00658) Insecure deserialization
- owasp-00685 (BenchmarkTest00685) XPath injection
- owasp-00712 (BenchmarkTest00712) Weak hashing
- owasp-00736 (BenchmarkTest00736) Command injection
- owasp-00743 (BenchmarkTest00743) Path traversal
- owasp-00745 (BenchmarkTest00745) Path traversal
- owasp-00821 (BenchmarkTest00821) Code injection
- owasp-00892 (BenchmarkTest00892) Code injection
- owasp-00922 (BenchmarkTest00922) Path traversal
- owasp-00929 (BenchmarkTest00929) XPath injection
- owasp-00983 (BenchmarkTest00983) Open redirect
- owasp-01025 (BenchmarkTest01025) XML external entities
- owasp-01096 (BenchmarkTest01096) Insecure deserialization
- owasp-01163 (BenchmarkTest01163) Trust boundary
- owasp-01164 (BenchmarkTest01164) Code injection
- owasp-01167 (BenchmarkTest01167) Code injection
- owasp-01170 (BenchmarkTest01170) LDAP injection
- owasp-01171 (BenchmarkTest01171) LDAP injection
- owasp-01173 (BenchmarkTest01173) Command injection
- owasp-01195 (BenchmarkTest01195) Weak hashing

