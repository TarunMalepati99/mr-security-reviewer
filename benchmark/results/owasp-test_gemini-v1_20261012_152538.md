# owasp benchmark: gemini (gemini-3.5-flash-lite, prompt v1, check off)

```
Suite: OWASP Benchmark for Python v0.1 -- 136 cases (67 real vulnerabilities, 69 safe look-alikes)
Analyzer: gemini (gemini-3.5-flash-lite, prompt v1, check off)
Benchmark score (avg TPR - FPR): +0.34  (95% CI +0.18 to +0.39)   [avg true-positive rate 74%, avg false-positive rate 40%]
Precision 65%   Recall 75%   F1 0.69   Accuracy 68%
Confusion: TP 50  FP 27  TN 42  FN 17
Hallucination check: dropped 0 of 79 candidate findings

Category                    TP  FN  FP  TN    TPR    FPR   Score
Path traversal               5   0   5   0   100%   100%   +0.00
Command injection            5   0   3   1   100%    75%   +0.25
Code injection               5   0   5   0   100%   100%   +0.00
Insecure deserialization     5   0   4   1   100%    80%   +0.20
Weak hashing                 5   0   0   5   100%     0%   +1.00
LDAP injection               3   2   0   5    60%     0%   +0.60
Open redirect                5   0   1   4   100%    20%   +0.80
Insecure cookie              4   1   0   5    80%     0%   +0.80
SQL injection                1   1   0   5    50%     0%   +0.50
Trust boundary               2   3   3   2    40%    60%   -0.20
Weak randomness              0   5   0   5     0%     0%   +0.00
XPath injection              5   0   4   1   100%    80%   +0.20
Cross-site scripting         0   5   0   5     0%     0%   +0.00
XML external entities        5   0   2   3   100%    40%   +0.60
API usage this run: 17 request(s) -- 136 new file reviews, 0 new exploitability checks; 136 answers reused from cache

Same cases, Bandit baseline: score +0.14 (95% CI +0.03 to +0.20), precision 58%, recall 45%, F1 0.50
```

## Missed real vulnerabilities

- owasp-00189 (BenchmarkTest00189) Cross-site scripting
- owasp-00225 (BenchmarkTest00225) Weak randomness
- owasp-00260 (BenchmarkTest00260) Trust boundary
- owasp-00284 (BenchmarkTest00284) SQL injection
- owasp-00340 (BenchmarkTest00340) Trust boundary
- owasp-00366 (BenchmarkTest00366) Cross-site scripting
- owasp-00427 (BenchmarkTest00427) LDAP injection
- owasp-00429 (BenchmarkTest00429) LDAP injection
- owasp-00515 (BenchmarkTest00515) Cross-site scripting
- owasp-00533 (BenchmarkTest00533) Cross-site scripting
- owasp-00593 (BenchmarkTest00593) Insecure cookie
- owasp-00628 (BenchmarkTest00628) Weak randomness
- owasp-00768 (BenchmarkTest00768) Weak randomness
- owasp-00839 (BenchmarkTest00839) Cross-site scripting
- owasp-00862 (BenchmarkTest00862) Weak randomness
- owasp-00889 (BenchmarkTest00889) Trust boundary
- owasp-01130 (BenchmarkTest01130) Weak randomness

## False alarms on safe code

- owasp-00071 (BenchmarkTest00071) Trust boundary
- owasp-00081 (BenchmarkTest00081) Insecure deserialization
- owasp-00111 (BenchmarkTest00111) XPath injection
- owasp-00261 (BenchmarkTest00261) Trust boundary
- owasp-00339 (BenchmarkTest00339) Trust boundary
- owasp-00350 (BenchmarkTest00350) Command injection
- owasp-00441 (BenchmarkTest00441) Path traversal
- owasp-00461 (BenchmarkTest00461) XML external entities
- owasp-00508 (BenchmarkTest00508) Insecure deserialization
- owasp-00521 (BenchmarkTest00521) Path traversal
- owasp-00544 (BenchmarkTest00544) XPath injection
- owasp-00658 (BenchmarkTest00658) Insecure deserialization
- owasp-00685 (BenchmarkTest00685) XPath injection
- owasp-00736 (BenchmarkTest00736) Command injection
- owasp-00743 (BenchmarkTest00743) Path traversal
- owasp-00745 (BenchmarkTest00745) Path traversal
- owasp-00821 (BenchmarkTest00821) Code injection
- owasp-00892 (BenchmarkTest00892) Code injection
- owasp-00922 (BenchmarkTest00922) Path traversal
- owasp-00929 (BenchmarkTest00929) XPath injection
- owasp-00983 (BenchmarkTest00983) Open redirect
- owasp-00987 (BenchmarkTest00987) Code injection
- owasp-01025 (BenchmarkTest01025) XML external entities
- owasp-01096 (BenchmarkTest01096) Insecure deserialization
- owasp-01164 (BenchmarkTest01164) Code injection
- owasp-01167 (BenchmarkTest01167) Code injection
- owasp-01173 (BenchmarkTest01173) Command injection

