# owasp benchmark: gemini (gemini-3.5-flash-lite, prompt v2, check on)

```
Suite: OWASP Benchmark for Python v0.1 -- 136 cases (67 real vulnerabilities, 69 safe look-alikes)
Analyzer: gemini (gemini-3.5-flash-lite, prompt v2, check on)
Benchmark score (avg TPR - FPR): +0.68  (95% CI +0.45 to +0.67)   [avg true-positive rate 91%, avg false-positive rate 23%]
Precision 79%   Recall 91%   F1 0.85   Accuracy 84%
Confusion: TP 61  FP 16  TN 53  FN 6
Hallucination check: dropped 0 of 95 candidate findings
Exploitability check: rejected 18 findings -- turned 15 false alarms into correct passes, lost 3 real catches

Category                    TP  FN  FP  TN    TPR    FPR   Score
Path traversal               5   0   3   2   100%    60%   +0.40
Command injection            5   0   1   3   100%    25%   +0.75
Code injection               5   0   2   3   100%    40%   +0.60
Insecure deserialization     5   0   1   4   100%    20%   +0.80
Weak hashing                 4   1   2   3    80%    40%   +0.40
LDAP injection               4   1   0   5    80%     0%   +0.80
Open redirect                5   0   1   4   100%    20%   +0.80
Insecure cookie              4   1   0   5    80%     0%   +0.80
SQL injection                2   0   0   5   100%     0%   +1.00
Trust boundary               5   0   2   3   100%    40%   +0.60
Weak randomness              5   0   0   5   100%     0%   +1.00
XPath injection              5   0   3   2   100%    60%   +0.40
Cross-site scripting         2   3   0   5    40%     0%   +0.40
XML external entities        5   0   1   4   100%    20%   +0.80
API usage this run: 29 request(s) -- 136 new file reviews, 95 new exploitability checks; 231 answers reused from cache

Same cases, Bandit baseline: score +0.14 (95% CI +0.03 to +0.20), precision 58%, recall 45%, F1 0.50
```

## Missed real vulnerabilities

- owasp-00189 (BenchmarkTest00189) Cross-site scripting
- owasp-00366 (BenchmarkTest00366) Cross-site scripting
- owasp-00505 (BenchmarkTest00505) LDAP injection
- owasp-00646 (BenchmarkTest00646) Weak hashing
- owasp-00719 (BenchmarkTest00719) Insecure cookie
- owasp-00839 (BenchmarkTest00839) Cross-site scripting

## False alarms on safe code

- owasp-00071 (BenchmarkTest00071) Trust boundary
- owasp-00339 (BenchmarkTest00339) Trust boundary
- owasp-00350 (BenchmarkTest00350) Command injection
- owasp-00411 (BenchmarkTest00411) Weak hashing
- owasp-00521 (BenchmarkTest00521) Path traversal
- owasp-00544 (BenchmarkTest00544) XPath injection
- owasp-00685 (BenchmarkTest00685) XPath injection
- owasp-00743 (BenchmarkTest00743) Path traversal
- owasp-00821 (BenchmarkTest00821) Code injection
- owasp-00892 (BenchmarkTest00892) Code injection
- owasp-00922 (BenchmarkTest00922) Path traversal
- owasp-00929 (BenchmarkTest00929) XPath injection
- owasp-00983 (BenchmarkTest00983) Open redirect
- owasp-01025 (BenchmarkTest01025) XML external entities
- owasp-01096 (BenchmarkTest01096) Insecure deserialization
- owasp-01195 (BenchmarkTest01195) Weak hashing

