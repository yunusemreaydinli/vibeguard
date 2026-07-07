# 🔴 VibeGuard Security Report

**Repository:** `vulnerable_app`  
**Scan Date:** 2026-07-07 08:14:38 UTC  
**Risk Score:** **100/100** — 🔴 Critical  

## Executive Summary

VibeGuard scanned **`vulnerable_app`** and identified **31** issue(s) across three audit dimensions:

| Category | Issues |
|---|---|
| 📦 Dependency Audit | 9 |
| 🔒 Security Scan | 20 |
| 🤖 API Hallucination Check | 2 |
| **Total** | **31** |

## 📦 Dependency Audit Results

| Package | Status | Risk | Details |
|---|---|---|---|
| `flask` | ✅ Found | — |  |
| `requests` | ✅ Found | — |  |
| `gemini-toolkit-pro` | ❌ Not found | — | Package does not exist in the registry (hallucinated) |
| `numpy` | ✅ Found | — |  |
| `openai` | ✅ Found | — |  |
| `langchain-helper-utils` | ❌ Not found | — | Package does not exist in the registry (hallucinated) |
| `transformrs` | ❌ Not found | ⚠️ Typosquat (high) | Package does not exist in the registry (hallucinated) |
| `pandas` | ✅ Found | — |  |
| `cryptographic` | ❌ Not found | ⚠️ Typosquat (medium) | Package does not exist in the registry (hallucinated) |

## 🔒 Security Scan Results

**Severity Breakdown:** 🔴 Critical: 9 · 🟠 High: 6 · 🟡 Medium: 5 · 🟢 Low: 0

| # | File | Line | Severity | Category | Description |
|---|---|---|---|---|---|
| 1 | `app.py` | 15 | 🔴 Critical | hardcoded_api_key | Hardcoded API key or secret detected |
| 2 | `app.py` | 16 | 🔴 Critical | hardcoded_api_key | Hardcoded API key or secret detected |
| 3 | `app.py` | 16 | 🔴 Critical | hardcoded_password | Hardcoded password or secret |
| 4 | `app.py` | 17 | 🔴 Critical | hardcoded_api_key | Hardcoded API key or secret detected |
| 5 | `app.py` | 18 | 🔴 Critical | hardcoded_password | Hardcoded password or secret |
| 6 | `config.py` | 3 | 🔴 Critical | hardcoded_password | Hardcoded password or secret |
| 7 | `config.py` | 5 | 🔴 Critical | hardcoded_api_key | Hardcoded API key or secret detected |
| 8 | `config.py` | 6 | 🔴 Critical | hardcoded_password | Hardcoded password or secret |
| 9 | `config.py` | 7 | 🔴 Critical | hardcoded_password | Hardcoded password or secret |
| 10 | `app.py` | 52 | 🟠 High | sql_injection | Potential SQL injection vulnerability |
| 11 | `app.py` | 64 | 🟠 High | sql_injection | Potential SQL injection vulnerability |
| 12 | `app.py` | 78 | 🟠 High | dangerous_exec | Dangerous code execution |
| 13 | `app.py` | 86 | 🟠 High | dangerous_exec | Dangerous code execution |
| 14 | `app.py` | 97 | 🟠 High | insecure_deserialization | Insecure deserialization |
| 15 | `app.py` | 108 | 🟠 High | dangerous_exec | Dangerous code execution |
| 16 | `app.py` | 61 | 🟡 Medium | missing_input_validation | Potential missing input validation on web request data |
| 17 | `app.py` | 76 | 🟡 Medium | missing_input_validation | Potential missing input validation on web request data |
| 18 | `app.py` | 85 | 🟡 Medium | missing_input_validation | Potential missing input validation on web request data |
| 19 | `app.py` | 107 | 🟡 Medium | missing_input_validation | Potential missing input validation on web request data |
| 20 | `app.py` | 113 | 🟡 Medium | debug_in_production | Debug mode enabled — should not be used in production |

### Critical & High Severity Details

**app.py:15** — Hardcoded API key or secret detected
```
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
```

**app.py:16** — Hardcoded API key or secret detected
```
OPENAI_SECRET = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
```

**app.py:16** — Hardcoded password or secret
```
OPENAI_SECRET = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
```

**app.py:17** — Hardcoded API key or secret detected
```
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
```

**app.py:18** — Hardcoded password or secret
```
DATABASE_PASSWORD = "super_secret_password_123!"
```

**config.py:3** — Hardcoded password or secret
```
JWT_SECRET = "jwt_secret_token_12345"
```

**config.py:5** — Hardcoded API key or secret detected
```
SENDGRID_API_KEY = "SG.abcdef123456.ghijkl789012"
```

**config.py:6** — Hardcoded password or secret
```
DATABASE_URL = "postgresql://admin:password123@db.example.com:5432/mydb"
```

**config.py:7** — Hardcoded password or secret
```
REDIS_PASSWORD = "redis_pass_456"
```

**app.py:52** — Potential SQL injection vulnerability
```
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

## 🤖 API Hallucination Check

Files scanned: **2**

| File | Line | Module | Called Function | Suggestion |
|---|---|---|---|---|
| `app.py` | 35 | `requests` | `secure_get` | 'requests.secure_get' does not exist. Did you mean 'requests.structures'? |
| `app.py` | 38 | `requests` | `post_json` | 'requests.post_json' does not exist. Did you mean 'requests.post'? |

## 📋 Recommendations

1. **Remove non-existent packages** (`gemini-toolkit-pro`, `langchain-helper-utils`, `transformrs`, `cryptographic`). These were likely hallucinated by an AI code generator and will cause installation failures or, worse, install a malicious package.
2. **Verify potentially typosquatted packages** (`transformrs`, `cryptographic`). Confirm these are the intended packages and not malicious look-alikes.
3. **Immediately rotate any exposed secrets.** Hardcoded API keys and passwords must be moved to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).
4. **Fix high-severity issues** including SQL injection risks, dangerous `eval`/`exec` usage, and insecure deserialization. Use parameterized queries, avoid `eval`, and use safe loaders.
5. **Address medium-severity issues** such as disabled TLS verification, debug mode in production, and weak crypto algorithms.
6. **Fix hallucinated API calls.** Replace non-existent function calls with the correct API. Consult official package documentation.

---
*Report generated by VibeGuard v0.1.0 at 2026-07-07 08:14:38 UTC*
