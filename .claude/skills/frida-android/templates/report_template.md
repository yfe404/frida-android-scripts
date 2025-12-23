# Security Assessment: {{APP_NAME}}

**Date:** {{DATE}}
**Package:** {{PACKAGE_NAME}}
**Version:** {{VERSION}}
**Analyst:** {{ANALYST}}

---

## Executive Summary

[Auto-generated summary based on findings severity]

**Risk Level:** [CRITICAL / HIGH / MEDIUM / LOW]

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

---

## Target Information

| Property | Value |
|----------|-------|
| Package Name | {{PACKAGE_NAME}} |
| Version | {{VERSION}} |
| Min SDK | {{MIN_SDK}} |
| Target SDK | {{TARGET_SDK}} |
| APK Hash (SHA256) | {{APK_HASH}} |

---

## Phase 1: Static Analysis (APKLeaks)

### Secrets Found

#### API Keys
```
[Paste API keys found]
```

#### Firebase Configuration
```
[Paste Firebase URLs/config]
```

#### Endpoints Discovered
```
[Paste endpoint URLs]
```

### Security Controls Detected

| Control | Detected | Bypass Required |
|---------|----------|-----------------|
| Root Detection | [ ] Yes / [ ] No | |
| Frida Detection | [ ] Yes / [ ] No | |
| SSL Pinning | [ ] Yes / [ ] No | |
| Emulator Detection | [ ] Yes / [ ] No | |
| Debug Detection | [ ] Yes / [ ] No | |

---

## Phase 2: Threat Model

### Attack Surface Map

```
[Diagram or description of attack surface]
```

### Prioritized Findings

| Priority | Finding | Status |
|----------|---------|--------|
| HIGH | | [ ] Tested |
| HIGH | | [ ] Tested |
| MEDIUM | | [ ] Tested |
| LOW | | [ ] Tested |

---

## Phase 3: API Key Assessment

### Google API Keys

| API Key | Services Enabled | Restrictions |
|---------|------------------|--------------|
| AIzaSy... | Maps, Firebase Auth | None / Restricted |

### Firebase

| Test | Result |
|------|--------|
| Anonymous Auth | Enabled / Disabled |
| Database Public Read | Yes / No |
| Storage Public Read | Yes / No |

---

## Phase 4: Dynamic Analysis

### Traffic Analysis

| Endpoint | Auth Method | Notes |
|----------|-------------|-------|
| /api/v1/... | Bearer Token | |
| /graphql | API Key | |

### Captured Credentials

```
[Redacted tokens/keys captured during runtime]
```

### Security Bypasses Used

| Bypass | Script | Result |
|--------|--------|--------|
| Root Detection | bypass_root_detection.js | Success / Fail |
| SSL Pinning | frida-android-unpinning.js | Success / Fail |

---

## Phase 5: Exploitation

### Confirmed Vulnerabilities

#### VULN-001: [Title]

- **Severity:** CRITICAL / HIGH / MEDIUM / LOW
- **Location:** [URL/endpoint/function]
- **Evidence:**
```
[curl command, screenshot, or output]
```
- **Impact:** [What an attacker could do]
- **Remediation:** [How to fix]

---

## API Replay Capability

### Endpoints Available for Scraping

| Endpoint | Auth Required | Pagination | Rate Limited |
|----------|---------------|------------|--------------|
| | | | |

### Sample Replay Script

```python
# See generated api_replay.py
```

---

## Recommendations

### Critical (Fix Immediately)
1.

### High Priority
1.

### Medium Priority
1.

### Best Practices
1.

---

## Appendix

### A. APKLeaks Raw Output
```json
[Paste full JSON output]
```

### B. HAR Traffic Summary
```
[Summary of captured traffic]
```

### C. Frida Script Output
```
[Relevant script output]
```

---

**Report generated using frida-android skill**
