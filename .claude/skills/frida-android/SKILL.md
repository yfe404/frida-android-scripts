---
name: frida-android
description: Android security research and penetration testing. Use when analyzing APKs with apkleaks, testing API key permissions, bypassing security controls (root/Frida/SSL), hooking runtime methods, or capturing secrets. Follows OWASP MASTG methodology.
---

# Android Security Research Skill

This skill follows established penetration testing methodologies (OWASP MASTG, PTES) where **intelligence gathering comes first**.

## 5-Phase Methodology

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: RECON          │  APKLeaks intel gathering           │
│  (apkleaks)              │  - API keys, secrets, URLs          │
│                          │  - Firebase, OAuth, endpoints       │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2: THREAT MODEL   │  Analyze findings, prioritize       │
│  (analysis)              │  - High/Medium/Low severity         │
│                          │  - Attack surface mapping           │
├─────────────────────────────────────────────────────────────────┤
│  Phase 3: PREPARATION    │  Based on intel:                    │
│  (setup)                 │  - Test exposed API keys            │
│                          │  - Prepare bypass scripts           │
├─────────────────────────────────────────────────────────────────┤
│  Phase 4: DYNAMIC        │  Runtime analysis:                  │
│  (frida)                 │  - Hook crypto/auth methods         │
│                          │  - Intercept network traffic        │
├─────────────────────────────────────────────────────────────────┤
│  Phase 5: EXPLOITATION   │  Use gathered intel:                │
│  (attack)                │  - API replay/scraping              │
│                          │  - Demonstrate impact               │
└─────────────────────────────────────────────────────────────────┘
```

## Report Generation

Throughout the workflow, build a security assessment report. See `templates/report_template.md`.

| Phase | Adds to Report |
|-------|----------------|
| 1. RECON | App metadata, APKLeaks raw output, detected secrets/URLs |
| 2. THREAT MODEL | Prioritized findings, attack surface map |
| 3. PREPARATION | API key test results, service capabilities confirmed |
| 4. DYNAMIC | Captured endpoints, auth tokens, request patterns |
| 5. EXPLOITATION | Working API replays, confirmed vulnerabilities |

---

## Phase 1: Intelligence Gathering (APKLeaks)

### Setup
```bash
# Create isolated environment
python -m venv venv && source venv/bin/activate
pip install apkleaks frida-tools

# Extract APK from device
adb shell pm list packages | grep -i <name>
adb shell pm path <package>
adb pull <path> app.apk

# Run analysis
apkleaks -f app.apk -o results.json
```

### What APKLeaks Reveals

| Category | Examples | Follow-up Action |
|----------|----------|------------------|
| **Google API Keys** | `AIzaSy...` | Test capabilities (see `reference/api_key_testing.md`) |
| **Firebase** | `*.firebaseio.com` | Check database rules, try unauthenticated read |
| **AWS** | `AKIA...`, S3 buckets | Test bucket permissions |
| **OAuth Client IDs** | `*.apps.googleusercontent.com` | Understand auth flow |
| **API Endpoints** | REST URLs, GraphQL | Map attack surface |
| **Hardcoded Secrets** | Passwords, tokens | Direct exploitation |

### Security Control Detection

| Pattern | Indicates | Bypass Script |
|---------|-----------|---------------|
| `/su/bin/su`, `magisk`, `Superuser.apk` | Root detection | `scripts/bypass/bypass_root_detection.js` |
| `frida-gadget`, `frida-server` | Frida detection | `scripts/bypass/bypass_root_detection.js` |
| `CertificatePinner`, `TrustManager` | SSL pinning | httptoolkit's frida-android-unpinning |
| `isDebuggerConnected`, `Debug.` | Debug detection | `scripts/bypass/bypass_debug.js` |
| `goldfish`, `generic`, `ro.hardware` | Emulator detection | `scripts/bypass/bypass_emulator.js` |

### Detect Root Detection in DEX Files

After extracting the APK, search for root detection function patterns directly in the dex files:

```bash
# Extract APK first
unzip app.apk -d extracted/

# Search for root detection patterns in dex files
cd extracted && strings classes*.dex | grep -iE \
  "isRooted|checkRoot|rootCheck|RootDetect|DeviceIntegrity|checkForRoot|detectRoot|RootTools"
```

Common findings and their meaning:

| Pattern | Library/Framework | Bypass Difficulty |
|---------|-------------------|-------------------|
| `isRooted` | Generic root check | Low |
| `checkRoot`, `rootCheck` | Custom implementation | Low-Medium |
| `RootDetection` | Security SDK | Medium |
| `DeviceIntegrity` | Play Integrity API | High |
| `RootTools` | RootTools library | Low |
| `detectRoot` | Custom/SDK | Medium |

---

## Phase 2: Threat Modeling

Categorize findings by priority:

### High Priority (Immediate Testing)
- Exposed API keys with broad permissions
- Firebase databases without auth
- Hardcoded credentials
- Unprotected admin endpoints

### Medium Priority (Requires Bypass)
- Protected endpoints (need SSL pinning bypass)
- Runtime secrets (need Frida hooks)
- Authenticated APIs (need token capture)

### Low Priority (Informational)
- SDK versions, third-party libraries, development artifacts

---

## Phase 3: Attack Preparation

### Frida Server Setup
```bash
# Get frida-server for device arch
ARCH=$(adb shell getprop ro.product.cpu.abi)
# Download matching frida-server from GitHub releases
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server -D &'"
```

### Test API Keys
When Google API keys are found, test their capabilities. See `reference/api_key_testing.md` for detailed testing workflow.

Quick tests:
```bash
# Firebase Auth (check if anonymous signup enabled)
curl "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY" \
  -H "Content-Type: application/json" -d '{}'

# Firebase Database (check public read)
curl "https://PROJECT.firebaseio.com/.json"
```

### When Frida Fails: Magisk DenyList

Some apps have native-level anti-tampering that detects Frida injection before scripts can run. Signs of this:
- App crashes immediately when spawned with Frida
- Frida server process detection
- Memory modification detection

**Solution: Use Magisk DenyList instead of runtime hooking**

```bash
# Add app to DenyList
magisk --denylist add <package_name>

# Enable enforcement
magisk --denylist enable

# Reboot may be required
adb reboot
```

**Why DenyList Works When Frida Doesn't**

| Frida Approach | Magisk DenyList |
|----------------|-----------------|
| Injects after app starts | Hides root before app loads |
| Detectable in memory | Uses Zygisk to create clean process |
| Modifies runtime | No modifications to app process |
| App sees frida strings | App sees stock Android |

DenyList creates an isolated environment where:
- `/system/bin/su` doesn't exist
- Magisk files are hidden from `/proc`
- Root packages are invisible to PackageManager
- Build properties appear stock

The app's root check runs in this "clean" environment and finds nothing suspicious.

**Trade-off**: You lose Frida hooking capability, but the app runs. Use this when you only need to:
- Capture traffic (use HTTP Toolkit instead)
- Test API functionality
- Observe normal app behavior

---

## Phase 4: Dynamic Analysis

### Traffic Interception

See `reference/traffic_interception.md` for detailed setup.

**Quick start with HTTP Toolkit (recommended):**
```bash
httptoolkit  # GUI auto-configures device + injects SSL unpinning
```

**Manual with mitmproxy:**
```bash
pip install mitmproxy
mitmdump -w traffic.har

# Set proxy on device
adb shell settings put global http_proxy <YOUR_IP>:8080
```

### SSL Pinning Bypass

Use **[httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)**:
```bash
# Clone the repo
git clone https://github.com/httptoolkit/frida-interception-and-unpinning.git
cd frida-interception-and-unpinning

# Full Android interception (recommended)
frida -U -f <package> \
  -l ./config.js \
  -l ./native-connect-hook.js \
  -l ./native-tls-hook.js \
  -l ./android/android-proxy-override.js \
  -l ./android/android-system-certificate-injection.js \
  -l ./android/android-certificate-unpinning.js \
  -l ./android/android-certificate-unpinning-fallback.js

# Or just certificate unpinning
frida -U -f <package> \
  -l ./android/android-certificate-unpinning.js \
  -l ./android/android-certificate-unpinning-fallback.js
```

Alternative: **[FridaBypassKit](https://github.com/okankurtuluss/FridaBypassKit)** - all-in-one bypass (root + SSL + emulator + debug)

### Available Frida Scripts

| Script | Location | Purpose |
|--------|----------|---------|
| Root/Frida bypass | `scripts/bypass/bypass_root_detection.js` | Disable root/Frida/Magisk checks |
| Debug bypass | `scripts/bypass/bypass_debug.js` | Disable debugger detection |
| Emulator bypass | `scripts/bypass/bypass_emulator.js` | Disable emulator detection |
| Secret catcher | `scripts/capture/catch_secrets.js` | Intercept crypto keys, auth tokens |
| Fake location | `scripts/capture/fake_location.js` | Spoof GPS coordinates |

### Running Frida Scripts

```bash
# Spawn app with bypass
frida -U -f <package> -l scripts/bypass/bypass_root_detection.js

# Capture secrets
frida -U -f <package> -l scripts/capture/catch_secrets.js | tee capture.log

# Fake location (with params)
frida -U -f <package> -l scripts/capture/fake_location.js \
  -P '{"lat": 40.7128, "lng": -74.0060}'
```

### HAR Analysis + APKLeaks Correlation

**Key insight: Correlate captured traffic with endpoints found by apkleaks**

```bash
# Extract unique endpoints from HAR
cat traffic.har | jq -r '.log.entries[].request.url' | sort -u

# Find auth patterns
cat traffic.har | jq '.log.entries[].request.headers[] |
  select(.name | test("auth|token|bearer|key"; "i"))'

# Correlate with APKLeaks endpoints
ENDPOINTS=$(cat apkleaks_results.json | jq -r '.LinkFinder[]' | grep -E '^/|^http')
for ep in $ENDPOINTS; do
  echo "=== $ep ==="
  cat traffic.har | jq ".log.entries[] | select(.request.url | contains(\"$ep\"))"
done
```

---

## Phase 5: API Replay & Scraping

**End goal: Understand and replay mobile API for data extraction**

### Extract from HAR for Replay

| Element | Purpose |
|---------|---------|
| Base URL | API host from apkleaks or HAR |
| Auth headers | `Authorization`, `X-API-Key`, bearer tokens |
| User-Agent | Mobile app signature (often required) |
| Custom headers | App-specific (`X-App-Version`, etc.) |
| Request body format | JSON structure, field names |
| Pagination | `offset`, `cursor`, `page` params |

### Build Replay Script

```python
#!/usr/bin/env python3
import requests

# Extracted from HAR capture
BASE_URL = "https://api.example.com"
HEADERS = {
    "Authorization": "Bearer <token_from_har>",
    "User-Agent": "AppName/1.0 Android/14",
    "X-App-Version": "2.1.0",
    "Content-Type": "application/json"
}

def get_data(page=1):
    resp = requests.get(
        f"{BASE_URL}/api/v1/endpoint",
        headers=HEADERS,
        params={"page": page, "limit": 50}
    )
    return resp.json()
```

### Misconfiguration Testing

```bash
# Firebase public read
curl "https://PROJECT.firebaseio.com/.json"

# GraphQL introspection
curl "https://api.example.com/graphql" -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

---

## Common Hook Patterns

**Hook a Java method:**
```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.example.ClassName");
    TargetClass.methodName.implementation = function(arg1) {
        console.log("Called with: " + arg1);
        return this.methodName(arg1);
    };
});
```

**Hook overloaded methods:**
```javascript
ClassName.method.overload('java.lang.String', 'int').implementation = function(str, num) {
    return this.method(str, num);
};
```

**Get stack trace:**
```javascript
function getStack() {
    return Java.use("android.util.Log")
        .getStackTraceString(Java.use("java.lang.Exception").$new());
}
```

---

## Reference Documentation

| Topic | File | When to Read |
|-------|------|--------------|
| API Key Testing | `reference/api_key_testing.md` | When Google/Firebase API keys found |
| Traffic Interception | `reference/traffic_interception.md` | When setting up proxy + HAR analysis |
| Cloud Providers | `reference/cloud_providers.md` | When AWS/Azure/GCP keys found |

---

## Security Warning

Captured output contains real secrets. Before sharing:
- Replace keys/tokens with `<REDACTED>`
- Never commit log files to git
- Use findings responsibly within authorized scope
