---
name: frida-android
description: Create and use Frida scripts for Android security research. Use when user needs to hook Android methods, intercept crypto operations, capture secrets/tokens, spoof GPS location, or analyze app runtime behavior.
---

# Frida Android Security Scripts

Frida scripts for Android application security research and runtime instrumentation.

## Available Scripts

| Script | Purpose |
|--------|---------|
| `catch_secrets.js` | Intercept crypto keys, auth headers, tokens, and SharedPreferences |
| `fake_location.js` | Spoof GPS coordinates |

## Running Scripts

**Attach to running app:**
```bash
frida -U -l script.js -n <package_name>
```

**Spawn and attach (recommended):**
```bash
frida -U -l script.js -f <package_name>
```

**With parameters (fake_location.js):**
```bash
frida -U -l fake_location.js -f <package> -P '{"lat": 40.7128, "lng": -74.0060}'
```

**Save output:**
```bash
frida -U -l catch_secrets.js -f <package> | tee capture.log
```

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

**Bytes to hex:**
```javascript
function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
    }
    return hex.join('');
}
```

## Common Hook Targets

| Target | Class | Method |
|--------|-------|--------|
| Crypto keys | `javax.crypto.spec.SecretKeySpec` | `$init` |
| IVs | `javax.crypto.spec.IvParameterSpec` | `$init` |
| Encryption | `javax.crypto.Cipher` | `doFinal` |
| Hashing | `java.security.MessageDigest` | `digest` |
| HTTP headers | `okhttp3.Request$Builder` | `addHeader` |
| SharedPrefs | `android.app.SharedPreferencesImpl` | `getString` |
| Location | `android.location.Location` | `getLatitude`, `getLongitude` |

## Security Workflow

1. **Recon**: Identify target package and interesting classes
2. **Capture**: Run `catch_secrets.js` to observe crypto/auth
3. **Target**: Create specific hooks for methods of interest
4. **Document**: Save logs and write analysis
5. **Clean**: Remove real secrets before sharing

## Output Warning

Captured output contains real secrets. Before sharing:
- Replace keys/tokens with `<REDACTED>`
- Never commit log files to git
