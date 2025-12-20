# Frida Android Scripts

A collection of Frida scripts for Android security research and runtime instrumentation.

## Scripts

| Script | Description |
|--------|-------------|
| `catch_secrets.js` | Intercept crypto keys, IVs, auth headers, tokens, and SharedPreferences secrets at runtime |
| `fake_location.js` | Spoof GPS coordinates for location-based applications |

## Requirements

- [Frida](https://frida.re/) installed on host machine
- Rooted Android device or emulator with `frida-server` running
- USB debugging enabled

```bash
# Install Frida
pip install frida-tools

# Verify installation
frida --version
```

## Usage

### catch_secrets.js

Captures cryptographic operations, authentication headers, and stored secrets:

```bash
# Spawn app and attach
frida -U -l catch_secrets.js -f com.target.app

# Attach to running app
frida -U -l catch_secrets.js -n com.target.app

# Save output to file
frida -U -l catch_secrets.js -f com.target.app | tee output.log
```

**What it hooks:**
- `SecretKeySpec` - Crypto keys (AES, HMAC, etc.)
- `IvParameterSpec` - Initialization vectors
- `Cipher.doFinal` - Encrypt/decrypt operations
- `MessageDigest` - Hash operations (SHA256, MD5, etc.)
- `OkHttp` / `HttpURLConnection` - Auth headers
- `SharedPreferences` - Stored tokens and keys
- `Base64.decode` - Decoded values

### fake_location.js

Spoofs GPS location for the target app:

```bash
# Default location (Paris)
frida -U -l fake_location.js -f com.target.app

# Custom location (New York)
frida -U -l fake_location.js -f com.target.app -P '{"lat": 40.7128, "lng": -74.0060}'

# With altitude and accuracy
frida -U -l fake_location.js -f com.target.app -P '{"lat": 40.7128, "lng": -74.0060, "alt": 10, "acc": 5}'
```

## Installation as Claude Code Skill

This repository includes a Claude Code skill for AI-assisted Android security research.

### Project-based (recommended for teams)

Clone the repo and the skill is ready to use:

```bash
git clone https://github.com/yfe404/frida-android-scripts.git
cd frida-android-scripts
# Skill is already at .claude/skills/frida-android/
```

### Global installation (personal use)

Symlink to your global Claude skills directory:

```bash
# Create global skills directory if it doesn't exist
mkdir -p ~/.claude/skills

# Symlink the skill
ln -s /path/to/frida-android-scripts/.claude/skills/frida-android ~/.claude/skills/frida-android
```

### Verify installation

The skill will appear in Claude Code's available skills. Claude will automatically use it when you work on Android security tasks.

## Configuration

### catch_secrets.js

Edit the `CONFIG` object at the top of the script:

```javascript
var CONFIG = {
    ENABLE_STRING_BUILDER: false,  // Very noisy, enable if needed
    ENABLE_BASE64: true,
    ENABLE_CIPHER: true,
    ENABLE_DIGEST: true,
    STACK_LINES: 8
};
```

### fake_location.js

Pass coordinates via Frida's `-P` parameter or edit defaults in the script:

```javascript
var FAKE_LAT = 48.8566;   // Latitude
var FAKE_LNG = 2.3522;    // Longitude
var FAKE_ALT = 35.0;      // Altitude (meters)
var FAKE_ACCURACY = 10.0; // Accuracy (meters)
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Failed to spawn" | App may have anti-Frida detection; try attaching instead |
| "Class not found" | Class loads later; add delay or use `Java.scheduleOnMainThread()` |
| No output | App isn't calling hooked methods; trigger the functionality manually |
| Device not found | Ensure `frida-server` is running: `adb shell "/data/local/tmp/frida-server &"` |

## Legal Disclaimer

These tools are intended for authorized security research, penetration testing, and educational purposes only. Only use on applications you own or have explicit permission to test.

## License

MIT
