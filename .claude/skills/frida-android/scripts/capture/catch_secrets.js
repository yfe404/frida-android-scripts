// catch_secrets.js - Android Secret Catcher for Frida
// Hooks crypto, auth headers, preferences, and more to intercept secrets at runtime

Java.perform(function() {

    // ==================== CONFIGURATION ====================
    var CONFIG = {
        ENABLE_STRING_BUILDER: false,  // Very noisy, enable only if needed
        ENABLE_BASE64: true,
        ENABLE_CIPHER: true,
        ENABLE_DIGEST: true,           // MessageDigest (SHA256, MD5, etc.)
        STACK_LINES: 8                 // Lines of stack trace in file log
    };

    // ==================== ANSI COLORS ====================
    var C = {
        RESET:   "\x1b[0m",
        BOLD:    "\x1b[1m",
        DIM:     "\x1b[2m",

        RED:     "\x1b[31m",
        GREEN:   "\x1b[32m",
        YELLOW:  "\x1b[33m",
        BLUE:    "\x1b[34m",
        MAGENTA: "\x1b[35m",
        CYAN:    "\x1b[36m",
        WHITE:   "\x1b[37m",

        BG_RED:    "\x1b[41m",
        BG_GREEN:  "\x1b[42m",
        BG_YELLOW: "\x1b[43m",
        BG_BLUE:   "\x1b[44m",
    };

    // ==================== STATS ====================
    var stats = {
        cryptoKeys: 0,
        ivSpecs: 0,
        cipherOps: 0,
        digests: 0,
        headers: 0,
        prefs: 0,
        base64: 0,
        strings: 0
    };



    // ==================== HELPERS ====================
    var inHelper = false;
    function withGuard(fn) {
        if (inHelper) return;
        inHelper = true;
        try { fn(); } finally { inHelper = false; }
    }

    function timestamp() {
        var d = new Date();
        return C.DIM + d.toTimeString().split(' ')[0] + "." +
               ("00" + d.getMilliseconds()).slice(-3) + C.RESET;
    }

    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join('');
    }

    function bytesToString(bytes) {
        var str = "";
        for (var i = 0; i < bytes.length; i++) {
            var c = bytes[i] & 0xFF;
            if (c >= 32 && c < 127) {
                str += String.fromCharCode(c);
            } else {
                str += ".";
            }
        }
        return str;
    }

    function getStack(limit) {
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        var lines = stack.split("\n").slice(2, 2 + (limit || CONFIG.STACK_LINES));
        return lines.join("\n");
    }

    function truncate(str, len) {
        if (str && str.length > len) {
            return str.substring(0, len) + "...(" + str.length + " chars)";
        }
        return str;
    }

    // ==================== BANNER ====================
    function printBanner() {
        console.log("");
        console.log(C.CYAN + C.BOLD + "  ╔═══════════════════════════════════════════════════════╗" + C.RESET);
        console.log(C.CYAN + C.BOLD + "  ║" + C.RESET + C.YELLOW + C.BOLD + "           🔐 SECRET CATCHER v1.0 🔐                  " + C.CYAN + C.BOLD + "║" + C.RESET);
        console.log(C.CYAN + C.BOLD + "  ║" + C.RESET + C.DIM + "        Frida script for Android secrets               " + C.CYAN + C.BOLD + "║" + C.RESET);
        console.log(C.CYAN + C.BOLD + "  ╚═══════════════════════════════════════════════════════╝" + C.RESET);
        console.log("");
        console.log(C.GREEN + "  [✓]" + C.RESET + " Hooks active:");
        console.log(C.DIM + "      • SecretKeySpec (crypto keys)" + C.RESET);
        console.log(C.DIM + "      • IvParameterSpec (IVs)" + C.RESET);
        if (CONFIG.ENABLE_CIPHER) console.log(C.DIM + "      • Cipher.doFinal (encrypt/decrypt)" + C.RESET);
        if (CONFIG.ENABLE_DIGEST) console.log(C.DIM + "      • MessageDigest (SHA256/MD5/SHA1)" + C.RESET);
        if (CONFIG.ENABLE_BASE64) console.log(C.DIM + "      • Base64 decode" + C.RESET);
        console.log(C.DIM + "      • OkHttp headers" + C.RESET);
        console.log(C.DIM + "      • SharedPreferences" + C.RESET);
        if (CONFIG.ENABLE_STRING_BUILDER) console.log(C.DIM + "      • StringBuilder (noisy)" + C.RESET);
        console.log("");
        console.log(C.BLUE + "  [i]" + C.RESET + " Tip: pipe output to file with | tee capture.log");
        console.log("");
        console.log(C.CYAN + "  ─────────────────────────────────────────────────────────" + C.RESET);
        console.log("");
    }

    function printSummary() {
        console.log("");
        console.log(C.CYAN + "  ═══════════════════════════════════════════════════════" + C.RESET);
        console.log(C.BOLD + "  📊 SESSION SUMMARY" + C.RESET);
        console.log(C.CYAN + "  ─────────────────────────────────────────────────────────" + C.RESET);
        console.log("  Crypto Keys:     " + C.YELLOW + stats.cryptoKeys + C.RESET);
        console.log("  IV Specs:        " + C.YELLOW + stats.ivSpecs + C.RESET);
        console.log("  Cipher Ops:      " + C.YELLOW + stats.cipherOps + C.RESET);
        console.log("  Digests:         " + C.YELLOW + stats.digests + C.RESET);
        console.log("  Auth Headers:    " + C.YELLOW + stats.headers + C.RESET);
        console.log("  Preferences:     " + C.YELLOW + stats.prefs + C.RESET);
        console.log("  Base64 Decodes:  " + C.YELLOW + stats.base64 + C.RESET);
        console.log("  String Matches:  " + C.YELLOW + stats.strings + C.RESET);
        console.log(C.CYAN + "  ═══════════════════════════════════════════════════════" + C.RESET);
    }

    // ==================== CONSOLE OUTPUT ====================
    function logCrypto(type, data) {
        stats.cryptoKeys++;
        console.log(timestamp() + " " + C.BG_RED + C.WHITE + C.BOLD + " 🔑 CRYPTO KEY " + C.RESET);
        console.log("         " + C.DIM + "Algorithm:" + C.RESET + " " + C.YELLOW + data.algo + C.RESET);
        console.log("         " + C.DIM + "Key (hex):" + C.RESET + " " + C.RED + data.hex + C.RESET);
        if (data.ascii) {
            console.log("         " + C.DIM + "Key (ascii):" + C.RESET + " " + data.ascii);
        }
        console.log("");
    }

    function logIV(data) {
        stats.ivSpecs++;
        console.log(timestamp() + " " + C.BG_YELLOW + C.WHITE + C.BOLD + " 🎲 IV SPEC " + C.RESET);
        console.log("         " + C.DIM + "IV (hex):" + C.RESET + " " + C.YELLOW + data.hex + C.RESET);
        console.log("");
    }

    function logCipher(type, data) {
        stats.cipherOps++;
        var label = type === "encrypt" ? " 🔒 ENCRYPT " : " 🔓 DECRYPT ";
        var bgColor = type === "encrypt" ? C.BG_BLUE : C.BG_GREEN;

        console.log(timestamp() + " " + bgColor + C.WHITE + C.BOLD + label + C.RESET + " " + C.DIM + data.algo + C.RESET);
        console.log("         " + C.DIM + "Input:" + C.RESET + "  " + truncate(data.inputHex, 64));
        console.log("         " + C.DIM + "Output:" + C.RESET + " " + truncate(data.outputHex, 64));
        console.log("");
    }

    function logDigest(data) {
        stats.digests++;
        console.log(timestamp() + " " + C.BG_BLUE + C.WHITE + C.BOLD + " #️⃣ HASH " + C.RESET + " " + C.DIM + data.algo + C.RESET);
        console.log("         " + C.DIM + "Input:" + C.RESET + "  " + C.WHITE + truncate(data.inputAscii, 80) + C.RESET);
        console.log("         " + C.DIM + "Output:" + C.RESET + " " + C.YELLOW + data.outputHex + C.RESET);
        console.log("");
    }

    function logHeader(name, value) {
        stats.headers++;
        console.log(timestamp() + " " + C.BG_MAGENTA + C.WHITE + C.BOLD + " 📡 HEADER " + C.RESET);
        console.log("         " + C.MAGENTA + name + C.RESET + ": " + C.WHITE + value + C.RESET);
        console.log("");
    }

    function logPref(key, value) {
        stats.prefs++;
        console.log(timestamp() + " " + C.BG_CYAN + C.WHITE + C.BOLD + " 💾 PREF " + C.RESET);
        console.log("         " + C.CYAN + key + C.RESET + " = " + C.WHITE + value + C.RESET);
        console.log("");
    }

    function logBase64(input, output) {
        stats.base64++;
        console.log(timestamp() + " " + C.BG_YELLOW + C.WHITE + C.BOLD + " 📦 BASE64 " + C.RESET);
        console.log("         " + C.DIM + "Decoded:" + C.RESET + " " + C.WHITE + truncate(output, 80) + C.RESET);
        console.log("");
    }

    function logString(owner, value) {
        stats.strings++;
        console.log(timestamp() + " " + C.BG_GREEN + C.WHITE + C.BOLD + " 📝 STRING " + C.RESET);
        console.log("         " + C.DIM + "Owner:" + C.RESET + " " + owner);
        console.log("         " + C.DIM + "Value:" + C.RESET + " " + C.WHITE + truncate(value, 60) + C.RESET);
        console.log("");
    }

    // ==================== HOOKS ====================

    // --- SecretKeySpec (Crypto Keys) ---
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        logCrypto("key", {
            algo: algo,
            hex: bytesToHex(key),
            ascii: bytesToString(key),
            stack: getStack()
        });
        return this.$init(key, algo);
    };

    // --- IvParameterSpec (IVs) ---
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        logIV({
            hex: bytesToHex(iv),
            stack: getStack()
        });
        return this.$init(iv);
    };

    // --- Cipher.doFinal (Encrypt/Decrypt) ---
    if (CONFIG.ENABLE_CIPHER) {
        try {
            var Cipher = Java.use("javax.crypto.Cipher");

            // Hook the most common overload
            Cipher.doFinal.overload('[B').implementation = function(input) {
                var output = this.doFinal(input);
                try {
                    var mode = this.getOpmode();
                    var algo = this.getAlgorithm();
                    var type = (mode === 1) ? "encrypt" : "decrypt";

                    logCipher(type, {
                        algo: algo,
                        inputHex: bytesToHex(input),
                        outputHex: bytesToHex(output),
                        inputAscii: bytesToString(input),
                        outputAscii: bytesToString(output),
                        stack: getStack()
                    });
                } catch(e) {
                    // Silently ignore logging errors
                }
                return output;
            };
            console.log(C.GREEN + "  [✓]" + C.RESET + " Cipher.doFinal hooked");
        } catch(e) {
            console.log(C.YELLOW + "  [!]" + C.RESET + " Cipher hook failed: " + e);
        }
    }

    // --- MessageDigest (SHA256, MD5, SHA1, etc.) ---
    if (CONFIG.ENABLE_DIGEST) {
        try {
            var MessageDigest = Java.use("java.security.MessageDigest");

            // Only hook digest([B) - the simpler, safer approach
            MessageDigest.digest.overload('[B').implementation = function(input) {
                var output = this.digest(input);
                try {
                    var algo = this.getAlgorithm();
                    logDigest({
                        algo: algo,
                        inputAscii: bytesToString(input),
                        inputHex: bytesToHex(input),
                        outputHex: bytesToHex(output)
                    });
                } catch(e) {}
                return output;
            };

            console.log(C.GREEN + "  [✓]" + C.RESET + " MessageDigest hooked (SHA256/MD5/etc)");
        } catch(e) {
            console.log(C.YELLOW + "  [!]" + C.RESET + " MessageDigest hook failed: " + e);
        }
    }

    // --- Base64 Decode ---
    if (CONFIG.ENABLE_BASE64) {
        var Base64 = Java.use("android.util.Base64");

        Base64.decode.overload('[B', 'int').implementation = function(input, flags) {
            var result = this.decode(input, flags);
            var decoded = bytesToString(result);

            if (decoded.length > 8 && decoded.match(/^[\x20-\x7E.]+$/)) {
                withGuard(function() {
                    logBase64(bytesToString(input), decoded);
                });
            }
            return result;
        };

        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            var result = this.decode(str, flags);
            var decoded = bytesToString(result);

            if (decoded.length > 8 && decoded.match(/^[\x20-\x7E.]+$/)) {
                withGuard(function() {
                    logBase64(str, decoded);
                });
            }
            return result;
        };
    }

    // --- OkHttp Headers ---
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        RequestBuilder.addHeader.implementation = function(name, value) {
            var nameLower = name.toLowerCase();
            if (nameLower.match(/auth|bearer|key|token|secret|sign|api[-_]?key|x-api|x-auth|x-token|cookie|session/)) {
                logHeader(name, value);
            }
            return this.addHeader(name, value);
        };
        console.log(C.GREEN + "  [✓]" + C.RESET + " OkHttp3 hooked");
    } catch(e) {
        console.log(C.YELLOW + "  [!]" + C.RESET + " OkHttp3 not found");
    }

    // --- HttpURLConnection ---
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            var keyLower = key.toLowerCase();
            if (keyLower.match(/auth|bearer|key|token|secret|sign|api[-_]?key|x-api|x-auth|x-token|cookie|session/)) {
                logHeader(key, value);
            }
            return this.setRequestProperty(key, value);
        };
        console.log(C.GREEN + "  [✓]" + C.RESET + " HttpURLConnection hooked");
    } catch(e) {
        console.log(C.YELLOW + "  [!]" + C.RESET + " HttpURLConnection hook failed");
    }

    // --- SharedPreferences ---
    var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferencesImpl.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        var keyLower = key.toLowerCase();

        if (keyLower.match(/key|secret|token|api|auth|pass|cred|session|jwt|bearer/)) {
            withGuard(function() {
                logPref(key, value);
            });
        }
        return value;
    };

    // --- StringBuilder (Optional, noisy) ---
    if (CONFIG.ENABLE_STRING_BUILDER) {
        var StringBuilder = Java.use("java.lang.StringBuilder");
        var sbToString = StringBuilder.toString;
        StringBuilder.toString.implementation = function() {
            if (inHelper) return sbToString.call(this);

            var result = sbToString.call(this);
            var owner = this.getClass().getName();

            if (result.length > 16 &&
                (result.match(/^[A-Za-z0-9_-]{20,}$/) ||
                 result.match(/^(sk_|pk_|api_|key_|secret|bearer)/i) ||
                 result.match(/^[A-Fa-f0-9]{32,}$/) ||
                 result.match(/^eyJ[A-Za-z0-9_-]+\./))) {  // JWT pattern
                withGuard(function() {
                    logString(owner, result);
                });
            }
            return result;
        };
    }

    // ==================== INIT ====================
    printBanner();
    console.log("");
});
