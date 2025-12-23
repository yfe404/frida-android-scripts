// bypass_debug.js - Debug Detection Bypass for Android
// Hooks debugger detection methods to prevent app from detecting debugging

Java.perform(function() {
    console.log("[*] Loading Debug Detection Bypass...");

    // ==================== android.os.Debug ====================
    try {
        var Debug = Java.use("android.os.Debug");

        // isDebuggerConnected() - most common check
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[DEBUG] Bypassed Debug.isDebuggerConnected() -> false");
            return false;
        };

        // waitingForDebugger()
        Debug.waitingForDebugger.implementation = function() {
            console.log("[DEBUG] Bypassed Debug.waitingForDebugger() -> false");
            return false;
        };

        console.log("[+] android.os.Debug hooked");
    } catch(e) {
        console.log("[!] android.os.Debug hook failed: " + e);
    }

    // ==================== TracerPid Check ====================
    // Apps read /proc/self/status to check TracerPid
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        BufferedReader.readLine.overload().implementation = function() {
            var line = this.readLine();
            if (line && line.indexOf("TracerPid:") !== -1) {
                console.log("[DEBUG] Bypassed TracerPid check -> TracerPid: 0");
                return "TracerPid:\t0";
            }
            return line;
        };
        console.log("[+] TracerPid check hooked");
    } catch(e) {
        console.log("[!] BufferedReader hook failed: " + e);
    }

    // ==================== ApplicationInfo.flags ====================
    // Check for FLAG_DEBUGGABLE
    try {
        var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
        var FLAG_DEBUGGABLE = 0x2;

        // Hook field access isn't directly possible, but we can hook getApplicationInfo
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
            var appInfo = this.getApplicationInfo(pkg, flags);
            // Clear debuggable flag
            appInfo.flags.value = appInfo.flags.value & ~FLAG_DEBUGGABLE;
            return appInfo;
        };
        console.log("[+] ApplicationInfo.flags hooked");
    } catch(e) {
        console.log("[!] ApplicationInfo hook failed: " + e);
    }

    // ==================== System Properties ====================
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");

        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            var value = this.get(key);
            if (key === "ro.debuggable") {
                console.log("[DEBUG] Bypassed ro.debuggable -> 0");
                return "0";
            }
            return value;
        };

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            var value = this.get(key, def);
            if (key === "ro.debuggable") {
                console.log("[DEBUG] Bypassed ro.debuggable -> 0");
                return "0";
            }
            return value;
        };

        console.log("[+] SystemProperties hooked");
    } catch(e) {
        console.log("[!] SystemProperties hook failed: " + e);
    }

    // ==================== JDWP Port Check ====================
    // Some apps check for JDWP listening port
    try {
        var ServerSocket = Java.use("java.net.ServerSocket");
        var originalBind = ServerSocket.bind;

        // We don't need to modify this, just note that JDWP typically uses port 8700+
        console.log("[i] JDWP check awareness loaded");
    } catch(e) {}

    // ==================== Build.TAGS ====================
    // Check for "test-keys" in build
    try {
        var Build = Java.use("android.os.Build");
        var tagsField = Build.class.getDeclaredField("TAGS");
        tagsField.setAccessible(true);
        tagsField.set(null, "release-keys");
        console.log("[+] Build.TAGS set to release-keys");
    } catch(e) {
        console.log("[!] Build.TAGS modification failed: " + e);
    }

    console.log("[+] Debug Detection Bypass loaded!");
    console.log("");
});
