// bypass_emulator.js - Emulator Detection Bypass for Android
// Hooks common emulator detection methods to make app think it's on real device

Java.perform(function() {
    console.log("[*] Loading Emulator Detection Bypass...");

    // ==================== Build Properties ====================
    try {
        var Build = Java.use("android.os.Build");

        // Common emulator indicators
        var fieldsToSpoof = {
            "FINGERPRINT": "google/sailfish/sailfish:8.1.0/OPM1.171019.011/4448085:user/release-keys",
            "MODEL": "Pixel",
            "MANUFACTURER": "Google",
            "BRAND": "google",
            "DEVICE": "sailfish",
            "PRODUCT": "sailfish",
            "HARDWARE": "sailfish",
            "BOARD": "sailfish",
            "BOOTLOADER": "8996-012001-1711291800",
            "SERIAL": "FA6A10305812",
            "HOST": "wphs1.hot.corp.google.com",
            "USER": "android-build"
        };

        for (var fieldName in fieldsToSpoof) {
            try {
                var field = Build.class.getDeclaredField(fieldName);
                field.setAccessible(true);
                field.set(null, fieldsToSpoof[fieldName]);
                console.log("[+] Build." + fieldName + " spoofed");
            } catch(e) {}
        }

    } catch(e) {
        console.log("[!] Build properties spoof failed: " + e);
    }

    // ==================== System Properties ====================
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");

        var propsToSpoof = {
            "ro.hardware": "sailfish",
            "ro.product.model": "Pixel",
            "ro.product.brand": "google",
            "ro.product.device": "sailfish",
            "ro.product.manufacturer": "Google",
            "ro.product.name": "sailfish",
            "ro.build.fingerprint": "google/sailfish/sailfish:8.1.0/OPM1.171019.011/4448085:user/release-keys",
            "ro.kernel.qemu": "0",
            "ro.kernel.qemu.gles": "",
            "ro.boot.qemu": "0",
            "init.svc.qemu-props": "",
            "init.svc.qemud": "",
            "ro.build.characteristics": ""
        };

        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (propsToSpoof.hasOwnProperty(key)) {
                console.log("[EMU] Spoofed " + key + " -> " + propsToSpoof[key]);
                return propsToSpoof[key];
            }
            return this.get(key);
        };

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            if (propsToSpoof.hasOwnProperty(key)) {
                console.log("[EMU] Spoofed " + key + " -> " + propsToSpoof[key]);
                return propsToSpoof[key];
            }
            return this.get(key, def);
        };

        console.log("[+] SystemProperties hooked");
    } catch(e) {
        console.log("[!] SystemProperties hook failed: " + e);
    }

    // ==================== TelephonyManager ====================
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getDeviceId.overload().implementation = function() {
            console.log("[EMU] Spoofed getDeviceId");
            return "358673091234567"; // Valid IMEI format
        };

        TelephonyManager.getSubscriberId.implementation = function() {
            console.log("[EMU] Spoofed getSubscriberId");
            return "310260000000000"; // Valid IMSI format
        };

        TelephonyManager.getLine1Number.implementation = function() {
            console.log("[EMU] Spoofed getLine1Number");
            return "+15551234567";
        };

        TelephonyManager.getNetworkOperatorName.implementation = function() {
            return "T-Mobile";
        };

        TelephonyManager.getSimOperatorName.implementation = function() {
            return "T-Mobile";
        };

        TelephonyManager.getPhoneType.implementation = function() {
            return 1; // PHONE_TYPE_GSM
        };

        TelephonyManager.getNetworkType.implementation = function() {
            return 13; // NETWORK_TYPE_LTE
        };

        console.log("[+] TelephonyManager hooked");
    } catch(e) {
        console.log("[!] TelephonyManager hook failed: " + e);
    }

    // ==================== Sensors ====================
    // Emulators often have 0 sensors or fake sensor values
    try {
        var SensorManager = Java.use("android.hardware.SensorManager");
        // Most apps check getSensorList - we let it pass through
        // Real detection happens at sensor value level
        console.log("[i] SensorManager awareness loaded");
    } catch(e) {}

    // ==================== File System Checks ====================
    // Block access to emulator-specific files
    try {
        var File = Java.use("java.io.File");

        var emuPaths = [
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/goldfish_pipe",
            "/sys/devices/virtual/misc/goldfish_pipe",
            "/data/data/com.android.emulator.smoke",
            "/init.goldfish.rc",
            "/init.ranchu.rc",
            "/fstab.goldfish",
            "/fstab.ranchu",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
            "/proc/tty/drivers"
        ];

        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < emuPaths.length; i++) {
                if (path.indexOf(emuPaths[i]) !== -1) {
                    console.log("[EMU] Blocked file check: " + path);
                    return false;
                }
            }
            return this.exists();
        };

        console.log("[+] Emulator file checks blocked");
    } catch(e) {
        console.log("[!] File hook failed: " + e);
    }

    // ==================== Network Interfaces ====================
    // Emulators often have eth0 instead of wlan0/rmnet
    try {
        var NetworkInterface = Java.use("java.net.NetworkInterface");

        NetworkInterface.getName.implementation = function() {
            var name = this.getName();
            if (name === "eth0") {
                console.log("[EMU] Spoofed eth0 -> wlan0");
                return "wlan0";
            }
            return name;
        };

        console.log("[+] NetworkInterface hooked");
    } catch(e) {
        console.log("[!] NetworkInterface hook failed: " + e);
    }

    // ==================== Battery ====================
    // Emulators often have specific battery characteristics
    try {
        var BatteryManager = Java.use("android.os.BatteryManager");
        // Battery checks typically done via Intent extras, harder to hook
        console.log("[i] BatteryManager awareness loaded");
    } catch(e) {}

    console.log("[+] Emulator Detection Bypass loaded!");
    console.log("");
});
