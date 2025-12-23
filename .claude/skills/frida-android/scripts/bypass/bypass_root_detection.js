// Combined Java + Native Root/Frida detection bypass

var blockedPaths = [
    "frida", "frida-gadget", "frida-server",
    "magisk", "/data/adb/magisk", "/sbin/.magisk",
    "/sbin/su", "/su/bin/su", "/system/xbin/su", "/system/bin/su",
    "/system/app/Superuser.apk", "/data/local/xbin/su", "/data/local/bin/su",
    "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
    "busybox", "supersu", "superuser", "xposed"
];

function isBlocked(path) {
    if (!path) return false;
    var p = path.toLowerCase();
    for (var i = 0; i < blockedPaths.length; i++) {
        if (p.indexOf(blockedPaths[i]) !== -1) return true;
    }
    return false;
}

// ============= NATIVE HOOKS (libc) =============
// Deferred until libc is ready
setTimeout(function() {
    console.log("[*] Setting up native hooks...");

    var libc = Process.getModuleByName("libc.so");

    function hookLibc(name, enterFn, leaveFn) {
        var sym = libc.findExportByName(name);
        if (sym) {
            Interceptor.attach(sym, { onEnter: enterFn, onLeave: leaveFn });
            console.log("[+] Hooked " + name);
        }
    }

    // Hook fopen
    hookLibc("fopen",
        function(args) { this.path = args[0].readCString(); },
        function(retval) {
            if (isBlocked(this.path)) {
                console.log("[NATIVE] Blocked fopen: " + this.path);
                retval.replace(ptr(0));
            }
        }
    );

    // Hook access
    hookLibc("access",
        function(args) { this.path = args[0].readCString(); },
        function(retval) {
            if (isBlocked(this.path)) {
                console.log("[NATIVE] Blocked access: " + this.path);
                retval.replace(ptr(-1));
            }
        }
    );

    // Hook stat variants
    ["stat", "lstat", "fstatat", "faccessat"].forEach(function(fn) {
        hookLibc(fn,
            function(args) { try { this.path = args[0].readCString(); } catch(e) { this.path = ""; } },
            function(retval) {
                if (isBlocked(this.path)) {
                    console.log("[NATIVE] Blocked " + fn + ": " + this.path);
                    retval.replace(ptr(-1));
                }
            }
        );
    });

    // Hook opendir
    hookLibc("opendir",
        function(args) { this.path = args[0].readCString(); },
        function(retval) {
            if (isBlocked(this.path)) {
                console.log("[NATIVE] Blocked opendir: " + this.path);
                retval.replace(ptr(0));
            }
        }
    );

    // Hook strstr for /proc/maps scanning
    hookLibc("strstr",
        function(args) { try { this.needle = args[1].readCString(); } catch(e) { this.needle = ""; } },
        function(retval) {
            if (this.needle && isBlocked(this.needle) && !retval.isNull()) {
                console.log("[NATIVE] Blocked strstr: " + this.needle);
                retval.replace(ptr(0));
            }
        }
    );

    console.log("[+] Native hooks installed");
}, 100);

// ============= JAVA HOOKS =============
Java.perform(function() {
    console.log("[*] Setting up Java hooks...");

    var File = Java.use("java.io.File");

    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (isBlocked(path)) {
            console.log("[JAVA] Blocked File.exists: " + path);
            return false;
        }
        return this.exists();
    };

    File.canRead.implementation = function() {
        var path = this.getAbsolutePath();
        if (isBlocked(path)) {
            console.log("[JAVA] Blocked File.canRead: " + path);
            return false;
        }
        return this.canRead();
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (isBlocked(cmd)) {
            console.log("[JAVA] Blocked Runtime.exec: " + cmd);
            throw Java.use("java.io.IOException").$new("Cannot run");
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
        var cmd = cmds.join(" ");
        if (isBlocked(cmd)) {
            console.log("[JAVA] Blocked Runtime.exec[]: " + cmd);
            throw Java.use("java.io.IOException").$new("Cannot run");
        }
        return this.exec(cmds);
    };

    // Hide root packages
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
            var rootPkgs = ["com.topjohnwu.magisk", "eu.chainfire.supersu",
                           "com.koushikdutta.superuser", "com.noshufou.android.su"];
            if (rootPkgs.indexOf(pkg) !== -1) {
                console.log("[JAVA] Blocked getPackageInfo: " + pkg);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
    } catch(e) {}

    console.log("[+] Java hooks installed");
    console.log("[+] Combined bypass fully loaded!");
});
