// fake_location.js - GPS Location Spoofing for Android
//
// Usage: frida -U -l fake_location.js -f <package> -P '{"lat": 40.7128, "lng": -74.0060}'
// Default: Paris (48.8566, 2.3522)

// Parse parameters from -P flag or use defaults
var params = (typeof parameters !== 'undefined') ? parameters : {};
var FAKE_LAT = params.lat || 48.8566;
var FAKE_LNG = params.lng || 2.3522;
var FAKE_ALT = params.alt || 35.0;
var FAKE_ACCURACY = params.acc || 10.0;

Java.perform(function() {

    // ==================== ANSI COLORS ====================
    var C = {
        RESET: "\x1b[0m", BOLD: "\x1b[1m", DIM: "\x1b[2m",
        GREEN: "\x1b[32m", YELLOW: "\x1b[33m", CYAN: "\x1b[36m",
        BG_GREEN: "\x1b[42m", WHITE: "\x1b[37m"
    };

    // ==================== BANNER ====================
    console.log("");
    console.log(C.CYAN + C.BOLD + "  ╔═══════════════════════════════════════════════════════╗" + C.RESET);
    console.log(C.CYAN + C.BOLD + "  ║" + C.RESET + C.YELLOW + C.BOLD + "           📍 FAKE LOCATION v1.0 📍                   " + C.CYAN + C.BOLD + "║" + C.RESET);
    console.log(C.CYAN + C.BOLD + "  ╚═══════════════════════════════════════════════════════╝" + C.RESET);
    console.log("");
    console.log(C.GREEN + "  [✓]" + C.RESET + " Spoofing to: " + C.YELLOW + FAKE_LAT + ", " + FAKE_LNG + C.RESET);
    console.log(C.DIM + "      Edit FAKE_LAT/FAKE_LNG at top of script to change" + C.RESET);
    console.log("");

    // ==================== HOOKS ====================

    var Location = Java.use("android.location.Location");

    Location.getLatitude.implementation = function() {
        console.log(C.BG_GREEN + C.WHITE + " 📍 " + C.RESET + " getLatitude() → " + C.YELLOW + FAKE_LAT + C.RESET);
        return FAKE_LAT;
    };

    Location.getLongitude.implementation = function() {
        console.log(C.BG_GREEN + C.WHITE + " 📍 " + C.RESET + " getLongitude() → " + C.YELLOW + FAKE_LNG + C.RESET);
        return FAKE_LNG;
    };

    Location.getAltitude.implementation = function() {
        return FAKE_ALT;
    };

    Location.getAccuracy.implementation = function() {
        return FAKE_ACCURACY;
    };

    // Hook LocationManager.getLastKnownLocation
    try {
        var LocationManager = Java.use("android.location.LocationManager");
        LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function(provider) {
            console.log(C.BG_GREEN + C.WHITE + " 📍 " + C.RESET + " getLastKnownLocation(" + provider + ")");
            var loc = this.getLastKnownLocation(provider);
            if (loc != null) {
                loc.setLatitude(FAKE_LAT);
                loc.setLongitude(FAKE_LNG);
            }
            return loc;
        };
        console.log(C.GREEN + "  [✓]" + C.RESET + " LocationManager hooked");
    } catch(e) {}

    // Hook Fused Location (Google Play Services)
    try {
        var LocationResult = Java.use("com.google.android.gms.location.LocationResult");
        LocationResult.getLastLocation.implementation = function() {
            var loc = this.getLastLocation();
            if (loc != null) {
                loc.setLatitude(FAKE_LAT);
                loc.setLongitude(FAKE_LNG);
            }
            console.log(C.BG_GREEN + C.WHITE + " 📍 " + C.RESET + " FusedLocation spoofed");
            return loc;
        };
        console.log(C.GREEN + "  [✓]" + C.RESET + " FusedLocationProvider hooked");
    } catch(e) {}

    console.log("");
    console.log(C.CYAN + "  ─────────────────────────────────────────────────────────" + C.RESET);
    console.log("");
});
