// Hook StringExtension.sha256 to capture inputs
Java.perform(function() {
    var StringExtension = Java.use("com.aum.extension.StringExtension");
    
    StringExtension.sha256.implementation = function(input) {
        console.log("\n=== SHA256 INPUT ===");
        console.log("Length: " + input.length);
        console.log("Input: " + input);
        
        // Also log hex
        var bytes = input.getBytes();
        var hex = "";
        for (var i = 0; i < Math.min(bytes.length, 200); i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        console.log("Hex (first 200): " + hex);
        
        var result = this.sha256(input);
        console.log("Result: " + result);
        console.log("===================\n");
        return result;
    };
    
    console.log("[+] SHA256 hook installed");
});
