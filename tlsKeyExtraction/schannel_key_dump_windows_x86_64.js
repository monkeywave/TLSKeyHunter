/*
 * Invoke:
 * frida -p (frida-ps | Where-Object { $_ -match "lsass\.exe" } | ForEach-Object { ($_ -split "\s+")[1] }) -l schannel_key_dump_liunx_x86_64.js
 */

// Constants for parsing
const SSL3_RANDOM_SIZE = 32; // Assuming SSL3_RANDOM_SIZE is 32 bytes which is defined in the RFC
const SSL_MAX_MD_SIZE = 48;  // Assuming SSL_MAX_MD_SIZE is 64 bytes

// Dynamic offsets based on architecture
const is64Bit = Process.arch === 'x64';




// some global definitions
var did_check = false;
var session_client_random = "";
var session_client_randoms_tls13 = {};

function buf2hex(buffer) {
            return Array.prototype.map.call(new Uint8Array(buffer), function(x){ return ('00' + x.toString(16)).slice(-2)} ).join('');
}

var client_randoms = {};

/*
 * This part was taken from https://github.com/ngo/win-frida-scripts/blob/master/lsasslkeylog-easy/keylog.js
 */
function get_secret_from_BDDD(struct_BDDD){
            var struct_3lss = struct_BDDD.add(0x10).readPointer();
            var struct_RUUU = struct_3lss.add(0x20).readPointer();
            var struct_YKSM = struct_RUUU.add(0x10).readPointer();
            var secret_ptr = struct_YKSM.add(0x18).readPointer();
            var size = struct_YKSM.add(0x10).readU32();

            return secret_ptr.readByteArray(size);
}

/*

Usually we can expect after the label are length value of that label.
The PRF would have a length of 0xD (13) and the HKDF 0xC (12)


*/

function get_working_func_args(context, check_for_length, is_hkdf){
     // Initialize an empty array to store arguments
     var argument_array = [];
     console.log("[*] Hooked function onEnter!");

     try {
         for (var i = 0; ; i++) { // Iterate until we hit an exception
            if(i > 13){
                return argument_array;
            }
             try {
                 var arg = context[i]; // // Access the ith argument
                 if (arg) {
                     argument_array.push(arg); // Save argument for later use
                     console.log('[*] Argument ' + i + ' at address ' + arg + ':');

                     if(check_for_length){
                        if(is_hkdf && arg == 0xC){
                            //return argument_array;
                        }else if(!is_hkdf && arg == 0xD){
                            //return argument_array;
                        }

                     }

                 } else {
                     console.log('[*] Argument ' + i + ' is null.');
                     argument_array.push(null);
                 }
             } catch (e) {
                 console.log('[!] Reached end of arguments at index ' + i + '.');
                 console.log(e.message);
                 return argument_array; // Exit the loop when we can't access more arguments
             }
         }
     } catch (e) {
         console.log('[!] Error in onEnter: ' + e.message);
         return argument_array;
     }
}



// Utility function to convert byte array to hex
function byteArrayToHex(byteArray) {
    if (!byteArray) return null;
    const array = new Uint8Array(byteArray);
    return Array.from(array)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}



function isMemoryReadable(ptr, size) {
    try {
        // Check if the pointer is null or likely invalid
        if (ptr.isNull() || ptr.toInt32() < 0x1000) {
            console.log(`[!] Skipping invalid or null pointer: ${ptr}`);
            return false;
        }

        // Attempt to read a small chunk of memory as a test
        Memory.readByteArray(ptr, size);
        return true; // If no exception, memory is readable
    } catch (e) {
        console.log(`[!] Memory not readable at ${ptr}: ${e.message}`);
        return false;
    }
}



function isAsciiString(bytes) {
    try {
        var view = new Uint8Array(bytes); // Convert to a byte array for iteration
        var asciiString = "";

        for (var i = 0; i < view.length; i++) {
            var byte = view[i];

            // Check if byte is printable ASCII or null-terminator
            if ((byte >= 0x20 && byte <= 0x7E) || byte === 0) {
                if (byte === 0) {
                    // Null-terminator found, stop here
                    break;
                }
                asciiString += String.fromCharCode(byte);
            } else {
                // Non-printable character found
                return false;
            }
        }

        return asciiString.length > 0 ? true : false; // Return the string if valid
    } catch (e) {
        console.log("[!] Error while validating string:", e.message);
        return false;
    }
}


function check_arguments(memoryPointer, arg_number){
    console.log("[*] Argument points to:", memoryPointer);


    // Try to read the memory region
    try {
        console.log("[*] Dumping memory at address:", memoryPointer);
        var memoryContent = dumpMemory(memoryPointer, 0x40);
        if(memoryContent != null){
            var is_arg_a_string = isAsciiString(memoryContent);
            if(is_arg_a_string){
                console.log("[+] Label found at argument ", arg_number);
            }else{
                try{
                    console.log("[!] Not a string: ",e.message); // actually a weird bug, when I don't have this exception the target program keeps crashing 
                }catch(e) {
                    console.log("[*] Not a String. Start to check its entropy...");

                    var num_zero_bytes = countZeroBytes(memoryContent);
                    if(num_zero_bytes > 5){
                        console.log("[*] Too many zero bytes. Unlikely a cryptographic key at argument "+arg_number);
                    }else{
                        console.log("[*] Likely a cryptographic key at argument "+arg_number);
                    }

                    /*
                
                    // check entropy
                    var entropy = calculateEntropy(memoryContent);
                    console.log("[*] Entropy:", entropy);

                    if (entropy > 4.0) {
                        console.log("[+] High entropy detected. Likely a cryptographic key at argument "+arg_number);
                    } else {
                        console.log("[+] Low entropy. Unlikely to be a key.");
                    } */

                }
                

            }

        }else{
            console.log("[!] Memory is not accessible.");
            console.log("[!] Argument "+arg_number+" is not a valid for a label or a key...");
        }

    } catch (e) {
        console.log("[!] Error accessing memory:", e.message);
        console.log("[!] Argument "+arg_number+" is not a valid argument...");
    }

}

function countZeroBytes(memoryContent) {
    // Ensure the content is valid
    if (!memoryContent || memoryContent.byteLength === 0) {
        console.log("[!] No memory content to analyze.");
        return 0;
    }

    // Convert the memory content into a typed array (Uint8Array)
    var byteArray = new Uint8Array(memoryContent);

    // Count the number of zero bytes
    var zeroCount = 0;
    // 32 is the number of bytes a TLS key usually has
    for (var i = 0; i < 32; i++) {
        if (byteArray[i] === 0x00) {
            zeroCount++;
        }
    }

    console.log(`[+] Found ${zeroCount} zero bytes in the memory region.`);
    return zeroCount;
}

// Function to calculate Shannon entropy
function calculateEntropy(byteArray) {
    const keyLength = 48;
    const frequency = new Array(256).fill(0); // Array for byte frequency (0-255)
    const length = Math.min(byteArray.byteLength, keyLength); // Limit to key length

    // Count byte occurrences
    const bytes = new Uint8Array(byteArray.slice(0,length));
    for (let i = 0; i < length; i++) {
        frequency[bytes[i]]++;
    }

    // Calculate entropy
    let entropy = 0;
    const epsilon = 1e-10; // Avoid issues with very small probabilities
    for (let i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            // Calculate the probability of this byte value
            const p = frequency[i] / length;
            entropy += p.toFixed(2);
            //const roundedP = p.toFixed(4); // Ensure a fixed precision parseFloat(p.toFixed(6));
            //let tmp = Math.log2(roundedP);
            
            /*if (roundedP > epsilon) { // Avoid extremely small probabilities
                //entropy -= roundedP * Math.log2(roundedP); // Use the rounded value
            }*/
        }
    }

    return entropy;
}


function dumpMemory(ptrValue,size) {
    //var size = 0x100;
    try {
        var data = Memory.readByteArray(ptrValue, size);
        console.log(hexdump(data));
        return data;
        // console.log(hexdump(data, { offset: 0, length: size, header: true, ansi: true }));
    } catch (error) {
        console.log("Error dumping memory at: " + ptrValue + " - " + error.message);
        console.log("\n")
        return null;
    }
}


// Function to dynamically handle arguments and dump them
function dumpFunctionArguments(context, maxArgs) {
    //console.log("Context content:"+JSON.stringify(context));
    for (var i = 0; i < maxArgs; i++) {
        try {
            var arg = context[i]; // Access the ith argument
            if (arg) {
                console.log('Argument ' + i + ' at address ' + arg + ':');
                dumpMemory(arg, 0x80); // Dump the first 32 bytes of the memory (adjust as needed)
                //var memoryContent = Memory.readByteArray(arg, 48); // Read 48 bytes - default key size
                //var entropy = calculateEntropy(memoryContent);
                //console.log("[*] Entropy:", entropy);
                //check_arguments(arg, i); // check for entropy and if there is a pointer to a string
            } else {
                console.log('Argument ' + i + ' is null or invalid.');
            }
        } catch (e) {
            console.log('Could not access argument ' + i + ': ' + e.message);
        }
    }
}

const tlsLabelMapping = {
    // TLS 1.3 Secrets
    "c ap traffic": "CLIENT_TRAFFIC_SECRET_0",
    "s ap traffic": "SERVER_TRAFFIC_SECRET_0",
    "c hs traffic": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "s hs traffic": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "e traffic": "EARLY_TRAFFIC_SECRET",
    "c finished": "CLIENT_FINISHED",
    "s finished": "SERVER_FINISHED",
    //"res master": "RESUMPTION_MASTER_SECRET",
    
    // TLS 1.2 Secrets
    "master secret": "MASTER_SECRET",
    "exp master": "EXPORTER_SECRET",
    "c finished tls12": "CLIENT_FINISHED_TLS12",
    "s finished tls12": "SERVER_FINISHED_TLS12",
    "c key expansion": "CLIENT_KEY_EXPANSION",
    "s key expansion": "SERVER_KEY_EXPANSION",
    "c ap key tls12": "CLIENT_APPLICATION_TRAFFIC_KEY_TLS12",
    "s ap key tls12": "SERVER_APPLICATION_TRAFFIC_KEY_TLS12",
    
    // Additional TLS 1.3 Labels
    "key update requested": "KEY_UPDATE_REQUESTED",
    "key update not requested": "KEY_UPDATE_NOT_REQUESTED",
    
    // Additional TLS 1.2 Labels
    "client write mac key": "CLIENT_WRITE_MAC_KEY",
    "server write mac key": "SERVER_WRITE_MAC_KEY",
    "client write key": "CLIENT_WRITE_KEY",
    "server write key": "SERVER_WRITE_KEY",
    "client iv": "CLIENT_IV",
    "server iv": "SERVER_IV",
    
    // General Labels
    "c key": "CLIENT_KEY",
    "s key": "SERVER_KEY",
};




function get_key_from_ptr(key_ptr){
    const KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    if (!key_ptr.isNull()) {
        const keyData = Memory.readByteArray(key_ptr, KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexKey = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space


        console.log("Key: "+hexKey); // Print the key as a space-separated hex string
    }

}


function get_label(label_to_span){
    var labelStr = "";
    try{
        if (!label_to_span.isNull()) {
            var label = label_to_span.readCString(); // Read the C string
            labelStr = getTLSLabel(label);
            if(labelStr === null){
                return "";
            }else{
                //console.log("Get Label result: "+labelStr);
                return labelStr;
            }
        }
    }catch(error){
        console.error("[!] Error reading pointer frmo label_to_span: ", error.message);
        return "";
    }
}


function is_arg_key_exp(ptr){
    var labelStr = "";
    try{
        if (!ptr.isNull()) {
            var label = ptr.readCString(); // Read the C string
            //console.log("Label:"+label);
            labelStr = label;
            if(labelStr === null){
                return false;
            }else{
                if(labelStr.startsWith("key expansion")){
                    return true;
                }
                return false;
            }
        }
    }catch(error){
        console.error("[!] Error reading pointer frmo label_to_span: ", error.message);
        return false;
    }
}



function getTLSLabel(input) {
    let label = tlsLabelMapping[input.toLowerCase()];
    if (label) {
        //console.log("Found TLS label: " + label);
        return label;
    } else {
        //console.log("TLS label not found for input: " + input);
        return null;
    }
}

function get_client_random(client_random_ptr) {
    if (!client_random_ptr.isNull()) {

        // Read the client_random bytes (32 bytes)
        var client_random = Memory.readByteArray(client_random_ptr, SSL3_RANDOM_SIZE);

        // Convert the bytes to an uppercase, concatenated hex string
        const hexClientRandom = Array
            .from(new Uint8Array(client_random))
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert to uppercase hex
            .join(''); // Concatenate the hex values without spaces

        //console.log("client_random (32 bytes): " + hexClientRandom);
        return hexClientRandom;
    } else {
        //console.log("[Error] client_random_ptr pointer is NULL: "+client_random_ptr);
        return "";
    }
}


function get_ssl_ptr_from_handshake(hs_ptr) {
    var hs = hs_ptr;  // SSL_HANDSHAKE *hs is passed as the first argument
    var ssl_ptr = hs.add(0x8).readPointer();  // Since SSL *ssl is at offset 0

    return ssl_ptr;
}

function dump_keys(label, identifier,key) {
    // Set the expected length of the key (in bytes). Adjust as needed.
    const KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    var labelStr = "";
    var client_random = "";
    var secret_key = "";

    // Read and print the string from label (first parameter)
    //console.log("Label:");
    if (!label.isNull()) {
        labelStr = label.readCString(); // Read the C string
        //console.log("Label: "+labelStr);
    } else {
        console.log("[Error] Argument 'label' is NULL");
    }

    if (!identifier.isNull()) {
        console.log("SSL_Struct_pointer (working): ",identifier);
        client_random = get_client_random_from_ssl_struct(identifier)
    } else {
        console.log("[Error] Argument 'identifier' is NULL");
    }


    // Read the binary key from key (second parameter) and print it in a clean hex format
    //console.log("Key:");
    if (!key.isNull()) {
        const keyData = Memory.readByteArray(key, KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexKey = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space

        secret_key = hexKey;

        //console.log("Key: "+hexKey); // Print the key as a space-separated hex string
    } else {
        console.log("[Error] Argument 'key' is NULL");
    }

    console.log(labelStr+" "+client_random+" "+secret_key);
}

function is_derived(label_to_span){
    // s hs t
    if (!label_to_span.isNull()) {
        var label = label_to_span.readCString();
        if(label.startsWith("derived")){
            return true;
        }else{
            return false;
        }
    }
    return false;
}



function dump_keys_from_prf(client_random_ptr,client_random_ptr_bk, key, key_len) {
    var KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    if(key_len > 16){
        KEY_LENGTH = key_len;
    }
    var labelStr = "CLIENT_RANDOM";
    var client_random = "";
    var client_random_bk = "";
    var secret_key = "";


    if (!key.isNull()) {
        const keyData = Memory.readByteArray(key, KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexKey = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space

        secret_key = hexKey;

        //console.log("Key: "+hexKey); // Print the key as a space-separated hex string
    } else {
        console.log("[!] Argument 'key' is NULL");
    }

    if(!client_random_ptr.isNull()){
        const keyData = Memory.readByteArray(client_random_ptr, SSL3_RANDOM_SIZE); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexClient_random = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space

            client_random = hexClient_random;
            //-------------------------------------------------------------------
            const keyData_bk = Memory.readByteArray(client_random_ptr_bk, SSL3_RANDOM_SIZE); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexClient_random_bk = Array
            .from(new Uint8Array(keyData_bk)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space

            client_random_bk = hexClient_random_bk;

    }else {
        console.log("[!] Argument 'client_random_ptr' is NULL");
    }

    

    //console.log(labelStr+" "+client_random+"(BK CR:"+client_random_bk+")"+" "+secret_key);
    console.log(labelStr+" "+client_random+" "+secret_key);
    return true;
    /**/
    //console.log("----");
}





function hookSchannelTLSByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;

    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    // First pattern to try
    var arch = Process.arch;
    console.log("[*] Start hooking on arch: "+arch)
    var pattern_mb_derive_secret_x64 = "";

    
    // TlsDeriveSeceret pattern
    var pattern_mb_derive_secret = "48 8B C4 44 88 48 20 4C 89 40 18 48 89 50 10 53 56 41 54 41 55 41 56 41 57 48 81 EC A8 00 00 00 33 DB 33 F6 89 9C 24 E0 00 00 00 45 0F B6 E1 4D 8B F0 4C 8B F9 48 85 C9 0F 84 08 06 00 00 48 8B";
    //console.log("[*] Using HKDF pattern: "+pattern_mb_derive_secret)

    // Try first pattern and if it fails, try the second one
    hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern_mb_derive_secret, "derive_secret");
    //hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern_mb_derive_secret, "SPSslExpandTrafficKeys");
    //var pattern_prf = "49 3B 66 10 0F 86 23 01 00 00 55 48 89 E5 48 83 EC 68 4C 89 8C 24 C0 00 00 00 48 89 B4 24 B0 00 00 00 48 89 BC 24 A8 00 00 00 48 89 8C 24 A0 00 00 00 48 89 9C 24 98 00 00 00 4C 89 84 24 B8 00 00 00 4C 89 94 24 C8 00 00 00 48 89 84 24 90 00 00 00 4C 8B 9C 24 80 00 00 00 4F 8D 24 13 4C 89 64 24 50 48 8B 52 08 48 89 54 24 58 48 8D 05 6D AC 01 00 4C 89 E3 4C 89 D1 4C 89 CF 0F 1F 40 00 E8 7B C1 E7 FF";
    //var pattern_prf =   "49 3B 66 10 0F 86 23 01 00 00 55 48 89 E5 48 83 EC 68 4C 89 8C 24 C0 00 00 00 48 89 B4 24 B0 00 00 00 48 89 BC 24 A8 00 00 00 48 89 8C 24 A0 00 00 00 48 89 9C 24 98 00 00 00 4C 89 84 24 B8 00 00 00 4C 89 94 24 C8 00 00 00 48 89 84 24 90 00 00 00 4C 8B 9C 24 80 00 00 00 4F 8D 24 13 4C 89 64 24 50 48 8B 52 08 48 89 54 24 58 48 8D"

    // Tls1Prf
    var pattern_tls1prf = "4C 8B DC 55 57 41 57 49 8D 6B D9 48 81 EC D0 00 00 00 48 8B 05 C7 6B 01 00 48 33 C4 48 89 45 DF 33 C0 49 89 5B 08 4D 89 63 D8 0F 57 C0 4C 8B 65 77 49 8B D8 4D 89 6B D0 4D 8B E9 48 89 45 87 44 8D 78 01 48 89 45 97 48 8B FA 89 45"
    hook_PRF_By_Pattern(moduleBase, moduleSize, pattern_tls1prf, "Tls1Prf");
}

function hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){
    var stages = {};

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                this.label = args[1]; // ptr to the label string
                                this.tls_label = this.label.readCString();
                                this.log_tls_label = getTLSLabel(this.tls_label);
                                

                                /*
                                BDDD --> arg i 12 --> c hs traffic secret
                                BDDD --> arg i 7 --> s hs traffic secret
                                BDDD --> arg i 9 --> exporter secret
                                BDDD --> arg i 12 --> c ap traffic secret
                                BDDD --> arg i 7 --> s ap traffic secret
                                */

                                this.do_tls13_key_dump = false;
                                if(this.log_tls_label != null){
                                    this.client_random = session_client_randoms_tls13[this.threadId] || "???";
                                    if(this.log_tls_label.includes("CLIENT_HANDSHAKE_TRAFFIC_SECRET")){
                                        this.mybdd = ptr(args[12]);
                                        this.do_tls13_key_dump =  true; 
                                    }else if(this.log_tls_label.includes("SERVER_HANDSHAKE_TRAFFIC_SECRET")){
                                        this.mybdd = ptr(args[7]);
                                        this.do_tls13_key_dump =  true;  
                                    }else if(this.log_tls_label.includes("EXPORTER_SECRET")){
                                        this.mybdd = ptr(args[9]);
                                        this.do_tls13_key_dump =  true; 
                                    }else if(this.log_tls_label.includes("CLIENT_TRAFFIC_SECRET_0")){
                                        this.mybdd = ptr(args[12]);
                                        this.do_tls13_key_dump =  true; 
                                    }else if(this.log_tls_label.includes("SERVER_TRAFFIC_SECRET_0")){
                                        this.mybdd = ptr(args[7]);
                                        this.do_tls13_key_dump =  true; 
                                    }
                                }



                            },
                            onLeave: function(retval) {
                                
                                if(this.do_tls13_key_dump){
                                    try{
                                        var tmp_secret = get_secret_from_BDDD(this.mybdd);
                                        console.log(this.log_tls_label+ " " + this.client_random + " " + buf2hex(tmp_secret));

                                    }catch(al1){
                                        console.log("Error with "+this.mybdd);
                                        console.log(al1);
                                        console.log("Error in parsing the struct - please make an issue on github");
                                    }

                                }

                            }
                        });
                    }
                });
}


function hook_PRF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){
    /*
    PRF(master_secret, "client finished", Hash(handshake_messages)) 
    PRF(pre_master_secret, "master secret", ClientRandom+ServerRandom) --> master secret
    PRF(pre_master_secret, "extended master secret", session_hash) --> master secret
    PRF(master_secret, "key expansion", ServerRandom+ClientRandom)
    */

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                console.log("Hooking PRF (Tls1Prf");
                                this.dump_keys = false;
                                did_check = false;
                                //console.log("gets invoked... by: "+address);
                                // arg0 == tls version as hex encoding
                                // arg1 == tls version as hex string 
                                // arg2 == hash version (in our example SHA-384)
                                // arg3 == key
                                // arg4 == 0x260000030 --> ?
                                // arg5 == label
                                // arg6 == ?
                                // arg7 == serverseed/probably the  hash of the handshake_messages
                                // arg8 == key length?
                                // arg9 == key?


                                this.label = args[5];
                                


                                

                                /* */
                                if(is_arg_key_exp(this.label)){
                                    this.client_random_ptr = args[7].add(0x20);
                                    this.client_random_ptr_bk = args[9].add(0x20);
                                    this.key = args[3];
                                    this.key_len = 48;
                                    this.dump_keys = true;
                                }
                                // */

                                /* *
                                if(did_check == false){
                                    this.dump_keys = true;
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                }
                                /* */ 


                            },
                            onLeave: function(retval) {
                                //console.log("Retval: "+retval);
                                


                                if (this.dump_keys) {
                                    dump_keys_from_prf(this.client_random_ptr,this.client_random_ptr_bk, this.key, this.key_len);
                                    this.dump_keys = false;

                                    /* **
                                    if(did_check == false){
                                        console.log("------------- Key Identificaiton -------------");
                                        console.log("[*] We identified "+this.myargs.length+" number of arguments");
                                        // Analyze the saved arguments from `onEnter`
                                        try {
                                            for (var i = 0; i < this.myargs.length; i++) {
                                                var arg = this.myargs[i];
                                                if (arg) {
                                                    console.log('[*] Checking Argument: ' + i);
                                                    check_arguments(arg, i);
                                                } else {
                                                    console.log('[!] Argument ' + i + ' is null or invalid.');
                                                }
                                            }
                                        } catch (e) {
                                            console.log('[!] Error in onLeave: ' + e.message);
                                            did_check = false;
                                        }

                                        did_check = false;

                                    }
                                    // */
                               
                                
                                }
                            }
                        });
                    }
                });
}


/*
function hook_hkdf_by_symbol(){
    var symbols = module.enumerateSymbols().filter(exports => exports.name.toLowerCase().includes("derivesec") );
    var functionAddress = symbols[0].address;
    Interceptor.attach(functionAddress, {
        onEnter: function (args) {
            console.log("[*] deriveSecret() called");
            //console.log("    Arg0:", args[0].toInt32());
        },
        onLeave: function (retval) {
            console.log("[*] deriveSecret() returned:", retval);
        }
    });

}


*/


/* TLS 1.3 Ground Truth */

function tls13_ground_truth_hooks(){
        /*
         *  This part was taken from https://github.com/ngo/win-frida-scripts/blob/master/lsasslkeylog-easy/keylog.js
         *   It is needed to retrieve teh CLIENT_RANDOM for TLS 1.3 as the client random is not provided as an argument there anymore
         */

        /* ----- COMMON (TLS 1.2 and 1.3) ----- */
        var keylog = function(s){
            console.log(s);
        }
        var buf2hex = function (buffer) {
            return Array.prototype.map.call(new Uint8Array(buffer), function(x){ return ('00' + x.toString(16)).slice(-2)} ).join('');
        }

        var client_randoms = {};

        /* This is called for TLS1.3 and  for TLS1.2 when RFC 7627 session hashing is used.
         * The first call is with client hello, denoted by msg_type == 1 and version == 0x0303
         * Note that version is 0x0303 both for TLS1.2 and TLS1.3, 
         * which is a backward compatibility hack in TLS 1.3
         */
        var shh = Module.findExportByName('ncrypt.dll', 'SslHashHandshake');
        if(shh != null){
            Interceptor.attach(shh, {
                onEnter: function (args) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslhashhandshake
                    var buf = ptr(args[2]);
                    //console.log("this.buf (client_random): "+buf);
                    var len = args[3].toInt32();
                    var mem = buf.readByteArray(len);
                    var msg_type = buf.readU8();
                    var version = buf.add(4).readU16();
                    if (msg_type == 1 && version == 0x0303){
                        // If we have client random, save it tied to current thread
                        var crandom = buf2hex(buf.add(6).readByteArray(32));
                        //console.log("Got client random from SslHashHandshake: " + crandom);
                        client_randoms[this.threadId] = crandom;
                        session_client_randoms_tls13[this.threadId] = crandom;
                        session_client_random = crandom;
                    }       
                },
                onLeave: function (retval) {
                }
            });
        }else{
            console.log("SslHashHandshake export not found!");
        }
}


// Find the Schannel module
function findSchannelTLSModule() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("test_client_") || name.startsWith("ncryptsslp") ) {
            console.log("Found Schannel SSP Module: " + name);
            return modules[i];
        }
    }
    console.log("Schannel module not found.");
    return null;
}


// Main function
function main() {
    var module = findSchannelTLSModule();
    if (module !== null) {
        hookSchannelTLSByPattern(module);
    }
    tls13_ground_truth_hooks();
}

// Run the main function
main();


/*
[*] Found pattern: 63 20 68 73 20 74 72 61 66 66 69 63 at: 0062f7d2
[*] Found big-endian pattern at: 0062f7d2
[*] String found in .rodata section at address: 0062f7d2
[*] Found reference to .rodata at 005b5ac3 in function: crypto/tls.(*clientHandshakeStateTLS13).establishHandshakeKeys
[!] Analyzing instruction at reference address: LEA RSI,[0x62f7d2]
[!] Reference stored in register: RSI
[!] Using infos for analysis: CALL 0x005d1140
[!] analysis (0): CALL 0x005d1140
[*] String (Register RSI) used as 1th argument in function call at address: 0x005b5ad9 (invoking CRYPTO/TLS.(*CIPHERSUITETLS13).DERIVESECRET)
[*] HKDF function identified: CRYPTO/TLS.(*CIPHERSUITETLS13).DERIVESECRET
Function: crypto/tls.(*cipherSuiteTLS13).deriveSecret
[*] Very short pattern detected (10). Trying to check if identified function is just a wrapper function...


[*] HKDF-Function identified with label: CRYPTO/TLS.(*CIPHERSUITETLS13).DERIVESECRET (crypto/tls.(*cipherSuiteTLS13).deriveSecret)
[*] HKDF-Function signature: undefined crypto/tls.(*cipherSuiteTLS13).deriveSecret(undefined param_1, undefined param_2, undefined param_3, undefined param_4, undefined param_5, undefined param_6, undefined8 param_7, undefined8 param_8, undefined8 param_9, undefined8 param_10, undefined8 param_11, undefined8 param_12, undefined8 param_13, undefined8 param_14)
[*] String (Register RSI) used as 1th argument in function call at address: 0x005b5ad9 (invoking CRYPTO/TLS.(*CIPHERSUITETLS13).DERIVESECRET)
[*] Function offset (Ghidra): 005D1140 (0x005D1140)
[*] Function offset (IDA with base 0x0): 004D1140 (0x004D1140)
[*] Byte pattern for frida: 49 3B 66 10 0F 86 EF 00 00 00



[*] Start identifying the PRF by looking for String "master secret"
[!] Found String at ref: 005d273a
[!] Instruction used there: MOV R9,qword ptr [0x007c86d0]
[!] Found String at ref: 007c86d0
[!] Instruction used there: null
[!] Analyzing instruction at reference address: MOV R9,qword ptr [0x007c86d0]
[!] Reference stored in register: R9
[*] Trying to find target address for instruction: CALL R12
[*] Call target address: 005d1ee0
[*] Function name: crypto/tls.prf10
[*] String (Register R9) used as 5th argument in function call at address: 0x005d278f (invoking CRYPTO/TLS.PRF10)
[*] PRF function identified: CRYPTO/TLS.PRF10
Function: crypto/tls.prf10
[*] Very short pattern detected (10). Trying to check if identified function is just a wrapper function...


[*] PRF-Function identified with label: CRYPTO/TLS.PRF10 (crypto/tls.prf10)
[*] PRF-Function signature: undefined crypto/tls.prf10(undefined param_1, undefined param_2, undefined param_3, undefined param_4, undefined param_5, undefined param_6, undefined8 param_7, undefined8 param_8, undefined param_9, undefined8 param_10, undefined8 param_11, undefined8 param_12, undefined8 param_13, undefined8 param_14, undefined8 param_15, undefined8 param_16, undefined8 param_17)
[*] String (Register R9) used as 5th argument in function call at address: 0x005d278f (invoking CRYPTO/TLS.PRF10)
[*] Function offset (Ghidra): 005D1EE0 (0x005D1EE0)
[*] Function offset (IDA with base 0x0): 004D1EE0 (0x004D1EE0)
[*] Byte pattern for frida: 49 3B 66 10 0F 86 F2 01 00 00

[*] Byte pattern for frida: 49 3B 66 10 0F 86 F2 01 00 00 55 48 89 E5 48 83 EC 68 4C 89 8C 24 C0 00 00 00 4C 89 94 24 C8 00 00 00 4C 89 84 24 B8 00 00 00 48 89 B4 24 B0 00 00 00 48 89 BC 24 A8 00 00 00 48 89 8C 24 A0 00 00 00 48 89 9C 24 98 00 00 00 48 89 84 24 90 00 00 00 48 8B 94 24 80 00 00 00 4E 8D 1C 12 4C 89 5C 24 50 48 8D 05 56 B7 01 00 4C 89 DB 4C 89 D1 4C 89 CF E8 68 CC E7 FF
*/