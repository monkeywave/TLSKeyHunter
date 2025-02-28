/*
Invoke

frida -p $(frida-ps | grep -i gotls | awk '{print $1}') -l universal_key_dump_liunx_x86_64.js

*/

// Constants for parsing
const SSL3_RANDOM_SIZE = 32; // Assuming SSL3_RANDOM_SIZE is 32 bytes which is defined in the RFC
const SSL_MAX_MD_SIZE = 48;  // Assuming SSL_MAX_MD_SIZE is 64 bytes

// Dynamic offsets based on architecture
const is64Bit = Process.arch === 'x64';

const boringSSL_Handshake_struct = is64Bit
    ?  { 
    secret: 0x48, 
    earlyTrafficSecret: 0x96, 
    clientHandshakeSecret: 0x144, 
    serverHandshakeSecret: 0x192, 
    clientTrafficSecret0: 0x240, 
    serverTrafficSecret0: 0x288, 
    expectedClientFinished: 0x336, 
    innerClientRandom: 0x384, 
    } 
    : { 
    secret: 0x150, 
    earlyTrafficSecret: 0x180, 
    clientHandshakeSecret: 0x1B0,
    erverHandshakeSecret: 0x1E0, 
    clientTrafficSecret0: 0x210, 
    serverTrafficSecret0: 0x240, 
    expectedClientFinished: 0x270, 
    innerClientRandom: 0x2A0, 
    };




// some global definitions
var did_check = false;
var session_client_random = "";


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
            if(i > 9){
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



// Function to parse the SSL_HANDSHAKE structure of GoTLS
// More infos at https://github.com/google/boringssl/blob/d9ad235cd8c203db7430c366751f1dddcf450060/ssl/internal.h#L1899
function parseSSLHandshake(structPointer) {
    try {
        var abi = is64Bit ? "x86-64" : "x86";
        console.log("Parsing SSL_HANDSHAKE on "+abi);
        // Pointer to the structure
        const sslHandshake = ptr(structPointer);
        console.log("[*] Parsing SSL_HANDSHAKE at address:", sslHandshake);

        // Access `inner_client_random`
        const innerClientRandom = Memory.readByteArray(
            sslHandshake.add(boringSSL_Handshake_struct.innerClientRandom),
            SSL3_RANDOM_SIZE
        );
        console.log("[*] inner_client_random:", byteArrayToHex(innerClientRandom));

        // Access keys
        const keys = {};
        for (const [key, offset] of Object.entries(boringSSL_Handshake_struct)) {
            if (key !== "innerClientRandom") {
                const keyData = Memory.readByteArray(
                    sslHandshake.add(offset),
                    SSL_MAX_MD_SIZE
                );
                keys[key] = byteArrayToHex(keyData);
            }
        }

        // Print all keys
        for (const [key, value] of Object.entries(keys)) {
            console.log(`[*] ${key}:`, value);
        }
    } catch (error) {
        console.error("[!] Error parsing SSL_HANDSHAKE:", error.message);
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

/*function isMemoryReadable(ptr, size) {
    try {
         // Check if the pointer is null or likely invalid
        if (ptr.isNull() || ptr.toInt32() < 0x1000) {
            console.log(`[!] Skipping invalid or null pointer: ${ptr}`);
            return false;
        }

        Memory.scan(ptr, size, '', {
            onMatch: function () {
                // Memory is readable
            },
            onComplete: function () {
                // Completed scan
            }
        });
        return true;
    } catch (e) {
        console.log("[!] Memory not readable:", e.message);
        return false;
    }
}*/

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

function get_client_random_from_ssl_struct(ssl_st_ptr){
    // parses the ssl_st in order to get the client_random
    // Define the size of SSL3_RANDOM_SIZE (usually 32 bytes)
    const SSL3_RANDOM_SIZE = 32;


    /* 
    https://github.com/google/boringssl/blob/d9ad235cd8c203db7430c366751f1dddcf450060/ssl/internal.h#L3926C1-L3958C53

    struct ssl_st {
      explicit ssl_st(SSL_CTX *ctx_arg);
      ssl_st(const ssl_st &) = delete;
      ssl_st &operator=(const ssl_st &) = delete;
      ~ssl_st();

      // method is the method table corresponding to the current protocol (DTLS or
      // TLS).
      const bssl::SSL_PROTOCOL_METHOD *method = nullptr;

      // config is a container for handshake configuration.  Accesses to this field
      // should check for nullptr, since configuration may be shed after the
      // handshake completes.  (If you have the |SSL_HANDSHAKE| object at hand, use
      // that instead, and skip the null check.)
      bssl::UniquePtr<bssl::SSL_CONFIG> config;

      // version is the protocol version.
      uint16_t version = 0;

      uint16_t max_send_fragment = 0;

      // There are 2 BIO's even though they are normally both the same. This is so
      // data can be read and written to different handlers

      bssl::UniquePtr<BIO> rbio;  // used by SSL_read
      bssl::UniquePtr<BIO> wbio;  // used by SSL_write

      // do_handshake runs the handshake. On completion, it returns |ssl_hs_ok|.
      // Otherwise, it returns a value corresponding to what operation is needed to
      // progress.
      bssl::ssl_hs_wait_t (*do_handshake)(bssl::SSL_HANDSHAKE *hs) = nullptr;

      bssl::SSL3_STATE *s3 = nullptr;   // TLS variables



    https://github.com/google/boringssl/blob/d9ad235cd8c203db7430c366751f1dddcf450060/ssl/internal.h#L2793C1-L2803C49



    struct SSL3_STATE {
          static constexpr bool kAllowUniquePtr = true;

          SSL3_STATE();
          ~SSL3_STATE();

          uint64_t read_sequence = 0;
          uint64_t write_sequence = 0;

          uint8_t server_random[SSL3_RANDOM_SIZE] = {0};
          uint8_t client_random[SSL3_RANDOM_SIZE] = {0};
    */
    var arch = Process.arch;
    var offset_s3 = 0x30;

    if (arch === 'x64' || arch === 'arm64') {
        offset_s3 = 0x30;  // Offset for x86-64 and arm64
    } else if (arch === 'x86' || arch === 'arm') {
        offset_s3 = 0x2C;  // Offset for x86 and arm
    }
    


    var s3_ptr = ssl_st_ptr.add(offset_s3).readPointer();
    return get_client_random(s3_ptr,SSL3_RANDOM_SIZE);
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

/*
"CLIENT_TRAFFIC_SECRET_0"
"c ap traffic" */

function dump_keys_from_derive_secrets(client_random, label_to_span, label_len, key, key_len) {
    var KEY_LENGTH = 32; // defaulting to 32
    if(key_len > 16){
        KEY_LENGTH = key_len;
    }
    var labelStr = "";
    var secret_key = "";

    
    if (!label_to_span.isNull()) {
        var label = label_to_span.readCString(); // Read the C string --> hier scheint es unter x86-64 eine access violation zu geben
        var final_label = label.substring(0,label_len);
        labelStr = getTLSLabel(final_label);
        if(labelStr === null){
            return false;
        }
    } else {
        console.log("[Error] Argument 'label' is NULL");
    }


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
    return true;
    /**/
    //console.log("----");
}


function dump_keys_from_prf(client_random_ptr, key, key_len) {
    var KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    if(key_len > 16){
        KEY_LENGTH = key_len;
    }
    var labelStr = "CLIENT_RANDOM";
    var client_random = "";
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

    }else {
        console.log("[!] Argument 'client_random_ptr' is NULL");
    }

    

    console.log(labelStr+" "+client_random+" "+secret_key);
    return true;
    /**/
    //console.log("----");
}





function hookGoTLSByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;

    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    // First pattern to try
    var arch = Process.arch;
    console.log("[*] Start hooking on arch: "+arch)
    var pattern_mb_derive_secret_x64 = "";

    
    // Select the appropriate patterns based on the architecture
    var pattern_mb_derive_secret = "49 3B 66 10 0F 86 EF 00 00 00 55 48 89 E5 48 83 EC 50 4C 89 8C 24 90 00 00 00 4C 89 94 24 98 00 00 00 48 89 44 24 60 48 89 7C 24 78 48 89 5C 24 68 48 89 4C 24 70 4C 89  84 24 88 00 00 00 48 89 B4 24 80 00 00 00 4D 85 C9 75 12";
    //console.log("[*] Using HKDF pattern: "+pattern_mb_derive_secret)

    // Try first pattern and if it fails, try the second one
    hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern_mb_derive_secret, "derive_secret");
    //var pattern_prf = "49 3B 66 10 0F 86 23 01 00 00 55 48 89 E5 48 83 EC 68 4C 89 8C 24 C0 00 00 00 48 89 B4 24 B0 00 00 00 48 89 BC 24 A8 00 00 00 48 89 8C 24 A0 00 00 00 48 89 9C 24 98 00 00 00 4C 89 84 24 B8 00 00 00 4C 89 94 24 C8 00 00 00 48 89 84 24 90 00 00 00 4C 8B 9C 24 80 00 00 00 4F 8D 24 13 4C 89 64 24 50 48 8B 52 08 48 89 54 24 58 48 8D 05 6D AC 01 00 4C 89 E3 4C 89 D1 4C 89 CF 0F 1F 40 00 E8 7B C1 E7 FF";
    var pattern_prf =   "49 3B 66 10 0F 86 23 01 00 00 55 48 89 E5 48 83 EC 68 4C 89 8C 24 C0 00 00 00 48 89 B4 24 B0 00 00 00 48 89 BC 24 A8 00 00 00 48 89 8C 24 A0 00 00 00 48 89 9C 24 98 00 00 00 4C 89 84 24 B8 00 00 00 4C 89 94 24 C8 00 00 00 48 89 84 24 90 00 00 00 4C 8B 9C 24 80 00 00 00 4F 8D 24 13 4C 89 64 24 50 48 8B 52 08 48 89 54 24 58 48 8D"

    var pattern_p_hash = "49 3B 66 10 0F 86 E1 01 00 00 55 48 89 E5 48 83 EC 58 48 89 BC 24 88 00 00 00 4C 89 9C 24 B0 00 00 00 4C 89 94 24 A8 00 00 00 4C 89 8C 24 A0 00 00 00 48 89 8C 24 80 00 00 00 48 89 5C 24 78 48 89 44 24 70 48 8B 44 24 68 48 89 FB 48 89 F1 4C"
    hook_PRF_By_Pattern(moduleBase, moduleSize, pattern_p_hash, "p_hash");
}


function hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                //this.hs = args[0]; // --> ptr to handshake struct
                                //this.key = args[1]; // when init its zero and only when returning it is filled with the key value
                                this.label = args[1]; // ptr to the label string
                                this.label_len = args[4].toInt32();
                                this.key_len = args[0].toInt32();
                                this.client_random_ptr = args[9];


                               
                                // Initialize an empty array to store arguments
                                /* *
                                if(did_check == false){
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                }
                                // */
                                






                            },
                            onLeave: function(retval) {
                                if(session_client_random.length < 2){
                                    if(is_derived(this.label)){
                                        session_client_random = get_client_random(this.client_random_ptr);
                                    }
                                }


                                if(!retval.isNull()){
                                    this.key = retval;

                                    dump_keys_from_derive_secrets(session_client_random,this.label, this.label_len, this.key, this.key_len);

                                }



                                    
                                
                            }
                        });
                    }
                });
}


function hook_PRF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                this.dump_keys = false;
                                //console.log("gets invoked... by: "+address);

                                this.label = args[5];
                                


                                

                                /* */
                                if(is_arg_key_exp(this.label)){
                                    this.client_random_ptr = args[5].add(0x2D);
                                    this.key = args[0];
                                    this.key_len = args[1].toInt32();
                                    this.dump_keys = true;
                                }
                                // */

                                /* 
                                if(did_check == false){
                                    this.dump_keys = true;
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                }
                                /* */ 


                            },
                            onLeave: function(retval) {

                                if (!retval.isNull() && this.dump_keys) {
                                    dump_keys_from_prf(this.client_random_ptr, this.key, this.key_len);
                                    this.dump_keys = false;

                                    /* *
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
                                     */
                               
                                
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

// Find the GoTLS module
function findGoTLSModule() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("test_client_") ) {
            console.log("Found GoTLS Module: " + name);
            return modules[i];
        }
    }
    console.log("GoTLS module not found.");
    return null;
}


// test_client_13_boringssl_key_export
// Main function
function main() {
    var module = findGoTLSModule();
    if (module !== null) {
        hookGoTLSByPattern(module);
    }
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