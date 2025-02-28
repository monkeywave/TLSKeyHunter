/*
Invoke

frida -p $(frida-ps | grep -i gnutls | awk '{print $1}') -l universal_key_dump_liunx_x86_64.js

*/

// Constants for parsing
const SSL3_RANDOM_SIZE = 32; // Assuming SSL3_RANDOM_SIZE is 32 bytes
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
            if(i > 7){
                return argument_array;
            }
             try {
                 var arg = context[i]; // // Access the ith argument
                 if (arg) {
                     argument_array.push(arg); // Save argument for later use
                     console.log('[*] Argument ' + i + ' at address ' + arg + ':');

                     if(check_for_length){
                        if(is_hkdf && arg == 0xC){
                            return argument_array;
                        }else if(!is_hkdf && arg == 0xD){
                            return argument_array;
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



// Function to parse the SSL_HANDSHAKE structure of GnuTLS
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
        console.log("dasdashdahs");
        // Check if the pointer is null or likely invalid
        if (ptr.isNull() || ptr.toInt32() < 0x1000) {
            console.log(`[!] Skipping invalid or null pointer: ${ptr}`);
            return false;
        }
        console.log("dasdashdahs2");

        // Attempt to read a small chunk of memory as a test
        Memory.readByteArray(ptr, size);
        console.log("dasdashdahs3");
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
                if(labelStr === "key expansion"){
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

function get_client_random(s3_ptr,SSL3_RANDOM_SIZE) {
    // Check if s3 pointer is valid
    if (!s3_ptr.isNull()) {
        // Offset for client_random is 0x30 in the s3 struct
        var client_random_ptr = s3_ptr.add(0x30);

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
        console.log("[Error] s3 pointer is NULL");
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

/*
"CLIENT_TRAFFIC_SECRET_0"
"c ap traffic" */

function dump_keys_from_derive_secrets(client_random, key, label_to_span) {
    
    // Set the expected length of the key (in bytes). Adjust as needed.
    const KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    var labelStr = "";
    //var client_random = "";
    var secret_key = "";

    // Read and print the string from label (first parameter)
    //console.log("Label:");
    
    if (!label_to_span.isNull()) {
        //console.log("label_to_span: "+label_to_span);
        //console.log("label_to_span.read: "+label_to_span.readCString());
        var label = label_to_span.readCString(); // Read the C string --> hier scheint es unter x86-64 eine access violation zu geben
        labelStr = getTLSLabel(label);
        if(labelStr === null){
            return false;
        }
        //console.log("\n\n----");
        //console.log("Label: "+labelStr);
    } else {
        console.log("[Error] Argument 'label' is NULL");
    }

    /*

    if (!identifier.isNull()) {
        client_random = get_client_random_from_ssl_struct(identifier)
    } else {
        console.log("[Error] Argument 'identifier' is NULL");
    }


    // Read the binary key from key (second parameter) and print it in a clean hex format
    //console.log("Key:");
    */
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


function dump_keys_from_prf(client_random_ptr, key) {
    
    // Set the expected length of the key (in bytes). Adjust as needed.
    const KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
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
        const keyData = Memory.readByteArray(client_random_ptr.add(0x20), KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
        
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


function hookGnuTLSByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;

    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    // First pattern to try
    var arch = Process.arch;
    console.log("[*] Start hooking on arch: "+arch)

    
    // Select the appropriate patterns based on the architecture
    // selbt kompiliert
    //var pattern_mb_derive_secret = "F3 0F 1E FA 55 48 89 E5 48 83 EC 50 48 89 7D D8 48 89 75 D0 89 55 CC 48 89 4D C0 4C 89 45 B8 4C 89 4D B0 48 8B 45 D8 48 8B 40 18 48 85 C0 0F 94 C0 0F B6 C0 48 85 C0 74 6D";
    // system gnutls 
    var pattern_mb_derive_secret = "F3 0F 1E FA 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 78 48 8B 45 10 48 89 B5 70 FF FF FF 48 89 85 68 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 48 85 FF 0F 84 C9 00 00 00";
    //console.log("[*] Using HKDF pattern: "+pattern_mb_derive_secret)

    // Try first pattern and if it fails, try the second one
    hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern_mb_derive_secret, "derive_secret");
    var pattern_prf = "F3 0F 1E FA 41 57 41 56 41 55 41 54 55 53 89 FB 48 81 EC 28 03 00 00 64 48 8B 04 25 28 00 00 00 48 89 84";
    //24 18 03 00 00 31 C0 8D 47 FA 4C 8B B4 24 60 03 00 00 4C 8B BC 24 70 03 00 00 83 F8 0B 77 26";

    //hook_PRF_By_Pattern(moduleBase, moduleSize, pattern_prf, "pattern_prf_secret");
}


function hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                console.log("Start hooking HKDF func");
                                //this.hs = args[0]; // --> ptr to handshake struct
                                //this.key = args[1]; // when init its zero and only when returning it is filled with the key value
                                //this.label = args[2]; // ptr to the label string


                               
                                // Initialize an empty array to store arguments
                                /*if(did_check == false){
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                }*/
                                


                                 console.log("finish..................................");
                                //this.client_random = "";



                            },
                            onLeave: function(retval) {



                                if (!retval.isNull()) {

                                    /*
                                    if(did_check == false){
                                        console.log("automation test start---------------------------");
                                        console.log("We identified "+this.myargs.length+" number of arguments");
                                        console.log(" now beginning wit the check...");
                                        // Analyze the saved arguments from `onEnter`
                                        try {
                                            for (var i = 0; i < this.myargs.length; i++) {
                                                var arg = this.myargs[i];
                                                if (arg) {
                                                    console.log('Argument ' + i + ' onLeave:');
                                                    //dumpMemory(arg, 0x80); // Optional: Dump memory at argument address
                                                    console.log("Start checking arguments....");
                                                    check_arguments(arg, i);
                                                } else {
                                                    console.log('Argument ' + i + ' is null or invalid onLeave.');
                                                }
                                            }
                                        } catch (e) {
                                            console.log('[!] Error in onLeave: ' + e.message);
                                            did_check = true;
                                        }

                                        did_check = true;

                                    }*/


                                    console.log("returning...");
                                    // working version for TLS 1.3
                                    //var sslStructPointer = this.hs.readPointer();

                                    //session_client_random = get_client_random_from_ssl_struct(sslStructPointer);

                                    //parseSSLHandshake(this.hs); --> not working but the rest is working :)
                                    

                                    //dump_keys_from_derive_secrets(session_client_random,this.key,this.label);
                                    
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
                                

                                /*if(is_arg_key_exp(args[6])){
                                    this.client_random_ptr = args[8];
                                    this.key = args[3];
                                    this.dump_keys = true;
                                }*/

                                /*
                                if(did_check == false){
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                }
                                */ 


                            },
                            onLeave: function(retval) {
                                console.log("");

                                if (!retval.isNull() && this.dump_keys) {
                                    //dump_keys_from_prf(this.client_random_ptr, this.key);

                                    /*if(did_check == false){
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
                                            did_check = true;
                                        }

                                        did_check = true;

                                    }*/
                               
                                
                                }
                            }
                        });
                    }
                });
} 

// Find the GnuTLS module
function findGnuTLSModule() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("test_client_") ) {
            console.log("Found GnuTLS Module: " + name);
            return modules[i];
        }
    }
    console.log("GnuTLS module not found.");
    return null;
}


// test_client_13_boringssl_key_export
// Main function
function main() {
    var module = findGnuTLSModule();
    if (module !== null) {
        hookGnuTLSByPattern(module);
    }
}

// Run the main function
main();


/*

In GnuTLS
https://github.com/gnutls/gnutls/blob/97f1baf6a7ad4aa1ff3db6e8543d910219ef9a16/lib/constate.c#L412


derive_secret(hs, hs->client_traffic_secret_0(),
                     label_to_span(kTLS13LabelClientApplicationTraffic))

                     bzw.

                     derive_secret(hs, hs->client_handshake_secret(),
                     label_to_span(kTLS13LabelClientHandshakeTraffic))

[!] Reference stored in register: RSI
[!] Using infos for analysis: CALL 0x00448ad0
[!] analysis (0): CALL 0x00448ad0
[*] String (Register RSI) used as 1th argument in function call at address: 0x0042e408 (invoking _TLS13_DERIVE_SECRET)
[*] HKDF function identified: _TLS13_DERIVE_SECRET

[*] HKDF-Function identified with label: _TLS13_DERIVE_SECRET
[*] String (Register RSI) used as 1th argument in function call at address: 0x0042e408 (invoking _TLS13_DERIVE_SECRET)
[*] Function offset (Ghidra): 00448AD0 (0x00448AD0)
[*] Function offset (IDA with base 0x0): 00348AD0 (0x00348AD0)
[*] Byte pattern for frida: F3 0F 1E FA 48 83 EC 08 48 8B 7F 18 48 8B 44 24 10 48 85 FF 74 12



***** PRF Research ****

[*] PRF-Function identified with label: _GNUTLS_PRF_RAW
[*] String (Register R8) used as 4th argument in function call at address: 0x00419252 (invoking _GNUTLS_PRF_RAW)
[*] Function offset (Ghidra): 004D0470 (0x004D0470)
[*] Function offset (IDA with base 0x0): 003D0470 (0x003D0470)
[*] Byte pattern for frida: F3 0F 1E FA 41 57 41 56 41 55 41 54 55 53 89 FB 48 81 EC 28 03 00 00 64 48 8B 04 25 28 00 00 00 48 89 84 24 18 03 00 00 31 C0 8D 47 FA 4C 8B B4 24 60 03 00 00 4C 8B BC 24 70 03 00 00 83 F8 0B 77 26



 ./test_client_13_gnutls_debug 
Starting client
Press Enter to proceed...

DEBUG: gnutls_global_init() 
DEBUG: gnutls_init() 
DEBUG: gnutls_certificate_allocate_credentials() 
DEBUG: gnutls_certificate_set_x509_system_trust() 
DEBUG: gnutls_priotity_set_direct() 
Established TCP connection 
DEBUG: gnutls_transport_set_int() 
DEBUG: gnutls_handshake_set_timeout() 
DEBUG: gnutls_credentials_set() 
DEBUG: gnutls_handshake() 
Connected to 127.0.0.1:4433. Press Enter to disconnect...

DEBUG: gnutls_deinit() 
DEBUG: gnutls_global_deinit() 


Hier mit frida attached:
 research/all_your_tls_keys_are_belong_to_us  ./test_client_13_gnutls_debug
Starting client
Press Enter to proceed...

DEBUG: gnutls_global_init() 
DEBUG: gnutls_init() 
DEBUG: gnutls_certificate_allocate_credentials() 
[1]    729967 segmentation fault (core dumped)  ./test_client_13_gnutls_debug



Normale SO:
[*] HKDF-Function identified with label: FUN_00196D30
[*] String (Register RSI) used as 1th argument in function call at address: 0x00173e5d (invoking FUN_00196D30)
[*] Function offset (Ghidra): 00196D30 (0x00196D30)
[*] Function offset (IDA with base 0x0): 00096D30 (0x00096D30)
[*] Byte pattern for frida: F3 0F 1E FA 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 78 48 8B 45 10 48 89 B5 70 FF FF FF 48 89 85 68 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 48 85 FF 0F 84 C9 00 00 00

[*] PRF-Function identified with label: _GNUTLS_PRF_RAW
[*] String (Register R8) used as 4th argument in function call at address: 0x001563e2 (invoking _GNUTLS_PRF_RAW)
[*] Function offset (Ghidra): 00248600 (0x00248600)
[*] Function offset (IDA with base 0x0): 00148600 (0x00148600)
[*] Byte pattern for frida: F3 0F 1E FA 55 48 89 E5 41 57 41 56 41 55 49 89 CD 41 54 53 89 FB 48 81 EC 48 05 00 00 4C 8B 7D 10 4C 8B 65 20 64 48 8B 0C 25 28 00 00 00 48 89 4D C8 31 C9 8D 4F FA 83 F9 0B 77 14


Selbst kompilierte SO:
[*] HKDF-Function identified with label: _TLS13_DERIVE_SECRET
[*] String (Register RSI) used as 1th argument in function call at address: 0x00195a8c (invoking _TLS13_DERIVE_SECRET)
[*] We tracked also a copy operation of the previous register: RAX used as -1th argument
[*] Function offset (Ghidra): 001DE9CA (0x001DE9CA)
[*] Function offset (IDA with base 0x0): 000DE9CA (0x000DE9CA)
[*] Byte pattern for frida: F3 0F 1E FA 55 48 89 E5 48 83 EC 50 48 89 7D D8 48 89 75 D0 89 55 CC 48 89 4D C0 4C 89 45 B8 4C 89 4D B0 48 8B 45 D8 48 8B 40 18 48 85 C0 0F 94 C0 0F B6 C0 48 85 C0 74 6D


[*] PRF-Function identified with label: _GNUTLS_PRF
[*] String (Register RCX) used as 3th argument in function call at address: 0x001691eb (invoking _GNUTLS_PRF)
[*] Function offset (Ghidra): 00168A0D (0x00168A0D)
[*] Function offset (IDA with base 0x0): 00068A0D (0x00068A0D)
[*] Byte pattern for frida: 55 48 89 E5 48 83 EC 30 48 89 7D F8 48 89 75 F0 89 55 EC 48 89 4D E0 44 89 45 E8 4C 89 4D D8 8B 45 18 48 63 F8 8B 45 10 4C 63 C8 8B 45 E8 48 63 C8 8B 75 EC 48 8B 45 F8 48 8B 40 18 8B 40 18 4C 8B 45 E0 48 8B 55 F0 48 83 EC 08 FF 75 20 57 FF 75 D8 89 C7 E8 0A D9 FC FF

*/