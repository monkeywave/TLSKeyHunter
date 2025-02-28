/*
Invoke

frida -p $(frida-ps | grep -i test_client | awk '{print $1}') -l universal_key_dump_liunx_x86_64.js

*/

// Constants for parsing
const SSL3_RANDOM_SIZE = 32; // Assuming SSL3_RANDOM_SIZE is 32 bytes
const SSL_MAX_MD_SIZE = 48;  // Assuming SSL_MAX_MD_SIZE is 64 bytes

// Dynamic offsets based on architecture
const is64Bit = Process.arch === 'x64';

var CHSTRAFFIC_LEN = 0;
var SHSTRAFFIC_LEN = 0;
var hkdf_key_len = 0;

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



// Function to parse the SSL_HANDSHAKE structure of BotanSSL
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

function dump_keys_from_derive_secrets(client_random, key, label_to_span, key_len) {
    
    const MAX_KEY_LENGTH = 64;
    const RANDOM_KEY_LENGTH = 32;
    var labelStr = "";
    //var client_random = "";
    var secret_key = "";

    
    if (!label_to_span.isNull()) {
        var label = label_to_span.readCString(); 
        labelStr = getTLSLabel(label);
        if(labelStr === null){
            return false;
        }
    } else {
        console.log("[Error] Argument 'label' is NULL");
    }

    if (!key.isNull()) {
        let KEY_LENGTH = 0;
        if(key_len == 0){
            console.log("[!] No key lenght provided - start calculating...");
            let calculatedKeyLength = 0;

            // Iterate through the memory to determine key length
            while (calculatedKeyLength < MAX_KEY_LENGTH) {
                const byte = Memory.readU8(key.add(calculatedKeyLength)); // Read one byte at a time


                if (byte === 0) { // Stop if null terminator is found (optional, adjust as needed)
                    if(calculatedKeyLength < 20){
                        calculatedKeyLength++;
                        continue;
                    }
                    break;
                }
                calculatedKeyLength++;
            }
            //console.log("calculatedKeyLength: "+calculatedKeyLength);

            if (calculatedKeyLength > 24 && calculatedKeyLength <= 46) {
                KEY_LENGTH = 32; // Closest match is 32 bytes
            } else if (calculatedKeyLength => 47 && calculatedKeyLength <=49) {
                KEY_LENGTH = 48; // Closest match is 48 bytes
            }else{
                KEY_LENGTH = 32; // fall back size
            }

            if(labelStr.includes("CLIENT_HANDSHAKE_TRAFFIC_SECRET")){
                CHSTRAFFIC_LEN = KEY_LENGTH;
            }else if(labelStr.includes("SERVER_HANDSHAKE_TRAFFIC_SECRET")){
                SHSTRAFFIC_LEN = KEY_LENGTH;
            }

            if(CHSTRAFFIC_LEN > 0 && SHSTRAFFIC_LEN > 0 && SHSTRAFFIC_LEN == CHSTRAFFIC_LEN){
                KEY_LENGTH = CHSTRAFFIC_LEN;
            }
        }else{
            KEY_LENGTH = key_len
            CHSTRAFFIC_LEN = KEY_LENGTH;
            SHSTRAFFIC_LEN = KEY_LENGTH;
        }


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
}


function dump_keys_from_prf(client_random_ptr, key, key_len) {
    var KEY_LENGTH = 0;
    // Set the expected length of the key (in bytes). Adjust as needed.
    if(key_len < 30){
        KEY_LENGTH = 32; // min key length
    }else{
        KEY_LENGTH = key_len;
    }
    
    // Set the expected length of the key (in bytes). Adjust as needed.
    const CLIENT_RANDOM_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    var labelStr = "CLIENT_RANDOM";
    var client_random = "";
    var secret_key = "";


    if (!key.isNull()) {
        try{
        
        const keyData = Memory.readByteArray(key, KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexKey = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space

        secret_key = hexKey;
    }catch(e){
        console.log("key error:"+e);
    }

        //console.log("Key: "+hexKey); // Print the key as a space-separated hex string
    } else {
        console.log("[!] Argument 'key' is NULL");
    }

    if(client_random_ptr === "undefined"){
        client_random_ptr = 0;
    }

    if(!client_random_ptr.isNull()){
        try{

        const keyData = Memory.readByteArray(client_random_ptr.add(0x20), CLIENT_RANDOM_LENGTH); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexClient_random = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space

            client_random = hexClient_random;
        }catch(e){
            console.log("random error: "+e);
        }

    }else {
        console.log("[!] Argument 'client_random_ptr' is NULL");
    }

    

    console.log(labelStr+" "+client_random+" "+secret_key);
    return true;
    /**/
    //console.log("----");
}


function hookBotanSSLByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;

    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    // First pattern to try
    var arch = Process.arch;
    console.log("[*] Start hooking on arch: "+arch)
    //var pattern_mb_derive_secret_x64 = "F3 0F 1E FA 55 48 89 E5 41 57 41 56 49 89 CE 41 55 41 54 53 48 81 EC 98 00 00 00 48 89 BD 68 FF FF FF 48 89 B5 58 FF FF FF 48 89 95 50 FF FF FF 4C 89 8D 48 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 49 8B 41 08 49 2B 01 48 8D 44 01 0A 48 89 45 90 48 85 C0 0F 88 39 10 00 00";

    
    // Select the appropriate patterns based on the architecture
    var pattern_mb_derive_secret = "F3 0F 1E FA 41 57 4D 89 CF 41 56 49 89 CE 41 55 4D 89 C5 41 54 49 89 D4 55 48 89 F5 53 48 89 FB 48 83 EC 08 48 8B 7E 28 48 8B 07 FF 10";
    //console.log("[*] Using HKDF pattern: "+pattern_mb_derive_secret)

    // Try first pattern and if it fails, try the second one
    hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern_mb_derive_secret, "derive_secret");
    var pattern_prf = "F3 0F 1E FA 41 57 41 56 41 55 41 54 55 53 48 81 EC 98 00 00 00 64 48 8B 04 25 28 00 00 00 48 89 84 24 88 00 00 00 31 C0 80 7E 70 00 0F 84 6C CB B6 FF";

    hook_PRF_By_Pattern(moduleBase, moduleSize, pattern_prf, "pattern_prf_secret");
}


function hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {

                                if(args[4].readCString().includes("derived")){
                                    this.key_len = args[0].readS16();
                                    if(this.key_len > 0){
                                        hkdf_key_len = this.key_len;
                                    }
                                }

                                /*
                                    * Derive a key
                                    * @param key_len the desired output length in bytes
                                    * @param secret the secret input
                                    * @param secret_len size of secret in bytes
                                    * @param salt a diversifier
                                    * @param salt_len size of salt in bytes
                                    * @param label purpose for the derived keying material
                                    * @param label_len size of label in bytes
                                    * @return the derived key
                                    *
                                    template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
                                    T derive_key(size_t key_len,
                                                const uint8_t secret[],
                                                size_t secret_len,
                                                const uint8_t salt[],
                                                size_t salt_len,
                                                const uint8_t label[] = nullptr,
                                                size_t label_len = 0) 
                                */

                                //this.salt = args[2];
                                //this.salt2 = args[1];

                                this.label = args[4]; // ptr to the label string


                    


                            },
                            onLeave: function(retval) {

                                if (!retval.isNull()) {
                                    /*console.log("salt: "+this.salt);
                                    dumpMemory(this.salt.readPointer(),0x140);
                                    console.log("salt2: "+this.salt2);
                                    dumpMemory(this.salt2.readPointer(),0x140);
                                    */

                                    /*
                                    Actually the key also given in args[0] while returning:
                                    this.key_in = args[0]; // done in on_enter
                                    this.key_in.readPointer() // in retval
                                    */
                                    var sec_vector = retval.readPointer(); // contains the key
                                    this.key = sec_vector;


                                    dump_keys_from_derive_secrets(session_client_random,this.key,this.label, hkdf_key_len);
                                    
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
                                //console.log("[!] Hooking the creation of the PRF");

                                /*
                                 Botan::TLS::Session_Keys::Session_Keys(Botan::TLS::Handshake_State const*, std::vector<unsigned char, Botan::secure_allocator<unsigned char>> const&, bool)
_ZN5Botan3TLS12Session_KeysC2EPKNS0_15Handshake_StateERKSt6vectorIhNS_16secure_allocatorIhEEEb proc near
                            (https://github.com/randombit/botan/blob/22bc2745a27fcc62bf5aba6d53481d0b52a987ac/src/lib/tls/tls12/tls_session_key.cpp#L19))
this is the constructor which is invoking the prf

There at first an object of the PRF is created:
auto prf = state->protocol_specific_prf();
                            (https://github.com/randombit/botan/blob/22bc2745a27fcc62bf5aba6d53481d0b52a987ac/src/lib/tls/tls12/tls_session_key.cpp#L37C4-L37C46))


                            But this is just returning the object which is internaly creating the PRF and than ivoking the "right" PRF:
                            const secure_vector<uint8_t> prf_output = prf->derive_key(
      prf_gen, m_master_sec.data(), m_master_sec.size(), salt.data(), salt.size(), label.data(), label.size());
                            (https://github.com/randombit/botan/blob/22bc2745a27fcc62bf5aba6d53481d0b52a987ac/src/lib/tls/tls12/tls_session_key.cpp#L63)

                            Therefore we have to access this function using it offset from the return value. We can see it in the disassembly like this:

                            mov     r14, [rbp+prf_class] // retval.readpointer()
                            mov     [rbp+n+8], rsi
                            mov     esi, 1          ; unsigned __int64
                            mov     [rbp+var_158], rax
                            call    __ZN5Botan15allocate_memoryEmm ; Botan::allocate_memory(ulong,ulong)
                            ;   } // starts at 645302
                            pxor    xmm0, xmm0
                            mov     r12, rax
                            lea     r13, [rax+30h]
                            mov     edx, 30h ; '0'
                            movups  xmmword ptr [rax], xmm0
                            mov     rcx, [rbp+var_160]
                            mov     rsi, r12
                            mov     rdi, r14
                            movups  xmmword ptr [rax+20h], xmm0
                            mov     r8, [rbp+var_158]
                            movups  xmmword ptr [rax+10h], xmm0
                            mov     rax, [r14] // var rax = retval.readpointer().readpointer()
                            mov     rax, [rax+20h] // var final_rax = rax.add(0x20).readpointer()
                            push    [rbp+n+8]
                            push    [rbp+n]
                            push    [rbp+var_138]
                            push    [rbp+var_140]
                            ;   try {
                            call    rax //prf->derive_key()


                                */

                             


                            },
                            onLeave: function(retval) {

                                if (!retval.isNull()) {
                                    try{
                                        
                                        // probably the prf-derive-key() function
                                        var rax = retval.readPointer().readPointer();
                                        var final_rax = rax.add(0x20).readPointer();
                                        Interceptor.attach(final_rax, { 
                                            onEnter: function (args){
                                                //console.log("[!] Hooked prf->derive_key()");

                                                this.derive_key_len = args[2].toInt32();

                                                if(this.derive_key_len > 16){
                                                    this.label = args[8];
                                                    if(is_arg_key_exp(this.label)){
                                                        this.key = args[3];
                                                        this.key_len = args[4].toInt32();
                                                        this.client_random_ptr = args[6];
                                                        dump_keys_from_prf(this.client_random_ptr, this.key, this.key_len);
                                                    }

                                                }

                                            },
                                            onLeave: function (retval){

                                            }
                                        });
                                }catch(e){
                                    console.log("err in derive_key identifier: "+e);
                                }

                               
                                
                                }
                            }
                        });
                    }
                });
} 

// Find the BotanSSL module
function findBotanSSLModule() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("libbotan") ) {
            console.log("Found BotanSSL Module: " + name);
            return modules[i];
        }
    }
    console.log("BotanSSL module not found.");
    return null;
}


// test_client_13_boringssl_key_export
// Main function
function main() {
    var module = findBotanSSLModule();
    if (module !== null) {
        hookBotanSSLByPattern(module);
    }
}

// Run the main function
main();


/*
HKDF https://github.com/randombit/botan/blob/09a7a98ec8be4678af4fc54b5b4b12c9f1c2dac7/src/lib/kdf/kdf.h#L86

[*] HKDF-Function identified with label: HKDF_EXPAND_LABEL
[*] String (Register R8) used as 5th argument in function call at address: 0x00870cec (invoking HKDF_EXPAND_LABEL)
[*] Function offset (Ghidra): 0086E590 (0x0086E590)
[*] Function offset (IDA with base 0x0): 0076E590 (0x0076E590)
[*] Byte pattern for frida: F3 0F 1E FA 55 48 89 E5 41 57 41 56 49 89 CE 41 55 41 54 53 48 81 EC 98 00 00 00 48 89 BD 68 FF FF FF 48 89 B5 58 FF FF FF 48 89 95 50 FF FF FF 4C 89 8D 48 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 49 8B 41 08 49 2B 01 48 8D 44 01 0A 48 89 45 90 48 85 C0 0F 88 39 10 00 00

https://github.com/randombit/botan/blob/09a7a98ec8be4678af4fc54b5b4b12c9f1c2dac7/src/lib/kdf/hkdf/hkdf.cpp#L131
secure_vector<uint8_t> hkdf_expand_label(std::string_view hash_fn,
                                         const uint8_t secret[],
                                         size_t secret_len,
                                         std::string_view label,
                                         const uint8_t hash_val[],
                                         size_t hash_val_len,
                                         size_t length)









https://github.com/randombit/botan/blob/6f26bcdf1f64aee89881ada4036b44c458424dcc/src/lib/tls/tls12/tls_session_key.cpp#L54C22-L54C37

In future releases it might be a way to get the key from the invoking function e.g
https://github.com/randombit/botan/blob/6f26bcdf1f64aee89881ada4036b44c458424dcc/src/lib/tls/tls12/tls_session_key.cpp#L19



[*] PRF-Function identified with label: PROTOCOL_SPECIFIC_PRF (Botan::TLS::Handshake_State::protocol_specific_prf)
[*] PRF-Function signature: undefined __stdcall protocol_specific_prf(void)
[*] String (Register RAX) used as -1th argument in function call at address: 0x00744c47 (invoking PROTOCOL_SPECIFIC_PRF)
[*] We tracked also a copy operation of the previous register: RAX used as -1th argument
[*] Function offset (Ghidra): 00731640 (0x00731640)
[*] Function offset (IDA with base 0x0): 00631640 (0x00631640)
[*] Byte pattern for frida: F3 0F 1E FA 41 57 41 56 41 55 41 54 55 53 48 81 EC 98 00 00 00 64 48 8B 04 25 28 00 00 00 48 89 84 24 88 00 00 00 31 C0 80 7E 70 00 0F 84 6C CB B6 FF


https://github.com/randombit/botan/blob/63746e757fe1892311e802c370790b889c5059c3/src/lib/tls/tls12/tls_handshake_state.cpp#L237
std::unique_ptr<KDF> Handshake_State::protocol_specific_prf() const {
   const std::string prf_algo = ciphersuite().prf_algo();

   if(prf_algo == "MD5" || prf_algo == "SHA-1") {
      return KDF::create_or_throw("TLS-12-PRF(SHA-256)");
   }

   return KDF::create_or_throw("TLS-12-PRF(" + prf_algo + ")");
}



Usage example:
...
         label.assign(MASTER_SECRET_MAGIC, MASTER_SECRET_MAGIC + sizeof(MASTER_SECRET_MAGIC));
         salt += state->client_hello()->random();
         salt += state->server_hello()->random();
...

      m_master_sec = prf->derive_key(48, pre_master_secret, salt, label);

*/