/*
Invoke

frida -p $(frida-ps | grep -i firefox | awk '{print $1}') -l universal_key_dump_liunx_x86_64.js

*/

// Constants for parsing
const SSL3_RANDOM_SIZE = 32; // Assuming SSL3_RANDOM_SIZE is 32 bytes
const SSL_MAX_MD_SIZE = 48;  // Assuming SSL_MAX_MD_SIZE is 64 bytes

const pointerSize = Process.pointerSize;
const SSL3_RANDOM_LENGTH = 32;
var visit_cnt = 0;

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
var session_prf_key = "";


/*

Usually we can expect after the label are length value of that label.
The PRF would have a length of 0xD (13) and the HKDF 0xC (12)


*/

function get_prf_value_as_hex_string(ptr, key_length){
    var ptr_offset = ptr.add(0xa0);
    var sec_str = getHexString(ptr_offset,key_length);
    return sec_str;

}

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



// Function to parse the SSL_HANDSHAKE structure of NSS
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




function dump_keys(label, identifier,key) {
    const MAX_KEY_LENGTH = 64;
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

function dump_keys_from_derive_secrets(sslSocket_ptr, key, label_to_span, label_c_or_s) {
    var labelStr = "";
    var client_random = "";
    var secret_key = "";
    var investigate = true;

    
    if (!label_to_span.isNull()) {
        var label = label_to_span.readCString(); // Read the C string
        if(!label_c_or_s.isNull() && label !== "exp master"){
            var praefix = label_c_or_s.readCString();
            label = praefix + " " + label;
            investigate = true;
        }else{
            investigate = true;
        }

        labelStr = getTLSLabel(label);
        if(labelStr === null){
            return false;
        }
    } else {
        console.log("[Error] Argument 'label' is NULL");
    }

    if(!sslSocket_ptr.isNull()){
        var sslSocketStr = parse_struct_sslSocketStr(sslSocket_ptr);
        var ssl3_struct = sslSocketStr.ssl3;
        var ssl3 = parse_struct_ssl3Str(ssl3_struct);

        client_random = getClientRandom(ssl3);

    } else {
        console.log("[Error] Argument 'sslSocket_ptr' is NULL");
    }

    if (!key.isNull()) {
        
        secret_key = get_Secret_As_HexString(key, false);

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
    const MAX_KEY_LENGTH = 64;
    
    // Set the expected length of the key (in bytes). Adjust as needed.
    const KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    var labelStr = "CLIENT_RANDOM";
    var client_random = "";
    var secret_key = "";


    if (!key.isNull()) {
        /*
        const keyData = Memory.readByteArray(key, KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexKey = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space
        */

        secret_key = get_Secret_As_HexString(key, false);

        //console.log("Key: "+hexKey); // Print the key as a space-separated hex string
    } else {
        console.log("[!] Argument 'key' is NULL");
    }

    if(!client_random_ptr.isNull()){
        /*
        const keyData = Memory.readByteArray(client_random_ptr.add(0x20), KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
        
        // Convert the byte array to a string of space-separated hex values
        const hexClient_random = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space
            */

            console.log("\nTrying to get Hex string trough client_random....");
            client_random = get_Secret_As_HexString(client_random_ptr, true);
            console.log("client_random search stop....\n");

    }else {
        console.log("[!] Argument 'client_random_ptr' is NULL");
    }

    

    console.log(labelStr+" "+client_random+" "+secret_key);
    return true;
    /**/
    //console.log("----");
}


function hookNSSByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;

    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    // First pattern to try
    var arch = Process.arch;
    console.log("[*] Start hooking on arch: "+arch)
  
    // Select the appropriate patterns based on the architecture
    //var pattern_mb_derive_secret = (arch === 'x64') ? pattern_mb_derive_secret_x64 : pattern_mb_derive_secret_arm64;
    //console.log("[*] Using HKDF pattern: "+pattern_mb_derive_secret)
    var pattern_mb_derive_secret = "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 4D 89 CE 4C 89 C3 49 89 CC 49 89 F5 49 89 FF 64 48 8B 04 25 28 00 00 00 48 89 84 24 C0 00 00 00 48 85 D2 74 67";

    // Try first pattern and if it fails, try the second one
    hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern_mb_derive_secret, "derive_secret");

    /*
    F3 0F 1E FA 55 48 89 E5 48 83 EC 30 89 7D FC 48 89 75 F0 48 89 55 E8 48 89 4D E0 4C 89 45 D8 44 89 4D F8 48 8B 05 44 93 01 00 48 85 C0 75 10 TLS_PHash
    */
    /*
    // Found but not invoked in our example ground truth
    var pattern_prf = "F3 0F 1E FA 55 48 89 E5 48 83 EC 30 48 89 7D F8 48 89 75 F0 48 89 55 E8 48 89 4D E0 44 89 45 DC 48 8B 05 98 99 01 00 48 85 C0 75 10";

    hook_PRF_By_Pattern(moduleBase, moduleSize, pattern_prf, "pattern_prf_secret");*/
    var pattern_prf = "55 41 57 41 56 41 54 53 48 8B 05 B9 FB 03 00 48 85 C0 74 11";

    hook_PRF_By_Pattern(moduleBase, moduleSize, pattern_prf, "pattern_p_hash");
}


  /**
    * 
    * @param {*} readAddr is the address where we start reading the bytes
    * @param {*} len is the length of bytes we want to convert to a hex string
    * @returns a hex string with the length of len
    */
  function  getHexString(readAddr, len) {
    var secret_str = "";

    for (var i = 0; i < len; i++) {
        // Read a byte, convert it to a hex string (0xab ==> "ab"), and append
        // it to secret_str.

        secret_str +=
            ("0" + readAddr.add(i).readU8().toString(16).toUpperCase()).substr(-2)
    }

    return secret_str;
}

function parse_struct_SECItem(secitem) {
    /*
     * struct SECItemStr {
     * SECItemType type;
     * unsigned char *data;
     * unsigned int len;
     * }; --> size = 20
    */
    return {
        "type": secitem.readU64(),
        "data": secitem.add(pointerSize).readPointer(),
        "len": secitem.add(pointerSize * 2).readU32()
    }
}

const SECStatus = Object.freeze({
    SECWouldBlock: -2,
    SECFailure: -1,
    SECSuccess: 0
});


function get_nss_as_module(){
    var nssLib = null;
    var loadedModules = Process.enumerateModules();

    for (let module of loadedModules) {
        if (/libnss[34]\.so/.test(module.name) || /nss[34]\.dll/.test(module.name)) {
            nssLib = module.name;
            //console.log(`[+] Found NSS library: ${nssLib}`); // debug log
            break; // Stop after finding the first match
        }
    }

    if (!nssLib) {
        console.log("[!] Could not find a matching NSS library (libnss3.so or libnss4.so)");
        
    }
    return nssLib;
}

function PK11_GetKeyData_SelfImpl(secret_key_Ptr) {
    var secitem = secret_key_Ptr.add(0x30);
    return secitem;
}

function get_Secret_As_HexString(secret_key_Ptr, is_client_random) {

    var nssLib = get_nss_as_module();

    // Define the PK11_ExtractKeyValue function
    /*
    const PK11_ExtractKeyValue = new NativeFunction(
        Module.findExportByName(nssLib, "PK11_ExtractKeyValue"),
        'int',  // Return type
        ['pointer'] // Argument types (assumed to take a pointer)
    );
    */

    var PK11_GetKeyData = null;

    try{
        // Define the PK11_GetKeyData function
        PK11_GetKeyData = new NativeFunction(
            Module.findExportByName(nssLib, "PK11_GetKeyData"),
            'pointer', // Return type (assumed to return a pointer)
            ['pointer'] // Argument types (assumed to take a pointer)
        );
    }catch(e){
        console.log("fallback...");
        // backup solution
        PK11_GetKeyData = PK11_GetKeyData_SelfImpl;
    }

    /*
    // This is just a check which is not really needed

    var rv = PK11_ExtractKeyValue(secret_key_Ptr);
    if (rv != SECStatus.SECSuccess) {
        console.log("[**] ERROR access the secret key");
        return "";
    }*/

    //console.log("dumping secret_key_Ptr"+secret_key_Ptr);
    //dumpMemory(secret_key_Ptr, 0x140);


    var keyData = PK11_GetKeyData(secret_key_Ptr);  // return value is a SECItem

    var keyData_SECITem = parse_struct_SECItem(keyData);


    var secret_as_hexString = "";

    try{


    if(is_client_random){
        secret_as_hexString = getHexString(keyData_SECITem.data, 32);
    }else{
        secret_as_hexString = getHexString(keyData_SECITem.data, keyData_SECITem.len);
    }
}catch(e){
    console.log("error hex: "+e);
}

    return secret_as_hexString;
    /* */
}

// https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L771
function parse_struct_ssl3Str(ssl3_struct) {
    /*
    struct ssl3StateStr {

    ssl3CipherSpec *crSpec; // current read spec. 
    ssl3CipherSpec *prSpec; // pending read spec. 
    ssl3CipherSpec *cwSpec; // current write spec. 
    ssl3CipherSpec *pwSpec; // pending write spec. 
    
    PRBool peerRequestedKeyUpdate;                     --> enum type
    
    PRBool keyUpdateDeferred;                          --> enum type
    tls13KeyUpdateRequest deferredKeyUpdateRequest;    --> enum type
   
    PRBool clientCertRequested;                        --> enum type

    CERTCertificate *clientCertificate;   
    SECKEYPrivateKey *clientPrivateKey;   
    CERTCertificateList *clientCertChain; 
    PRBool sendEmptyCert;                 

    PRUint8 policy;
    PLArenaPool *peerCertArena;
    
    void *peerCertChain;
    
    CERTDistNames *ca_list;
    
    SSL3HandshakeState hs;
    ...
    }
    */
    return {
        "crSpec": ssl3_struct.readPointer(),
        "prSpec": ssl3_struct.add(pointerSize).readPointer(),
        "cwSpec": ssl3_struct.add(pointerSize * 2).readPointer(),
        "pwSpec": ssl3_struct.add(pointerSize * 3).readPointer(),
        "peerRequestedKeyUpdate": ssl3_struct.add(pointerSize * 4).readU32(),
        "keyUpdateDeferred": ssl3_struct.add(pointerSize * 4 + 4).readU32(),
        "deferredKeyUpdateRequest": ssl3_struct.add(pointerSize * 4 + 8).readU32(),
        "clientCertRequested": ssl3_struct.add(pointerSize * 4 + 12).readU32(),
        "clientCertificate": ssl3_struct.add(pointerSize * 4 + 16).readPointer(),
        "clientPrivateKey": ssl3_struct.add(pointerSize * 5 + 16).readPointer(),
        "clientCertChain": ssl3_struct.add(pointerSize * 6 + 16).readPointer(),
        "sendEmptyCert": ssl3_struct.add(pointerSize * 7 + 16).readU32(),
        "policy": ssl3_struct.add(pointerSize * 7 + 20).readU32(),
        "peerCertArena": ssl3_struct.add(pointerSize * 7 + 24).readPointer(),
        "peerCertChain": ssl3_struct.add(pointerSize * 8 + 24).readPointer(),
        "ca_list": ssl3_struct.add(pointerSize * 9 + 24).readPointer(), // + 0x10
        "hs": { // https://github.com/nss-dev/nss/blob/c277877bd8c01e107b097bbd57df094b34e37aab/lib/ssl/sslimpl.h#L615
            "server_random": ssl3_struct.add(pointerSize * 10 + 24 + 8),  //SSL3Random --> typedef PRUint8 SSL3Random[SSL3_RANDOM_LENGTH];
            "client_random": ssl3_struct.add(pointerSize * 10 + 56 + 8),
            "client_inner_random": ssl3_struct.add(pointerSize * 10 + 88+ 8),
            "ws": ssl3_struct.add(pointerSize * 10 + 120+ 8).readU32(),
            "hashType": ssl3_struct.add(pointerSize * 10 + 124+ 8).readU32(),
            "messages": { // sslBuffer
                "data": ssl3_struct.add(pointerSize * 10 + 128+ 8).readPointer(),
                "len": ssl3_struct.add(pointerSize * 11 + 128+ 8).readU32(),
                "space": ssl3_struct.add(pointerSize * 11 + 132+ 8).readU32(),
                "fixed": ssl3_struct.add(pointerSize * 11 + 136+ 8).readU32(),

            },
            "echInnerMessages": { // sslBuffer
                "data": ssl3_struct.add(pointerSize * 11 + 140+ 8).readPointer(),
                "len": ssl3_struct.add(pointerSize * 12 + 140+ 8).readU32(),
                "space": ssl3_struct.add(pointerSize * 12 + 144+ 8).readU32(),
                "fixed": ssl3_struct.add(pointerSize * 12 + 148+ 8).readU32(),

            },
            "md5": ssl3_struct.add(pointerSize * 12 + 152+ 8).readPointer(),
            "sha": ssl3_struct.add(pointerSize * 13 + 152+ 8).readPointer(),
            "shaEchInner": ssl3_struct.add(pointerSize * 14 + 152+ 8).readPointer(),
            "shaPostHandshake": ssl3_struct.add(pointerSize * 15 + 152+ 8).readPointer(),
            "signatureScheme": ssl3_struct.add(pointerSize * 16 + 152+ 8).readU32(),
            "kea_def": ssl3_struct.add(pointerSize * 16 + 156+ 8).readPointer(),
            "cipher_suite": ssl3_struct.add(pointerSize * 17 + 156+ 8).readU32(),
            "suite_def": ssl3_struct.add(pointerSize * 17 + 160+ 8).readPointer(),
            "msg_body": { // sslBuffer
                "data": ssl3_struct.add(pointerSize * 18 + 160+ 8).readPointer(),
                "len": ssl3_struct.add(pointerSize * 19 + 160+ 8).readU32(),
                "space": ssl3_struct.add(pointerSize * 19 + 164+ 8).readU32(),
                "fixed": ssl3_struct.add(pointerSize * 19 + 168+ 8).readU32(),

            },
            "header_bytes": ssl3_struct.add(pointerSize * 19 + 172).readU32(),
            "msg_type": ssl3_struct.add(pointerSize * 19 + 176).readU32(),
            "msg_len": ssl3_struct.add(pointerSize * 19 + 180).readU32(),
            "isResuming": ssl3_struct.add(pointerSize * 19 + 184).readU32(),
            "sendingSCSV": ssl3_struct.add(pointerSize * 19 + 188).readU32(),
            "receivedNewSessionTicket": ssl3_struct.add(pointerSize * 19 + 192).readU32(),
            "newSessionTicket": ssl3_struct.add(pointerSize * 19 + 196),          // for now we calculate only its offset (44 bytes); detailes at https://github.com/nss-dev/nss/blob/master/lib/ssl/ssl3prot.h#L162
            "finishedBytes": ssl3_struct.add(pointerSize * 19 + 240).readU32(),
            "finishedMsgs": ssl3_struct.add(pointerSize * 19 + 244),
            "authCertificatePending": ssl3_struct.add(pointerSize * 18 + 316).readU32(),
            "restartTarget": ssl3_struct.add(pointerSize * 19 + 320).readU32(),
            "canFalseStart": ssl3_struct.add(pointerSize * 19 + 324).readU32(),
            "preliminaryInfo": ssl3_struct.add(pointerSize * 19 + 328).readU32(),
            "remoteExtensions": {
                "next": ssl3_struct.add(pointerSize * 19 + 332).readPointer(),
                "prev": ssl3_struct.add(pointerSize * 20 + 332).readPointer(),
            },
            "echOuterExtensions": {
                "next": ssl3_struct.add(pointerSize * 21 + 332).readPointer(),
                "prev": ssl3_struct.add(pointerSize * 22 + 332).readPointer(),
            },
            "sendMessageSeq": ssl3_struct.add(pointerSize * 23 + 332).readU32(),  //u16 but through alignment  U32
            "lastMessageFlight": {
                "next": ssl3_struct.add(pointerSize * 23 + 336).readPointer(),
                "prev": ssl3_struct.add(pointerSize * 24 + 336).readPointer(),
            },
            "maxMessageSent": ssl3_struct.add(pointerSize * 25 + 336+ 8).readU16(),  //u16
            "recvMessageSeq": ssl3_struct.add(pointerSize * 25 + 338+ 8).readU16(),
            "recvdFragments": { // sslBuffer
                "data": ssl3_struct.add(pointerSize * 25 + 340+ 8).readPointer(),
                "len": ssl3_struct.add(pointerSize * 26 + 340+ 8).readU32(),
                "space": ssl3_struct.add(pointerSize * 26 + 344+ 8).readU32(),
                "fixed": ssl3_struct.add(pointerSize * 26 + 348+ 8).readU32(),

            },
            "recvdHighWater": ssl3_struct.add(pointerSize * 26 + 352+ 8).readU32(),
            "cookie": {
                "type": ssl3_struct.add(pointerSize * 26 + 356+ 8).readU64(),
                "data": ssl3_struct.add(pointerSize * 27 + 356+ 8).readPointer(),
                "len": ssl3_struct.add(pointerSize * 28 + 356+ 8).readU32(),
            },
            "times_array": ssl3_struct.add(pointerSize * 28 + 360+ 8).readU32(),
            "rtTimer": ssl3_struct.add(pointerSize * 28 + 432+ 8).readPointer(),
            "ackTimer": ssl3_struct.add(pointerSize * 29 + 432+ 8).readPointer(),
            "hdTimer": ssl3_struct.add(pointerSize * 30 + 432+ 8).readPointer(),
            "rtRetries": ssl3_struct.add(pointerSize * 31 + 432+ 8).readU32(),
            "srvVirtName": {
                "type": ssl3_struct.add(pointerSize * 31 + 436+ 8).readU64(),
                "data": ssl3_struct.add(pointerSize * 32 + 436+ 8).readPointer(),
                "len": ssl3_struct.add(pointerSize * 33 + 436+ 8).readU32(),
            },
            "currentSecret": ssl3_struct.add(pointerSize * 33 + 440+ 8).readPointer(),
            "resumptionMasterSecret": ssl3_struct.add(pointerSize * 34 + 440+ 8).readPointer(),
            "dheSecret": ssl3_struct.add(pointerSize * 35 + 440+ 8).readPointer(),
            "clientEarlyTrafficSecret": ssl3_struct.add(pointerSize * 36 + 440+ 8).readPointer(),
            "clientHsTrafficSecret": ssl3_struct.add(pointerSize * 37 + 440+ 8).readPointer(),
            "serverHsTrafficSecret": ssl3_struct.add(pointerSize * 38 + 440+ 8).readPointer(),
            "clientTrafficSecret": ssl3_struct.add(pointerSize * 39 + 440+ 8).readPointer(),
            "serverTrafficSecret": ssl3_struct.add(pointerSize * 40 + 440+ 8).readPointer(),
            "earlyExporterSecret": ssl3_struct.add(pointerSize * 41 + 440+ 8).readPointer(),
            "exporterSecret": ssl3_struct.add(pointerSize * 42 + 440+ 8).readPointer()

        } // end of hs struct

        /*
        typedef struct SSL3HandshakeStateStr {
    SSL3Random server_random;
    SSL3Random client_random;
    SSL3Random client_inner_random; 
    SSL3WaitState ws;                       --> enum type      

    
    SSL3HandshakeHashType hashType;         --> enum type      
    sslBuffer messages;                     --> struct of 20 bytes (1 ptr + 12 bytes;see lib/ssl/sslencode.h)
    sslBuffer echInnerMessages; 
    
    PK11Context *md5;
    PK11Context *sha;
    PK11Context *shaEchInner;
    PK11Context *shaPostHandshake;
    SSLSignatureScheme signatureScheme;     --> enum type( see lib/ssl/sslt.h)
    const ssl3KEADef *kea_def;
    ssl3CipherSuite cipher_suite;           --> typedef PRUint16 ssl3CipherSuite (see lib/ssl/ssl3prot.h)
    const ssl3CipherSuiteDef *suite_def;
    sslBuffer msg_body; 
                        
    unsigned int header_bytes;
    
    SSLHandshakeType msg_type;
    unsigned long msg_len;
    PRBool isResuming;  
    PRBool sendingSCSV; 

    
    PRBool receivedNewSessionTicket;
    NewSessionTicket newSessionTicket;      --> (see lib/ssl/ssl3prot.h)

    PRUint16 finishedBytes; 
    union {
        TLSFinished tFinished[2];           --> 12 bytes
        SSL3Finished sFinished[2];          --> 36 bytes
        PRUint8 data[72];
    } finishedMsgs;                         --> 72

    PRBool authCertificatePending;
    
    sslRestartTarget restartTarget;

    PRBool canFalseStart; 
    
    PRUint32 preliminaryInfo;

    
    PRCList remoteExtensions;  
    PRCList echOuterExtensions;

    
    PRUint16 sendMessageSeq;   
    PRCList lastMessageFlight; 
    PRUint16 maxMessageSent;   
    PRUint16 recvMessageSeq;   
    sslBuffer recvdFragments;  
    PRInt32 recvdHighWater;    
    SECItem cookie;            
    dtlsTimer timers[3];       24 * 3
    dtlsTimer *rtTimer;        
    dtlsTimer *ackTimer;       
    dtlsTimer *hdTimer;        
    PRUint32 rtRetries;        
    SECItem srvVirtName;       
                                    

    // This group of values is used for TLS 1.3 and above 
    PK11SymKey *currentSecret;            // The secret down the "left hand side"   --> ssl3_struct.add(704)
                                            //of the TLS 1.3 key schedule.          
    PK11SymKey *resumptionMasterSecret;   // The resumption_master_secret.          --> ssl3_struct.add(712)
    PK11SymKey *dheSecret;                // The (EC)DHE shared secret.             --> ssl3_struct.add(720)
    PK11SymKey *clientEarlyTrafficSecret; // The secret we use for 0-RTT.           --> ssl3_struct.add(728)
    PK11SymKey *clientHsTrafficSecret;    // The source keys for handshake          --> ssl3_struct.add(736)
    PK11SymKey *serverHsTrafficSecret;    // traffic keys.                          --> ssl3_struct.add(744)
    PK11SymKey *clientTrafficSecret;      // The source keys for application        --> ssl3_struct.add(752)
    PK11SymKey *serverTrafficSecret;      // traffic keys                           --> ssl3_struct.add(760)
    PK11SymKey *earlyExporterSecret;      // for 0-RTT exporters                    --> ssl3_struct.add(768)
    PK11SymKey *exporterSecret;           // for exporters                          --> ssl3_struct.add(776)
    ...


    typedef struct {
    const char *label; 8
    DTLSTimerCb cb; 8
    PRIntervalTime started; 4
    PRUint32 timeout; 4
} dtlsTimer;

        */
    }

}


function parse_struct_sslSocketStr(sslSocketFD) {
    return {
        "fd": sslSocketFD.readPointer(),
        "version": sslSocketFD.add(160),
        "handshakeCallback": sslSocketFD.add(464),
        "secretCallback": sslSocketFD.add(568),
        "ssl3": sslSocketFD.add(1432)
    }
}


function getClientRandom(ssl3) {
    var client_random = getHexString(ssl3.hs.client_random, SSL3_RANDOM_LENGTH);

    return client_random;

}


function hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                //console.log("invoking derive_secret");

                                /*
                                static SECStatus
                                tls13_DeriveSecretWrap(sslSocket *ss, PK11SymKey *key,
                                                    const char *prefix,
                                                    const char *suffix,
                                                    const char *keylogLabel,
                                                    PK11SymKey **dest);
                                */
                                
                                this.sslSocket = args[0]; // --> ptr to handshake struct
                                this.key = args[5]; // when init its zero and only when returning it is filled with the key value
                                this.label_c_or_s = args[2]; // indicates if its the client (c) or the server (s)
                                this.label = args[3]; // ptr to the label string like hs traffic
                                this.label_human = args[4]; // ptr to the label string like SERVER_HANDSHAKE_TRAFFIC_SECRET

                                // Dumping readptr of arg 0 contains at offset 0x70 the output of the keylog when set


                            },
                            onLeave: function(retval) {

                                


                                    dump_keys_from_derive_secrets(this.sslSocket,this.key.readPointer(),this.label, this.label_c_or_s);
                                    
                                //}
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
                                //console.log("start hook");
                                this.dump_keys = false;

                                // ; SECStatus __cdecl TLS_PRF(const SECItem *secret, const char *label, SECItem *seed, SECItem *result, PRBool isFIPS)

                                // SECStatus __cdecl TLS_P_hash(HASH_HashType hashAlg, const SECItem *secret, const char *label, SECItem *seed, SECItem *result, PRBool isFIPS)
                                if(pattern_name.includes("p_hash")){
                                    this.input_secret = args[1];
                                    this.label = args[2];
                                    this.seed = args[3];
                                    this.key = args[4];
                                }else{
                                    this.input_secret = args[0];
                                    this.label = args[1];
                                    this.seed = args[2];
                                    this.key = args[3];
                                }


                                //console.log("\n---------------------------------------start-----------------------------------------");
                                    //var label = this.label.readCString(); // Read the C string
                                //console.log("Visit cnt: "+visit_cnt);
                                //console.log("\nLabel: ");
                                //dumpMemory(this.label, 0x20);


                                

                               /* /
                               if(is_arg_key_exp(this.label){
                                    this.dump_keys = true;
                                }*/

                                /* 
                                if(did_check == false){
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                }
                                /* */ 


                            },
                            onLeave: function(retval) {
                                

                                //if (!retval.isNull() && this.dump_keys) {
                                //    dump_keys_from_prf(this.client_random_ptr, this.key);

                                    /* 
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

                                    }  */
                               
                                
                                //}
                                if(visit_cnt == 0){
                                    session_prf_key = get_prf_value_as_hex_string(this.key,48);
                                }

                                if(visit_cnt == 1){
                                    session_client_random = get_prf_value_as_hex_string(this.key,32);
                                    console.log("CLIENT_RANDOM "+ session_client_random+ " "+session_prf_key);
                                }

                                try{

                                    visit_cnt++;
                                    //console.log("processing..");
                                    //console.log("Input Secret: "+this.input_secret);
                                    
                                    //console.log("Input Secret2: "+get_Secret_As_HexString(this.input_secret), false);
                                    }catch(e){
                                        console.log("err:"+e);
                                    }


                                // should work but when printing the keys it seems to block the program flow...
                                //dump_keys_from_prf(this.seed, this.key);
                                if(visit_cnt > 3){
                                    visit_cnt = 0;
                                }
                                //console.log("---------------------------------------end--------------------------------------\n");

                            }
                        });
                    }
                });
} 

// Find the NSS module
function findNSSModuleHKDF() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("libssl3") ) {
            console.log("Found NSS Module which used the HKDF: " + name);
            return modules[i];
        }
    }
    console.log("NSS module not found.");
    return null;
}

function findNSSModulePRF() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("libsoftokn3") ) {
            console.log("Found NSS Module which used the PRF: " + name);
            return modules[i];
        }
    }

    // libsoftokn3 gets dynamiclly loaded for TLS 1.2
    console.log("NSS module not found.");
    return null;
}

function hookDynamicLinker() {
    var dlopenAddr = Module.findExportByName("libdl.so.2", "dlopen");
    //var androidDlopenExtAddr = Module.findExportByName("libdl.so", "android_dlopen_ext");

    function processLibraryLoad(libraryName) {
        if (libraryName.includes("libsoftokn3")) {
            console.log("[Dynamic Load] "+libraryName+" loaded dynamically.");

        
        /*
        // is working but the code we want to hook is already being executed    
            // Wait briefly to ensure the module is fully loaded
        setTimeout(() => {
            var resolvedModule = null;
            Process.enumerateModules().forEach(function (mod) {
                if (mod.name.endsWith("libsoftokn3.so")) { 
                    resolvedModule = mod;
                }
            });



            //var module = Process.getModuleByName(libraryName);
            if (resolvedModule !== null) {
                hookNSSByPattern(resolvedModule);
            } else {
                console.log("[Dynamic Load] Failed to retrieve "+libraryName+" module.");
            }
        }, 100); // Small delay to ensure the module is loaded
        */
        }
    }

    if (dlopenAddr) {
        console.log("Hooking dlopen");
        Interceptor.attach(dlopenAddr, {
            onEnter: function (args) {
                try{
                    this.libraryName = Memory.readCString(args[0]);
                    console.log("[dlopen] Loading library: " + this.libraryName);
                }catch(e){
                    return;
                }

                if(this.libraryName != null){

                if(this.libraryName.includes("libsoftokn")){
                    this.blockExecution = true;

                // Run hooks in a separate thread to avoid deadlock
                var hookThread = new Thread(function () {
                    console.log("[*] Applying hooks...");
                    
                    // Wait for the library to be fully loaded
                    var resolvedModule = null;
                    while (resolvedModule === null) {
                        Process.enumerateModules().forEach(function (mod) {
                            if (mod.name.endsWith("libsoftokn3.so")) {
                                resolvedModule = mod;
                            }
                        });
                        Thread.sleep(500); // Small delay before re-checking
                    }

                    console.log(`[+] Resolved module: ${resolvedModule.name} at ${resolvedModule.base}`);
                    
                    // Apply hooks
                    hookNSSByPattern(resolvedModule);

                    console.log("[+] Hooks applied! Resuming execution.");
                    this.blockExecution = false;
                });

                // Loop to keep blocking execution until hooks are done
                while (this.blockExecution) {
                    Thread.sleep(500); // Keeps process waiting
                }
                }
                }


            },
            onLeave: function (retval) {
                if (this.libraryName) {
                    //processLibraryLoad(this.libraryName);
                }
            }
        });
    } else {
        console.log("dlopen not found in libdl.so");
    }

    /*
    if (androidDlopenExtAddr) {
        console.log("Hooking android_dlopen_ext");
        Interceptor.attach(androidDlopenExtAddr, {
            onEnter: function (args) {
                this.libraryName = Memory.readCString(args[0]);
                console.log("[android_dlopen_ext] Loading library: " + this.libraryName);
            },
            onLeave: function (retval) {
                if (this.libraryName) {
                    processLibraryLoad(this.libraryName);
                }
            }
        });
    } else {
        console.log("android_dlopen_ext not found in libdl.so");
    }*/
}

function hook_checker(){
    const target_hook = "PR_Connect";
    const target_mod = "libnspr4.so";
    var target_addr = Module.findExportByName(target_mod, target_hook);
    Interceptor.attach(target_addr, {
            onEnter: function (args) {
                var module = findNSSModulePRF();
                if (module !== null) {
                    hookNSSByPattern(module);}

                console.log("connection started...");
                //Thread.sleep(5);

                },
            onLeave: function (retval) {
                if (this.libraryName) {
                    console.log("trying to apply hook...");
                    processLibraryLoad(this.libraryName);
                }
                console.log("connection finished...");
            }
        });
}


// test_client_13_boringssl_key_export
// Main function
function main() {
    var module = findNSSModuleHKDF();
    if (module !== null) {
        hookNSSByPattern(module);
    }
    var module2 = findNSSModulePRF();
    if (module2 !== null) {
        hookNSSByPattern(module2);
    }
    //hookDynamicLinker();
    hook_checker();
}

// Run the main function
main();


/*

https://github.com/nss-dev/nss

HKDF libssl3.so

HKDF identified with TLSKEyHunter
SECStatus __cdecl tls13_DeriveSecretWrap(sslSocket *ss_0, PK11SymKey *key, const char *prefix, const char *suffix, const char *keylogLabel, PK11SymKey **dest)

[*] HKDF-Function identified with label: TLS13_DERIVESECRETWRAP (tls13_DeriveSecretWrap)
[*] HKDF-Function signature: undefined tls13_DeriveSecretWrap(void)
[*] String (Register RCX) used as 3th argument in function call at address: 0x00162054 (invoking TLS13_DERIVESECRETWRAP)
[*] We tracked also a copy operation of the previous register: RDX used as 2th argument
[*] Function offset (Ghidra): 0016AD07 (0x0016AD07)
[*] Function offset (IDA with base 0x0): 0006AD07 (0x0006AD07)
[*] Byte pattern for frida: F3 0F 1E FA 55 48 89 E5 53 48 81 EC 08 01 00 00 48 89 BD 18 FF FF FF 48 89 B5 10 FF FF FF 48 89 95 08 FF FF FF 48 89 8D 00 FF FF FF 4C 89 85 F8 FE FF FF 4C 89 8D F0 FE FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 E8 31 C0 48 83 BD 08 FF FF FF 00 0F 84 9E 00 00 00

https://github.com/nss-dev/nss/blob/75f5643187e6e5bed774267f48c8057a3b21b82c/lib/ssl/tls13con.c#L62


PRF libsoftokn3.so

[*] PRF-Function identified with label: TLS_PRF (TLS_PRF)
[*] PRF-Function signature: undefined TLS_PRF(void)
[*] String (Register RSI) used as 1th argument in function call at address: 0x00131980 (invoking TLS_PRF)
[*] Function offset (Ghidra): 0014F219 (0x0014F219)
[*] Function offset (IDA with base 0x0): 0004F219 (0x0004F219)
[*] Byte pattern for frida: F3 0F 1E FA 55 48 89 E5 48 83 EC 30 48 89 7D F8 48 89 75 F0 48 89 55 E8 48 89 4D E0 44 89 45 DC 48 8B 05 98 99 01 00 48 85 C0 75 10

[*] PRF-Function identified with label: TLS_P_HASH (TLS_P_hash)
[*] PRF-Function signature: undefined TLS_P_hash(void)
[*] String (Register RDX) used as 2th argument in function call at address: 0x0013194b (invoking TLS_P_HASH)
[*] Function offset (Ghidra): 0014F86A (0x0014F86A)
[*] Function offset (IDA with base 0x0): 0004F86A (0x0004F86A)
[*] Byte pattern for frida: F3 0F 1E FA 55 48 89 E5 48 83 EC 30 89 7D FC 48 89 75 F0 48 89 55 E8 48 89 4D E0 4C 89 45 D8 44 89 4D F8 48 8B 05 44 93 01 00 48 85 C0 75 10

*/