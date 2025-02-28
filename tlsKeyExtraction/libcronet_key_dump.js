var module_name_prefix = "libcronet";

var keylog_callback = new NativeCallback(function (ctxPtr, mes) {
    console.log(mes.readCString());
}, "void", ["pointer", "pointer"]);


function dumpMemory(ptrValue,size) {
    //var size = 0x100;
    try {
        var data = Memory.readByteArray(ptrValue, size);
        console.log(hexdump(data));
        // console.log(hexdump(data, { offset: 0, length: size, header: true, ansi: true }));
    } catch (error) {
        console.log("Error dumping memory at: " + ptrValue + " - " + error.message);
        console.log("\n")
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
            } else {
                console.log('Argument ' + i + ' is null or invalid.');
            }
        } catch (e) {
            console.log('Could not access argument ' + i + ': ' + e.message);
        }
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
    /* How to we identified the client_random while we build our parser
    console.log("CLIENT_RANDOM");
    var data = Memory.readByteArray(ssl_st_ptr, 0x40);
    console.log(hexdump(data));

    var s3_ptr = ssl_st_ptr.add(0x30).readPointer();
    console.log("Pointer to s3 struct at offset 0x30: " + s3_ptr);
    // Step 3: Check if the pointer is valid, then dump the memory at that location
    if (!s3_ptr.isNull()) {
        // Read the memory at the s3 pointer (e.g., 0x100 bytes, adjust as needed)
        var s3_data = Memory.readByteArray(s3_ptr, 0x100);  // Adjust size as needed
        console.log("s3 struct (first 0x100 bytes):");
        console.log(hexdump(s3_data));
    } else {
        console.log("[Error] s3 pointer is NULL");
    }*/
    var s3_ptr = ssl_st_ptr.add(0x30).readPointer();
    return get_client_random(s3_ptr,SSL3_RANDOM_SIZE);
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

// Pattern for mb_SSL_CTX_new
var pattern = "3F 23 03 D5 FF C3 00 D1 FD 7B 01 A9 F4 4F 02 A9 FD 43 00 91 E0 07 00 F9 40 07 00 B4 E0 23 00 91 62 08 00 94";

// Pattern for SSL_CTX_set_keylog_callback
var keylog_callback_pattern = "5F 24 03 D5 01 10 01 F9 C0 03 5F D6";

var pattern_mb_tls13_hkdf_expand_andere_variante = "3F 23 03 D5 FF 43 03 D1 FD 7B 07 A9 FB 43 00 F9 FA 67 09 A9 F8 5F 0A A9 F6 57 0B A9 F4 4F 0C A9 FD C3 01 91 F7 03 00 AA B9 33 40 F9 A0 C3 00 D1 F8 03 07 AA FA 03 06 AA FB 03 05 AA F3 03 04 AA F4 03 03 AA F5 03 02 AA F6 03 01 AA BF 0F 00 F9 FC 7F F7 97";

var pattern_mb_tls13_hkdf_expand = "3F 23 03 D5 FF 43 03 D1 FD 7B 08 A9 F9 4B 00 F9 F8 5F 0A A9 F6 57 0B A9 F4 4F 0C A9 FD 03 02 91 F7 03 00 AA A0 C3 00 D1 F5 03 04 AA F8 03 03 AA F4 03 02 AA F6 03 01 AA F3 03 08 AA 89 52 F5 97";


var pattern_mb_hkdf_Stuff_1 =  "3F 23 03 D5 FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 E8 03 06 AA E9 03 00 AA F3 03 01 AA A6 73 00 91 E0 03 02 AA E1 03 05 AA E2 03 08 AA E5 03 09 AA 8F 00 00 94 A0 00 00 B4";

var pattern_mb_global_hhkdf_setup_stuff1 = "";

var pattern_mb_cronet_ssl_key_expantion = "";

var pattern_mb_derive_secret = "3F 23 03 D5 FF C3 02 D1 FD 7B 06 A9 FA 67 07 A9 F8 5F 08 A9 F6 57 09 A9 F4 4F 0A A9 FD 83 01 91 59 D0 3B D5 F5 03 02 AA F6 03 01 AA 28 17 40 F9 F7 03 00 AA E1 63 00 91 E2 43 00 91 E0 03 03 AA F3 03 05 AA F4 03 04 AA F8 03 03 AA A8 83 1F F8 FA 63 00 91";

/*
True for libcronet.119.0.6045.31.so and libcronet.113.0.5672.61.so
*/
var pattern_mb_ssl_log_secret = "3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4";
//var pattern_mb_ssl_log_secret =   "3F 23 03 D5 FF ?? ?? D1 FD 7B 04 A9 F6 57 ?? A9 F4 4F ?? A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 ?? ?? ?? B4"
/*
Youtube-App findings: Found Cronet Module: libcronet.127.0.6510.5.so aber pattern wird nicht gefunden

var module = Process.findModuleByName('libcronet.127.0.6510.5.so');



var pattern = "3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9                 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4";
var pattern = "3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9   F7 2B 00 F9   F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 E8 0F 00 B4";
               3F 23 03 D5 FF ?3 0? D1 FD 7B 04 A9                 F6 57 0? A9 F4 4F 0? A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 ?8 0? 00 B4"



"3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4" // http3
"3F 23 03 D5 FF ?3 0? D1 FD 7B 04 A9 ?? ?? ?? ?? F6 57 0? A9 F4 4F 0? A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 ?8 0? 00 B4"; // youtube
"3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 E8 0F 00 B4" // youtube
*/

// Find the Cronet module
function findCronetModule() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("libcronet") && name.endsWith(".so")) {
            console.log("Found Cronet Module: " + name);
            return modules[i];
        }
    }
    console.log("Cronet module not found.");
    return null;
}

// Function to find a function in memory using a pattern
function findFunctionByPattern(pattern, callback, module) {
    Memory.scan(module.base, module.size, pattern, {
        onMatch: function(address) {
            console.log("Pattern found at: " + address);
            callback(address);
        },
        onComplete: function() {
            console.log("Memory scan complete.");
        }
    });  
}

// Function to install SSL keylog callback
function installSSLKeylogCallback(ssl_context_ptr, module) {
    console.log("Installing SSL_CTX_set_keylog_callback...");

    findFunctionByPattern(keylog_callback_pattern, function(keylog_callback_addr) {
        console.log("SSL_CTX_set_keylog_callback found at: " + keylog_callback_addr);

        // Ensure permissions to write to the SSL context memory region
        Memory.protect(ssl_context_ptr.add(544), Process.pointerSize, 'rw-');

        var SSL_CTX_set_keylog_callback_fn = new NativeFunction(keylog_callback_addr, 'void', ['pointer', 'pointer']);

        // Ensure SSL context pointer is valid
        console.log("The address of our ssl_context_ptr: " + ssl_context_ptr);
        if (ssl_context_ptr.isNull()) {
            console.log("Error: ssl_context_ptr is NULL! Cannot install callback.");
            return;
        }

        // Install keylog callback
        SSL_CTX_set_keylog_callback_fn(ssl_context_ptr, keylog_callback);
        console.log("Installed callback at address: " + ssl_context_ptr.add(544));

        // Dump memory for debugging purposes
        var ssl_memory = Memory.readByteArray(ssl_context_ptr, 0x300);
        console.log("Memory after installation:");
        console.log(hexdump(ssl_memory));
    }, module);
}

// Hooking by pattern
function hookByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;

    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    /*
    This is hooking the SSL_CTX_new function but somehow the hooks aren't applied

    Memory.scan(moduleBase, moduleSize, pattern, {
        onMatch: function(address, size) {
            console.log("Pattern found at: " + address);

            Interceptor.attach(address, {
                onEnter: function(args) {
                    console.log("SSL_CTX_new function called!");
                    this.para1=args[0];
                    //var ssl_ctx_ptr = args[0];
                    //console.log("Installing SSLKeylogCallback at address (onEnter): "+ssl_ctx_ptr);
                    //installSSLKeylogCallback(ssl_ctx_ptr, module);
                },
                onLeave: function(retval) {
                    var ssl_ctx_ptr = retval;
                    console.log("CTX address: " + ssl_ctx_ptr);
                    
                    // Check if SSL_CTX creation was successful
                    if (retval.isNull()) {
                        console.log("SSL_CTX creation failed, retval is NULL.");
                        return;
                    }
                    console.log("mb_SSL_CTX_new function returned!");

                    // Dump memory for debugging purposes
                    var ssl_memory = Memory.readByteArray(this.para1, 0x300);
                    console.log("SSL_CTX (from SSL_new):");
                    console.log(hexdump(ssl_memory));
                    
                    console.log("Installing SSLKeylogCallback at address (onLeave):: "+this.para1);
                    installSSLKeylogCallback(this.para1, module);
                }
            });
        },
        onComplete: function() {
            console.log("Memory scan complete!");
        }
    });

    */ 

    /* wird zwar aufgerufen, allerdings brauchen wir das hier nicht

    Memory.scan(moduleBase, moduleSize, pattern_mb_derive_secret, {
        onMatch: function(address, size) {
            console.log("Pattern found at (pattern_mb_derive_secret): " + address);

            Interceptor.attach(address, {
                onEnter: function(args) {
                    console.log("pattern_mb_derive_secret function called!");
                    //this.para1=args[0];
                    var maxArgs = 6;
                    dumpFunctionArguments(args, maxArgs);
                    
                    //var ssl_ctx_ptr = args[0];
                    //console.log("Installing SSLKeylogCallback at address (onEnter): "+ssl_ctx_ptr);
                    //installSSLKeylogCallback(ssl_ctx_ptr, module);
                    console.log("----------- end of pattern_mb_derive_secret ---");
                    console.log("\n\n\n");
                },
                onLeave: function(retval) {                
                    
                }
            });
        },
        onComplete: function() {
            
        }
    });
    */

    // pattern_mb_ssl_log_secret
    Memory.scan(moduleBase, moduleSize, pattern_mb_ssl_log_secret, {
        onMatch: function(address, size) {
            console.log("Pattern found at  (pattern_mb_ssl_log_secret): " + address);

            Interceptor.attach(address, {
                onEnter: function(args) {
                    //console.log("pattern_mb_ssl_log_secret function called!");
                    //this.paran1=args[0];

                    /*

                    This was done for the re process

                    var maxArgs = 6;
                    dumpFunctionArguments(args, maxArgs);*/

                    dump_keys(args[1],args[0],args[2]);

                    //console.log("----------- end of pattern_mb_ssl_log_secret ---");
                    //console.log("");
                },
                onLeave: function(retval) {                
                    
                }
            });
        },
        onComplete: function() {
            
        }
    });
}

// Main function
function main() {
    var module = findCronetModule();
    if (module !== null) {
        hookByPattern(module);
    }
}

// Run the main function
main();




/*
Here we have some notes on how we identified and build the pattern for the functions we want to hook

https://github.com/google/boringssl/blob/e724ef02089bf2bb494203231fc5cb62acc2fad6/ssl/tls13_enc.cc#L322

pattern_mb_ssl_log_secret

mb_ssl_log_secret

var_40= -0x40
var_30= -0x30
var_s0=  0
var_s10=  0x10
var_s20=  0x20

PACIASP
SUB             SP, SP, #0x70
STP             X29, X30, [SP,#0x40+var_s0]
STP             X22, X21, [SP,#0x40+var_s10]
STP             X20, X19, [SP,#0x40+var_s20]
ADD             X29, SP, #0x40
LDR             X8, [X0,#0x68]
LDR             X8, [X8,#0x220]
CBZ             X8, loc_374E54

Pattern: 3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4

Bytes:
FD 7B C4 A8 BF 23 03 D5  C0 03 5F D6 3F 23 03 D5
FF C3 01 D1 FD 7B 04 A9  F6 57 05 A9 F4 4F 06 A9
FD 03 01 91 08 34 40 F9  08 11 41 F9 C8 07 00 B4


For youtube App on device (libcronet 127)
mb_ssl_log_secret

var_60= -0x60
var_50= -0x50
var_20= -0x20
var_10= -0x10
var_8= -8
var_s0=  0
var_s10=  0x10


PACIASP
SUB             SP, SP, #0x80
STP             X29, X30, [SP,#0x60+var_20]
STR             X23, [SP,#0x60+var_10]
STP             X22, X21, [SP,#0x60+var_s0]
STP             X20, X19, [SP,#0x60+var_s10]
ADD             X29, SP, #0x40
LDR             X8, [X0,#0x68]
LDR             X8, [X8,#0x220]
CBZ             X8, loc_3E653

Pattern: 3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 E8 0F 00 B4

Bytes:
C0 03 5F D6 3F 23 03 D5  FF 03 02 D1 FD 7B 04 A9
F7 2B 00 F9 F6 57 06 A9  F4 4F 07 A9 FD 03 01 91
08 34 40 F9 08 11 41 F9  E8 0F 00 B4 F3 03 00 AA
E0 43 00 91 F4 03 03 AA  F5 03 02 AA F7 03 01 AA
A5 9D F5 97 E0 03 17 AA  FF 7F 00 A9 93 C2 05 94
96 FA 7F D3 C8 02 00 8B  E0 43 00 91 01 0D 01 91

------

; Attributes: bp-based frame

mb_derive_secret

var_60= -0x60
var_50= -0x50
var_48= -0x48
var_8= -8
var_s0=  0
var_s10=  0x10
var_s20=  0x20
var_s30=  0x30
var_s40=  0x40

PACIASP
SUB             SP, SP, #0xB0
STP             X29, X30, [SP,#0x60+var_s0]
STP             X26, X25, [SP,#0x60+var_s10]
STP             X24, X23, [SP,#0x60+var_s20]
STP             X22, X21, [SP,#0x60+var_s30]
STP             X20, X19, [SP,#0x60+var_s40]
ADD             X29, SP, #0x60
MRS             X25, #3, c13, c0, #2
MOV             X21, X2
MOV             X22, X1
LDR             X8, [X25,#0x28]
MOV             X23, X0
ADD             X1, SP, #0x60+var_48
ADD             X2, SP, #0x60+var_50
MOV             X0, X3
MOV             X19, X5
MOV             X20, X4
MOV             X24, X3
STUR            X8, [X29,#var_8]
ADD             X26, SP, #0x60+var_48
BL              sub_379C1C
TBZ             W0, #0, loc_37E34C

Pattern: 3F 23 03 D5 FF C3 02 D1 FD 7B 06 A9 FA 67 07 A9 F8 5F 08 A9 F6 57 09 A9 F4 4F 0A A9 FD 83 01 91 59 D0 3B D5 F5 03 02 AA F6 03 01 AA 28 17 40 F9 F7 03 00 AA E1 63 00 91 E2 43 00 91 E0 03 03 AA F3 03 05 AA F4 03 04 AA F8 03 03 AA A8 83 1F F8 FA 63 00 91

Bytes:
FD 7B C4 A8 BF 23 03 D5  C0 03 5F D6 3F 23 03 D5
FF C3 02 D1 FD 7B 06 A9  FA 67 07 A9 F8 5F 08 A9
F6 57 09 A9 F4 4F 0A A9  FD 83 01 91 59 D0 3B D5
F5 03 02 AA F6 03 01 AA  28 17 40 F9 F7 03 00 AA
E1 63 00 91 E2 43 00 91  E0 03 03 AA F3 03 05 AA
F4 03 04 AA F8 03 03 AA  A8 83 1F F8 FA 63 00 91
*/