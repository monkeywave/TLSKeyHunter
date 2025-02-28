var session_client_random = "";


function hookOpenSSLByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;

    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    // First pattern to try
    var arch = Process.arch;
    console.log("[*] Start hooking on arch: "+arch)


    // hooking this result into a suspending state of openssl client
    var pattern_mb_derive_secret = "41 57 4D 89 CF 41 56 41 89 CE 41 55 4D 89 C5 41 54 49 89 D4 55 48 89 FD 48 89 F7 53 48 89 F3 48 83 EC 08 E8";
                  
    // Select the appropriate patterns based on the architecture
    //var pattern_mb_derive_secret =  "F3 0F 1E FA 48 89 B7 D8 03 00 00 C3"; //set_ctx
    console.log("[*] Using HKDF pattern: "+pattern_mb_derive_secret)

    // Try first pattern and if it fails, try the second one
    hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern_mb_derive_secret, "derive_secret");
    //var pattern_prf = "41 57 41 56 41 55 49 89 D5 41 54 49 89 F4 55 53 48 89 FB 48 81 EC B8 01 00 00 48 8B 84 24 F8 01 00 00 48 89 0C 24 4C 89 44 24 08 4C 8B BC 24 08 02 00 00 48 89 44 24 18 48 8B 84 24 18 02 00 00 4C 89 4C 24 10 48 89 44 24 20 64 48 8B 04 25 28 00 00 00 48 89 84 24 A8 01 00 00 31 C0 E8 CE 31 F9 FF";
    var pattern_prf = "41 57 41 56 41 55 49 89 D5 41 54 49 89 F4 55 53 48 89 FB 48 81 EC B8 01 00 00 48 8B 84 24 F8 01 00 00 48 89 0C 24 4C 89 44 24 08 4C 8B BC 24 08 02 00 00 48 89 44 24 18 48 8B 84 24 18 02 00 00 4C 89 4C 24 10 48 89 44 24 20 64 48 8B 04 25 28 00 00 00 48 89 84 24 A8 01 00 00 31 C0 E8 CE 64 FE FF";
    hook_PRF_By_Pattern(moduleBase, moduleSize, pattern_prf, "pattern_prf_secret");
}


function hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                
                                this.sc = args[0]; // --> ptr to SSL_Connection struct
                                this.key = args[9]; // when init its zero and only when returning it is filled with the key value
                                this.label = args[7]; // ptr to the label string

                                /*
                                if(!this.label.isNull()){
                                     var mylabel = this.label.readCString();
                                     console.log("[!] Label: "+mylabel);

                                }*/


                               
                                // Initialize an empty array to store arguments
                                /*
                                if(did_check == false){
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                }*/
                                


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
                                                    dumpMemory(arg, 0x180); // Optional: Dump memory at argument address
                                                    console.log("Start checking arguments....");
                                                    check_arguments(arg, i);
                                                } else {
                                                    console.log('Argument ' + i + ' is null or invalid onLeave.');
                                                }
                                            }
                                        } catch (e) {
                                            console.log('[!] Error in onLeave: ' + e.message);
                                            did_check = false;
                                        }

                                        console.log("------------ Leave part end ---------");

                                        did_check = false;

                                    }  */


                                    // working version for TLS 1.3
                                    // currently the EXPORTER_SECRET is not derived using this method
                                    /*
                                    In future release this func:
                                    https://github.com/openssl/openssl/blob/b049ce0e354011be075e620b9ba7cf4d7c8f9577/ssl/tls13_enc.c#L689
                                    the exporter is directly derived using the tls13_hkdf_expand

                                    In the next paper it should improved so that if we identify the string used for traffc secrets result into
                                    the same function as one used for the exporter secret
                                    */
                                    if(session_client_random.length < 2){
                                        session_client_random = get_client_random_from_ssl_connection(this.label, this.sc);
                                    }
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
                                
                                
                                
                                
                                
                                if(is_arg_key_exp(args[1])){
                                    this.client_random_ptr = args[5];
                                    this.key = args[9];
                                    this.key_length = args[10].toInt32();
                                    this.dump_keys = true;
                                }

                                /* 
                                if(did_check == false){
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                    this.dump_keys = true;
                                }
                                /*  */


                            },
                            onLeave: function(retval) {
                

                                if (!retval.isNull() && this.dump_keys) {
                                    //dump_keys_from_prf(this.client_random_ptr, this.key, this.key_length);
                                    this.dump_keys = false;

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
                                                    dumpMemory(arg, 0x180);
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

                                    } */
                               
                                
                                }
                            }
                        });
                    }
                });
} 




// Find the CoreTLS module
function findCoreTLSModule() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("libssl") ) {
            console.log("Found CoreTLS Module: " + name);
            return modules[i];
        }
    }
    console.log("CoreTLS module not found.");
    return null;
}


// test_client_13_coretls_key_export
// Main function
function main() {
    var module = findCoreTLSModule();
    if (module !== null) {
        hookCoreTLSByPattern(module);
    }
}

// Run the main function
main();


/*
CoreTLS is deprecated and not OpenSource but


-- PRF --

Here we can see the usage of the "master secret" label in the function:

https://github.com/darlinghq/darling-coretls/blob/b61a4f075726e7d5ef4652033f8d7b829c008d06/lib/tls1Callouts.c#L382


tls_handshake_internal_prf(ctx,
            ctx->preMasterSecret.data,
            ctx->preMasterSecret.length,
            (const unsigned char *)PLS_MASTER_SECRET,
            PLS_MASTER_SECRET_LEN,
            randBuf,
            2 * SSL_CLIENT_SRVR_RAND_SIZE,
            ctx->masterSecret,		// destination
            SSL_MASTER_SECRET_SIZE);



randBuf is the concatination of CLIENT_RANDOM and SERVER_RANDOM


--- HKDF ---
 There is no HKDF as CoreTLS supports only up to TLS 1.2


*/