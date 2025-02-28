/*
Invoke

frida -p $(frida-ps | grep -i test_client | awk '{print $1}') -l universal_key_dump_liunx_x86_64.js

*/


/*
Currently we have the problem, that JSSE is not provided on Android and frida ist not supporting the hooking of 
JVM invoked other than on Android, therefore we want to use the following approach in hooking it:

https://bytebuddy.net/#/
https://github.com/raphw/byte-buddy
https://github.com/SySS-Research/hallucinate/blob/main/java/src/main/java/gs/sy/m8/hallucinate/Agent.java


*/


var session_client_random = "";

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


// Main function
function main() {
    setImmediate(function () {
        Java.perform(function () {


            try {
            var TlsMasterSecretGenerator = Java.use('org.openjsse.com.sun.crypto.provider.TlsMasterSecretGenerator');
            var deepCopiedInstance;
            var deepCopiedInstance_HKDF;


            function hookJSSE_PRF() {

                // Hook the deriveSecret method
                TlsMasterSecretGenerator.doTLS12PRF.overload('[B', '[B', '[B', 'int', 'java.lang.String', 'int', 'int').implementation = function (premaster, label, seed, length, prf_has_algo, prf_hash_length, prf_block_size) {
                    //console.log("[*] PRF called!");
                    var result = this.doTLS12PRF(premaster, label, seed, length, prf_has_algo, prf_hash_length, prf_block_size);

                    
                    if(session_client_random.length < 2){
                        try{
                            var seed_length = seed.length;
                            var halfLength = Math.floor(seed_length / 2);
                            var client_random = Java.array('byte', Array.prototype.slice.call(seed, 0, halfLength));
                            session_client_random = client_random;
                        }catch(e){
                            console.log("[-] Error while getting the client random: "+e);
                        }
                    }
                        

                    try {
                        console.log("LAbel:" +label);
                        if (label.toString().includes("client finished")) {
                            // with Java.retain we do a deep copy of the Java object
                            //deepCopiedInstance = Java.retain(securityParams);
                        } 

                        if (label.toString().includes("server finished")) {
                            console.log("CLIENT_RANDOM_fin" + " "+ bytesToHex(session_client_random)+ " " +bytesToHex(result));
                        }else{
                            console.log("CLIENT_RANDOM" + " "+ bytesToHex(session_client_random)+ " " +bytesToHex(result));
                        }


                    } catch (e) {
                        console.log(e);

                    }

                    return result;
                };



            }
        }catch(prf_e){
            console.log("[-] Unable to find class TlsMasterSecretGenerator: "+prf_e);
        }

        try{
            // maybe for the Clien_RANdom the
            // https://github.com/openjsse/openjsse/blob/master/src/main/java/org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation.java#L121
            // constructor of T13TrafficKeyDerivation or SSLKeyDerivation createKeyDerivation( needs to be hooked

            var SSLKeyDerivation =  Java.use('org.openjsse.sun.security.ssl.SSLKeyDerivation');
        


            function hookJSSE_HKDF() {

                // Hook the deriveSecret method
                SSLKeyDerivation.deriveKey.overload(
                    "java.lang.String", 
                    "java.security.spec.AlgorithmParameterSpec"
                ).implementation = function (algorithm, params) {
                    console.log("[*] deriveSecret called!");
                    var result = this.deriveKey(algorithm, params);

                    //var tls_label = getTLSLabel(label);
                    var exporter_copy = Java.retain(result);
                    console.log('Algorithm:', algorithm);
                    console.log('AlgorithmParameterSpec:', params ? params.toString() : 'null');
                    //console.log(tls_label + " " + bytesToHex(session_client_random) + " " + bytesToHex(exporter_copy.getEncoded()));


                    try {
                        console.log(algorithm + " " + bytesToHex(session_client_random) + " " + bytesToHex(exporter_copy.getEncoded()));
                        /*
                        if (!label.toString().includes("derived")) {


                            if (tls_label.includes("CLIENT_HANDSHAKE")) {
                                //tls_secret = securityParams.trafficSecretClient;
                            } else if (tls_label.includes("SERVER_HANDSHAKE")) {
                                //tls_secret = securityParams.trafficSecretServer; 
                            } else if (tls_label.includes("CLIENT_TRAFFIC")) {
                                deepCopiedInstance_HKDF = Java.retain(securityParams);
                                session_client_random = deepCopiedInstance_HKDF.getClientRandom();
                                console.log("CLIENT_HANDSHAKE_TRAFFIC_SECRET" + " " + bytesToHex(session_client_random) + " " + bytesToHex(deepCopiedInstance_HKDF.getTrafficSecretClient().extract()));
                                console.log("SERVER_HANDSHAKE_TRAFFIC_SECRET" + " " + bytesToHex(session_client_random) + " " + bytesToHex(deepCopiedInstance_HKDF.getTrafficSecretServer().extract()));
                                //tls_secret = securityParams.trafficSecretClient; 
                            } else if (tls_label.includes("SERVER_TRAFFIC")) {
                                //tls_secret = securityParams.trafficSecretServer; 
                            } else if (tls_label.includes("EXPORTER")) {
                                deepCopiedInstance_HKDF = Java.retain(securityParams);
                                console.log("CLIENT_TRAFFIC_SECRET_0" + " " + bytesToHex(session_client_random) + " " + bytesToHex(deepCopiedInstance_HKDF.getTrafficSecretClient().extract()));
                                console.log("SERVER_TRAFFIC_SECRET_0" + " " + bytesToHex(session_client_random) + " " + bytesToHex(deepCopiedInstance_HKDF.getTrafficSecretServer().extract()));
                                var exporter_copy = Java.retain(result);
                                console.log(tls_label + " " + bytesToHex(session_client_random) + " " + bytesToHex(exporter_copy.extract()));
                            }

                        }*/


                    } catch (e) {
                        console.log(e);

                    }

                    return result;
                };


            }
        }catch(hkdf_e){
            console.log("[-] Unable to find class SSLKeyDerivation: "+hkdf_e);
        }


        
            hookJSSE_PRF();
            //hookJSSE_HKDF();


        });

    });


}


// Run the main function
main();


/*
https://github.com/openjsse/openjsse

https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html?utm_source=chatgpt.com


PRF: https://github.com/openjdk/jdk/blob/3a625f38aa4ab611fe5c7dffe420abce826d0d7e/src/java.base/share/classes/com/sun/crypto/provider/TlsMasterSecretGenerator.java#L123

*/