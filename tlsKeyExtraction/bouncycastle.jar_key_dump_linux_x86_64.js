/*
Invoke

frida -p $(frida-ps | grep -i boring | awk '{print $1}') -l universal_key_dump_liunx_x86_64.js

on mac
frida $(ps -A | grep "java -jar test_clie" | tail -n 1 | awk '{print $1}') -l bouncycastle.jar_key_dump_linux_x86_64.js

on linux
frida $(ps -aux | grep -i java | head -n 1 | awk '{print $2}') -l TLSKeyHunterResearch/frida-scripte/bouncycastle.jar_key_dump_linux_x86_64.js

*/

// Constants for parsing
const SSL3_RANDOM_SIZE = 32; // Assuming SSL3_RANDOM_SIZE is 32 bytes
const SSL_MAX_MD_SIZE = 48;  // Assuming SSL_MAX_MD_SIZE is 64 bytes

// Dynamic offsets based on architecture
const is64Bit = Process.arch === 'x64';

const boringSSL_Handshake_struct = is64Bit
    ? {
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



// Utility function to convert byte array to hex
function byteArrayToHex(byteArray) {
    if (!byteArray) return null;
    const array = new Uint8Array(byteArray);
    return Array.from(array)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
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


function bytesToHex(bytes) {
    var hexArray = "0123456789ABCDEF";
    var hexChars = [];
    for (var j = 0; j < bytes.length; j++) {
        var v = bytes[j] & 0xFF;
        hexChars.push(hexArray[v >>> 4]);
        hexChars.push(hexArray[v & 0x0F]);
    }
    return hexChars.join('');
}

// Main function
function main() {
    setImmediate(function () {
        Java.perform(function () {


            var HashMap = Java.use('java.util.HashMap');
            var visited = HashMap.$new();

            function deepCopy(original) {
                console.log("Deep copy started...")
                // Handle null objects
                if (original === null) {
                    return null;
                }

                try{
                // Handle primitive types and immutables
                if (isPrimitiveOrImmutable(original)) {
                    return original;
                }
            }catch(prime_e){
                console.log("isPrimitiveOrImmutable: "+prime_e)
            }

                // Handle arrays
                try{
                if (Java.arrayType(original.getClass()) !== null) {
                    return copyArray(original);
                } }catch(prime_ar){
                    console.log("copyArray: "+prime_ar)
                }

                // Handle collections
                try{
                if (original.getClass().getName().startsWith('java.util.')) {
                    return copyCollection(original);
                } }catch(prime_ar){
                    console.log("copyCollection: "+prime_ar)
                }

                try{

                // Use Serializable if supported
                if (isSerializable(original)) {
                    return copyUsingSerialization(original);
                } }catch(prime_ar){
                    console.log("isSerializable: "+prime_ar)
                }

                // Reflection-based deep copy
                console.log("using copyUsingReflection");
                return copyUsingReflection(original);
            }

            function isPrimitiveOrImmutable(obj) {
                return (
                    typeof obj === 'number' ||
                    typeof obj === 'string' ||
                    typeof obj === 'boolean' ||
                    obj.getClass().isPrimitive() ||
                    obj.getClass().getName().startsWith('java.lang.')
                );
            }

            function copyArray(array) {
                var length = array.length;
                var newArray = Java.array(array.getClass().getComponentType(), length);
                for (var i = 0; i < length; i++) {
                    newArray[i] = deepCopy(array[i]);
                }
                return newArray;
            }

            function copyCollection(collection) {
                var newCollection = collection.getClass().newInstance();
                var iterator = collection.iterator();
                while (iterator.hasNext()) {
                    newCollection.add(deepCopy(iterator.next()));
                }
                return newCollection;
            }

            function isSerializable(obj) {
                var Serializable = Java.use('java.io.Serializable');
                return Serializable.class.isInstance(obj);
            }

            function copyUsingSerialization(obj) {
                try {
                    var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
                    var ObjectOutputStream = Java.use('java.io.ObjectOutputStream');
                    var ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
                    var ObjectInputStream = Java.use('java.io.ObjectInputStream');

                    var byteOut = ByteArrayOutputStream.$new();
                    var objOut = ObjectOutputStream.$new(byteOut);
                    objOut.writeObject(obj);
                    objOut.close();

                    var byteIn = ByteArrayInputStream.$new(byteOut.toByteArray());
                    var objIn = ObjectInputStream.$new(byteIn);
                    return objIn.readObject();
                } catch (e) {
                    console.log('Serialization copy failed:', e.message);
                    return null;
                }
            }

            function copyUsingReflection(original) {
                console.log("copyUsingReflection invoked");
                try{
                if (visited.containsKey(original)) {
                    return visited.get(original);
                }}catch(e_h){
                    console.log("visited.containsKey"+e_h);
                }
                console.log("!using copyUsingReflection now getClass");

                var clone = original.getClass().newInstance();
                console.log("clone created");
                visited.put(original, clone);

                var fields = original.getClass().getDeclaredFields();
                console.log("using getDeclaredFields");
                fields.forEach(function (field) {
                    field.setAccessible(true);
                    try {
                        var fieldValue = field.get(original);
                        var fieldCopy = deepCopy(fieldValue);
                        field.set(clone, fieldCopy);
                    } catch (e) {
                        console.log('Failed to copy field:', field.getName(), e.message);
                    }
                });

                return clone;
            }


            var TargetClass = Java.use("org.bouncycastle.tls.TlsUtils");
            var deepCopiedInstance;
            var deepCopiedInstance_HKDF;





            function hookBouncyCastlePRF() {


                

                // Hook the deriveSecret method
                TargetClass.PRF.overload(
                    "org.bouncycastle.tls.SecurityParameters",
                    "org.bouncycastle.tls.crypto.TlsSecret",
                    "java.lang.String",
                    "[B",
                    "int"
                ).implementation = function (securityParams, tlsSecret, label, data, i) {
                    //console.log("[*] PRF called!");
                    var result = this.PRF(securityParams, tlsSecret, label, data, i);

                    try {
                        if (label.toString().includes("client finished")) {
                            // with Java.retain we do a deep copy of the Java object
                            deepCopiedInstance = Java.retain(securityParams);
                        } 

                        if (label.toString().includes("server finished")) {
                            console.log("CLIENT_RANDOM" + " "+ bytesToHex(deepCopiedInstance.getClientRandom())+ " " +bytesToHex(deepCopiedInstance.getMasterSecret().extract()));
                        }


                    } catch (e) {
                        console.log(e);

                    }

                    return result;
                };



            }


            function hookBouncyCastleHKDF() {

                // Hook the deriveSecret method
                TargetClass.deriveSecret.overload(
                    "org.bouncycastle.tls.SecurityParameters",
                    "org.bouncycastle.tls.crypto.TlsSecret",
                    "java.lang.String",
                    "[B"
                ).implementation = function (securityParams, tlsSecret, label, data) {
                    console.log("[*] deriveSecret called!");
                    var result = this.deriveSecret(securityParams, tlsSecret, label, data);

                    var tls_label = getTLSLabel(label);

                    try {
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

                        }


                    } catch (e) {
                        console.log(e);

                    }

                    return result;
                };


            }


        
            hookBouncyCastlePRF();
            hookBouncyCastleHKDF();


        });

    });

    
    //Java.perform(function() {
    //findBouncyCastleModule()
    //hookBouncyCastelHKDF();
    //hookBouncyCastelPRF();
    //});
}

// Run the main function
main();


/*
Some good intro Cronet and its QUIC support:
https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g/edit#heading=h.in8d8fe8u7v

In BoringSSL
https://github.com/google/boringssl/blob/5a94aff9aebcf9738c7bc464bc95fa4ac3a46ed7/ssl/tls13_enc.cc#L323


when I look into the code I can see that the derive_secret function is finally invoking the HKDF expand label funktion
https://github.com/google/boringssl/blob/5a94aff9aebcf9738c7bc464bc95fa4ac3a46ed7/ssl/tls13_enc.cc#L172

In GnuTLS
https://github.com/gnutls/gnutls/blob/97f1baf6a7ad4aa1ff3db6e8543d910219ef9a16/lib/constate.c#L412


derive_secret(hs, hs->client_traffic_secret_0(),
                     label_to_span(kTLS13LabelClientApplicationTraffic))

                     bzw.

                     derive_secret(hs, hs->client_handshake_secret(),
                     label_to_span(kTLS13LabelClientHandshakeTraffic))



***** PRF Research ****

Right now this script is only able to hook the HKDF which helps us only for TLS 1.3

For TLS 1.2 we need to hook the PRF 
master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random) [0..47]


static const char kMasterSecretLabel[] = "master secret";
auto label = MakeConstSpan(kMasterSecretLabel, sizeof(kMasterSecretLabel) - 1);
if (!tls1_prf(hs->transcript.Digest(), out, premaster, label,
                  ssl->s3->client_random, ssl->s3->server_random)
https://github.com/google/boringssl/blob/ee3f9468584b6607f944b885ad50db35a70daf8d/ssl/t1_enc.cc#L270

(this might help https://github.com/google/boringssl/blob/ee3f9468584b6607f944b885ad50db35a70daf8d/ssl/handshake.cc#L530)
*/