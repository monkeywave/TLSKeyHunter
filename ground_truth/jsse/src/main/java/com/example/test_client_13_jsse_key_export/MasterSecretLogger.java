package com.example.test_client_13_jsse_key_export;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.LoaderClassPath;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLSession;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class MasterSecretLogger {
    private static final Logger log = Logger.getLogger(MasterSecretLogger.class.getName());

    private static Map<String, String> TLS13_SECRET_NAMES = new HashMap<>();
    static {
        TLS13_SECRET_NAMES.put("TlsClientAppTrafficSecret", "CLIENT_TRAFFIC_SECRET_0");
        TLS13_SECRET_NAMES.put("TlsServerAppTrafficSecret", "SERVER_TRAFFIC_SECRET_0");
    }

    /**
     * Installs the hooks into the relevant TLS classes.
     */
    public static boolean installHooks() {
        try {
            ClassPool pool = ClassPool.getDefault();
            pool.appendClassPath(new LoaderClassPath(ClassLoader.getSystemClassLoader()));

            // Hook the SSLTrafficKeyDerivation class
            CtClass clazz = pool.get("sun.security.ssl.SSLTrafficKeyDerivation");
            CtMethod method = clazz.getDeclaredMethod("createKeyDerivation");
            method.insertAfter(MasterSecretLogger.class.getName() + ".logTrafficSecret($1, $2);");

            clazz.toClass(); // Apply the instrumentation
            log.info("TLS hooks installed successfully.");
            return true;
        } catch (Exception e) {
            Throwable cause = (e instanceof java.lang.reflect.InvocationTargetException) ? e.getCause() : e;
            log.severe("Failed to install TLS hooks: " + cause.getMessage());
            cause.printStackTrace();
            return false;
        }
    }

    /**
     * Logs traffic secrets when `createKeyDerivation` is called.
     *
     * @param context The handshake context
     * @param key     The derived secret key
     */
    public static void logTrafficSecret(Object context, SecretKey key) {
        String secretName = TLS13_SECRET_NAMES.get(key.getAlgorithm());
        if (secretName == null) {
            return; // Not a traffic secret we're interested in
        }

        try {
            SSLSession sslSession = (SSLSession) getField(context, "handshakeSession");
            byte[] clientRandom = (byte[]) getField(getField(context, "clientHelloRandom"), "randomBytes");

            String clientRandomHex = bytesToHex(clientRandom);
            String secretHex = bytesToHex(key.getEncoded());

            writeLog(secretName + " " + clientRandomHex + " " + secretHex);
        } catch (Exception e) {
            log.warning("Failed to log traffic secret: " + e.getMessage());
        }
    }

    private static void writeLog(String logEntry) {
        System.out.println(logEntry);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    private static Object getField(Object obj, String fieldName) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException("Field " + fieldName + " not found in " + obj.getClass().getName());
    }
}