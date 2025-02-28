package com.example.test_client_13_jsse_key_export;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.LoaderClassPath;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLSession;

/* loaded from: test_client_12_jsse_key_export.jar:com/example/test_client_13_jsse_key_export/MasterSecretLogger.class */
public class MasterSecretLogger {
    private static final Logger log = Logger.getLogger(MasterSecretLogger.class.getName());
    private static Map<String, String> TLS13_SECRET_NAMES = new HashMap();

    static {
        TLS13_SECRET_NAMES.put("TlsClientAppTrafficSecret", "CLIENT_TRAFFIC_SECRET_0");
        TLS13_SECRET_NAMES.put("TlsServerAppTrafficSecret", "SERVER_TRAFFIC_SECRET_0");
    }

    public static boolean installHooks() {
        try {
            ClassPool pool = ClassPool.getDefault();
            pool.appendClassPath(new LoaderClassPath(ClassLoader.getSystemClassLoader()));
            CtClass clazz = pool.get("sun.security.ssl.SSLTrafficKeyDerivation");
            CtMethod method = clazz.getDeclaredMethod("createKeyDerivation");
            method.insertAfter(MasterSecretLogger.class.getName() + ".logTrafficSecret($1, $2);");
            clazz.toClass();
            log.info("TLS hooks installed successfully.");
            return true;
        } catch (Exception e) {
            Throwable cause = e instanceof InvocationTargetException ? e.getCause() : e;
            log.severe("Failed to install TLS hooks: " + cause.getMessage());
            cause.printStackTrace();
            return false;
        }
    }

    public static void logTrafficSecret(Object context, SecretKey key) {
        String secretName = TLS13_SECRET_NAMES.get(key.getAlgorithm());
        if (secretName == null) {
            return;
        }
        try {
            SSLSession sSLSession = (SSLSession) getField(context, "handshakeSession");
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
            hex.append(String.format("%02X", Byte.valueOf(b)));
        }
        return hex.toString();
    }

    private static Object getField(Object obj, String fieldName) throws Exception {
        Class<?> cls = obj.getClass();
        while (true) {
            Class<?> clazz = cls;
            if (clazz != null) {
                try {
                    Field field = clazz.getDeclaredField(fieldName);
                    field.setAccessible(true);
                    return field.get(obj);
                } catch (NoSuchFieldException e) {
                    cls = clazz.getSuperclass();
                }
            } else {
                throw new NoSuchFieldException("Field " + fieldName + " not found in " + obj.getClass().getName());
            }
        }
    }
}