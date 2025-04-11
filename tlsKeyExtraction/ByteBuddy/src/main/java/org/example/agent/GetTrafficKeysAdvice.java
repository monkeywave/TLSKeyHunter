package org.example.agent;

import net.bytebuddy.asm.Advice;

import javax.crypto.SecretKey;
import java.util.HashMap;

import java.lang.reflect.Field;

public class GetTrafficKeysAdvice {
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args) {
        String green = "\u001B[32m";
        String reset = "\u001B[0m";

        System.out.println("[Byte Buddy] entering method: " + methodName);

        Object client_context = args[0];
        // Get the random using reflection
        try {
            Class<?> hs_context = client_context.getClass().getSuperclass();

            Field randomField = hs_context.getDeclaredField("clientHelloRandom");
            randomField.setAccessible(true);
            Object random = randomField.get(client_context);

            Field randomBytesField = random.getClass().getDeclaredField("randomBytes");
            randomBytesField.setAccessible(true);
            byte[] randomBytes = (byte[]) randomBytesField.get(random);

            String randomString;
            StringBuilder hexRandom = new StringBuilder();
            for (byte b : randomBytes) {
                hexRandom.append(String.format("%02x", b));
            }
            randomString = hexRandom.toString();

            // get the secrets
            SecretKey secretKey = (SecretKey) args[1];
            byte[] keyBytes = secretKey.getEncoded();

            // Convert to Hex
            String hexKey;
            StringBuilder hexString = new StringBuilder();
            for (byte b : keyBytes) {
                hexString.append(String.format("%02X", b));
            }
            hexKey = hexString.toString();

            HashMap<String, String> map = new HashMap<>();
            map.put("TlsServerHandshakeTrafficSecret", "SERVER_HANDSHAKE_TRAFFIC_SECRET");
            map.put("TlsClientHandshakeTrafficSecret", "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
            map.put("TlsServerAppTrafficSecret", "SERVER_TRAFFIC_SECRET_0");
            map.put("TlsClientAppTrafficSecret", "CLIENT_TRAFFIC_SECRET_0");

            System.out.println(green + "[Byte Buddy] " + map.get(secretKey.getAlgorithm()) + " " + randomString  + " " + hexKey + reset);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
