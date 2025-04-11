package org.example.agent;

import net.bytebuddy.asm.Advice;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.util.Base64;

public class GetMasterSecretAdvice {
    @Advice .OnMethodEnter
    public static void onEnter(@Advice.Origin("#m") String methodName) {
        System.out.println("[Byte Buddy] entering method: " + methodName);
    }

    @Advice .OnMethodExit (onThrowable = Throwable.class)
    public static void onExit(@Advice.Origin("#m") String methodName, @Advice.Return(readOnly = false) SecretKey retval) {
        String green = "\u001B[32m";
        String reset = "\u001B[0m";

        byte[] keyBytes = retval.getEncoded();

        // Convert to Hex
        String hexKey;
        StringBuilder hexString = new StringBuilder();
        for (byte b : keyBytes) {
            hexString.append(String.format("%02X", b));
        }
        hexKey = hexString.toString();

        System.out.println(green + "[Byte Buddy] MASTER_SECRET " + hexKey + reset);
    }
}
