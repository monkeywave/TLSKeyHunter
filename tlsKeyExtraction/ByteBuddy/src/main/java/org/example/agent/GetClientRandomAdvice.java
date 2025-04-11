package org.example.agent;

import net.bytebuddy.asm.Advice;

import javax.crypto.SecretKey;
import java.util.Base64;

public class GetClientRandomAdvice {
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#m") String methodName) {
        System.out.println("[Byte Buddy] entering method: " + methodName);
    }

    @Advice .OnMethodExit (onThrowable = Throwable.class)
    public static void onExit(@Advice.Origin("#m") String methodName, @Advice.Return(readOnly = false) byte[] retval) {
        String green = "\u001B[32m";
        String reset = "\u001B[0m";

        // Convert to Base64
        String base64Key = Base64.getEncoder().encodeToString(retval);

        // Convert to Hex
        String hexKey;
        StringBuilder hexString = new StringBuilder();
        for (byte b : retval) {
            hexString.append(String.format("%02X", b));
        }
        hexKey = hexString.toString();

        System.out.println(green + "[Byte Buddy] CLIENT_RANDOM " + hexKey + reset);
    }
}
