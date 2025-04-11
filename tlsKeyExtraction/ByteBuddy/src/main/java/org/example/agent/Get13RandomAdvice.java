package org.example.agent;

import net.bytebuddy.asm.Advice;

public class Get13RandomAdvice {

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args) {
        String green = "\u001B[32m";
        String reset = "\u001B[0m";

        System.out.println("[Byte Buddy] entering method: " + methodName);
        byte[] client_random_bytes = (byte[]) args[3];

        // Convert to Hex
        String hexKey;
        StringBuilder hexString = new StringBuilder();
        for (byte b : client_random_bytes) {
            hexString.append(String.format("%02X", b));
        }
        hexKey = hexString.toString();

        System.out.println(green + "[Byte Buddy] CLIENT_RANDOM " + hexKey + reset);
    }

}
