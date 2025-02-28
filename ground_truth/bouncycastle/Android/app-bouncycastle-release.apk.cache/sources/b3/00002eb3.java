package org.bouncycastle.util.test;

/* loaded from: classes2.dex */
public final class NumberParsing {
    private NumberParsing() {
    }

    public static int decodeIntFromHex(String str) {
        return (str.charAt(1) == 'x' || str.charAt(1) == 'X') ? Integer.parseInt(str.substring(2), 16) : Integer.parseInt(str, 16);
    }

    public static long decodeLongFromHex(String str) {
        return (str.charAt(1) == 'x' || str.charAt(1) == 'X') ? Long.parseLong(str.substring(2), 16) : Long.parseLong(str, 16);
    }
}