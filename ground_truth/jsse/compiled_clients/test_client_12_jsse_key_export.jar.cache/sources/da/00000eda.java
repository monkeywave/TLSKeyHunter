package org.bouncycastle.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/Longs.class */
public class Longs {
    public static final int BYTES = 8;
    public static final int SIZE = 64;

    public static int numberOfLeadingZeros(long j) {
        return Long.numberOfLeadingZeros(j);
    }

    public static int numberOfTrailingZeros(long j) {
        return Long.numberOfTrailingZeros(j);
    }

    public static long reverse(long j) {
        return Long.reverse(j);
    }

    public static long reverseBytes(long j) {
        return Long.reverseBytes(j);
    }

    public static long rotateLeft(long j, int i) {
        return Long.rotateLeft(j, i);
    }

    public static long rotateRight(long j, int i) {
        return Long.rotateRight(j, i);
    }

    public static Long valueOf(long j) {
        return Long.valueOf(j);
    }
}