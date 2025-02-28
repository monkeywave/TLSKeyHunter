package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class CertificateCompressionAlgorithm {
    public static final int brotli = 2;
    public static final int zlib = 1;
    public static final int zstd = 3;

    public static String getName(int i) {
        return i != 1 ? i != 2 ? i != 3 ? "UNKNOWN" : "zstd" : "brotli" : "zlib";
    }

    public static String getText(int i) {
        return getName(i) + "(" + i + ")";
    }

    public static boolean isRecognized(int i) {
        return i == 1 || i == 2 || i == 3;
    }
}