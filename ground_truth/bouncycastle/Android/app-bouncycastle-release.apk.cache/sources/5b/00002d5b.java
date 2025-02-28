package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class MACAlgorithm {
    public static final int _null = 0;
    public static final int hmac_md5 = 1;
    public static final int hmac_sha1 = 2;
    public static final int hmac_sha256 = 3;
    public static final int hmac_sha384 = 4;
    public static final int hmac_sha512 = 5;
    public static final int md5 = 1;
    public static final int sha = 2;

    public static String getName(int i) {
        return i != 0 ? i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "UNKNOWN" : "hmac_sha512" : "hmac_sha384" : "hmac_sha256" : "hmac_sha1" : "hmac_md5" : "null";
    }

    public static String getText(int i) {
        return getName(i) + "(" + i + ")";
    }

    public static boolean isHMAC(int i) {
        return i == 1 || i == 2 || i == 3 || i == 4 || i == 5;
    }
}