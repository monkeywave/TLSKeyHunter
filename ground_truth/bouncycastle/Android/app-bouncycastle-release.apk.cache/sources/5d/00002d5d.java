package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class NameType {
    public static final short host_name = 0;

    public static String getName(short s) {
        return s != 0 ? "UNKNOWN" : "host_name";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }

    public static boolean isRecognized(short s) {
        return s == 0;
    }

    public static boolean isValid(short s) {
        return TlsUtils.isValidUint8(s);
    }
}