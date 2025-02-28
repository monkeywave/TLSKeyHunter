package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class CertChainType {
    public static final short individual_certs = 0;
    public static final short pkipath = 1;

    public static String getName(short s) {
        return s != 0 ? s != 1 ? "UNKNOWN" : "pkipath" : "individual_certs";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }

    public static boolean isValid(short s) {
        return s >= 0 && s <= 1;
    }
}