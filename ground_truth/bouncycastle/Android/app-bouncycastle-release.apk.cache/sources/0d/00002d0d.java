package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class CachedInformationType {
    public static final short cert = 1;
    public static final short cert_req = 2;

    public static String getName(short s) {
        return s != 1 ? s != 2 ? "UNKNOWN" : "cert_req" : "cert";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }
}