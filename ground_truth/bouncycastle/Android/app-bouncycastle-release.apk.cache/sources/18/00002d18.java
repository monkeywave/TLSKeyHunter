package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class CertificateType {
    public static final short OpenPGP = 1;
    public static final short RawPublicKey = 2;
    public static final short X509 = 0;

    public static boolean isValid(short s) {
        return s >= 0 && s <= 2;
    }
}