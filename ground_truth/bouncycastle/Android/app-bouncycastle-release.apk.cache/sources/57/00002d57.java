package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class IdentifierType {
    public static final short cert_sha1_hash = 3;
    public static final short key_sha1_hash = 1;
    public static final short pre_agreed = 0;
    public static final short x509_name = 2;

    public static String getName(short s) {
        return s != 0 ? s != 1 ? s != 2 ? s != 3 ? "UNKNOWN" : "cert_sha1_hash" : "x509_name" : "key_sha1_hash" : "pre_agreed";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }
}