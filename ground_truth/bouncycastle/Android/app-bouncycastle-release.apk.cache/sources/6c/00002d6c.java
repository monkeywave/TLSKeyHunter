package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class PskKeyExchangeMode {
    public static final short psk_dhe_ke = 1;
    public static final short psk_ke = 0;

    public static String getName(short s) {
        return s != 0 ? s != 1 ? "UNKNOWN" : "psk_dhe_ke" : "psk_ke";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }
}