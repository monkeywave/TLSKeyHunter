package org.bouncycastle.pqc.crypto.newhope;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/newhope/Reduce.class */
class Reduce {
    static final int QInv = 12287;
    static final int RLog = 18;
    static final int RMask = 262143;

    Reduce() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short montgomery(int i) {
        return (short) (((((i * QInv) & RMask) * 12289) + i) >>> 18);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short barrett(short s) {
        int i = s & 65535;
        return (short) (i - (((i * 5) >>> 16) * 12289));
    }
}