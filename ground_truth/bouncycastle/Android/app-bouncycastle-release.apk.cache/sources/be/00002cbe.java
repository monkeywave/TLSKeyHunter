package org.bouncycastle.pqc.legacy.crypto.qtesla;

/* loaded from: classes2.dex */
public class QTESLASecurityCategory {
    public static final int PROVABLY_SECURE_I = 5;
    public static final int PROVABLY_SECURE_III = 6;

    private QTESLASecurityCategory() {
    }

    public static String getName(int i) {
        if (i != 5) {
            if (i == 6) {
                return "qTESLA-p-III";
            }
            throw new IllegalArgumentException("unknown security category: " + i);
        }
        return "qTESLA-p-I";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getPrivateSize(int i) {
        if (i != 5) {
            if (i == 6) {
                return 12392;
            }
            throw new IllegalArgumentException("unknown security category: " + i);
        }
        return 5224;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getPublicSize(int i) {
        if (i != 5) {
            if (i == 6) {
                return 38432;
            }
            throw new IllegalArgumentException("unknown security category: " + i);
        }
        return 14880;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getSignatureSize(int i) {
        if (i != 5) {
            if (i == 6) {
                return 5664;
            }
            throw new IllegalArgumentException("unknown security category: " + i);
        }
        return 2592;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void validate(int i) {
        if (i != 5 && i != 6) {
            throw new IllegalArgumentException("unknown security category: " + i);
        }
    }
}