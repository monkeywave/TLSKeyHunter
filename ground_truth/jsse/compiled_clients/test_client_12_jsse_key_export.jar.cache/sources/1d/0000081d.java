package org.bouncycastle.jcajce.provider.asymmetric.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/util/PrimeCertaintyCalculator.class */
public class PrimeCertaintyCalculator {
    private PrimeCertaintyCalculator() {
    }

    public static int getDefaultCertainty(int i) {
        if (i <= 1024) {
            return 80;
        }
        return 96 + (16 * ((i - 1) / 1024));
    }
}