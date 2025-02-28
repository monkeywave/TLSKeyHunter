package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

/* loaded from: classes2.dex */
public class MLDSAParameters {
    public static final int TYPE_PURE = 0;
    public static final int TYPE_SHA2_512 = 1;

    /* renamed from: k */
    private final int f1341k;
    private final String name;
    private final int preHashDigest;
    public static final MLDSAParameters ml_dsa_44 = new MLDSAParameters("ml-dsa-44", 2, 0);
    public static final MLDSAParameters ml_dsa_65 = new MLDSAParameters("ml-dsa-65", 3, 0);
    public static final MLDSAParameters ml_dsa_87 = new MLDSAParameters("ml-dsa-87", 5, 0);
    public static final MLDSAParameters ml_dsa_44_with_sha512 = new MLDSAParameters("ml-dsa-44-with-sha512", 2, 1);
    public static final MLDSAParameters ml_dsa_65_with_sha512 = new MLDSAParameters("ml-dsa-65-with-sha512", 3, 1);
    public static final MLDSAParameters ml_dsa_87_with_sha512 = new MLDSAParameters("ml-dsa-87-with-sha512", 5, 1);

    private MLDSAParameters(String str, int i, int i2) {
        this.name = str;
        this.f1341k = i;
        this.preHashDigest = i2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MLDSAEngine getEngine(SecureRandom secureRandom) {
        return new MLDSAEngine(this.f1341k, secureRandom);
    }

    public String getName() {
        return this.name;
    }

    public int getType() {
        return this.preHashDigest;
    }

    public boolean isPreHash() {
        return this.preHashDigest != 0;
    }
}