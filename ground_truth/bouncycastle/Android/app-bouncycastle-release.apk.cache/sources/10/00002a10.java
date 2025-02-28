package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.pqc.crypto.KEMParameters;

/* loaded from: classes2.dex */
public class MLKEMParameters implements KEMParameters {

    /* renamed from: k */
    private final int f1350k;
    private final String name;
    private final int sessionKeySize;
    public static final MLKEMParameters ml_kem_512 = new MLKEMParameters("ML-KEM-512", 2, 256);
    public static final MLKEMParameters ml_kem_768 = new MLKEMParameters("ML-KEM-768", 3, 256);
    public static final MLKEMParameters ml_kem_1024 = new MLKEMParameters("ML-KEM-1024", 4, 256);

    private MLKEMParameters(String str, int i, int i2) {
        this.name = str;
        this.f1350k = i;
        this.sessionKeySize = i2;
    }

    public MLKEMEngine getEngine() {
        return new MLKEMEngine(this.f1350k);
    }

    public String getName() {
        return this.name;
    }

    public int getSessionKeySize() {
        return this.sessionKeySize;
    }
}