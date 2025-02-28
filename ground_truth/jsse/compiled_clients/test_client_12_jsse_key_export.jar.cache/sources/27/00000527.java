package org.bouncycastle.crypto.modes.kgcm;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/kgcm/BasicKGCMMultiplier_256.class */
public class BasicKGCMMultiplier_256 implements KGCMMultiplier {

    /* renamed from: H */
    private final long[] f496H = new long[4];

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] jArr) {
        KGCMUtil_256.copy(jArr, this.f496H);
    }

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] jArr) {
        KGCMUtil_256.multiply(jArr, this.f496H, jArr);
    }
}