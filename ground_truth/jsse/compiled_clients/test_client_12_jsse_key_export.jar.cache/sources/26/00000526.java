package org.bouncycastle.crypto.modes.kgcm;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/kgcm/BasicKGCMMultiplier_128.class */
public class BasicKGCMMultiplier_128 implements KGCMMultiplier {

    /* renamed from: H */
    private final long[] f495H = new long[2];

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] jArr) {
        KGCMUtil_128.copy(jArr, this.f495H);
    }

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] jArr) {
        KGCMUtil_128.multiply(jArr, this.f495H, jArr);
    }
}