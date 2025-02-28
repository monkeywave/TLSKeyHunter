package org.bouncycastle.crypto.modes.kgcm;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/kgcm/BasicKGCMMultiplier_512.class */
public class BasicKGCMMultiplier_512 implements KGCMMultiplier {

    /* renamed from: H */
    private final long[] f497H = new long[8];

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] jArr) {
        KGCMUtil_512.copy(jArr, this.f497H);
    }

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] jArr) {
        KGCMUtil_512.multiply(jArr, this.f497H, jArr);
    }
}