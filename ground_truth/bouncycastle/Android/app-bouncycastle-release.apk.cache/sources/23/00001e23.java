package org.bouncycastle.crypto.modes.kgcm;

/* loaded from: classes2.dex */
public class BasicKGCMMultiplier_512 implements KGCMMultiplier {

    /* renamed from: H */
    private final long[] f815H = new long[8];

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] jArr) {
        KGCMUtil_512.copy(jArr, this.f815H);
    }

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] jArr) {
        KGCMUtil_512.multiply(jArr, this.f815H, jArr);
    }
}