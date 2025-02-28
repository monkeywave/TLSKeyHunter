package org.bouncycastle.crypto.modes.kgcm;

import java.lang.reflect.Array;

/* loaded from: classes2.dex */
public class Tables4kKGCMMultiplier_128 implements KGCMMultiplier {

    /* renamed from: T */
    private long[][] f817T;

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] jArr) {
        long[][] jArr2 = this.f817T;
        if (jArr2 == null) {
            this.f817T = (long[][]) Array.newInstance(Long.TYPE, 256, 2);
        } else if (KGCMUtil_128.equal(jArr, jArr2[1])) {
            return;
        }
        KGCMUtil_128.copy(jArr, this.f817T[1]);
        for (int i = 2; i < 256; i += 2) {
            long[][] jArr3 = this.f817T;
            KGCMUtil_128.multiplyX(jArr3[i >> 1], jArr3[i]);
            long[][] jArr4 = this.f817T;
            KGCMUtil_128.add(jArr4[i], jArr4[1], jArr4[i + 1]);
        }
    }

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] jArr) {
        long[] jArr2 = new long[2];
        KGCMUtil_128.copy(this.f817T[((int) (jArr[1] >>> 56)) & 255], jArr2);
        for (int i = 14; i >= 0; i--) {
            KGCMUtil_128.multiplyX8(jArr2, jArr2);
            KGCMUtil_128.add(this.f817T[((int) (jArr[i >>> 3] >>> ((i & 7) << 3))) & 255], jArr2, jArr2);
        }
        KGCMUtil_128.copy(jArr2, jArr);
    }
}