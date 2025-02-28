package org.bouncycastle.crypto.modes.kgcm;

import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/kgcm/Tables16kKGCMMultiplier_512.class */
public class Tables16kKGCMMultiplier_512 implements KGCMMultiplier {

    /* renamed from: T */
    private long[][] f498T;

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] jArr) {
        if (this.f498T == null) {
            this.f498T = new long[256][8];
        } else if (KGCMUtil_512.equal(jArr, this.f498T[1])) {
            return;
        }
        KGCMUtil_512.copy(jArr, this.f498T[1]);
        for (int i = 2; i < 256; i += 2) {
            KGCMUtil_512.multiplyX(this.f498T[i >> 1], this.f498T[i]);
            KGCMUtil_512.add(this.f498T[i], this.f498T[1], this.f498T[i + 1]);
        }
    }

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] jArr) {
        long[] jArr2 = new long[8];
        KGCMUtil_512.copy(this.f498T[((int) (jArr[7] >>> 56)) & GF2Field.MASK], jArr2);
        for (int i = 62; i >= 0; i--) {
            KGCMUtil_512.multiplyX8(jArr2, jArr2);
            KGCMUtil_512.add(this.f498T[((int) (jArr[i >>> 3] >>> ((i & 7) << 3))) & GF2Field.MASK], jArr2, jArr2);
        }
        KGCMUtil_512.copy(jArr2, jArr);
    }
}