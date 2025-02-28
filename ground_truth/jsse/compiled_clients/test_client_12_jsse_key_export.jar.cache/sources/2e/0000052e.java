package org.bouncycastle.crypto.modes.kgcm;

import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/kgcm/Tables4kKGCMMultiplier_128.class */
public class Tables4kKGCMMultiplier_128 implements KGCMMultiplier {

    /* renamed from: T */
    private long[][] f499T;

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] jArr) {
        if (this.f499T == null) {
            this.f499T = new long[256][2];
        } else if (KGCMUtil_128.equal(jArr, this.f499T[1])) {
            return;
        }
        KGCMUtil_128.copy(jArr, this.f499T[1]);
        for (int i = 2; i < 256; i += 2) {
            KGCMUtil_128.multiplyX(this.f499T[i >> 1], this.f499T[i]);
            KGCMUtil_128.add(this.f499T[i], this.f499T[1], this.f499T[i + 1]);
        }
    }

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] jArr) {
        long[] jArr2 = new long[2];
        KGCMUtil_128.copy(this.f499T[((int) (jArr[1] >>> 56)) & GF2Field.MASK], jArr2);
        for (int i = 14; i >= 0; i--) {
            KGCMUtil_128.multiplyX8(jArr2, jArr2);
            KGCMUtil_128.add(this.f499T[((int) (jArr[i >>> 3] >>> ((i & 7) << 3))) & GF2Field.MASK], jArr2, jArr2);
        }
        KGCMUtil_128.copy(jArr2, jArr);
    }
}