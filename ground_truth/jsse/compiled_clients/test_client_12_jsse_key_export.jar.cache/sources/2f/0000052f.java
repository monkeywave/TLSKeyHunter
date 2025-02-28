package org.bouncycastle.crypto.modes.kgcm;

import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/kgcm/Tables8kKGCMMultiplier_256.class */
public class Tables8kKGCMMultiplier_256 implements KGCMMultiplier {

    /* renamed from: T */
    private long[][] f500T;

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] jArr) {
        if (this.f500T == null) {
            this.f500T = new long[256][4];
        } else if (KGCMUtil_256.equal(jArr, this.f500T[1])) {
            return;
        }
        KGCMUtil_256.copy(jArr, this.f500T[1]);
        for (int i = 2; i < 256; i += 2) {
            KGCMUtil_256.multiplyX(this.f500T[i >> 1], this.f500T[i]);
            KGCMUtil_256.add(this.f500T[i], this.f500T[1], this.f500T[i + 1]);
        }
    }

    @Override // org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] jArr) {
        long[] jArr2 = new long[4];
        KGCMUtil_256.copy(this.f500T[((int) (jArr[3] >>> 56)) & GF2Field.MASK], jArr2);
        for (int i = 30; i >= 0; i--) {
            KGCMUtil_256.multiplyX8(jArr2, jArr2);
            KGCMUtil_256.add(this.f500T[((int) (jArr[i >>> 3] >>> ((i & 7) << 3))) & GF2Field.MASK], jArr2, jArr2);
        }
        KGCMUtil_256.copy(jArr2, jArr);
    }
}