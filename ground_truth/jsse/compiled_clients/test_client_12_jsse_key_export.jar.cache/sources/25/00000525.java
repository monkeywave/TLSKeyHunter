package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/gcm/Tables8kGCMMultiplier.class */
public class Tables8kGCMMultiplier implements GCMMultiplier {

    /* renamed from: H */
    private byte[] f493H;

    /* renamed from: T */
    private long[][][] f494T;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] bArr) {
        if (this.f494T == null) {
            this.f494T = new long[32][16][2];
        } else if (0 != GCMUtil.areEqual(this.f493H, bArr)) {
            return;
        }
        this.f493H = new byte[16];
        GCMUtil.copy(bArr, this.f493H);
        for (int i = 0; i < 32; i++) {
            long[][] jArr = this.f494T[i];
            if (i == 0) {
                GCMUtil.asLongs(this.f493H, jArr[1]);
                GCMUtil.multiplyP3(jArr[1], jArr[1]);
            } else {
                GCMUtil.multiplyP4(this.f494T[i - 1][1], jArr[1]);
            }
            for (int i2 = 2; i2 < 16; i2 += 2) {
                GCMUtil.divideP(jArr[i2 >> 1], jArr[i2]);
                GCMUtil.xor(jArr[i2], jArr[1], jArr[i2 + 1]);
            }
        }
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] bArr) {
        long j = 0;
        long j2 = 0;
        for (int i = 15; i >= 0; i--) {
            long[] jArr = this.f494T[i + i + 1][bArr[i] & 15];
            long[] jArr2 = this.f494T[i + i][(bArr[i] & 240) >>> 4];
            j ^= jArr[0] ^ jArr2[0];
            j2 ^= jArr[1] ^ jArr2[1];
        }
        Pack.longToBigEndian(j, bArr, 0);
        Pack.longToBigEndian(j2, bArr, 8);
    }
}