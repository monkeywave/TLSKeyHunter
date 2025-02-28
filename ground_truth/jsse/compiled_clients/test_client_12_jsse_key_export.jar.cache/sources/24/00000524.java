package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/gcm/Tables64kGCMMultiplier.class */
public class Tables64kGCMMultiplier implements GCMMultiplier {

    /* renamed from: H */
    private byte[] f491H;

    /* renamed from: T */
    private long[][][] f492T;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] bArr) {
        if (this.f492T == null) {
            this.f492T = new long[16][256][2];
        } else if (0 != GCMUtil.areEqual(this.f491H, bArr)) {
            return;
        }
        this.f491H = new byte[16];
        GCMUtil.copy(bArr, this.f491H);
        for (int i = 0; i < 16; i++) {
            long[][] jArr = this.f492T[i];
            if (i == 0) {
                GCMUtil.asLongs(this.f491H, jArr[1]);
                GCMUtil.multiplyP7(jArr[1], jArr[1]);
            } else {
                GCMUtil.multiplyP8(this.f492T[i - 1][1], jArr[1]);
            }
            for (int i2 = 2; i2 < 256; i2 += 2) {
                GCMUtil.divideP(jArr[i2 >> 1], jArr[i2]);
                GCMUtil.xor(jArr[i2], jArr[1], jArr[i2 + 1]);
            }
        }
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] bArr) {
        long[] jArr = this.f492T[15][bArr[15] & 255];
        long j = jArr[0];
        long j2 = jArr[1];
        for (int i = 14; i >= 0; i--) {
            long[] jArr2 = this.f492T[i][bArr[i] & 255];
            j ^= jArr2[0];
            j2 ^= jArr2[1];
        }
        Pack.longToBigEndian(j, bArr, 0);
        Pack.longToBigEndian(j2, bArr, 8);
    }
}