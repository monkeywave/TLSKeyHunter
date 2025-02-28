package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/gcm/Tables4kGCMMultiplier.class */
public class Tables4kGCMMultiplier implements GCMMultiplier {

    /* renamed from: H */
    private byte[] f489H;

    /* renamed from: T */
    private long[][] f490T;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] bArr) {
        if (this.f490T == null) {
            this.f490T = new long[256][2];
        } else if (0 != GCMUtil.areEqual(this.f489H, bArr)) {
            return;
        }
        this.f489H = new byte[16];
        GCMUtil.copy(bArr, this.f489H);
        GCMUtil.asLongs(this.f489H, this.f490T[1]);
        GCMUtil.multiplyP7(this.f490T[1], this.f490T[1]);
        for (int i = 2; i < 256; i += 2) {
            GCMUtil.divideP(this.f490T[i >> 1], this.f490T[i]);
            GCMUtil.xor(this.f490T[i], this.f490T[1], this.f490T[i + 1]);
        }
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] bArr) {
        long[] jArr = this.f490T[bArr[15] & 255];
        long j = jArr[0];
        long j2 = jArr[1];
        for (int i = 14; i >= 0; i--) {
            long[] jArr2 = this.f490T[bArr[i] & 255];
            long j3 = j2 << 56;
            j2 = jArr2[1] ^ ((j2 >>> 8) | (j << 56));
            j = ((((jArr2[0] ^ (j >>> 8)) ^ j3) ^ (j3 >>> 1)) ^ (j3 >>> 2)) ^ (j3 >>> 7);
        }
        Pack.longToBigEndian(j, bArr, 0);
        Pack.longToBigEndian(j2, bArr, 8);
    }
}