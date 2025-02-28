package org.bouncycastle.crypto.modes.gcm;

import java.lang.reflect.Array;
import kotlin.UByte;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class Tables8kGCMMultiplier implements GCMMultiplier {

    /* renamed from: H */
    private byte[] f811H;

    /* renamed from: T */
    private long[][][] f812T;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] bArr) {
        if (this.f812T == null) {
            this.f812T = (long[][][]) Array.newInstance(Long.TYPE, 2, 256, 2);
        } else if (GCMUtil.areEqual(this.f811H, bArr) != 0) {
            return;
        }
        byte[] bArr2 = new byte[16];
        this.f811H = bArr2;
        GCMUtil.copy(bArr, bArr2);
        for (int i = 0; i < 2; i++) {
            long[][][] jArr = this.f812T;
            long[][] jArr2 = jArr[i];
            if (i == 0) {
                GCMUtil.asLongs(this.f811H, jArr2[1]);
                long[] jArr3 = jArr2[1];
                GCMUtil.multiplyP7(jArr3, jArr3);
            } else {
                GCMUtil.multiplyP8(jArr[i - 1][1], jArr2[1]);
            }
            for (int i2 = 2; i2 < 256; i2 += 2) {
                GCMUtil.divideP(jArr2[i2 >> 1], jArr2[i2]);
                GCMUtil.xor(jArr2[i2], jArr2[1], jArr2[i2 + 1]);
            }
        }
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] bArr) {
        long[][][] jArr = this.f812T;
        long[][] jArr2 = jArr[0];
        long[][] jArr3 = jArr[1];
        long[] jArr4 = jArr2[bArr[14] & UByte.MAX_VALUE];
        long[] jArr5 = jArr3[bArr[15] & UByte.MAX_VALUE];
        long j = jArr4[0] ^ jArr5[0];
        long j2 = jArr5[1] ^ jArr4[1];
        for (int i = 12; i >= 0; i -= 2) {
            long[] jArr6 = jArr2[bArr[i] & UByte.MAX_VALUE];
            long[] jArr7 = jArr3[bArr[i + 1] & UByte.MAX_VALUE];
            long j3 = j2 << 48;
            j2 = (jArr6[1] ^ jArr7[1]) ^ ((j2 >>> 16) | (j << 48));
            j = (((((j >>> 16) ^ (jArr6[0] ^ jArr7[0])) ^ j3) ^ (j3 >>> 1)) ^ (j3 >>> 2)) ^ (j3 >>> 7);
        }
        Pack.longToBigEndian(j, bArr, 0);
        Pack.longToBigEndian(j2, bArr, 8);
    }
}