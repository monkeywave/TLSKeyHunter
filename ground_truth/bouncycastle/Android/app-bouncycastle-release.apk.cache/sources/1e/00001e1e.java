package org.bouncycastle.crypto.modes.gcm;

import java.lang.reflect.Array;
import kotlin.UByte;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class Tables4kGCMMultiplier implements GCMMultiplier {

    /* renamed from: H */
    private byte[] f807H;

    /* renamed from: T */
    private long[][] f808T;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] bArr) {
        if (this.f808T == null) {
            this.f808T = (long[][]) Array.newInstance(Long.TYPE, 256, 2);
        } else if (GCMUtil.areEqual(this.f807H, bArr) != 0) {
            return;
        }
        byte[] bArr2 = new byte[16];
        this.f807H = bArr2;
        GCMUtil.copy(bArr, bArr2);
        GCMUtil.asLongs(this.f807H, this.f808T[1]);
        long[] jArr = this.f808T[1];
        GCMUtil.multiplyP7(jArr, jArr);
        for (int i = 2; i < 256; i += 2) {
            long[][] jArr2 = this.f808T;
            GCMUtil.divideP(jArr2[i >> 1], jArr2[i]);
            long[][] jArr3 = this.f808T;
            GCMUtil.xor(jArr3[i], jArr3[1], jArr3[i + 1]);
        }
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] bArr) {
        long[] jArr = this.f808T[bArr[15] & UByte.MAX_VALUE];
        long j = jArr[0];
        long j2 = jArr[1];
        for (int i = 14; i >= 0; i--) {
            long[] jArr2 = this.f808T[bArr[i] & UByte.MAX_VALUE];
            long j3 = j2 << 56;
            j2 = ((j2 >>> 8) | (j << 56)) ^ jArr2[1];
            j = (((((j >>> 8) ^ jArr2[0]) ^ j3) ^ (j3 >>> 1)) ^ (j3 >>> 2)) ^ (j3 >>> 7);
        }
        Pack.longToBigEndian(j, bArr, 0);
        Pack.longToBigEndian(j2, bArr, 8);
    }
}