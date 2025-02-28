package org.bouncycastle.crypto.modes.gcm;

/* loaded from: classes2.dex */
public class BasicGCMExponentiator implements GCMExponentiator {

    /* renamed from: x */
    private long[] f804x;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMExponentiator
    public void exponentiateX(long j, byte[] bArr) {
        long[] oneAsLongs = GCMUtil.oneAsLongs();
        if (j <= 0) {
            GCMUtil.asBytes(oneAsLongs, bArr);
        }
        long[] jArr = new long[2];
        GCMUtil.copy(this.f804x, jArr);
        do {
            if ((1 & j) != 0) {
                GCMUtil.multiply(oneAsLongs, jArr);
            }
            GCMUtil.square(jArr, jArr);
            j >>>= 1;
        } while (j > 0);
        GCMUtil.asBytes(oneAsLongs, bArr);
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMExponentiator
    public void init(byte[] bArr) {
        this.f804x = GCMUtil.asLongs(bArr);
    }
}