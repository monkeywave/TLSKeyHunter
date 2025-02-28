package org.bouncycastle.crypto.modes.gcm;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/gcm/BasicGCMExponentiator.class */
public class BasicGCMExponentiator implements GCMExponentiator {

    /* renamed from: x */
    private long[] f486x;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMExponentiator
    public void init(byte[] bArr) {
        this.f486x = GCMUtil.asLongs(bArr);
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMExponentiator
    public void exponentiateX(long j, byte[] bArr) {
        long[] oneAsLongs = GCMUtil.oneAsLongs();
        if (j <= 0) {
            GCMUtil.asBytes(oneAsLongs, bArr);
        }
        long[] jArr = new long[2];
        GCMUtil.copy(this.f486x, jArr);
        do {
            if ((j & 1) != 0) {
                GCMUtil.multiply(oneAsLongs, jArr);
            }
            GCMUtil.square(jArr, jArr);
            j >>>= 1;
        } while (j > 0);
        GCMUtil.asBytes(oneAsLongs, bArr);
    }
}