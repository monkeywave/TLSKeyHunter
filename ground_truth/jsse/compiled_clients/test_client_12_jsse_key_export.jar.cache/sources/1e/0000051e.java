package org.bouncycastle.crypto.modes.gcm;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/gcm/BasicGCMMultiplier.class */
public class BasicGCMMultiplier implements GCMMultiplier {

    /* renamed from: H */
    private long[] f487H;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] bArr) {
        this.f487H = GCMUtil.asLongs(bArr);
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] bArr) {
        long[] asLongs = GCMUtil.asLongs(bArr);
        GCMUtil.multiply(asLongs, this.f487H);
        GCMUtil.asBytes(asLongs, bArr);
    }
}