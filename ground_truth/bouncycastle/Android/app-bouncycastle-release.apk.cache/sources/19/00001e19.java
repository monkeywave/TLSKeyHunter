package org.bouncycastle.crypto.modes.gcm;

/* loaded from: classes2.dex */
public class BasicGCMMultiplier implements GCMMultiplier {

    /* renamed from: H */
    private long[] f805H;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] bArr) {
        this.f805H = GCMUtil.asLongs(bArr);
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] bArr) {
        GCMUtil.multiply(bArr, this.f805H);
    }
}