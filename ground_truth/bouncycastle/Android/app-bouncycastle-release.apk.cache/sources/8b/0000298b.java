package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class FalconPublicKeyParameters extends FalconKeyParameters {

    /* renamed from: H */
    private byte[] f1238H;

    public FalconPublicKeyParameters(FalconParameters falconParameters, byte[] bArr) {
        super(false, falconParameters);
        this.f1238H = Arrays.clone(bArr);
    }

    public byte[] getH() {
        return Arrays.clone(this.f1238H);
    }
}