package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class HQCPrivateKeyParameters extends HQCKeyParameters {

    /* renamed from: sk */
    private byte[] f1313sk;

    public HQCPrivateKeyParameters(HQCParameters hQCParameters, byte[] bArr) {
        super(true, hQCParameters);
        this.f1313sk = Arrays.clone(bArr);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.f1313sk);
    }

    public byte[] getPrivateKey() {
        return Arrays.clone(this.f1313sk);
    }
}