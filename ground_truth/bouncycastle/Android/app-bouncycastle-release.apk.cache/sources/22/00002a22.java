package org.bouncycastle.pqc.crypto.newhope;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class NHPublicKeyParameters extends AsymmetricKeyParameter {
    final byte[] pubData;

    public NHPublicKeyParameters(byte[] bArr) {
        super(false);
        this.pubData = Arrays.clone(bArr);
    }

    public byte[] getPubData() {
        return Arrays.clone(this.pubData);
    }
}