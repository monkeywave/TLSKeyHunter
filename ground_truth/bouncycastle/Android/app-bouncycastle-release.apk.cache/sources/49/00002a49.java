package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class SNTRUPrimePublicKeyParameters extends SNTRUPrimeKeyParameters {
    private final byte[] encH;

    public SNTRUPrimePublicKeyParameters(SNTRUPrimeParameters sNTRUPrimeParameters, byte[] bArr) {
        super(false, sNTRUPrimeParameters);
        this.encH = Arrays.clone(bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getEncH() {
        return this.encH;
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.encH);
    }
}