package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.DerivationParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/KDFParameters.class */
public class KDFParameters implements DerivationParameters {

    /* renamed from: iv */
    byte[] f554iv;
    byte[] shared;

    public KDFParameters(byte[] bArr, byte[] bArr2) {
        this.shared = bArr;
        this.f554iv = bArr2;
    }

    public byte[] getSharedSecret() {
        return this.shared;
    }

    public byte[] getIV() {
        return this.f554iv;
    }
}