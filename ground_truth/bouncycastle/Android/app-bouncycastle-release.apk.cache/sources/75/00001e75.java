package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.DerivationParameters;

/* loaded from: classes2.dex */
public class KDFParameters implements DerivationParameters {

    /* renamed from: iv */
    byte[] f872iv;
    byte[] shared;

    public KDFParameters(byte[] bArr, byte[] bArr2) {
        this.shared = bArr;
        this.f872iv = bArr2;
    }

    public byte[] getIV() {
        return this.f872iv;
    }

    public byte[] getSharedSecret() {
        return this.shared;
    }
}