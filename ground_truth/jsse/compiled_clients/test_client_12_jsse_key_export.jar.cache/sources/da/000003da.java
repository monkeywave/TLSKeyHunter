package org.bouncycastle.crypto.agreement.kdf;

import org.bouncycastle.crypto.DerivationParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/agreement/kdf/GSKKDFParameters.class */
public class GSKKDFParameters implements DerivationParameters {

    /* renamed from: z */
    private final byte[] f106z;
    private final int startCounter;
    private final byte[] nonce;

    public GSKKDFParameters(byte[] bArr, int i) {
        this(bArr, i, null);
    }

    public GSKKDFParameters(byte[] bArr, int i, byte[] bArr2) {
        this.f106z = bArr;
        this.startCounter = i;
        this.nonce = bArr2;
    }

    public byte[] getZ() {
        return this.f106z;
    }

    public int getStartCounter() {
        return this.startCounter;
    }

    public byte[] getNonce() {
        return this.nonce;
    }
}