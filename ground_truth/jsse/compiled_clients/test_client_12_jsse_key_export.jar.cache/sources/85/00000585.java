package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ParametersWithSBox.class */
public class ParametersWithSBox implements CipherParameters {
    private CipherParameters parameters;
    private byte[] sBox;

    public ParametersWithSBox(CipherParameters cipherParameters, byte[] bArr) {
        this.parameters = cipherParameters;
        this.sBox = bArr;
    }

    public byte[] getSBox() {
        return this.sBox;
    }

    public CipherParameters getParameters() {
        return this.parameters;
    }
}