package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ParametersWithID.class */
public class ParametersWithID implements CipherParameters {
    private CipherParameters parameters;

    /* renamed from: id */
    private byte[] f557id;

    public ParametersWithID(CipherParameters cipherParameters, byte[] bArr) {
        this.parameters = cipherParameters;
        this.f557id = bArr;
    }

    public byte[] getID() {
        return this.f557id;
    }

    public CipherParameters getParameters() {
        return this.parameters;
    }
}