package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/ExchangePair.class */
public class ExchangePair {
    private final AsymmetricKeyParameter publicKey;
    private final byte[] shared;

    public ExchangePair(AsymmetricKeyParameter asymmetricKeyParameter, byte[] bArr) {
        this.publicKey = asymmetricKeyParameter;
        this.shared = Arrays.clone(bArr);
    }

    public AsymmetricKeyParameter getPublicKey() {
        return this.publicKey;
    }

    public byte[] getSharedValue() {
        return Arrays.clone(this.shared);
    }
}