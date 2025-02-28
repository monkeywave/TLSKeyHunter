package org.bouncycastle.tls;

import java.math.BigInteger;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class TlsSRPLoginParameters {
    protected byte[] identity;
    protected byte[] salt;
    protected TlsSRPConfig srpConfig;
    protected BigInteger verifier;

    public TlsSRPLoginParameters(byte[] bArr, TlsSRPConfig tlsSRPConfig, BigInteger bigInteger, byte[] bArr2) {
        this.identity = Arrays.clone(bArr);
        this.srpConfig = tlsSRPConfig;
        this.verifier = bigInteger;
        this.salt = Arrays.clone(bArr2);
    }

    public TlsSRPConfig getConfig() {
        return this.srpConfig;
    }

    public byte[] getIdentity() {
        return this.identity;
    }

    public byte[] getSalt() {
        return this.salt;
    }

    public BigInteger getVerifier() {
        return this.verifier;
    }
}