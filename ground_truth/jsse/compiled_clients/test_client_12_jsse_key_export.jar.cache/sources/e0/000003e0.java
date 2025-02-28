package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/agreement/srp/SRP6VerifierGenerator.class */
public class SRP6VerifierGenerator {

    /* renamed from: N */
    protected BigInteger f129N;

    /* renamed from: g */
    protected BigInteger f130g;
    protected Digest digest;

    public void init(BigInteger bigInteger, BigInteger bigInteger2, Digest digest) {
        this.f129N = bigInteger;
        this.f130g = bigInteger2;
        this.digest = digest;
    }

    public void init(SRP6GroupParameters sRP6GroupParameters, Digest digest) {
        this.f129N = sRP6GroupParameters.getN();
        this.f130g = sRP6GroupParameters.getG();
        this.digest = digest;
    }

    public BigInteger generateVerifier(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        return this.f130g.modPow(SRP6Util.calculateX(this.digest, this.f129N, bArr, bArr2, bArr3), this.f129N);
    }
}