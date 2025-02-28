package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;

/* loaded from: classes2.dex */
public class SRP6VerifierGenerator {

    /* renamed from: N */
    protected BigInteger f373N;
    protected Digest digest;

    /* renamed from: g */
    protected BigInteger f374g;

    public BigInteger generateVerifier(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        return this.f374g.modPow(SRP6Util.calculateX(this.digest, this.f373N, bArr, bArr2, bArr3), this.f373N);
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, Digest digest) {
        this.f373N = bigInteger;
        this.f374g = bigInteger2;
        this.digest = digest;
    }

    public void init(SRP6GroupParameters sRP6GroupParameters, Digest digest) {
        this.f373N = sRP6GroupParameters.getN();
        this.f374g = sRP6GroupParameters.getG();
        this.digest = digest;
    }
}