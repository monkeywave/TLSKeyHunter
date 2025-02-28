package org.bouncycastle.tls.crypto.impl.jcajce.srp;

import java.math.BigInteger;
import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.TlsHash;

/* loaded from: classes2.dex */
public class SRP6VerifierGenerator {

    /* renamed from: N */
    protected BigInteger f1578N;
    protected TlsHash digest;

    /* renamed from: g */
    protected BigInteger f1579g;

    public BigInteger generateVerifier(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        return this.f1579g.modPow(SRP6Util.calculateX(this.digest, this.f1578N, bArr, bArr2, bArr3), this.f1578N);
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, TlsHash tlsHash) {
        this.f1578N = bigInteger;
        this.f1579g = bigInteger2;
        this.digest = tlsHash;
    }

    public void init(SRP6Group sRP6Group, TlsHash tlsHash) {
        this.f1578N = sRP6Group.getN();
        this.f1579g = sRP6Group.getG();
        this.digest = tlsHash;
    }
}