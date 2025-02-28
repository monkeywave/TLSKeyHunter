package org.bouncycastle.tls.crypto.impl.jcajce.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.TlsHash;

/* loaded from: classes2.dex */
public class SRP6Client {

    /* renamed from: A */
    protected BigInteger f1558A;

    /* renamed from: B */
    protected BigInteger f1559B;
    protected BigInteger Key;

    /* renamed from: M1 */
    protected BigInteger f1560M1;

    /* renamed from: M2 */
    protected BigInteger f1561M2;

    /* renamed from: N */
    protected BigInteger f1562N;

    /* renamed from: S */
    protected BigInteger f1563S;

    /* renamed from: a */
    protected BigInteger f1564a;
    protected TlsHash digest;

    /* renamed from: g */
    protected BigInteger f1565g;
    protected SecureRandom random;

    /* renamed from: u */
    protected BigInteger f1566u;

    /* renamed from: x */
    protected BigInteger f1567x;

    private BigInteger calculateS() {
        BigInteger calculateK = SRP6Util.calculateK(this.digest, this.f1562N, this.f1565g);
        return this.f1559B.subtract(this.f1565g.modPow(this.f1567x, this.f1562N).multiply(calculateK).mod(this.f1562N)).mod(this.f1562N).modPow(this.f1566u.multiply(this.f1567x).add(this.f1564a), this.f1562N);
    }

    public BigInteger calculateClientEvidenceMessage() throws IllegalStateException {
        BigInteger bigInteger;
        BigInteger bigInteger2;
        BigInteger bigInteger3 = this.f1558A;
        if (bigInteger3 == null || (bigInteger = this.f1559B) == null || (bigInteger2 = this.f1563S) == null) {
            throw new IllegalStateException("Impossible to compute M1: some data are missing from the previous operations (A,B,S)");
        }
        BigInteger calculateM1 = SRP6Util.calculateM1(this.digest, this.f1562N, bigInteger3, bigInteger, bigInteger2);
        this.f1560M1 = calculateM1;
        return calculateM1;
    }

    public BigInteger calculateSecret(BigInteger bigInteger) {
        BigInteger validatePublicValue = SRP6Util.validatePublicValue(this.f1562N, bigInteger);
        this.f1559B = validatePublicValue;
        this.f1566u = SRP6Util.calculateU(this.digest, this.f1562N, this.f1558A, validatePublicValue);
        BigInteger calculateS = calculateS();
        this.f1563S = calculateS;
        return calculateS;
    }

    public BigInteger calculateSessionKey() throws IllegalStateException {
        BigInteger bigInteger = this.f1563S;
        if (bigInteger == null || this.f1560M1 == null || this.f1561M2 == null) {
            throw new IllegalStateException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
        }
        BigInteger calculateKey = SRP6Util.calculateKey(this.digest, this.f1562N, bigInteger);
        this.Key = calculateKey;
        return calculateKey;
    }

    public BigInteger generateClientCredentials(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        this.f1567x = SRP6Util.calculateX(this.digest, this.f1562N, bArr, bArr2, bArr3);
        BigInteger selectPrivateValue = selectPrivateValue();
        this.f1564a = selectPrivateValue;
        BigInteger modPow = this.f1565g.modPow(selectPrivateValue, this.f1562N);
        this.f1558A = modPow;
        return modPow;
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, TlsHash tlsHash, SecureRandom secureRandom) {
        this.f1562N = bigInteger;
        this.f1565g = bigInteger2;
        this.digest = tlsHash;
        this.random = secureRandom;
    }

    public void init(SRP6Group sRP6Group, TlsHash tlsHash, SecureRandom secureRandom) {
        init(sRP6Group.getN(), sRP6Group.getG(), tlsHash, secureRandom);
    }

    protected BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.f1562N, this.f1565g, this.random);
    }

    public boolean verifyServerEvidenceMessage(BigInteger bigInteger) throws IllegalStateException {
        BigInteger bigInteger2;
        BigInteger bigInteger3;
        BigInteger bigInteger4 = this.f1558A;
        if (bigInteger4 == null || (bigInteger2 = this.f1560M1) == null || (bigInteger3 = this.f1563S) == null) {
            throw new IllegalStateException("Impossible to compute and verify M2: some data are missing from the previous operations (A,M1,S)");
        }
        if (SRP6Util.calculateM2(this.digest, this.f1562N, bigInteger4, bigInteger2, bigInteger3).equals(bigInteger)) {
            this.f1561M2 = bigInteger;
            return true;
        }
        return false;
    }
}