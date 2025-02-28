package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;

/* loaded from: classes2.dex */
public class SRP6Server {

    /* renamed from: A */
    protected BigInteger f363A;

    /* renamed from: B */
    protected BigInteger f364B;
    protected BigInteger Key;

    /* renamed from: M1 */
    protected BigInteger f365M1;

    /* renamed from: M2 */
    protected BigInteger f366M2;

    /* renamed from: N */
    protected BigInteger f367N;

    /* renamed from: S */
    protected BigInteger f368S;

    /* renamed from: b */
    protected BigInteger f369b;
    protected Digest digest;

    /* renamed from: g */
    protected BigInteger f370g;
    protected SecureRandom random;

    /* renamed from: u */
    protected BigInteger f371u;

    /* renamed from: v */
    protected BigInteger f372v;

    private BigInteger calculateS() {
        return this.f372v.modPow(this.f371u, this.f367N).multiply(this.f363A).mod(this.f367N).modPow(this.f369b, this.f367N);
    }

    public BigInteger calculateSecret(BigInteger bigInteger) throws CryptoException {
        BigInteger validatePublicValue = SRP6Util.validatePublicValue(this.f367N, bigInteger);
        this.f363A = validatePublicValue;
        this.f371u = SRP6Util.calculateU(this.digest, this.f367N, validatePublicValue, this.f364B);
        BigInteger calculateS = calculateS();
        this.f368S = calculateS;
        return calculateS;
    }

    public BigInteger calculateServerEvidenceMessage() throws CryptoException {
        BigInteger bigInteger;
        BigInteger bigInteger2;
        BigInteger bigInteger3 = this.f363A;
        if (bigInteger3 == null || (bigInteger = this.f365M1) == null || (bigInteger2 = this.f368S) == null) {
            throw new CryptoException("Impossible to compute M2: some data are missing from the previous operations (A,M1,S)");
        }
        BigInteger calculateM2 = SRP6Util.calculateM2(this.digest, this.f367N, bigInteger3, bigInteger, bigInteger2);
        this.f366M2 = calculateM2;
        return calculateM2;
    }

    public BigInteger calculateSessionKey() throws CryptoException {
        BigInteger bigInteger = this.f368S;
        if (bigInteger == null || this.f365M1 == null || this.f366M2 == null) {
            throw new CryptoException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
        }
        BigInteger calculateKey = SRP6Util.calculateKey(this.digest, this.f367N, bigInteger);
        this.Key = calculateKey;
        return calculateKey;
    }

    public BigInteger generateServerCredentials() {
        BigInteger calculateK = SRP6Util.calculateK(this.digest, this.f367N, this.f370g);
        this.f369b = selectPrivateValue();
        BigInteger mod = calculateK.multiply(this.f372v).mod(this.f367N).add(this.f370g.modPow(this.f369b, this.f367N)).mod(this.f367N);
        this.f364B = mod;
        return mod;
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, Digest digest, SecureRandom secureRandom) {
        this.f367N = bigInteger;
        this.f370g = bigInteger2;
        this.f372v = bigInteger3;
        this.random = secureRandom;
        this.digest = digest;
    }

    public void init(SRP6GroupParameters sRP6GroupParameters, BigInteger bigInteger, Digest digest, SecureRandom secureRandom) {
        init(sRP6GroupParameters.getN(), sRP6GroupParameters.getG(), bigInteger, digest, secureRandom);
    }

    protected BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.digest, this.f367N, this.f370g, this.random);
    }

    public boolean verifyClientEvidenceMessage(BigInteger bigInteger) throws CryptoException {
        BigInteger bigInteger2;
        BigInteger bigInteger3;
        BigInteger bigInteger4 = this.f363A;
        if (bigInteger4 == null || (bigInteger2 = this.f364B) == null || (bigInteger3 = this.f368S) == null) {
            throw new CryptoException("Impossible to compute and verify M1: some data are missing from the previous operations (A,B,S)");
        }
        if (SRP6Util.calculateM1(this.digest, this.f367N, bigInteger4, bigInteger2, bigInteger3).equals(bigInteger)) {
            this.f365M1 = bigInteger;
            return true;
        }
        return false;
    }
}