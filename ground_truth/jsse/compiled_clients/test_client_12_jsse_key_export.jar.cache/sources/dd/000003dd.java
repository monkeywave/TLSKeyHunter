package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/agreement/srp/SRP6Server.class */
public class SRP6Server {

    /* renamed from: N */
    protected BigInteger f119N;

    /* renamed from: g */
    protected BigInteger f120g;

    /* renamed from: v */
    protected BigInteger f121v;
    protected SecureRandom random;
    protected Digest digest;

    /* renamed from: A */
    protected BigInteger f122A;

    /* renamed from: b */
    protected BigInteger f123b;

    /* renamed from: B */
    protected BigInteger f124B;

    /* renamed from: u */
    protected BigInteger f125u;

    /* renamed from: S */
    protected BigInteger f126S;

    /* renamed from: M1 */
    protected BigInteger f127M1;

    /* renamed from: M2 */
    protected BigInteger f128M2;
    protected BigInteger Key;

    public void init(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, Digest digest, SecureRandom secureRandom) {
        this.f119N = bigInteger;
        this.f120g = bigInteger2;
        this.f121v = bigInteger3;
        this.random = secureRandom;
        this.digest = digest;
    }

    public void init(SRP6GroupParameters sRP6GroupParameters, BigInteger bigInteger, Digest digest, SecureRandom secureRandom) {
        init(sRP6GroupParameters.getN(), sRP6GroupParameters.getG(), bigInteger, digest, secureRandom);
    }

    public BigInteger generateServerCredentials() {
        BigInteger calculateK = SRP6Util.calculateK(this.digest, this.f119N, this.f120g);
        this.f123b = selectPrivateValue();
        this.f124B = calculateK.multiply(this.f121v).mod(this.f119N).add(this.f120g.modPow(this.f123b, this.f119N)).mod(this.f119N);
        return this.f124B;
    }

    public BigInteger calculateSecret(BigInteger bigInteger) throws CryptoException {
        this.f122A = SRP6Util.validatePublicValue(this.f119N, bigInteger);
        this.f125u = SRP6Util.calculateU(this.digest, this.f119N, this.f122A, this.f124B);
        this.f126S = calculateS();
        return this.f126S;
    }

    protected BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.digest, this.f119N, this.f120g, this.random);
    }

    private BigInteger calculateS() {
        return this.f121v.modPow(this.f125u, this.f119N).multiply(this.f122A).mod(this.f119N).modPow(this.f123b, this.f119N);
    }

    public boolean verifyClientEvidenceMessage(BigInteger bigInteger) throws CryptoException {
        if (this.f122A == null || this.f124B == null || this.f126S == null) {
            throw new CryptoException("Impossible to compute and verify M1: some data are missing from the previous operations (A,B,S)");
        }
        if (SRP6Util.calculateM1(this.digest, this.f119N, this.f122A, this.f124B, this.f126S).equals(bigInteger)) {
            this.f127M1 = bigInteger;
            return true;
        }
        return false;
    }

    public BigInteger calculateServerEvidenceMessage() throws CryptoException {
        if (this.f122A == null || this.f127M1 == null || this.f126S == null) {
            throw new CryptoException("Impossible to compute M2: some data are missing from the previous operations (A,M1,S)");
        }
        this.f128M2 = SRP6Util.calculateM2(this.digest, this.f119N, this.f122A, this.f127M1, this.f126S);
        return this.f128M2;
    }

    public BigInteger calculateSessionKey() throws CryptoException {
        if (this.f126S == null || this.f127M1 == null || this.f128M2 == null) {
            throw new CryptoException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
        }
        this.Key = SRP6Util.calculateKey(this.digest, this.f119N, this.f126S);
        return this.Key;
    }
}