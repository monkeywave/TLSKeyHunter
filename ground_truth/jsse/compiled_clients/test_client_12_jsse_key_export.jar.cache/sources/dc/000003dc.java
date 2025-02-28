package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/agreement/srp/SRP6Client.class */
public class SRP6Client {

    /* renamed from: N */
    protected BigInteger f109N;

    /* renamed from: g */
    protected BigInteger f110g;

    /* renamed from: a */
    protected BigInteger f111a;

    /* renamed from: A */
    protected BigInteger f112A;

    /* renamed from: B */
    protected BigInteger f113B;

    /* renamed from: x */
    protected BigInteger f114x;

    /* renamed from: u */
    protected BigInteger f115u;

    /* renamed from: S */
    protected BigInteger f116S;

    /* renamed from: M1 */
    protected BigInteger f117M1;

    /* renamed from: M2 */
    protected BigInteger f118M2;
    protected BigInteger Key;
    protected Digest digest;
    protected SecureRandom random;

    public void init(BigInteger bigInteger, BigInteger bigInteger2, Digest digest, SecureRandom secureRandom) {
        this.f109N = bigInteger;
        this.f110g = bigInteger2;
        this.digest = digest;
        this.random = secureRandom;
    }

    public void init(SRP6GroupParameters sRP6GroupParameters, Digest digest, SecureRandom secureRandom) {
        init(sRP6GroupParameters.getN(), sRP6GroupParameters.getG(), digest, secureRandom);
    }

    public BigInteger generateClientCredentials(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        this.f114x = SRP6Util.calculateX(this.digest, this.f109N, bArr, bArr2, bArr3);
        this.f111a = selectPrivateValue();
        this.f112A = this.f110g.modPow(this.f111a, this.f109N);
        return this.f112A;
    }

    public BigInteger calculateSecret(BigInteger bigInteger) throws CryptoException {
        this.f113B = SRP6Util.validatePublicValue(this.f109N, bigInteger);
        this.f115u = SRP6Util.calculateU(this.digest, this.f109N, this.f112A, this.f113B);
        this.f116S = calculateS();
        return this.f116S;
    }

    protected BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.digest, this.f109N, this.f110g, this.random);
    }

    private BigInteger calculateS() {
        BigInteger calculateK = SRP6Util.calculateK(this.digest, this.f109N, this.f110g);
        return this.f113B.subtract(this.f110g.modPow(this.f114x, this.f109N).multiply(calculateK).mod(this.f109N)).mod(this.f109N).modPow(this.f115u.multiply(this.f114x).add(this.f111a), this.f109N);
    }

    public BigInteger calculateClientEvidenceMessage() throws CryptoException {
        if (this.f112A == null || this.f113B == null || this.f116S == null) {
            throw new CryptoException("Impossible to compute M1: some data are missing from the previous operations (A,B,S)");
        }
        this.f117M1 = SRP6Util.calculateM1(this.digest, this.f109N, this.f112A, this.f113B, this.f116S);
        return this.f117M1;
    }

    public boolean verifyServerEvidenceMessage(BigInteger bigInteger) throws CryptoException {
        if (this.f112A == null || this.f117M1 == null || this.f116S == null) {
            throw new CryptoException("Impossible to compute and verify M2: some data are missing from the previous operations (A,M1,S)");
        }
        if (SRP6Util.calculateM2(this.digest, this.f109N, this.f112A, this.f117M1, this.f116S).equals(bigInteger)) {
            this.f118M2 = bigInteger;
            return true;
        }
        return false;
    }

    public BigInteger calculateSessionKey() throws CryptoException {
        if (this.f116S == null || this.f117M1 == null || this.f118M2 == null) {
            throw new CryptoException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
        }
        this.Key = SRP6Util.calculateKey(this.digest, this.f109N, this.f116S);
        return this.Key;
    }
}