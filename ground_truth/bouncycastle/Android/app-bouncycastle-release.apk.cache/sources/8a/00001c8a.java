package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;

/* loaded from: classes2.dex */
public class SRP6Client {

    /* renamed from: A */
    protected BigInteger f353A;

    /* renamed from: B */
    protected BigInteger f354B;
    protected BigInteger Key;

    /* renamed from: M1 */
    protected BigInteger f355M1;

    /* renamed from: M2 */
    protected BigInteger f356M2;

    /* renamed from: N */
    protected BigInteger f357N;

    /* renamed from: S */
    protected BigInteger f358S;

    /* renamed from: a */
    protected BigInteger f359a;
    protected Digest digest;

    /* renamed from: g */
    protected BigInteger f360g;
    protected SecureRandom random;

    /* renamed from: u */
    protected BigInteger f361u;

    /* renamed from: x */
    protected BigInteger f362x;

    private BigInteger calculateS() {
        BigInteger calculateK = SRP6Util.calculateK(this.digest, this.f357N, this.f360g);
        return this.f354B.subtract(this.f360g.modPow(this.f362x, this.f357N).multiply(calculateK).mod(this.f357N)).mod(this.f357N).modPow(this.f361u.multiply(this.f362x).add(this.f359a), this.f357N);
    }

    public BigInteger calculateClientEvidenceMessage() throws CryptoException {
        BigInteger bigInteger;
        BigInteger bigInteger2;
        BigInteger bigInteger3 = this.f353A;
        if (bigInteger3 == null || (bigInteger = this.f354B) == null || (bigInteger2 = this.f358S) == null) {
            throw new CryptoException("Impossible to compute M1: some data are missing from the previous operations (A,B,S)");
        }
        BigInteger calculateM1 = SRP6Util.calculateM1(this.digest, this.f357N, bigInteger3, bigInteger, bigInteger2);
        this.f355M1 = calculateM1;
        return calculateM1;
    }

    public BigInteger calculateSecret(BigInteger bigInteger) throws CryptoException {
        BigInteger validatePublicValue = SRP6Util.validatePublicValue(this.f357N, bigInteger);
        this.f354B = validatePublicValue;
        this.f361u = SRP6Util.calculateU(this.digest, this.f357N, this.f353A, validatePublicValue);
        BigInteger calculateS = calculateS();
        this.f358S = calculateS;
        return calculateS;
    }

    public BigInteger calculateSessionKey() throws CryptoException {
        BigInteger bigInteger = this.f358S;
        if (bigInteger == null || this.f355M1 == null || this.f356M2 == null) {
            throw new CryptoException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
        }
        BigInteger calculateKey = SRP6Util.calculateKey(this.digest, this.f357N, bigInteger);
        this.Key = calculateKey;
        return calculateKey;
    }

    public BigInteger generateClientCredentials(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        this.f362x = SRP6Util.calculateX(this.digest, this.f357N, bArr, bArr2, bArr3);
        BigInteger selectPrivateValue = selectPrivateValue();
        this.f359a = selectPrivateValue;
        BigInteger modPow = this.f360g.modPow(selectPrivateValue, this.f357N);
        this.f353A = modPow;
        return modPow;
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, Digest digest, SecureRandom secureRandom) {
        this.f357N = bigInteger;
        this.f360g = bigInteger2;
        this.digest = digest;
        this.random = secureRandom;
    }

    public void init(SRP6GroupParameters sRP6GroupParameters, Digest digest, SecureRandom secureRandom) {
        init(sRP6GroupParameters.getN(), sRP6GroupParameters.getG(), digest, secureRandom);
    }

    protected BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.digest, this.f357N, this.f360g, this.random);
    }

    public boolean verifyServerEvidenceMessage(BigInteger bigInteger) throws CryptoException {
        BigInteger bigInteger2;
        BigInteger bigInteger3;
        BigInteger bigInteger4 = this.f353A;
        if (bigInteger4 == null || (bigInteger2 = this.f355M1) == null || (bigInteger3 = this.f358S) == null) {
            throw new CryptoException("Impossible to compute and verify M2: some data are missing from the previous operations (A,M1,S)");
        }
        if (SRP6Util.calculateM2(this.digest, this.f357N, bigInteger4, bigInteger2, bigInteger3).equals(bigInteger)) {
            this.f356M2 = bigInteger;
            return true;
        }
        return false;
    }
}