package org.bouncycastle.tls.crypto.impl.jcajce.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.TlsHash;

/* loaded from: classes2.dex */
public class SRP6Server {

    /* renamed from: A */
    protected BigInteger f1568A;

    /* renamed from: B */
    protected BigInteger f1569B;
    protected BigInteger Key;

    /* renamed from: M1 */
    protected BigInteger f1570M1;

    /* renamed from: M2 */
    protected BigInteger f1571M2;

    /* renamed from: N */
    protected BigInteger f1572N;

    /* renamed from: S */
    protected BigInteger f1573S;

    /* renamed from: b */
    protected BigInteger f1574b;
    protected TlsHash digest;

    /* renamed from: g */
    protected BigInteger f1575g;
    protected SecureRandom random;

    /* renamed from: u */
    protected BigInteger f1576u;

    /* renamed from: v */
    protected BigInteger f1577v;

    private BigInteger calculateS() {
        return this.f1577v.modPow(this.f1576u, this.f1572N).multiply(this.f1568A).mod(this.f1572N).modPow(this.f1574b, this.f1572N);
    }

    public BigInteger calculateSecret(BigInteger bigInteger) throws IllegalArgumentException {
        BigInteger validatePublicValue = SRP6Util.validatePublicValue(this.f1572N, bigInteger);
        this.f1568A = validatePublicValue;
        this.f1576u = SRP6Util.calculateU(this.digest, this.f1572N, validatePublicValue, this.f1569B);
        BigInteger calculateS = calculateS();
        this.f1573S = calculateS;
        return calculateS;
    }

    public BigInteger calculateServerEvidenceMessage() throws IllegalStateException {
        BigInteger bigInteger;
        BigInteger bigInteger2;
        BigInteger bigInteger3 = this.f1568A;
        if (bigInteger3 == null || (bigInteger = this.f1570M1) == null || (bigInteger2 = this.f1573S) == null) {
            throw new IllegalStateException("Impossible to compute M2: some data are missing from the previous operations (A,M1,S)");
        }
        BigInteger calculateM2 = SRP6Util.calculateM2(this.digest, this.f1572N, bigInteger3, bigInteger, bigInteger2);
        this.f1571M2 = calculateM2;
        return calculateM2;
    }

    public BigInteger calculateSessionKey() throws IllegalArgumentException {
        BigInteger bigInteger = this.f1573S;
        if (bigInteger == null || this.f1570M1 == null || this.f1571M2 == null) {
            throw new IllegalStateException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
        }
        BigInteger calculateKey = SRP6Util.calculateKey(this.digest, this.f1572N, bigInteger);
        this.Key = calculateKey;
        return calculateKey;
    }

    public BigInteger generateServerCredentials() {
        BigInteger calculateK = SRP6Util.calculateK(this.digest, this.f1572N, this.f1575g);
        this.f1574b = selectPrivateValue();
        BigInteger mod = calculateK.multiply(this.f1577v).mod(this.f1572N).add(this.f1575g.modPow(this.f1574b, this.f1572N)).mod(this.f1572N);
        this.f1569B = mod;
        return mod;
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, TlsHash tlsHash, SecureRandom secureRandom) {
        this.f1572N = bigInteger;
        this.f1575g = bigInteger2;
        this.f1577v = bigInteger3;
        this.random = secureRandom;
        this.digest = tlsHash;
    }

    public void init(SRP6Group sRP6Group, BigInteger bigInteger, TlsHash tlsHash, SecureRandom secureRandom) {
        init(sRP6Group.getN(), sRP6Group.getG(), bigInteger, tlsHash, secureRandom);
    }

    protected BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.f1572N, this.f1575g, this.random);
    }

    public boolean verifyClientEvidenceMessage(BigInteger bigInteger) throws IllegalStateException {
        BigInteger bigInteger2;
        BigInteger bigInteger3;
        BigInteger bigInteger4 = this.f1568A;
        if (bigInteger4 == null || (bigInteger2 = this.f1569B) == null || (bigInteger3 = this.f1573S) == null) {
            throw new IllegalStateException("Impossible to compute and verify M1: some data are missing from the previous operations (A,B,S)");
        }
        if (SRP6Util.calculateM1(this.digest, this.f1572N, bigInteger4, bigInteger2, bigInteger3).equals(bigInteger)) {
            this.f1570M1 = bigInteger;
            return true;
        }
        return false;
    }
}