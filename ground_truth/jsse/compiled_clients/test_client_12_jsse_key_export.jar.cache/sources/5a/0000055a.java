package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.asn1.p003x9.X9ECParameters;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ECDomainParameters.class */
public class ECDomainParameters implements ECConstants {
    private final ECCurve curve;
    private final byte[] seed;

    /* renamed from: G */
    private final ECPoint f529G;

    /* renamed from: n */
    private final BigInteger f530n;

    /* renamed from: h */
    private final BigInteger f531h;
    private BigInteger hInv;

    public ECDomainParameters(X9ECParameters x9ECParameters) {
        this(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed());
    }

    public ECDomainParameters(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger) {
        this(eCCurve, eCPoint, bigInteger, ONE, null);
    }

    public ECDomainParameters(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger, BigInteger bigInteger2) {
        this(eCCurve, eCPoint, bigInteger, bigInteger2, null);
    }

    public ECDomainParameters(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger, BigInteger bigInteger2, byte[] bArr) {
        this.hInv = null;
        if (eCCurve == null) {
            throw new NullPointerException("curve");
        }
        if (bigInteger == null) {
            throw new NullPointerException("n");
        }
        this.curve = eCCurve;
        this.f529G = validatePublicPoint(eCCurve, eCPoint);
        this.f530n = bigInteger;
        this.f531h = bigInteger2;
        this.seed = Arrays.clone(bArr);
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECPoint getG() {
        return this.f529G;
    }

    public BigInteger getN() {
        return this.f530n;
    }

    public BigInteger getH() {
        return this.f531h;
    }

    public synchronized BigInteger getHInv() {
        if (this.hInv == null) {
            this.hInv = BigIntegers.modOddInverseVar(this.f530n, this.f531h);
        }
        return this.hInv;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof ECDomainParameters) {
            ECDomainParameters eCDomainParameters = (ECDomainParameters) obj;
            return this.curve.equals(eCDomainParameters.curve) && this.f529G.equals(eCDomainParameters.f529G) && this.f530n.equals(eCDomainParameters.f530n);
        }
        return false;
    }

    public int hashCode() {
        return (((((4 * 257) ^ this.curve.hashCode()) * 257) ^ this.f529G.hashCode()) * 257) ^ this.f530n.hashCode();
    }

    public BigInteger validatePrivateScalar(BigInteger bigInteger) {
        if (null == bigInteger) {
            throw new NullPointerException("Scalar cannot be null");
        }
        if (bigInteger.compareTo(ECConstants.ONE) < 0 || bigInteger.compareTo(getN()) >= 0) {
            throw new IllegalArgumentException("Scalar is not in the interval [1, n - 1]");
        }
        return bigInteger;
    }

    public ECPoint validatePublicPoint(ECPoint eCPoint) {
        return validatePublicPoint(getCurve(), eCPoint);
    }

    static ECPoint validatePublicPoint(ECCurve eCCurve, ECPoint eCPoint) {
        if (null == eCPoint) {
            throw new NullPointerException("Point cannot be null");
        }
        ECPoint normalize = ECAlgorithms.importPoint(eCCurve, eCPoint).normalize();
        if (normalize.isInfinity()) {
            throw new IllegalArgumentException("Point at infinity");
        }
        if (normalize.isValid()) {
            return normalize;
        }
        throw new IllegalArgumentException("Point not on curve");
    }
}