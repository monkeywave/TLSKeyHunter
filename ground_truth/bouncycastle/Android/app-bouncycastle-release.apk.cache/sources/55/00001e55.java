package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.asn1.p009x9.X9ECParameters;
import org.bouncycastle.math.p016ec.ECAlgorithms;
import org.bouncycastle.math.p016ec.ECConstants;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public class ECDomainParameters implements ECConstants {

    /* renamed from: G */
    private final ECPoint f847G;
    private final ECCurve curve;

    /* renamed from: h */
    private final BigInteger f848h;
    private BigInteger hInv;

    /* renamed from: n */
    private final BigInteger f849n;
    private final byte[] seed;

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
        this.f847G = validatePublicPoint(eCCurve, eCPoint);
        this.f849n = bigInteger;
        this.f848h = bigInteger2;
        this.seed = Arrays.clone(bArr);
    }

    static ECPoint validatePublicPoint(ECCurve eCCurve, ECPoint eCPoint) {
        if (eCPoint != null) {
            ECPoint normalize = ECAlgorithms.importPoint(eCCurve, eCPoint).normalize();
            if (normalize.isInfinity()) {
                throw new IllegalArgumentException("Point at infinity");
            }
            if (normalize.isValid()) {
                return normalize;
            }
            throw new IllegalArgumentException("Point not on curve");
        }
        throw new NullPointerException("Point cannot be null");
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof ECDomainParameters) {
            ECDomainParameters eCDomainParameters = (ECDomainParameters) obj;
            return this.curve.equals(eCDomainParameters.curve) && this.f847G.equals(eCDomainParameters.f847G) && this.f849n.equals(eCDomainParameters.f849n);
        }
        return false;
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECPoint getG() {
        return this.f847G;
    }

    public BigInteger getH() {
        return this.f848h;
    }

    public synchronized BigInteger getHInv() {
        if (this.hInv == null) {
            this.hInv = BigIntegers.modOddInverseVar(this.f849n, this.f848h);
        }
        return this.hInv;
    }

    public BigInteger getN() {
        return this.f849n;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public int hashCode() {
        return ((((this.curve.hashCode() ^ 1028) * 257) ^ this.f847G.hashCode()) * 257) ^ this.f849n.hashCode();
    }

    public BigInteger validatePrivateScalar(BigInteger bigInteger) {
        if (bigInteger != null) {
            if (bigInteger.compareTo(ECConstants.ONE) < 0 || bigInteger.compareTo(getN()) >= 0) {
                throw new IllegalArgumentException("Scalar is not in the interval [1, n - 1]");
            }
            return bigInteger;
        }
        throw new NullPointerException("Scalar cannot be null");
    }

    public ECPoint validatePublicPoint(ECPoint eCPoint) {
        return validatePublicPoint(getCurve(), eCPoint);
    }
}