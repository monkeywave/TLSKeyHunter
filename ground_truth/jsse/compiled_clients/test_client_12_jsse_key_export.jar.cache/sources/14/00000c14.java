package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECPoint;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ECParameterSpec.class */
public class ECParameterSpec implements AlgorithmParameterSpec {
    private ECCurve curve;
    private byte[] seed;

    /* renamed from: G */
    private ECPoint f641G;

    /* renamed from: n */
    private BigInteger f642n;

    /* renamed from: h */
    private BigInteger f643h;

    public ECParameterSpec(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger) {
        this.curve = eCCurve;
        this.f641G = eCPoint.normalize();
        this.f642n = bigInteger;
        this.f643h = BigInteger.valueOf(1L);
        this.seed = null;
    }

    public ECParameterSpec(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger, BigInteger bigInteger2) {
        this.curve = eCCurve;
        this.f641G = eCPoint.normalize();
        this.f642n = bigInteger;
        this.f643h = bigInteger2;
        this.seed = null;
    }

    public ECParameterSpec(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger, BigInteger bigInteger2, byte[] bArr) {
        this.curve = eCCurve;
        this.f641G = eCPoint.normalize();
        this.f642n = bigInteger;
        this.f643h = bigInteger2;
        this.seed = bArr;
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECPoint getG() {
        return this.f641G;
    }

    public BigInteger getN() {
        return this.f642n;
    }

    public BigInteger getH() {
        return this.f643h;
    }

    public byte[] getSeed() {
        return this.seed;
    }

    public boolean equals(Object obj) {
        if (obj instanceof ECParameterSpec) {
            ECParameterSpec eCParameterSpec = (ECParameterSpec) obj;
            return getCurve().equals(eCParameterSpec.getCurve()) && getG().equals(eCParameterSpec.getG());
        }
        return false;
    }

    public int hashCode() {
        return getCurve().hashCode() ^ getG().hashCode();
    }
}