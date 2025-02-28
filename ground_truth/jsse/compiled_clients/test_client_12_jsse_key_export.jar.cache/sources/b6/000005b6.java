package org.bouncycastle.crypto.prng.drbg;

import org.bouncycastle.math.p010ec.ECPoint;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/drbg/DualECPoints.class */
public class DualECPoints {

    /* renamed from: p */
    private final ECPoint f574p;

    /* renamed from: q */
    private final ECPoint f575q;
    private final int securityStrength;
    private final int cofactor;

    public DualECPoints(int i, ECPoint eCPoint, ECPoint eCPoint2, int i2) {
        if (!eCPoint.getCurve().equals(eCPoint2.getCurve())) {
            throw new IllegalArgumentException("points need to be on the same curve");
        }
        this.securityStrength = i;
        this.f574p = eCPoint;
        this.f575q = eCPoint2;
        this.cofactor = i2;
    }

    public int getSeedLen() {
        return this.f574p.getCurve().getFieldSize();
    }

    public int getMaxOutlen() {
        return ((this.f574p.getCurve().getFieldSize() - (13 + log2(this.cofactor))) / 8) * 8;
    }

    public ECPoint getP() {
        return this.f574p;
    }

    public ECPoint getQ() {
        return this.f575q;
    }

    public int getSecurityStrength() {
        return this.securityStrength;
    }

    public int getCofactor() {
        return this.cofactor;
    }

    private static int log2(int i) {
        int i2 = 0;
        while (true) {
            int i3 = i >> 1;
            i = i3;
            if (i3 == 0) {
                return i2;
            }
            i2++;
        }
    }
}