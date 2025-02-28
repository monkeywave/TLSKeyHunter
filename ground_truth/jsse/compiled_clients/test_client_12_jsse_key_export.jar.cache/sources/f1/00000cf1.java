package org.bouncycastle.math.p010ec.endo;

import java.math.BigInteger;

/* renamed from: org.bouncycastle.math.ec.endo.ScalarSplitParameters */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/endo/ScalarSplitParameters.class */
public class ScalarSplitParameters {
    protected final BigInteger v1A;
    protected final BigInteger v1B;
    protected final BigInteger v2A;
    protected final BigInteger v2B;

    /* renamed from: g1 */
    protected final BigInteger f761g1;

    /* renamed from: g2 */
    protected final BigInteger f762g2;
    protected final int bits;

    private static void checkVector(BigInteger[] bigIntegerArr, String str) {
        if (bigIntegerArr == null || bigIntegerArr.length != 2 || bigIntegerArr[0] == null || bigIntegerArr[1] == null) {
            throw new IllegalArgumentException("'" + str + "' must consist of exactly 2 (non-null) values");
        }
    }

    public ScalarSplitParameters(BigInteger[] bigIntegerArr, BigInteger[] bigIntegerArr2, BigInteger bigInteger, BigInteger bigInteger2, int i) {
        checkVector(bigIntegerArr, "v1");
        checkVector(bigIntegerArr2, "v2");
        this.v1A = bigIntegerArr[0];
        this.v1B = bigIntegerArr[1];
        this.v2A = bigIntegerArr2[0];
        this.v2B = bigIntegerArr2[1];
        this.f761g1 = bigInteger;
        this.f762g2 = bigInteger2;
        this.bits = i;
    }

    public BigInteger getV1A() {
        return this.v1A;
    }

    public BigInteger getV1B() {
        return this.v1B;
    }

    public BigInteger getV2A() {
        return this.v2A;
    }

    public BigInteger getV2B() {
        return this.v2B;
    }

    public BigInteger getG1() {
        return this.f761g1;
    }

    public BigInteger getG2() {
        return this.f762g2;
    }

    public int getBits() {
        return this.bits;
    }
}