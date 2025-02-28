package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class DHGroup {

    /* renamed from: g */
    private final BigInteger f1551g;

    /* renamed from: l */
    private final int f1552l;

    /* renamed from: p */
    private final BigInteger f1553p;

    /* renamed from: q */
    private final BigInteger f1554q;

    public DHGroup(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, int i) {
        this.f1553p = bigInteger;
        this.f1551g = bigInteger3;
        this.f1554q = bigInteger2;
        this.f1552l = i;
    }

    public BigInteger getG() {
        return this.f1551g;
    }

    public int getL() {
        return this.f1552l;
    }

    public BigInteger getP() {
        return this.f1553p;
    }

    public BigInteger getQ() {
        return this.f1554q;
    }
}