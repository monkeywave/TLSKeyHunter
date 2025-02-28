package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class TlsSRPConfig {
    protected BigInteger[] explicitNG;

    public BigInteger[] getExplicitNG() {
        return (BigInteger[]) this.explicitNG.clone();
    }

    public void setExplicitNG(BigInteger[] bigIntegerArr) {
        this.explicitNG = (BigInteger[]) bigIntegerArr.clone();
    }
}