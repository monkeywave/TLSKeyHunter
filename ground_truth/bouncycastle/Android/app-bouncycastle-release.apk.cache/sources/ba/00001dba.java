package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public class SM2KeyPairGenerator extends ECKeyPairGenerator {
    public SM2KeyPairGenerator() {
        super("SM2KeyGen");
    }

    @Override // org.bouncycastle.crypto.generators.ECKeyPairGenerator
    protected boolean isOutOfRangeD(BigInteger bigInteger, BigInteger bigInteger2) {
        return bigInteger.compareTo(ONE) < 0 || bigInteger.compareTo(bigInteger2.subtract(BigIntegers.ONE)) >= 0;
    }
}