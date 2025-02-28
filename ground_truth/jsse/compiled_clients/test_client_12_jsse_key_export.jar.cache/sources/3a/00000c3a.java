package org.bouncycastle.math.p010ec;

import java.math.BigInteger;

/* renamed from: org.bouncycastle.math.ec.ECMultiplier */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECMultiplier.class */
public interface ECMultiplier {
    ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger);
}