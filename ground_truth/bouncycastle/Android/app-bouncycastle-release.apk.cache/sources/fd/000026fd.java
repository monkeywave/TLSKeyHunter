package org.bouncycastle.math.p016ec;

import java.math.BigInteger;

/* renamed from: org.bouncycastle.math.ec.ECMultiplier */
/* loaded from: classes2.dex */
public interface ECMultiplier {
    ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger);
}