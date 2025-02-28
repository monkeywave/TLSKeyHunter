package org.bouncycastle.math.p010ec.endo;

import java.math.BigInteger;

/* renamed from: org.bouncycastle.math.ec.endo.GLVEndomorphism */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/endo/GLVEndomorphism.class */
public interface GLVEndomorphism extends ECEndomorphism {
    BigInteger[] decomposeScalar(BigInteger bigInteger);
}