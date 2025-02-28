package org.bouncycastle.math.p010ec.endo;

import org.bouncycastle.math.p010ec.ECPointMap;

/* renamed from: org.bouncycastle.math.ec.endo.ECEndomorphism */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/endo/ECEndomorphism.class */
public interface ECEndomorphism {
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}