package org.bouncycastle.math.p016ec.endo;

import org.bouncycastle.math.p016ec.ECPointMap;

/* renamed from: org.bouncycastle.math.ec.endo.ECEndomorphism */
/* loaded from: classes2.dex */
public interface ECEndomorphism {
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}