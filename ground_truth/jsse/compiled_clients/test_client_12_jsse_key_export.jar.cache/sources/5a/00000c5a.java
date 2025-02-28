package org.bouncycastle.math.p010ec;

import org.bouncycastle.math.p010ec.ECPoint;

/* renamed from: org.bouncycastle.math.ec.WTauNafPreCompInfo */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/WTauNafPreCompInfo.class */
public class WTauNafPreCompInfo implements PreCompInfo {
    protected ECPoint.AbstractF2m[] preComp = null;

    public ECPoint.AbstractF2m[] getPreComp() {
        return this.preComp;
    }

    public void setPreComp(ECPoint.AbstractF2m[] abstractF2mArr) {
        this.preComp = abstractF2mArr;
    }
}