package org.bouncycastle.math.p016ec;

import org.bouncycastle.math.p016ec.ECPoint;

/* renamed from: org.bouncycastle.math.ec.WTauNafPreCompInfo */
/* loaded from: classes2.dex */
public class WTauNafPreCompInfo implements PreCompInfo {
    protected ECPoint.AbstractF2m[] preComp = null;

    public ECPoint.AbstractF2m[] getPreComp() {
        return this.preComp;
    }

    public void setPreComp(ECPoint.AbstractF2m[] abstractF2mArr) {
        this.preComp = abstractF2mArr;
    }
}