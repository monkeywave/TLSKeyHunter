package org.bouncycastle.asn1.p009x9;

import org.bouncycastle.math.p016ec.ECCurve;

/* renamed from: org.bouncycastle.asn1.x9.X9ECParametersHolder */
/* loaded from: classes.dex */
public abstract class X9ECParametersHolder {
    private ECCurve curve;
    private X9ECParameters params;

    protected ECCurve createCurve() {
        return createParameters().getCurve();
    }

    protected abstract X9ECParameters createParameters();

    public synchronized ECCurve getCurve() {
        if (this.curve == null) {
            this.curve = createCurve();
        }
        return this.curve;
    }

    public synchronized X9ECParameters getParameters() {
        if (this.params == null) {
            this.params = createParameters();
        }
        return this.params;
    }
}