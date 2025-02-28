package org.bouncycastle.pqc.math.ntru.parameters;

import org.bouncycastle.pqc.math.ntru.HRSS1373Polynomial;
import org.bouncycastle.pqc.math.ntru.HRSSPolynomial;
import org.bouncycastle.pqc.math.ntru.Polynomial;

/* loaded from: classes2.dex */
public abstract class NTRUHRSSParameterSet extends NTRUParameterSet {
    /* JADX INFO: Access modifiers changed from: package-private */
    public NTRUHRSSParameterSet(int i, int i2, int i3, int i4, int i5) {
        super(i, i2, i3, i4, i5);
    }

    @Override // org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet
    public Polynomial createPolynomial() {
        return m1n() == 1373 ? new HRSS1373Polynomial(this) : new HRSSPolynomial(this);
    }

    @Override // org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet
    public int sampleFgBytes() {
        return sampleIidBytes() * 2;
    }

    @Override // org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet
    public int sampleRmBytes() {
        return sampleIidBytes() * 2;
    }
}