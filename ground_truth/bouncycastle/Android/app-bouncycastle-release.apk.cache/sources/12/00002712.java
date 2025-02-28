package org.bouncycastle.math.p016ec;

/* renamed from: org.bouncycastle.math.ec.SimpleLookupTable */
/* loaded from: classes2.dex */
public class SimpleLookupTable extends AbstractECLookupTable {
    private final ECPoint[] points;

    public SimpleLookupTable(ECPoint[] eCPointArr, int i, int i2) {
        this.points = copy(eCPointArr, i, i2);
    }

    private static ECPoint[] copy(ECPoint[] eCPointArr, int i, int i2) {
        ECPoint[] eCPointArr2 = new ECPoint[i2];
        for (int i3 = 0; i3 < i2; i3++) {
            eCPointArr2[i3] = eCPointArr[i + i3];
        }
        return eCPointArr2;
    }

    @Override // org.bouncycastle.math.p016ec.ECLookupTable
    public int getSize() {
        return this.points.length;
    }

    @Override // org.bouncycastle.math.p016ec.ECLookupTable
    public ECPoint lookup(int i) {
        throw new UnsupportedOperationException("Constant-time lookup not supported");
    }

    @Override // org.bouncycastle.math.p016ec.AbstractECLookupTable, org.bouncycastle.math.p016ec.ECLookupTable
    public ECPoint lookupVar(int i) {
        return this.points[i];
    }
}