package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.SimpleLookupTable */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/SimpleLookupTable.class */
public class SimpleLookupTable extends AbstractECLookupTable {
    private final ECPoint[] points;

    private static ECPoint[] copy(ECPoint[] eCPointArr, int i, int i2) {
        ECPoint[] eCPointArr2 = new ECPoint[i2];
        for (int i3 = 0; i3 < i2; i3++) {
            eCPointArr2[i3] = eCPointArr[i + i3];
        }
        return eCPointArr2;
    }

    public SimpleLookupTable(ECPoint[] eCPointArr, int i, int i2) {
        this.points = copy(eCPointArr, i, i2);
    }

    @Override // org.bouncycastle.math.p010ec.ECLookupTable
    public int getSize() {
        return this.points.length;
    }

    @Override // org.bouncycastle.math.p010ec.ECLookupTable
    public ECPoint lookup(int i) {
        throw new UnsupportedOperationException("Constant-time lookup not supported");
    }

    @Override // org.bouncycastle.math.p010ec.AbstractECLookupTable, org.bouncycastle.math.p010ec.ECLookupTable
    public ECPoint lookupVar(int i) {
        return this.points[i];
    }
}