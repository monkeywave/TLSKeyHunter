package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.FixedPointPreCompInfo */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/FixedPointPreCompInfo.class */
public class FixedPointPreCompInfo implements PreCompInfo {
    protected ECPoint offset = null;
    protected ECLookupTable lookupTable = null;
    protected int width = -1;

    public ECLookupTable getLookupTable() {
        return this.lookupTable;
    }

    public void setLookupTable(ECLookupTable eCLookupTable) {
        this.lookupTable = eCLookupTable;
    }

    public ECPoint getOffset() {
        return this.offset;
    }

    public void setOffset(ECPoint eCPoint) {
        this.offset = eCPoint;
    }

    public int getWidth() {
        return this.width;
    }

    public void setWidth(int i) {
        this.width = i;
    }
}