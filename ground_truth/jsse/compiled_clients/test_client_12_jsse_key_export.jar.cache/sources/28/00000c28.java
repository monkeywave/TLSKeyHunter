package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.AbstractECLookupTable */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/AbstractECLookupTable.class */
public abstract class AbstractECLookupTable implements ECLookupTable {
    @Override // org.bouncycastle.math.p010ec.ECLookupTable
    public ECPoint lookupVar(int i) {
        return lookup(i);
    }
}