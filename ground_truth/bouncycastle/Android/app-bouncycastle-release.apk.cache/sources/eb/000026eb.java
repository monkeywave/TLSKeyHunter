package org.bouncycastle.math.p016ec;

/* renamed from: org.bouncycastle.math.ec.AbstractECLookupTable */
/* loaded from: classes2.dex */
public abstract class AbstractECLookupTable implements ECLookupTable {
    @Override // org.bouncycastle.math.p016ec.ECLookupTable
    public ECPoint lookupVar(int i) {
        return lookup(i);
    }
}