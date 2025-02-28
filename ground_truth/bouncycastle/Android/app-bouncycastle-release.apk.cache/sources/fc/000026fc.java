package org.bouncycastle.math.p016ec;

/* renamed from: org.bouncycastle.math.ec.ECLookupTable */
/* loaded from: classes2.dex */
public interface ECLookupTable {
    int getSize();

    ECPoint lookup(int i);

    ECPoint lookupVar(int i);
}