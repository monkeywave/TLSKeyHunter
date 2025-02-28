package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.ECLookupTable */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECLookupTable.class */
public interface ECLookupTable {
    int getSize();

    ECPoint lookup(int i);

    ECPoint lookupVar(int i);
}