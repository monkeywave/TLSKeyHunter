package org.bouncycastle.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/Memoable.class */
public interface Memoable {
    Memoable copy();

    void reset(Memoable memoable);
}