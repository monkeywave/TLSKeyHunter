package org.bouncycastle.util;

/* loaded from: classes2.dex */
public interface Memoable {
    Memoable copy();

    void reset(Memoable memoable);
}