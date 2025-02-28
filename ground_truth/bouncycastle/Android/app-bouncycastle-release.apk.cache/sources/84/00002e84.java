package org.bouncycastle.util;

/* loaded from: classes2.dex */
public interface Selector<T> extends Cloneable {
    Object clone();

    boolean match(T t);
}