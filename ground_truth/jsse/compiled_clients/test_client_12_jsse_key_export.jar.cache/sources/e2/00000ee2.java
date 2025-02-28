package org.bouncycastle.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/Selector.class */
public interface Selector<T> extends Cloneable {
    boolean match(T t);

    Object clone();
}