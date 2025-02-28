package org.bouncycastle.util;

import java.util.Collection;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/Store.class */
public interface Store<T> {
    Collection<T> getMatches(Selector<T> selector) throws StoreException;
}