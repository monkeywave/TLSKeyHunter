package org.bouncycastle.jcajce;

import java.security.cert.CRL;
import java.util.Collection;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/PKIXCRLStore.class */
public interface PKIXCRLStore<T extends CRL> extends Store<T> {
    @Override // org.bouncycastle.util.Store
    Collection<T> getMatches(Selector<T> selector) throws StoreException;
}