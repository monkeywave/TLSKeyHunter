package org.bouncycastle.x509;

import java.util.Collection;
import org.bouncycastle.util.Selector;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/x509/X509StoreSpi.class */
public abstract class X509StoreSpi {
    public abstract void engineInit(X509StoreParameters x509StoreParameters);

    public abstract Collection engineGetMatches(Selector selector);
}