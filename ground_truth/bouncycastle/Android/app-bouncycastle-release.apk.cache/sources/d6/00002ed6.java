package org.bouncycastle.x509;

import java.util.Collection;
import org.bouncycastle.util.Selector;

/* loaded from: classes2.dex */
public abstract class X509StoreSpi {
    public abstract Collection engineGetMatches(Selector selector);

    public abstract void engineInit(X509StoreParameters x509StoreParameters);
}