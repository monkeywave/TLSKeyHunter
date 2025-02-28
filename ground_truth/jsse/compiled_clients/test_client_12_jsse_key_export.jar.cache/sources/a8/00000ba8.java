package org.bouncycastle.jce;

import java.security.cert.CertStoreParameters;
import java.util.Collection;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/MultiCertStoreParameters.class */
public class MultiCertStoreParameters implements CertStoreParameters {
    private Collection certStores;
    private boolean searchAllStores;

    public MultiCertStoreParameters(Collection collection) {
        this(collection, true);
    }

    public MultiCertStoreParameters(Collection collection, boolean z) {
        this.certStores = collection;
        this.searchAllStores = z;
    }

    public Collection getCertStores() {
        return this.certStores;
    }

    public boolean getSearchAllStores() {
        return this.searchAllStores;
    }

    @Override // java.security.cert.CertStoreParameters
    public Object clone() {
        return this;
    }
}