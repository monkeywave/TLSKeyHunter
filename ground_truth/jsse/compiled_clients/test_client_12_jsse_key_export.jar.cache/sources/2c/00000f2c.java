package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/x509/X509CertPairStoreSelector.class */
public class X509CertPairStoreSelector implements Selector {
    private X509CertStoreSelector forwardSelector;
    private X509CertStoreSelector reverseSelector;
    private X509CertificatePair certPair;

    public X509CertificatePair getCertPair() {
        return this.certPair;
    }

    public void setCertPair(X509CertificatePair x509CertificatePair) {
        this.certPair = x509CertificatePair;
    }

    public void setForwardSelector(X509CertStoreSelector x509CertStoreSelector) {
        this.forwardSelector = x509CertStoreSelector;
    }

    public void setReverseSelector(X509CertStoreSelector x509CertStoreSelector) {
        this.reverseSelector = x509CertStoreSelector;
    }

    @Override // org.bouncycastle.util.Selector
    public Object clone() {
        X509CertPairStoreSelector x509CertPairStoreSelector = new X509CertPairStoreSelector();
        x509CertPairStoreSelector.certPair = this.certPair;
        if (this.forwardSelector != null) {
            x509CertPairStoreSelector.setForwardSelector((X509CertStoreSelector) this.forwardSelector.clone());
        }
        if (this.reverseSelector != null) {
            x509CertPairStoreSelector.setReverseSelector((X509CertStoreSelector) this.reverseSelector.clone());
        }
        return x509CertPairStoreSelector;
    }

    @Override // org.bouncycastle.util.Selector
    public boolean match(Object obj) {
        try {
            if (obj instanceof X509CertificatePair) {
                X509CertificatePair x509CertificatePair = (X509CertificatePair) obj;
                if (this.forwardSelector == null || this.forwardSelector.match((Object) x509CertificatePair.getForward())) {
                    if (this.reverseSelector == null || this.reverseSelector.match((Object) x509CertificatePair.getReverse())) {
                        if (this.certPair != null) {
                            return this.certPair.equals(obj);
                        }
                        return true;
                    }
                    return false;
                }
                return false;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public X509CertStoreSelector getForwardSelector() {
        return this.forwardSelector;
    }

    public X509CertStoreSelector getReverseSelector() {
        return this.reverseSelector;
    }
}