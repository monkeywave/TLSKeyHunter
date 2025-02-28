package org.bouncycastle.x509;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRL;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/x509/X509CRLStoreSelector.class */
public class X509CRLStoreSelector extends X509CRLSelector implements Selector {
    private boolean deltaCRLIndicator = false;
    private boolean completeCRLEnabled = false;
    private BigInteger maxBaseCRLNumber = null;
    private byte[] issuingDistributionPoint = null;
    private boolean issuingDistributionPointEnabled = false;
    private X509AttributeCertificate attrCertChecking;

    public boolean isIssuingDistributionPointEnabled() {
        return this.issuingDistributionPointEnabled;
    }

    public void setIssuingDistributionPointEnabled(boolean z) {
        this.issuingDistributionPointEnabled = z;
    }

    public void setAttrCertificateChecking(X509AttributeCertificate x509AttributeCertificate) {
        this.attrCertChecking = x509AttributeCertificate;
    }

    public X509AttributeCertificate getAttrCertificateChecking() {
        return this.attrCertChecking;
    }

    @Override // org.bouncycastle.util.Selector
    public boolean match(Object obj) {
        if (obj instanceof X509CRL) {
            X509CRL x509crl = (X509CRL) obj;
            ASN1Integer aSN1Integer = null;
            try {
                byte[] extensionValue = x509crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
                if (extensionValue != null) {
                    aSN1Integer = ASN1Integer.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue));
                }
                if (isDeltaCRLIndicatorEnabled() && aSN1Integer == null) {
                    return false;
                }
                if (!isCompleteCRLEnabled() || aSN1Integer == null) {
                    if (aSN1Integer == null || this.maxBaseCRLNumber == null || aSN1Integer.getPositiveValue().compareTo(this.maxBaseCRLNumber) != 1) {
                        if (this.issuingDistributionPointEnabled) {
                            byte[] extensionValue2 = x509crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
                            if (this.issuingDistributionPoint == null) {
                                if (extensionValue2 != null) {
                                    return false;
                                }
                            } else if (!Arrays.areEqual(extensionValue2, this.issuingDistributionPoint)) {
                                return false;
                            }
                        }
                        return super.match((CRL) ((X509CRL) obj));
                    }
                    return false;
                }
                return false;
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    @Override // java.security.cert.X509CRLSelector, java.security.cert.CRLSelector
    public boolean match(CRL crl) {
        return match((Object) crl);
    }

    public boolean isDeltaCRLIndicatorEnabled() {
        return this.deltaCRLIndicator;
    }

    public void setDeltaCRLIndicatorEnabled(boolean z) {
        this.deltaCRLIndicator = z;
    }

    public static X509CRLStoreSelector getInstance(X509CRLSelector x509CRLSelector) {
        if (x509CRLSelector == null) {
            throw new IllegalArgumentException("cannot create from null selector");
        }
        X509CRLStoreSelector x509CRLStoreSelector = new X509CRLStoreSelector();
        x509CRLStoreSelector.setCertificateChecking(x509CRLSelector.getCertificateChecking());
        x509CRLStoreSelector.setDateAndTime(x509CRLSelector.getDateAndTime());
        try {
            x509CRLStoreSelector.setIssuerNames(x509CRLSelector.getIssuerNames());
            x509CRLStoreSelector.setIssuers(x509CRLSelector.getIssuers());
            x509CRLStoreSelector.setMaxCRLNumber(x509CRLSelector.getMaxCRL());
            x509CRLStoreSelector.setMinCRLNumber(x509CRLSelector.getMinCRL());
            return x509CRLStoreSelector;
        } catch (IOException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override // java.security.cert.X509CRLSelector, java.security.cert.CRLSelector, org.bouncycastle.util.Selector
    public Object clone() {
        X509CRLStoreSelector x509CRLStoreSelector = getInstance(this);
        x509CRLStoreSelector.deltaCRLIndicator = this.deltaCRLIndicator;
        x509CRLStoreSelector.completeCRLEnabled = this.completeCRLEnabled;
        x509CRLStoreSelector.maxBaseCRLNumber = this.maxBaseCRLNumber;
        x509CRLStoreSelector.attrCertChecking = this.attrCertChecking;
        x509CRLStoreSelector.issuingDistributionPointEnabled = this.issuingDistributionPointEnabled;
        x509CRLStoreSelector.issuingDistributionPoint = Arrays.clone(this.issuingDistributionPoint);
        return x509CRLStoreSelector;
    }

    public boolean isCompleteCRLEnabled() {
        return this.completeCRLEnabled;
    }

    public void setCompleteCRLEnabled(boolean z) {
        this.completeCRLEnabled = z;
    }

    public BigInteger getMaxBaseCRLNumber() {
        return this.maxBaseCRLNumber;
    }

    public void setMaxBaseCRLNumber(BigInteger bigInteger) {
        this.maxBaseCRLNumber = bigInteger;
    }

    public byte[] getIssuingDistributionPoint() {
        return Arrays.clone(this.issuingDistributionPoint);
    }

    public void setIssuingDistributionPoint(byte[] bArr) {
        this.issuingDistributionPoint = Arrays.clone(bArr);
    }
}