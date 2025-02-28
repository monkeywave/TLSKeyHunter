package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Principal;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.Certificate;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jcajce.PKIXCertStoreSelector;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jce.exception.ExtCertPathBuilderException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.X509AttributeCertStoreSelector;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CertStoreSelector;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/PKIXAttrCertPathBuilderSpi.class */
public class PKIXAttrCertPathBuilderSpi extends CertPathBuilderSpi {
    private Exception certPathException;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v73, types: [org.bouncycastle.x509.ExtendedPKIXBuilderParameters] */
    /* JADX WARN: Type inference failed for: r0v79, types: [java.util.List] */
    @Override // java.security.cert.CertPathBuilderSpi
    public CertPathBuilderResult engineBuild(CertPathParameters certPathParameters) throws CertPathBuilderException, InvalidAlgorithmParameterException {
        PKIXExtendedBuilderParameters pKIXExtendedBuilderParameters;
        if ((certPathParameters instanceof PKIXBuilderParameters) || (certPathParameters instanceof ExtendedPKIXBuilderParameters) || (certPathParameters instanceof PKIXExtendedBuilderParameters)) {
            ArrayList arrayList = new ArrayList();
            if (certPathParameters instanceof PKIXBuilderParameters) {
                PKIXExtendedBuilderParameters.Builder builder = new PKIXExtendedBuilderParameters.Builder((PKIXBuilderParameters) certPathParameters);
                if (certPathParameters instanceof ExtendedPKIXParameters) {
                    ?? r0 = (ExtendedPKIXBuilderParameters) certPathParameters;
                    builder.addExcludedCerts(r0.getExcludedCerts());
                    builder.setMaxPathLength(r0.getMaxPathLength());
                    arrayList = r0.getStores();
                }
                pKIXExtendedBuilderParameters = builder.build();
            } else {
                pKIXExtendedBuilderParameters = (PKIXExtendedBuilderParameters) certPathParameters;
            }
            ArrayList arrayList2 = new ArrayList();
            PKIXExtendedParameters baseParameters = pKIXExtendedBuilderParameters.getBaseParameters();
            PKIXCertStoreSelector targetConstraints = baseParameters.getTargetConstraints();
            if (targetConstraints instanceof X509AttributeCertStoreSelector) {
                try {
                    Collection findCertificates = findCertificates((X509AttributeCertStoreSelector) targetConstraints, arrayList);
                    if (findCertificates.isEmpty()) {
                        throw new CertPathBuilderException("No attribute certificate found matching targetConstraints.");
                    }
                    CertPathBuilderResult certPathBuilderResult = null;
                    Iterator it = findCertificates.iterator();
                    while (it.hasNext() && certPathBuilderResult == null) {
                        X509AttributeCertificate x509AttributeCertificate = (X509AttributeCertificate) it.next();
                        X509CertStoreSelector x509CertStoreSelector = new X509CertStoreSelector();
                        Principal[] principals = x509AttributeCertificate.getIssuer().getPrincipals();
                        LinkedHashSet linkedHashSet = new LinkedHashSet();
                        for (int i = 0; i < principals.length; i++) {
                            try {
                                if (principals[i] instanceof X500Principal) {
                                    x509CertStoreSelector.setSubject(((X500Principal) principals[i]).getEncoded());
                                }
                                PKIXCertStoreSelector<? extends Certificate> build = new PKIXCertStoreSelector.Builder(x509CertStoreSelector).build();
                                CertPathValidatorUtilities.findCertificates(linkedHashSet, build, baseParameters.getCertStores());
                                CertPathValidatorUtilities.findCertificates(linkedHashSet, build, baseParameters.getCertificateStores());
                            } catch (IOException e) {
                                throw new ExtCertPathBuilderException("cannot encode X500Principal.", e);
                            } catch (AnnotatedException e2) {
                                throw new ExtCertPathBuilderException("Public key certificate for attribute certificate cannot be searched.", e2);
                            }
                        }
                        if (linkedHashSet.isEmpty()) {
                            throw new CertPathBuilderException("Public key certificate for attribute certificate cannot be found.");
                        }
                        Iterator it2 = linkedHashSet.iterator();
                        while (it2.hasNext() && certPathBuilderResult == null) {
                            certPathBuilderResult = build(x509AttributeCertificate, (X509Certificate) it2.next(), pKIXExtendedBuilderParameters, arrayList2);
                        }
                    }
                    if (certPathBuilderResult != null || this.certPathException == null) {
                        if (certPathBuilderResult == null && this.certPathException == null) {
                            throw new CertPathBuilderException("Unable to find certificate chain.");
                        }
                        return certPathBuilderResult;
                    }
                    throw new ExtCertPathBuilderException("Possible certificate chain could not be validated.", this.certPathException);
                } catch (AnnotatedException e3) {
                    throw new ExtCertPathBuilderException("Error finding target attribute certificate.", e3);
                }
            }
            throw new CertPathBuilderException("TargetConstraints must be an instance of " + X509AttributeCertStoreSelector.class.getName() + " for " + getClass().getName() + " class.");
        }
        throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + PKIXBuilderParameters.class.getName() + " or " + PKIXExtendedBuilderParameters.class.getName() + ".");
    }

    /* JADX WARN: Removed duplicated region for block: B:61:0x01ac  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private java.security.cert.CertPathBuilderResult build(org.bouncycastle.x509.X509AttributeCertificate r8, java.security.cert.X509Certificate r9, org.bouncycastle.jcajce.PKIXExtendedBuilderParameters r10, java.util.List r11) {
        /*
            Method dump skipped, instructions count: 440
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jce.provider.PKIXAttrCertPathBuilderSpi.build(org.bouncycastle.x509.X509AttributeCertificate, java.security.cert.X509Certificate, org.bouncycastle.jcajce.PKIXExtendedBuilderParameters, java.util.List):java.security.cert.CertPathBuilderResult");
    }

    protected static Collection findCertificates(X509AttributeCertStoreSelector x509AttributeCertStoreSelector, List list) throws AnnotatedException {
        HashSet hashSet = new HashSet();
        for (Object obj : list) {
            if (obj instanceof Store) {
                try {
                    hashSet.addAll(((Store) obj).getMatches(x509AttributeCertStoreSelector));
                } catch (StoreException e) {
                    throw new AnnotatedException("Problem while picking certificates from X.509 store.", e);
                }
            }
        }
        return hashSet;
    }
}