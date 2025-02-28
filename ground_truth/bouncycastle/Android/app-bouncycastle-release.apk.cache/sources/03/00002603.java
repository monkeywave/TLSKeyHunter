package org.bouncycastle.jce.provider;

import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

/* loaded from: classes2.dex */
abstract class PKIXCRLUtil {
    PKIXCRLUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Set findCRLs(PKIXCRLStoreSelector pKIXCRLStoreSelector, Date date, List list, List list2) throws AnnotatedException {
        HashSet<X509CRL> hashSet = new HashSet();
        try {
            findCRLs(hashSet, pKIXCRLStoreSelector, list2);
            findCRLs(hashSet, pKIXCRLStoreSelector, list);
            HashSet hashSet2 = new HashSet();
            for (X509CRL x509crl : hashSet) {
                Date nextUpdate = x509crl.getNextUpdate();
                if (nextUpdate == null || nextUpdate.after(date)) {
                    X509Certificate certificateChecking = pKIXCRLStoreSelector.getCertificateChecking();
                    if (certificateChecking == null || x509crl.getThisUpdate().before(certificateChecking.getNotAfter())) {
                        hashSet2.add(x509crl);
                    }
                }
            }
            return hashSet2;
        } catch (AnnotatedException e) {
            throw new AnnotatedException("Exception obtaining complete CRLs.", e);
        }
    }

    private static void findCRLs(Set set, PKIXCRLStoreSelector pKIXCRLStoreSelector, List list) throws AnnotatedException {
        AnnotatedException annotatedException;
        AnnotatedException annotatedException2 = null;
        boolean z = false;
        for (Object obj : list) {
            if (obj instanceof Store) {
                try {
                    set.addAll(((Store) obj).getMatches(pKIXCRLStoreSelector));
                } catch (StoreException e) {
                    annotatedException = new AnnotatedException("Exception searching in X.509 CRL store.", e);
                    annotatedException2 = annotatedException;
                }
            } else {
                try {
                    set.addAll(PKIXCRLStoreSelector.getCRLs(pKIXCRLStoreSelector, (CertStore) obj));
                } catch (CertStoreException e2) {
                    annotatedException = new AnnotatedException("Exception searching in X.509 CRL store.", e2);
                    annotatedException2 = annotatedException;
                }
            }
            z = true;
        }
        if (!z && annotatedException2 != null) {
            throw annotatedException2;
        }
    }
}