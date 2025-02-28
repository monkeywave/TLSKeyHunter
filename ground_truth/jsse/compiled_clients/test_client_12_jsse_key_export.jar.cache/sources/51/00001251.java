package org.openjsse.sun.security.validator;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/validator/TrustStoreUtil.class */
public final class TrustStoreUtil {
    private TrustStoreUtil() {
    }

    public static Set<X509Certificate> getTrustedCerts(KeyStore ks) {
        Certificate[] certs;
        Set<X509Certificate> set = new HashSet<>();
        try {
            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()) {
                String alias = e.nextElement();
                if (ks.isCertificateEntry(alias)) {
                    Certificate cert = ks.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        set.add((X509Certificate) cert);
                    }
                } else if (ks.isKeyEntry(alias) && (certs = ks.getCertificateChain(alias)) != null && certs.length > 0 && (certs[0] instanceof X509Certificate)) {
                    set.add((X509Certificate) certs[0]);
                }
            }
        } catch (KeyStoreException e2) {
        }
        return Collections.unmodifiableSet(set);
    }
}