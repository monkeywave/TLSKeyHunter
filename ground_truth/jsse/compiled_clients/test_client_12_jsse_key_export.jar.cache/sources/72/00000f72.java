package org.openjsse.com.sun.net.ssl.internal.www.protocol.https;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import sun.security.util.DerValue;
import sun.security.util.HostnameChecker;
import sun.security.x509.X500Name;

/* compiled from: DelegateHttpsURLConnection.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/internal/www/protocol/https/VerifierWrapper.class */
class VerifierWrapper implements HostnameVerifier {
    private org.openjsse.com.sun.net.ssl.HostnameVerifier verifier;

    /* JADX INFO: Access modifiers changed from: package-private */
    public VerifierWrapper(org.openjsse.com.sun.net.ssl.HostnameVerifier verifier) {
        this.verifier = verifier;
    }

    @Override // javax.net.ssl.HostnameVerifier
    public boolean verify(String hostname, SSLSession session) {
        try {
            Certificate[] serverChain = session.getPeerCertificates();
            if (serverChain == null || serverChain.length == 0 || !(serverChain[0] instanceof X509Certificate)) {
                return false;
            }
            X509Certificate serverCert = (X509Certificate) serverChain[0];
            String serverName = getServername(serverCert);
            if (serverName == null) {
                return false;
            }
            return this.verifier.verify(hostname, serverName);
        } catch (SSLPeerUnverifiedException e) {
            return false;
        }
    }

    private static String getServername(X509Certificate peerCert) {
        try {
            Collection<List<?>> subjAltNames = peerCert.getSubjectAlternativeNames();
            if (subjAltNames != null) {
                for (List<?> next : subjAltNames) {
                    if (((Integer) next.get(0)).intValue() == 2) {
                        String dnsName = (String) next.get(1);
                        return dnsName;
                    }
                }
            }
            X500Name subject = HostnameChecker.getSubjectX500Name(peerCert);
            DerValue derValue = subject.findMostSpecificAttribute(X500Name.commonName_oid);
            if (derValue != null) {
                try {
                    String name = derValue.getAsString();
                    return name;
                } catch (IOException e) {
                }
            }
            return null;
        } catch (CertificateException e2) {
            return null;
        }
    }
}