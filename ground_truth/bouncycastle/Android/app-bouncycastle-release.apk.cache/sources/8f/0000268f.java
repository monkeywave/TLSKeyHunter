package org.bouncycastle.jsse.provider;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.Date;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;
import javax.security.cert.CertificateExpiredException;
import javax.security.cert.CertificateNotYetValidException;
import javax.security.cert.X509Certificate;
import org.bouncycastle.jsse.BCExtendedSSLSession;

/* loaded from: classes2.dex */
class OldCertUtil {

    /* loaded from: classes2.dex */
    private static class X509CertificateWrapper extends X509Certificate {

        /* renamed from: c */
        private final java.security.cert.X509Certificate f998c;

        private X509CertificateWrapper(java.security.cert.X509Certificate x509Certificate) {
            this.f998c = x509Certificate;
        }

        @Override // javax.security.cert.X509Certificate
        public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
            try {
                this.f998c.checkValidity();
            } catch (java.security.cert.CertificateExpiredException e) {
                throw new CertificateExpiredException(e.getMessage());
            } catch (java.security.cert.CertificateNotYetValidException e2) {
                throw new CertificateNotYetValidException(e2.getMessage());
            }
        }

        @Override // javax.security.cert.X509Certificate
        public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
            try {
                this.f998c.checkValidity(date);
            } catch (java.security.cert.CertificateExpiredException e) {
                throw new CertificateExpiredException(e.getMessage());
            } catch (java.security.cert.CertificateNotYetValidException e2) {
                throw new CertificateNotYetValidException(e2.getMessage());
            }
        }

        @Override // javax.security.cert.Certificate
        public byte[] getEncoded() throws CertificateEncodingException {
            try {
                return this.f998c.getEncoded();
            } catch (java.security.cert.CertificateEncodingException e) {
                throw new CertificateEncodingException(e.getMessage());
            }
        }

        @Override // javax.security.cert.X509Certificate
        public Principal getIssuerDN() {
            return this.f998c.getIssuerX500Principal();
        }

        @Override // javax.security.cert.X509Certificate
        public Date getNotAfter() {
            return this.f998c.getNotAfter();
        }

        @Override // javax.security.cert.X509Certificate
        public Date getNotBefore() {
            return this.f998c.getNotBefore();
        }

        @Override // javax.security.cert.Certificate
        public PublicKey getPublicKey() {
            return this.f998c.getPublicKey();
        }

        @Override // javax.security.cert.X509Certificate
        public BigInteger getSerialNumber() {
            return this.f998c.getSerialNumber();
        }

        @Override // javax.security.cert.X509Certificate
        public String getSigAlgName() {
            return this.f998c.getSigAlgName();
        }

        @Override // javax.security.cert.X509Certificate
        public String getSigAlgOID() {
            return this.f998c.getSigAlgOID();
        }

        @Override // javax.security.cert.X509Certificate
        public byte[] getSigAlgParams() {
            return this.f998c.getSigAlgParams();
        }

        @Override // javax.security.cert.X509Certificate
        public Principal getSubjectDN() {
            return this.f998c.getSubjectX500Principal();
        }

        @Override // javax.security.cert.X509Certificate
        public int getVersion() {
            return this.f998c.getVersion() - 1;
        }

        @Override // javax.security.cert.Certificate
        public String toString() {
            return this.f998c.toString();
        }

        @Override // javax.security.cert.Certificate
        public void verify(PublicKey publicKey) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            try {
                this.f998c.verify(publicKey);
            } catch (java.security.cert.CertificateEncodingException e) {
                throw new CertificateEncodingException(e.getMessage());
            } catch (java.security.cert.CertificateExpiredException e2) {
                throw new CertificateExpiredException(e2.getMessage());
            } catch (java.security.cert.CertificateNotYetValidException e3) {
                throw new CertificateNotYetValidException(e3.getMessage());
            } catch (CertificateParsingException e4) {
                throw new javax.security.cert.CertificateParsingException(e4.getMessage());
            } catch (java.security.cert.CertificateException e5) {
                throw new CertificateException(e5.getMessage());
            }
        }

        @Override // javax.security.cert.Certificate
        public void verify(PublicKey publicKey, String str) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            try {
                this.f998c.verify(publicKey, str);
            } catch (java.security.cert.CertificateEncodingException e) {
                throw new CertificateEncodingException(e.getMessage());
            } catch (java.security.cert.CertificateExpiredException e2) {
                throw new CertificateExpiredException(e2.getMessage());
            } catch (java.security.cert.CertificateNotYetValidException e3) {
                throw new CertificateNotYetValidException(e3.getMessage());
            } catch (CertificateParsingException e4) {
                throw new javax.security.cert.CertificateParsingException(e4.getMessage());
            } catch (java.security.cert.CertificateException e5) {
                throw new CertificateException(e5.getMessage());
            }
        }
    }

    OldCertUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static X509Certificate[] getPeerCertificateChain(BCExtendedSSLSession bCExtendedSSLSession) throws SSLPeerUnverifiedException {
        boolean isFipsMode = bCExtendedSSLSession.isFipsMode();
        Certificate[] peerCertificates = bCExtendedSSLSession.getPeerCertificates();
        int length = peerCertificates.length;
        X509Certificate[] x509CertificateArr = new X509Certificate[length];
        int i = 0;
        for (Certificate certificate : peerCertificates) {
            try {
                if (certificate instanceof java.security.cert.X509Certificate) {
                    java.security.cert.X509Certificate x509Certificate = (java.security.cert.X509Certificate) certificate;
                    int i2 = i + 1;
                    if (isFipsMode) {
                        x509CertificateArr[i] = new X509CertificateWrapper(x509Certificate);
                    } else {
                        x509CertificateArr[i] = X509Certificate.getInstance(x509Certificate.getEncoded());
                    }
                    i = i2;
                }
            } catch (Exception e) {
                throw new SSLPeerUnverifiedException(e.getMessage());
            }
        }
        if (i >= length) {
            return x509CertificateArr;
        }
        X509Certificate[] x509CertificateArr2 = new X509Certificate[i];
        System.arraycopy(x509CertificateArr, 0, x509CertificateArr2, 0, i);
        return x509CertificateArr2;
    }
}