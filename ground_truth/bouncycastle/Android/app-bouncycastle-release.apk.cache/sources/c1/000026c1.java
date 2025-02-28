package org.bouncycastle.jsse.provider;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.X509KeyManager;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.tls.TlsUtils;

/* loaded from: classes2.dex */
class ProvX509Key implements BCX509Key {
    private static final Logger LOG = Logger.getLogger(ProvX509Key.class.getName());
    private final X509Certificate[] certificateChain;
    private final String keyType;
    private final PrivateKey privateKey;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvX509Key(String str, PrivateKey privateKey, X509Certificate[] x509CertificateArr) {
        this.keyType = str;
        this.privateKey = privateKey;
        this.certificateChain = x509CertificateArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ProvX509Key from(X509KeyManager x509KeyManager, String str, String str2) {
        X509Certificate[] certificateChain;
        PrivateKey privateKey;
        if (x509KeyManager != null) {
            if (str == null || str2 == null || (certificateChain = getCertificateChain(x509KeyManager, str2)) == null || (privateKey = getPrivateKey(x509KeyManager, str2)) == null) {
                return null;
            }
            return new ProvX509Key(str, privateKey, certificateChain);
        }
        throw new NullPointerException("'x509KeyManager' cannot be null");
    }

    private static X509Certificate[] getCertificateChain(X509KeyManager x509KeyManager, String str) {
        Logger logger;
        StringBuilder append;
        String str2;
        X509Certificate[] certificateChain = x509KeyManager.getCertificateChain(str);
        if (TlsUtils.isNullOrEmpty(certificateChain)) {
            logger = LOG;
            append = new StringBuilder("Rejecting alias '").append(str);
            str2 = "': no certificate chain";
        } else {
            X509Certificate[] x509CertificateArr = (X509Certificate[]) certificateChain.clone();
            if (!JsseUtils.containsNull(x509CertificateArr)) {
                return x509CertificateArr;
            }
            logger = LOG;
            append = new StringBuilder("Rejecting alias '").append(str);
            str2 = "': invalid certificate chain";
        }
        logger.finer(append.append(str2).toString());
        return null;
    }

    private static PrivateKey getPrivateKey(X509KeyManager x509KeyManager, String str) {
        PrivateKey privateKey = x509KeyManager.getPrivateKey(str);
        if (privateKey == null) {
            LOG.finer("Rejecting alias '" + str + "': no private key");
            return null;
        }
        return privateKey;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ProvX509Key validate(X509KeyManager x509KeyManager, boolean z, String str, String str2, TransportData transportData) {
        X509Certificate[] certificateChain;
        if (x509KeyManager != null) {
            if (str == null || str2 == null || (certificateChain = getCertificateChain(x509KeyManager, str2)) == null) {
                return null;
            }
            if (ProvX509KeyManager.isSuitableKeyType(z, str, certificateChain[0], transportData)) {
                PrivateKey privateKey = getPrivateKey(x509KeyManager, str2);
                if (privateKey == null) {
                    return null;
                }
                return new ProvX509Key(str, privateKey, certificateChain);
            }
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINER)) {
                logger.finer("Rejecting alias '" + str2 + "': not suitable for key type '" + str + "'");
            }
            return null;
        }
        throw new NullPointerException("'x509KeyManager' cannot be null");
    }

    @Override // org.bouncycastle.jsse.BCX509Key
    public X509Certificate[] getCertificateChain() {
        return (X509Certificate[]) this.certificateChain.clone();
    }

    @Override // org.bouncycastle.jsse.BCX509Key
    public String getKeyType() {
        return this.keyType;
    }

    @Override // org.bouncycastle.jsse.BCX509Key
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}