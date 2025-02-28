package org.openjsse.sun.security.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.CertPathParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;
import org.openjsse.sun.security.validator.TrustStoreUtil;
import org.openjsse.sun.security.validator.Validator;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/TrustManagerFactoryImpl.class */
abstract class TrustManagerFactoryImpl extends TrustManagerFactorySpi {
    private X509TrustManager trustManager = null;
    private boolean isInitialized = false;

    abstract X509TrustManager getInstance(Collection<X509Certificate> collection);

    abstract X509TrustManager getInstance(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException;

    TrustManagerFactoryImpl() {
    }

    @Override // javax.net.ssl.TrustManagerFactorySpi
    protected void engineInit(KeyStore ks) throws KeyStoreException {
        if (ks == null) {
            try {
                this.trustManager = getInstance(TrustStoreManager.getTrustedCerts());
            } catch (Error err) {
                if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                    SSLLogger.fine("SunX509: skip default keystore", err);
                }
                throw err;
            } catch (SecurityException se) {
                if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                    SSLLogger.fine("SunX509: skip default keystore", se);
                }
            } catch (RuntimeException re) {
                if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                    SSLLogger.fine("SunX509: skip default keystor", re);
                }
                throw re;
            } catch (Exception e) {
                if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                    SSLLogger.fine("SunX509: skip default keystore", e);
                }
                throw new KeyStoreException("problem accessing trust store", e);
            }
        } else {
            this.trustManager = getInstance(TrustStoreUtil.getTrustedCerts(ks));
        }
        this.isInitialized = true;
    }

    @Override // javax.net.ssl.TrustManagerFactorySpi
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        this.trustManager = getInstance(spec);
        this.isInitialized = true;
    }

    @Override // javax.net.ssl.TrustManagerFactorySpi
    protected TrustManager[] engineGetTrustManagers() {
        if (this.isInitialized) {
            return new TrustManager[]{this.trustManager};
        }
        throw new IllegalStateException("TrustManagerFactoryImpl is not initialized");
    }

    private static FileInputStream getFileInputStream(final File file) throws Exception {
        return (FileInputStream) AccessController.doPrivileged(new PrivilegedExceptionAction<FileInputStream>() { // from class: org.openjsse.sun.security.ssl.TrustManagerFactoryImpl.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedExceptionAction
            public FileInputStream run() throws Exception {
                try {
                    if (file.exists()) {
                        return new FileInputStream(file);
                    }
                    return null;
                } catch (FileNotFoundException e) {
                    return null;
                }
            }
        });
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/TrustManagerFactoryImpl$SimpleFactory.class */
    public static final class SimpleFactory extends TrustManagerFactoryImpl {
        @Override // org.openjsse.sun.security.ssl.TrustManagerFactoryImpl
        X509TrustManager getInstance(Collection<X509Certificate> trustedCerts) {
            return new X509TrustManagerImpl(Validator.TYPE_SIMPLE, trustedCerts);
        }

        @Override // org.openjsse.sun.security.ssl.TrustManagerFactoryImpl
        X509TrustManager getInstance(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("SunX509 TrustManagerFactory does not use ManagerFactoryParameters");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/TrustManagerFactoryImpl$PKIXFactory.class */
    public static final class PKIXFactory extends TrustManagerFactoryImpl {
        @Override // org.openjsse.sun.security.ssl.TrustManagerFactoryImpl
        X509TrustManager getInstance(Collection<X509Certificate> trustedCerts) {
            return new X509TrustManagerImpl(Validator.TYPE_PKIX, trustedCerts);
        }

        @Override // org.openjsse.sun.security.ssl.TrustManagerFactoryImpl
        X509TrustManager getInstance(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
            if (!(spec instanceof CertPathTrustManagerParameters)) {
                throw new InvalidAlgorithmParameterException("Parameters must be CertPathTrustManagerParameters");
            }
            CertPathParameters params = ((CertPathTrustManagerParameters) spec).getParameters();
            if (!(params instanceof PKIXBuilderParameters)) {
                throw new InvalidAlgorithmParameterException("Encapsulated parameters must be PKIXBuilderParameters");
            }
            PKIXBuilderParameters pkixParams = (PKIXBuilderParameters) params;
            return new X509TrustManagerImpl(Validator.TYPE_PKIX, pkixParams);
        }
    }
}