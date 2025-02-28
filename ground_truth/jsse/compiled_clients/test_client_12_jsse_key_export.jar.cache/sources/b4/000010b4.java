package org.openjsse.sun.security.ssl;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyManagerFactoryImpl.class */
abstract class KeyManagerFactoryImpl extends KeyManagerFactorySpi {
    X509ExtendedKeyManager keyManager;
    boolean isInitialized;

    KeyManagerFactoryImpl() {
    }

    @Override // javax.net.ssl.KeyManagerFactorySpi
    protected KeyManager[] engineGetKeyManagers() {
        if (this.isInitialized) {
            return new KeyManager[]{this.keyManager};
        }
        throw new IllegalStateException("KeyManagerFactoryImpl is not initialized");
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyManagerFactoryImpl$SunX509.class */
    public static final class SunX509 extends KeyManagerFactoryImpl {
        @Override // javax.net.ssl.KeyManagerFactorySpi
        protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
            if (ks != null && OpenJSSE.isFIPS() && ks.getProvider() != OpenJSSE.cryptoProvider) {
                throw new KeyStoreException("FIPS mode: KeyStore must be from provider " + OpenJSSE.cryptoProvider.getName());
            }
            this.keyManager = new SunX509KeyManagerImpl(ks, password);
            this.isInitialized = true;
        }

        @Override // javax.net.ssl.KeyManagerFactorySpi
        protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("SunX509KeyManager does not use ManagerFactoryParameters");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyManagerFactoryImpl$X509.class */
    public static final class X509 extends KeyManagerFactoryImpl {
        @Override // javax.net.ssl.KeyManagerFactorySpi
        protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
            if (ks == null) {
                this.keyManager = new X509KeyManagerImpl(Collections.emptyList());
            } else if (OpenJSSE.isFIPS() && ks.getProvider() != OpenJSSE.cryptoProvider) {
                throw new KeyStoreException("FIPS mode: KeyStore must be from provider " + OpenJSSE.cryptoProvider.getName());
            } else {
                try {
                    KeyStore.Builder builder = KeyStore.Builder.newInstance(ks, new KeyStore.PasswordProtection(password));
                    this.keyManager = new X509KeyManagerImpl(builder);
                } catch (RuntimeException e) {
                    throw new KeyStoreException("initialization failed", e);
                }
            }
            this.isInitialized = true;
        }

        @Override // javax.net.ssl.KeyManagerFactorySpi
        protected void engineInit(ManagerFactoryParameters params) throws InvalidAlgorithmParameterException {
            if (!(params instanceof KeyStoreBuilderParameters)) {
                throw new InvalidAlgorithmParameterException("Parameters must be instance of KeyStoreBuilderParameters");
            }
            if (OpenJSSE.isFIPS()) {
                throw new InvalidAlgorithmParameterException("FIPS mode: KeyStoreBuilderParameters not supported");
            }
            List<KeyStore.Builder> builders = ((KeyStoreBuilderParameters) params).getParameters();
            this.keyManager = new X509KeyManagerImpl(builders);
            this.isInitialized = true;
        }
    }
}