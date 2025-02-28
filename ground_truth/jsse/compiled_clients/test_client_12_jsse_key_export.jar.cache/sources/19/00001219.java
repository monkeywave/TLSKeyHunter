package org.openjsse.sun.security.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.lang.ref.WeakReference;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.Set;
import org.openjsse.sun.security.validator.TrustStoreUtil;
import sun.security.action.GetPropertyAction;
import sun.security.action.OpenFileInputStreamAction;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/TrustStoreManager.class */
final class TrustStoreManager {
    private static final TrustAnchorManager tam = new TrustAnchorManager();

    private TrustStoreManager() {
    }

    public static Set<X509Certificate> getTrustedCerts() throws Exception {
        return tam.getTrustedCerts(TrustStoreDescriptor.createInstance());
    }

    public static KeyStore getTrustedKeyStore() throws Exception {
        return tam.getKeyStore(TrustStoreDescriptor.createInstance());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/TrustStoreManager$TrustStoreDescriptor.class */
    public static final class TrustStoreDescriptor {
        private static final String fileSep = File.separator;
        private static final String defaultStorePath = GetPropertyAction.privilegedGetProperty("java.home") + fileSep + "lib" + fileSep + "security";
        private static final String defaultStore = defaultStorePath + fileSep + "cacerts";
        private static final String jsseDefaultStore = defaultStorePath + fileSep + "jssecacerts";
        private final String storeName;
        private final String storeType;
        private final String storeProvider;
        private final String storePassword;
        private final File storeFile;
        private final long lastModified;

        private TrustStoreDescriptor(String storeName, String storeType, String storeProvider, String storePassword, File storeFile, long lastModified) {
            this.storeName = storeName;
            this.storeType = storeType;
            this.storeProvider = storeProvider;
            this.storePassword = storePassword;
            this.storeFile = storeFile;
            this.lastModified = lastModified;
            if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                SSLLogger.fine("trustStore is: " + storeName + "\ntrustStore type is: " + storeType + "\ntrustStore provider is: " + storeProvider + "\nthe last modified time is: " + new Date(lastModified), new Object[0]);
            }
        }

        static TrustStoreDescriptor createInstance() {
            return (TrustStoreDescriptor) AccessController.doPrivileged(new PrivilegedAction<TrustStoreDescriptor>() { // from class: org.openjsse.sun.security.ssl.TrustStoreManager.TrustStoreDescriptor.1
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedAction
                public TrustStoreDescriptor run() {
                    String storePropName = System.getProperty("javax.net.ssl.trustStore", TrustStoreDescriptor.jsseDefaultStore);
                    String storePropType = System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType());
                    String storePropProvider = System.getProperty("javax.net.ssl.trustStoreProvider", "");
                    String storePropPassword = System.getProperty("javax.net.ssl.trustStorePassword", "");
                    String temporaryName = "";
                    File temporaryFile = null;
                    long temporaryTime = 0;
                    if (!"NONE".equals(storePropName)) {
                        String[] fileNames = {storePropName, TrustStoreDescriptor.defaultStore};
                        int length = fileNames.length;
                        int i = 0;
                        while (true) {
                            if (i >= length) {
                                break;
                            }
                            String fileName = fileNames[i];
                            File f = new File(fileName);
                            if (f.isFile() && f.canRead()) {
                                temporaryName = fileName;
                                temporaryFile = f;
                                temporaryTime = f.lastModified();
                                break;
                            }
                            if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                                SSLLogger.fine("Inaccessible trust store: " + storePropName, new Object[0]);
                            }
                            i++;
                        }
                    } else {
                        temporaryName = storePropName;
                    }
                    return new TrustStoreDescriptor(temporaryName, storePropType, storePropProvider, storePropPassword, temporaryFile, temporaryTime);
                }
            });
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (obj instanceof TrustStoreDescriptor) {
                TrustStoreDescriptor that = (TrustStoreDescriptor) obj;
                return this.lastModified == that.lastModified && Objects.equals(this.storeName, that.storeName) && Objects.equals(this.storeType, that.storeType) && Objects.equals(this.storeProvider, that.storeProvider);
            }
            return false;
        }

        public int hashCode() {
            int result = 17;
            if (this.storeName != null && !this.storeName.isEmpty()) {
                result = (31 * 17) + this.storeName.hashCode();
            }
            if (this.storeType != null && !this.storeType.isEmpty()) {
                result = (31 * result) + this.storeType.hashCode();
            }
            if (this.storeProvider != null && !this.storeProvider.isEmpty()) {
                result = (31 * result) + this.storeProvider.hashCode();
            }
            if (this.storeFile != null) {
                result = (31 * result) + this.storeFile.hashCode();
            }
            if (this.lastModified != 0) {
                result = (int) ((31 * result) + this.lastModified);
            }
            return result;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/TrustStoreManager$TrustAnchorManager.class */
    private static final class TrustAnchorManager {
        private TrustStoreDescriptor descriptor;
        private WeakReference<KeyStore> ksRef;
        private WeakReference<Set<X509Certificate>> csRef;

        private TrustAnchorManager() {
            this.descriptor = null;
            this.ksRef = new WeakReference<>(null);
            this.csRef = new WeakReference<>(null);
        }

        synchronized KeyStore getKeyStore(TrustStoreDescriptor descriptor) throws Exception {
            TrustStoreDescriptor temporaryDesc = this.descriptor;
            KeyStore ks = this.ksRef.get();
            if (ks != null && descriptor.equals(temporaryDesc)) {
                return ks;
            }
            if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                SSLLogger.fine("Reload the trust store", new Object[0]);
            }
            KeyStore ks2 = loadKeyStore(descriptor);
            this.descriptor = descriptor;
            this.ksRef = new WeakReference<>(ks2);
            return ks2;
        }

        synchronized Set<X509Certificate> getTrustedCerts(TrustStoreDescriptor descriptor) throws Exception {
            KeyStore ks = null;
            TrustStoreDescriptor temporaryDesc = this.descriptor;
            Set<X509Certificate> certs = this.csRef.get();
            if (certs != null) {
                if (descriptor.equals(temporaryDesc)) {
                    return certs;
                }
                this.descriptor = descriptor;
            } else if (descriptor.equals(temporaryDesc)) {
                ks = this.ksRef.get();
            } else {
                this.descriptor = descriptor;
            }
            if (ks == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                    SSLLogger.fine("Reload the trust store", new Object[0]);
                }
                ks = loadKeyStore(descriptor);
            }
            if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                SSLLogger.fine("Reload trust certs", new Object[0]);
            }
            Set<X509Certificate> certs2 = loadTrustedCerts(ks);
            if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                SSLLogger.fine("Reloaded " + certs2.size() + " trust certs", new Object[0]);
            }
            this.csRef = new WeakReference<>(certs2);
            return certs2;
        }

        private static KeyStore loadKeyStore(TrustStoreDescriptor descriptor) throws Exception {
            KeyStore ks;
            if ("NONE".equals(descriptor.storeName) || descriptor.storeFile != null) {
                if (descriptor.storeProvider.isEmpty()) {
                    ks = KeyStore.getInstance(descriptor.storeType);
                } else {
                    ks = KeyStore.getInstance(descriptor.storeType, descriptor.storeProvider);
                }
                char[] password = null;
                if (!descriptor.storePassword.isEmpty()) {
                    password = descriptor.storePassword.toCharArray();
                }
                if (!"NONE".equals(descriptor.storeName)) {
                    try {
                        FileInputStream fis = (FileInputStream) AccessController.doPrivileged((PrivilegedExceptionAction<Object>) new OpenFileInputStreamAction(descriptor.storeFile));
                        ks.load(fis, password);
                        if (fis != null) {
                            if (0 != 0) {
                                fis.close();
                            } else {
                                fis.close();
                            }
                        }
                    } catch (FileNotFoundException e) {
                        if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                            SSLLogger.fine("Not available key store: " + descriptor.storeName, new Object[0]);
                            return null;
                        }
                        return null;
                    }
                } else {
                    ks.load(null, password);
                }
                return ks;
            } else if (SSLLogger.isOn && SSLLogger.isOn("trustmanager")) {
                SSLLogger.fine("No available key store", new Object[0]);
                return null;
            } else {
                return null;
            }
        }

        private static Set<X509Certificate> loadTrustedCerts(KeyStore ks) {
            if (ks == null) {
                return Collections.emptySet();
            }
            return TrustStoreUtil.getTrustedCerts(ks);
        }
    }
}