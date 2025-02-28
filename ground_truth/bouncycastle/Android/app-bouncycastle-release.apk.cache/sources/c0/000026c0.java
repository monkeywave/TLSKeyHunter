package org.bouncycastle.jsse.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathParameters;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import org.bouncycastle.jcajce.provider.keystore.util.AdaptingKeyStoreSpi;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.TlsUtils;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvTrustManagerFactorySpi extends TrustManagerFactorySpi {
    private static final Logger LOG = Logger.getLogger(ProvTrustManagerFactorySpi.class.getName());
    private static final boolean provKeyStoreTypeCompat = PropertyUtils.getBooleanSecurityProperty(AdaptingKeyStoreSpi.COMPAT_OVERRIDE, false);
    protected final JcaJceHelper helper;
    protected final boolean isInFipsMode;
    protected ProvX509TrustManager x509TrustManager;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvTrustManagerFactorySpi(boolean z, JcaJceHelper jcaJceHelper) {
        this.isInFipsMode = z;
        this.helper = jcaJceHelper;
    }

    private static void collectTrustAnchor(Set<TrustAnchor> set, Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            set.add(new TrustAnchor((X509Certificate) certificate, null));
        }
    }

    private static KeyStore createTrustStore(String str) throws NoSuchProviderException, KeyStoreException {
        String trustStoreType = getTrustStoreType(str);
        String stringSystemProperty = PropertyUtils.getStringSystemProperty("javax.net.ssl.trustStoreProvider");
        return TlsUtils.isNullOrEmpty(stringSystemProperty) ? KeyStore.getInstance(trustStoreType) : KeyStore.getInstance(trustStoreType, stringSystemProperty);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Can't wrap try/catch for region: R(6:(9:(1:9)(2:34|(2:36|(2:(1:39)|40)(2:41|(1:(1:44)))))|11|(1:13)(1:33)|14|(1:16)(1:31)|17|18|(1:20)|21)|17|18|(0)|21|(2:(1:25)|(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0031, code lost:
        if (new java.io.File(r3).exists() != false) goto L11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00d3, code lost:
        r1 = java.security.KeyStore.getInstance("BCFKS");
        r1.load(null, null);
     */
    /* JADX WARN: Removed duplicated region for block: B:29:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00a6 A[Catch: all -> 0x00e2, TRY_ENTER, TryCatch #0 {all -> 0x00e2, blocks: (B:32:0x00a6, B:33:0x00af), top: B:46:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00af A[Catch: all -> 0x00e2, TRY_LEAVE, TryCatch #0 {all -> 0x00e2, blocks: (B:32:0x00a6, B:33:0x00af), top: B:46:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00de  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static java.security.KeyStore getDefaultTrustStore() throws java.lang.Exception {
        /*
            java.lang.String r0 = "Initializing default trust store from path: "
            java.lang.String r1 = java.security.KeyStore.getDefaultType()
            boolean r2 = org.bouncycastle.jsse.provider.ProvTrustManagerFactorySpi.provKeyStoreTypeCompat
            if (r2 == 0) goto L14
            java.lang.String r2 = "pkcs12"
            boolean r2 = r2.equalsIgnoreCase(r1)
            if (r2 == 0) goto L14
            r2 = 1
            goto L15
        L14:
            r2 = 0
        L15:
            java.lang.String r3 = "javax.net.ssl.trustStore"
            java.lang.String r3 = org.bouncycastle.jsse.provider.PropertyUtils.getStringSystemProperty(r3)
            java.lang.String r4 = "NONE"
            boolean r4 = r4.equals(r3)
            r5 = 0
            if (r4 == 0) goto L26
            goto L91
        L26:
            if (r3 == 0) goto L34
            java.io.File r2 = new java.io.File
            r2.<init>(r3)
            boolean r2 = r2.exists()
            if (r2 == 0) goto L91
            goto L92
        L34:
            java.lang.String r3 = "java.home"
            java.lang.String r3 = org.bouncycastle.jsse.provider.PropertyUtils.getStringSystemProperty(r3)
            if (r3 == 0) goto L91
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>()
            java.lang.StringBuilder r4 = r4.append(r3)
            java.lang.String r6 = "/lib/security/jssecacerts"
            java.lang.String r7 = java.io.File.separator
            java.lang.String r8 = "/"
            java.lang.String r6 = r6.replace(r8, r7)
            java.lang.StringBuilder r4 = r4.append(r6)
            java.lang.String r4 = r4.toString()
            java.io.File r6 = new java.io.File
            r6.<init>(r4)
            boolean r6 = r6.exists()
            java.lang.String r7 = "jks"
            if (r6 == 0) goto L69
            if (r2 == 0) goto L67
            r1 = r7
        L67:
            r3 = r4
            goto L92
        L69:
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>()
            java.lang.StringBuilder r3 = r4.append(r3)
            java.lang.String r4 = "/lib/security/cacerts"
            java.lang.String r6 = java.io.File.separator
            java.lang.String r4 = r4.replace(r8, r6)
            java.lang.StringBuilder r3 = r3.append(r4)
            java.lang.String r3 = r3.toString()
            java.io.File r4 = new java.io.File
            r4.<init>(r3)
            boolean r4 = r4.exists()
            if (r4 == 0) goto L91
            if (r2 == 0) goto L92
            r1 = r7
            goto L92
        L91:
            r3 = r5
        L92:
            java.security.KeyStore r1 = createTrustStore(r1)
            java.lang.String r2 = "javax.net.ssl.trustStorePassword"
            java.lang.String r2 = org.bouncycastle.jsse.provider.PropertyUtils.getSensitiveStringSystemProperty(r2)
            if (r2 == 0) goto La3
            char[] r2 = r2.toCharArray()
            goto La4
        La3:
            r2 = r5
        La4:
            if (r3 != 0) goto Laf
            java.util.logging.Logger r0 = org.bouncycastle.jsse.provider.ProvTrustManagerFactorySpi.LOG     // Catch: java.lang.Throwable -> Le2
            java.lang.String r3 = "Initializing default trust store as empty"
            r0.config(r3)     // Catch: java.lang.Throwable -> Le2
            r0 = r5
            goto Lcb
        Laf:
            java.util.logging.Logger r4 = org.bouncycastle.jsse.provider.ProvTrustManagerFactorySpi.LOG     // Catch: java.lang.Throwable -> Le2
            java.lang.StringBuilder r6 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> Le2
            r6.<init>(r0)     // Catch: java.lang.Throwable -> Le2
            java.lang.StringBuilder r0 = r6.append(r3)     // Catch: java.lang.Throwable -> Le2
            java.lang.String r0 = r0.toString()     // Catch: java.lang.Throwable -> Le2
            r4.config(r0)     // Catch: java.lang.Throwable -> Le2
            java.io.BufferedInputStream r0 = new java.io.BufferedInputStream     // Catch: java.lang.Throwable -> Le2
            java.io.FileInputStream r4 = new java.io.FileInputStream     // Catch: java.lang.Throwable -> Le2
            r4.<init>(r3)     // Catch: java.lang.Throwable -> Le2
            r0.<init>(r4)     // Catch: java.lang.Throwable -> Le2
        Lcb:
            r1.load(r0, r2)     // Catch: java.lang.Throwable -> Lcf java.lang.NullPointerException -> Ld3
            goto Ldc
        Lcf:
            r1 = move-exception
            r5 = r0
            r0 = r1
            goto Le3
        Ld3:
            java.lang.String r1 = "BCFKS"
            java.security.KeyStore r1 = java.security.KeyStore.getInstance(r1)     // Catch: java.lang.Throwable -> Lcf
            r1.load(r5, r5)     // Catch: java.lang.Throwable -> Lcf
        Ldc:
            if (r0 == 0) goto Le1
            r0.close()
        Le1:
            return r1
        Le2:
            r0 = move-exception
        Le3:
            if (r5 == 0) goto Le8
            r5.close()
        Le8:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jsse.provider.ProvTrustManagerFactorySpi.getDefaultTrustStore():java.security.KeyStore");
    }

    private static Set<TrustAnchor> getTrustAnchors(KeyStore keyStore) throws KeyStoreException {
        Certificate certificate;
        Certificate[] certificateChain;
        if (keyStore == null) {
            return Collections.emptySet();
        }
        HashSet hashSet = new HashSet();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String nextElement = aliases.nextElement();
            if (keyStore.isCertificateEntry(nextElement)) {
                certificate = keyStore.getCertificate(nextElement);
            } else if (keyStore.isKeyEntry(nextElement) && (certificateChain = keyStore.getCertificateChain(nextElement)) != null && certificateChain.length > 0) {
                certificate = certificateChain[0];
            }
            collectTrustAnchor(hashSet, certificate);
        }
        return hashSet;
    }

    private static String getTrustStoreType(String str) {
        String stringSystemProperty = PropertyUtils.getStringSystemProperty("javax.net.ssl.trustStoreType");
        return stringSystemProperty == null ? str : stringSystemProperty;
    }

    @Override // javax.net.ssl.TrustManagerFactorySpi
    protected TrustManager[] engineGetTrustManagers() {
        ProvX509TrustManager provX509TrustManager = this.x509TrustManager;
        if (provX509TrustManager != null) {
            return new TrustManager[]{provX509TrustManager.getExportX509TrustManager()};
        }
        throw new IllegalStateException("TrustManagerFactory not initialized");
    }

    @Override // javax.net.ssl.TrustManagerFactorySpi
    protected void engineInit(KeyStore keyStore) throws KeyStoreException {
        if (keyStore == null) {
            try {
                keyStore = getDefaultTrustStore();
            } catch (Error e) {
                LOG.log(Level.WARNING, "Skipped default trust store", (Throwable) e);
                throw e;
            } catch (SecurityException e2) {
                LOG.log(Level.WARNING, "Skipped default trust store", (Throwable) e2);
            } catch (RuntimeException e3) {
                LOG.log(Level.WARNING, "Skipped default trust store", (Throwable) e3);
                throw e3;
            } catch (Exception e4) {
                LOG.log(Level.WARNING, "Skipped default trust store", (Throwable) e4);
                throw new KeyStoreException("Failed to load default trust store", e4);
            }
        }
        try {
            this.x509TrustManager = new ProvX509TrustManager(this.isInFipsMode, this.helper, getTrustAnchors(keyStore));
        } catch (InvalidAlgorithmParameterException e5) {
            throw new KeyStoreException("Failed to create trust manager", e5);
        }
    }

    @Override // javax.net.ssl.TrustManagerFactorySpi
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        if (!(managerFactoryParameters instanceof CertPathTrustManagerParameters)) {
            if (managerFactoryParameters != null) {
                throw new InvalidAlgorithmParameterException("unknown spec: " + managerFactoryParameters.getClass().getName());
            }
            throw new InvalidAlgorithmParameterException("spec cannot be null");
        }
        CertPathParameters parameters = ((CertPathTrustManagerParameters) managerFactoryParameters).getParameters();
        if (!(parameters instanceof PKIXParameters)) {
            throw new InvalidAlgorithmParameterException("parameters must inherit from PKIXParameters");
        }
        this.x509TrustManager = new ProvX509TrustManager(this.isInFipsMode, this.helper, (PKIXParameters) parameters);
    }
}