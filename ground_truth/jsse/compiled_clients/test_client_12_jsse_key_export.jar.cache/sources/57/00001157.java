package org.openjsse.sun.security.ssl;

import java.io.FileInputStream;
import java.security.AccessController;
import java.security.CryptoPrimitive;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.PrivilegedExceptionAction;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.openjsse.javax.net.ssl.SSLEngine;
import org.openjsse.sun.security.ssl.HelloCookieManager;
import sun.security.action.GetPropertyAction;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl.class */
public abstract class SSLContextImpl extends SSLContextSpi {
    private boolean isInitialized;
    private X509ExtendedKeyManager keyManager;
    private X509TrustManager trustManager;
    private SecureRandom secureRandom;
    private volatile HelloCookieManager.Builder helloCookieManagerBuilder;
    private static final Collection<CipherSuite> clientCustomizedCipherSuites = getCustomizedCipherSuites("jdk.tls.client.cipherSuites");
    private static final Collection<CipherSuite> serverCustomizedCipherSuites = getCustomizedCipherSuites("jdk.tls.server.cipherSuites");
    private volatile StatusResponseManager statusResponseManager;
    private final boolean clientEnableStapling = Utilities.getBooleanProperty("jdk.tls.client.enableStatusRequestExtension", true);
    private final boolean serverEnableStapling = Utilities.getBooleanProperty("jdk.tls.server.enableStatusRequestExtension", false);
    private final EphemeralKeyManager ephemeralKeyManager = new EphemeralKeyManager();
    private final SSLSessionContextImpl clientCache = new SSLSessionContextImpl();
    private final SSLSessionContextImpl serverCache = new SSLSessionContextImpl();

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$DTLSContext.class */
    public static final class DTLSContext extends CustomizedDTLSContext {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$TLSContext.class */
    public static final class TLSContext extends CustomizedTLSContext {
    }

    abstract SSLEngine createSSLEngineImpl();

    abstract SSLEngine createSSLEngineImpl(String str, int i);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract List<ProtocolVersion> getSupportedProtocolVersions();

    abstract List<ProtocolVersion> getServerDefaultProtocolVersions();

    abstract List<ProtocolVersion> getClientDefaultProtocolVersions();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract List<CipherSuite> getSupportedCipherSuites();

    abstract List<CipherSuite> getServerDefaultCipherSuites();

    abstract List<CipherSuite> getClientDefaultCipherSuites();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract boolean isDTLS();

    SSLContextImpl() {
    }

    @Override // javax.net.ssl.SSLContextSpi
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        this.isInitialized = false;
        this.keyManager = chooseKeyManager(km);
        if (tm == null) {
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((KeyStore) null);
                tm = tmf.getTrustManagers();
            } catch (Exception e) {
            }
        }
        this.trustManager = chooseTrustManager(tm);
        if (sr == null) {
            this.secureRandom = JsseJce.getSecureRandom();
        } else if (OpenJSSE.isFIPS() && sr.getProvider() != OpenJSSE.cryptoProvider) {
            throw new KeyManagementException("FIPS mode: SecureRandom must be from provider " + OpenJSSE.cryptoProvider.getName());
        } else {
            this.secureRandom = sr;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
            SSLLogger.finest("trigger seeding of SecureRandom", new Object[0]);
        }
        this.secureRandom.nextInt();
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
            SSLLogger.finest("done seeding of SecureRandom", new Object[0]);
        }
        this.isInitialized = true;
    }

    private X509TrustManager chooseTrustManager(TrustManager[] tm) throws KeyManagementException {
        for (int i = 0; tm != null && i < tm.length; i++) {
            if (tm[i] instanceof X509TrustManager) {
                if (OpenJSSE.isFIPS() && !(tm[i] instanceof X509TrustManagerImpl)) {
                    throw new KeyManagementException("FIPS mode: only OpenJSSE TrustManagers may be used");
                } else {
                    if (tm[i] instanceof X509ExtendedTrustManager) {
                        return (X509TrustManager) tm[i];
                    }
                    return new AbstractTrustManagerWrapper((X509TrustManager) tm[i]);
                }
            }
        }
        return DummyX509TrustManager.INSTANCE;
    }

    private X509ExtendedKeyManager chooseKeyManager(KeyManager[] kms) throws KeyManagementException {
        for (int i = 0; kms != null && i < kms.length; i++) {
            KeyManager km = kms[i];
            if (km instanceof X509KeyManager) {
                if (OpenJSSE.isFIPS()) {
                    if ((km instanceof X509KeyManagerImpl) || (km instanceof SunX509KeyManagerImpl)) {
                        return (X509ExtendedKeyManager) km;
                    }
                    throw new KeyManagementException("FIPS mode: only OpenJSSE KeyManagers may be used");
                } else if (km instanceof X509ExtendedKeyManager) {
                    return (X509ExtendedKeyManager) km;
                } else {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
                        SSLLogger.warning("X509KeyManager passed to SSLContext.init():  need an X509ExtendedKeyManager for SSLEngine use", new Object[0]);
                    }
                    return new AbstractKeyManagerWrapper((X509KeyManager) km);
                }
            }
        }
        return DummyX509KeyManager.INSTANCE;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // javax.net.ssl.SSLContextSpi
    public SSLEngine engineCreateSSLEngine() {
        if (!this.isInitialized) {
            throw new IllegalStateException("SSLContext is not initialized");
        }
        return createSSLEngineImpl();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // javax.net.ssl.SSLContextSpi
    public SSLEngine engineCreateSSLEngine(String host, int port) {
        if (!this.isInitialized) {
            throw new IllegalStateException("SSLContext is not initialized");
        }
        return createSSLEngineImpl(host, port);
    }

    @Override // javax.net.ssl.SSLContextSpi
    protected SSLSocketFactory engineGetSocketFactory() {
        if (!this.isInitialized) {
            throw new IllegalStateException("SSLContext is not initialized");
        }
        return new SSLSocketFactoryImpl(this);
    }

    @Override // javax.net.ssl.SSLContextSpi
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        if (!this.isInitialized) {
            throw new IllegalStateException("SSLContext is not initialized");
        }
        return new SSLServerSocketFactoryImpl(this);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // javax.net.ssl.SSLContextSpi
    public SSLSessionContext engineGetClientSessionContext() {
        return this.clientCache;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // javax.net.ssl.SSLContextSpi
    public SSLSessionContext engineGetServerSessionContext() {
        return this.serverCache;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecureRandom getSecureRandom() {
        return this.secureRandom;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509ExtendedKeyManager getX509KeyManager() {
        return this.keyManager;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509TrustManager getX509TrustManager() {
        return this.trustManager;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public EphemeralKeyManager getEphemeralKeyManager() {
        return this.ephemeralKeyManager;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public HelloCookieManager getHelloCookieManager(ProtocolVersion protocolVersion) {
        if (this.helloCookieManagerBuilder == null) {
            synchronized (this) {
                if (this.helloCookieManagerBuilder == null) {
                    this.helloCookieManagerBuilder = new HelloCookieManager.Builder(this.secureRandom);
                }
            }
        }
        return this.helloCookieManagerBuilder.valueOf(protocolVersion);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public StatusResponseManager getStatusResponseManager() {
        if (this.serverEnableStapling && this.statusResponseManager == null) {
            synchronized (this) {
                if (this.statusResponseManager == null) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
                        SSLLogger.finest("Initializing StatusResponseManager", new Object[0]);
                    }
                    this.statusResponseManager = new StatusResponseManager();
                }
            }
        }
        return this.statusResponseManager;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<ProtocolVersion> getDefaultProtocolVersions(boolean roleIsServer) {
        return roleIsServer ? getServerDefaultProtocolVersions() : getClientDefaultProtocolVersions();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<CipherSuite> getDefaultCipherSuites(boolean roleIsServer) {
        return roleIsServer ? getServerDefaultCipherSuites() : getClientDefaultCipherSuites();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isDefaultProtocolVesions(List<ProtocolVersion> protocols) {
        return protocols == getServerDefaultProtocolVersions() || protocols == getClientDefaultProtocolVersions();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isDefaultCipherSuiteList(List<CipherSuite> cipherSuites) {
        return cipherSuites == getServerDefaultCipherSuites() || cipherSuites == getClientDefaultCipherSuites();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isStaplingEnabled(boolean isClient) {
        return isClient ? this.clientEnableStapling : this.serverEnableStapling;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static List<CipherSuite> getApplicableSupportedCipherSuites(List<ProtocolVersion> protocols) {
        return getApplicableCipherSuites(CipherSuite.allowedCipherSuites(), protocols);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static List<CipherSuite> getApplicableEnabledCipherSuites(List<ProtocolVersion> protocols, boolean isClient) {
        if (isClient) {
            if (!clientCustomizedCipherSuites.isEmpty()) {
                return getApplicableCipherSuites(clientCustomizedCipherSuites, protocols);
            }
        } else if (!serverCustomizedCipherSuites.isEmpty()) {
            return getApplicableCipherSuites(serverCustomizedCipherSuites, protocols);
        }
        return getApplicableCipherSuites(CipherSuite.defaultCipherSuites(), protocols);
    }

    private static List<CipherSuite> getApplicableCipherSuites(Collection<CipherSuite> allowedCipherSuites, List<ProtocolVersion> protocols) {
        TreeSet<CipherSuite> suites = new TreeSet<>();
        if (protocols != null && !protocols.isEmpty()) {
            for (CipherSuite suite : allowedCipherSuites) {
                if (suite.isAvailable()) {
                    boolean isSupported = false;
                    Iterator<ProtocolVersion> it = protocols.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        ProtocolVersion protocol = it.next();
                        if (suite.supports(protocol) && suite.bulkCipher.isAvailable()) {
                            if (SSLAlgorithmConstraints.DEFAULT.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), suite.name, null)) {
                                suites.add(suite);
                                isSupported = true;
                            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx,verbose")) {
                                SSLLogger.fine("Ignore disabled cipher suite: " + suite.name, new Object[0]);
                            }
                        }
                    }
                    if (!isSupported && SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx,verbose")) {
                        SSLLogger.finest("Ignore unsupported cipher suite: " + suite, new Object[0]);
                    }
                }
            }
        }
        return new ArrayList(suites);
    }

    private static Collection<CipherSuite> getCustomizedCipherSuites(String propertyName) {
        String property = GetPropertyAction.privilegedGetProperty(propertyName);
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
            SSLLogger.fine("System property " + propertyName + " is set to '" + property + "'", new Object[0]);
        }
        if (property != null && property.length() != 0 && property.length() > 1 && property.charAt(0) == '\"' && property.charAt(property.length() - 1) == '\"') {
            property = property.substring(1, property.length() - 1);
        }
        if (property != null && property.length() != 0) {
            String[] cipherSuiteNames = property.split(",");
            Collection<CipherSuite> cipherSuites = new ArrayList<>(cipherSuiteNames.length);
            for (int i = 0; i < cipherSuiteNames.length; i++) {
                cipherSuiteNames[i] = cipherSuiteNames[i].trim();
                if (!cipherSuiteNames[i].isEmpty()) {
                    try {
                        CipherSuite suite = CipherSuite.nameOf(cipherSuiteNames[i]);
                        if (suite != null && suite.isAvailable()) {
                            cipherSuites.add(suite);
                        } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
                            SSLLogger.fine("The current installed providers do not support cipher suite: " + cipherSuiteNames[i], new Object[0]);
                        }
                    } catch (IllegalArgumentException e) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
                            SSLLogger.fine("Unknown or unsupported cipher suite name: " + cipherSuiteNames[i], new Object[0]);
                        }
                    }
                }
            }
            return cipherSuites;
        }
        return Collections.emptyList();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static List<ProtocolVersion> getAvailableProtocols(ProtocolVersion[] protocolCandidates) {
        List<ProtocolVersion> availableProtocols = Collections.emptyList();
        if (protocolCandidates != null && protocolCandidates.length != 0) {
            availableProtocols = new ArrayList<>(protocolCandidates.length);
            for (ProtocolVersion p : protocolCandidates) {
                if (p.isAvailable) {
                    availableProtocols.add(p);
                }
            }
        }
        return availableProtocols;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$AbstractTLSContext.class */
    public static abstract class AbstractTLSContext extends SSLContextImpl {
        private static final List<ProtocolVersion> supportedProtocols;
        private static final List<ProtocolVersion> serverDefaultProtocols;
        private static final List<CipherSuite> supportedCipherSuites;
        private static final List<CipherSuite> serverDefaultCipherSuites;

        private AbstractTLSContext() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl, javax.net.ssl.SSLContextSpi
        protected /* bridge */ /* synthetic */ javax.net.ssl.SSLEngine engineCreateSSLEngine(String str, int i) {
            return super.engineCreateSSLEngine(str, i);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl, javax.net.ssl.SSLContextSpi
        protected /* bridge */ /* synthetic */ javax.net.ssl.SSLEngine engineCreateSSLEngine() {
            return super.engineCreateSSLEngine();
        }

        static {
            if (OpenJSSE.isFIPS()) {
                supportedProtocols = Arrays.asList(ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10);
                serverDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10});
            } else {
                supportedProtocols = Arrays.asList(ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10, ProtocolVersion.SSL30, ProtocolVersion.SSL20Hello);
                serverDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10, ProtocolVersion.SSL30, ProtocolVersion.SSL20Hello});
            }
            supportedCipherSuites = SSLContextImpl.getApplicableSupportedCipherSuites(supportedProtocols);
            serverDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(serverDefaultProtocols, false);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getSupportedProtocolVersions() {
            return supportedProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getSupportedCipherSuites() {
            return supportedCipherSuites;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getServerDefaultProtocolVersions() {
            return serverDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getServerDefaultCipherSuites() {
            return serverDefaultCipherSuites;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        SSLEngine createSSLEngineImpl() {
            return new SSLEngineImpl(this);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        SSLEngine createSSLEngineImpl(String host, int port) {
            return new SSLEngineImpl(this, host, port);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        boolean isDTLS() {
            return false;
        }

        static ProtocolVersion[] getSupportedProtocols() {
            return OpenJSSE.isFIPS() ? new ProtocolVersion[]{ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10} : new ProtocolVersion[]{ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10, ProtocolVersion.SSL30, ProtocolVersion.SSL20Hello};
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$TLS10Context.class */
    public static final class TLS10Context extends AbstractTLSContext {
        private static final List<ProtocolVersion> clientDefaultProtocols;
        private static final List<CipherSuite> clientDefaultCipherSuites;

        public TLS10Context() {
            super();
        }

        static {
            if (OpenJSSE.isFIPS()) {
                clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS10});
            } else {
                clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS10, ProtocolVersion.SSL30});
            }
            clientDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(clientDefaultProtocols, true);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$TLS11Context.class */
    public static final class TLS11Context extends AbstractTLSContext {
        private static final List<ProtocolVersion> clientDefaultProtocols;
        private static final List<CipherSuite> clientDefaultCipherSuites;

        public TLS11Context() {
            super();
        }

        static {
            if (OpenJSSE.isFIPS()) {
                clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS11, ProtocolVersion.TLS10});
            } else {
                clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS11, ProtocolVersion.TLS10, ProtocolVersion.SSL30});
            }
            clientDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(clientDefaultProtocols, true);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$TLS12Context.class */
    public static final class TLS12Context extends AbstractTLSContext {
        private static final List<ProtocolVersion> clientDefaultProtocols;
        private static final List<CipherSuite> clientDefaultCipherSuites;

        public TLS12Context() {
            super();
        }

        static {
            if (OpenJSSE.isFIPS()) {
                clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10});
            } else {
                clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10, ProtocolVersion.SSL30});
            }
            clientDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(clientDefaultProtocols, true);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$TLS13Context.class */
    public static final class TLS13Context extends AbstractTLSContext {
        private static final List<ProtocolVersion> clientDefaultProtocols;
        private static final List<CipherSuite> clientDefaultCipherSuites;

        public TLS13Context() {
            super();
        }

        static {
            if (OpenJSSE.isFIPS()) {
                clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10});
            } else {
                clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10, ProtocolVersion.SSL30});
            }
            clientDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(clientDefaultProtocols, true);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$CustomizedSSLProtocols.class */
    private static class CustomizedSSLProtocols {
        private static final String JDK_TLS_CLIENT_PROTOCOLS = "jdk.tls.client.protocols";
        private static final String JDK_TLS_SERVER_PROTOCOLS = "jdk.tls.server.protocols";
        static IllegalArgumentException reservedException = null;
        static final ArrayList<ProtocolVersion> customizedClientProtocols = new ArrayList<>();
        static final ArrayList<ProtocolVersion> customizedServerProtocols = new ArrayList<>();

        private CustomizedSSLProtocols() {
        }

        static {
            populate(JDK_TLS_CLIENT_PROTOCOLS, customizedClientProtocols);
            populate(JDK_TLS_SERVER_PROTOCOLS, customizedServerProtocols);
        }

        private static void populate(String propname, ArrayList<ProtocolVersion> arrayList) {
            String property = GetPropertyAction.privilegedGetProperty(propname);
            if (property == null) {
                return;
            }
            if (property.length() != 0 && property.length() > 1 && property.charAt(0) == '\"' && property.charAt(property.length() - 1) == '\"') {
                property = property.substring(1, property.length() - 1);
            }
            if (property.length() != 0) {
                String[] protocols = property.split(",");
                for (int i = 0; i < protocols.length; i++) {
                    protocols[i] = protocols[i].trim();
                    ProtocolVersion pv = ProtocolVersion.nameOf(protocols[i]);
                    if (pv == null) {
                        reservedException = new IllegalArgumentException(propname + ": " + protocols[i] + " is not a supported SSL protocol name");
                    }
                    if (OpenJSSE.isFIPS() && (pv == ProtocolVersion.SSL30 || pv == ProtocolVersion.SSL20Hello)) {
                        reservedException = new IllegalArgumentException(propname + ": " + pv + " is not FIPS compliant");
                        return;
                    }
                    if (!arrayList.contains(pv)) {
                        arrayList.add(pv);
                    }
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$CustomizedTLSContext.class */
    private static class CustomizedTLSContext extends AbstractTLSContext {
        private static final List<ProtocolVersion> clientDefaultProtocols;
        private static final List<ProtocolVersion> serverDefaultProtocols;
        private static final List<CipherSuite> clientDefaultCipherSuites;
        private static final List<CipherSuite> serverDefaultCipherSuites;
        private static final IllegalArgumentException reservedException = CustomizedSSLProtocols.reservedException;

        static {
            if (reservedException == null) {
                clientDefaultProtocols = customizedProtocols(true, CustomizedSSLProtocols.customizedClientProtocols);
                serverDefaultProtocols = customizedProtocols(false, CustomizedSSLProtocols.customizedServerProtocols);
                clientDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(clientDefaultProtocols, true);
                serverDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(serverDefaultProtocols, false);
                return;
            }
            clientDefaultProtocols = null;
            serverDefaultProtocols = null;
            clientDefaultCipherSuites = null;
            serverDefaultCipherSuites = null;
        }

        private static List<ProtocolVersion> customizedProtocols(boolean client, List<ProtocolVersion> customized) {
            ProtocolVersion[] candidates;
            List<ProtocolVersion> refactored = new ArrayList<>();
            for (ProtocolVersion pv : customized) {
                if (!pv.isDTLS) {
                    refactored.add(pv);
                }
            }
            if (refactored.isEmpty()) {
                if (client) {
                    candidates = getProtocols();
                } else {
                    candidates = getSupportedProtocols();
                }
            } else {
                candidates = (ProtocolVersion[]) refactored.toArray(new ProtocolVersion[refactored.size()]);
            }
            return SSLContextImpl.getAvailableProtocols(candidates);
        }

        static ProtocolVersion[] getProtocols() {
            return OpenJSSE.isFIPS() ? new ProtocolVersion[]{ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10} : new ProtocolVersion[]{ProtocolVersion.TLS13, ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10, ProtocolVersion.SSL30};
        }

        protected CustomizedTLSContext() {
            super();
            if (reservedException != null) {
                throw reservedException;
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl.AbstractTLSContext, org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getServerDefaultProtocolVersions() {
            return serverDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl.AbstractTLSContext, org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getServerDefaultCipherSuites() {
            return serverDefaultCipherSuites;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$DefaultManagersHolder.class */
    private static final class DefaultManagersHolder {
        private static final String NONE = "NONE";
        private static final String P11KEYSTORE = "PKCS11";
        private static final TrustManager[] trustManagers;
        private static final KeyManager[] keyManagers;
        private static final Exception reservedException;

        private DefaultManagersHolder() {
        }

        static {
            TrustManager[] tmMediator;
            KeyManager[] kmMediator;
            Exception reserved = null;
            try {
                tmMediator = getTrustManagers();
            } catch (Exception e) {
                reserved = e;
                tmMediator = new TrustManager[0];
            }
            trustManagers = tmMediator;
            if (reserved == null) {
                try {
                    kmMediator = getKeyManagers();
                } catch (Exception e2) {
                    reserved = e2;
                    kmMediator = new KeyManager[0];
                }
                keyManagers = kmMediator;
            } else {
                keyManagers = new KeyManager[0];
            }
            reservedException = reserved;
        }

        private static TrustManager[] getTrustManagers() throws Exception {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            if ("OpenJSSE".equals(tmf.getProvider().getName())) {
                tmf.init((KeyStore) null);
            } else {
                KeyStore ks = TrustStoreManager.getTrustedKeyStore();
                tmf.init(ks);
            }
            return tmf.getTrustManagers();
        }

        /* JADX WARN: Finally extract failed */
        private static KeyManager[] getKeyManagers() throws Exception {
            final Map<String, String> props = new HashMap<>();
            AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() { // from class: org.openjsse.sun.security.ssl.SSLContextImpl.DefaultManagersHolder.1
                @Override // java.security.PrivilegedExceptionAction
                public Object run() throws Exception {
                    props.put("keyStore", System.getProperty("javax.net.ssl.keyStore", ""));
                    props.put("keyStoreType", System.getProperty("javax.net.ssl.keyStoreType", KeyStore.getDefaultType()));
                    props.put("keyStoreProvider", System.getProperty("javax.net.ssl.keyStoreProvider", ""));
                    props.put("keyStorePasswd", System.getProperty("javax.net.ssl.keyStorePassword", ""));
                    return null;
                }
            });
            final String defaultKeyStore = props.get("keyStore");
            String defaultKeyStoreType = props.get("keyStoreType");
            String defaultKeyStoreProvider = props.get("keyStoreProvider");
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
                SSLLogger.fine("keyStore is : " + defaultKeyStore, new Object[0]);
                SSLLogger.fine("keyStore type is : " + defaultKeyStoreType, new Object[0]);
                SSLLogger.fine("keyStore provider is : " + defaultKeyStoreProvider, new Object[0]);
            }
            if (P11KEYSTORE.equals(defaultKeyStoreType) && !NONE.equals(defaultKeyStore)) {
                throw new IllegalArgumentException("if keyStoreType is PKCS11, then keyStore must be NONE");
            }
            FileInputStream fs = null;
            KeyStore ks = null;
            char[] passwd = null;
            try {
                if (defaultKeyStore.length() != 0 && !NONE.equals(defaultKeyStore)) {
                    fs = (FileInputStream) AccessController.doPrivileged(new PrivilegedExceptionAction<FileInputStream>() { // from class: org.openjsse.sun.security.ssl.SSLContextImpl.DefaultManagersHolder.2
                        /* JADX WARN: Can't rename method to resolve collision */
                        @Override // java.security.PrivilegedExceptionAction
                        public FileInputStream run() throws Exception {
                            return new FileInputStream(defaultKeyStore);
                        }
                    });
                }
                String defaultKeyStorePassword = props.get("keyStorePasswd");
                if (defaultKeyStorePassword.length() != 0) {
                    passwd = defaultKeyStorePassword.toCharArray();
                }
                if (defaultKeyStoreType.length() != 0) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
                        SSLLogger.finest("init keystore", new Object[0]);
                    }
                    if (defaultKeyStoreProvider.length() == 0) {
                        ks = KeyStore.getInstance(defaultKeyStoreType);
                    } else {
                        ks = KeyStore.getInstance(defaultKeyStoreType, defaultKeyStoreProvider);
                    }
                    ks.load(fs, passwd);
                }
                if (fs != null) {
                    fs.close();
                }
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
                    SSLLogger.fine("init keymanager of type " + KeyManagerFactory.getDefaultAlgorithm(), new Object[0]);
                }
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                if (P11KEYSTORE.equals(defaultKeyStoreType)) {
                    kmf.init(ks, null);
                } else {
                    kmf.init(ks, passwd);
                }
                return kmf.getKeyManagers();
            } catch (Throwable th) {
                if (fs != null) {
                    fs.close();
                }
                throw th;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$DefaultSSLContextHolder.class */
    private static final class DefaultSSLContextHolder {
        private static final SSLContextImpl sslContext;
        static Exception reservedException;

        private DefaultSSLContextHolder() {
        }

        static {
            reservedException = null;
            SSLContextImpl mediator = null;
            if (DefaultManagersHolder.reservedException != null) {
                reservedException = DefaultManagersHolder.reservedException;
            } else {
                try {
                    mediator = new DefaultSSLContext();
                } catch (Exception e) {
                    reservedException = e;
                }
            }
            sslContext = mediator;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$DefaultSSLContext.class */
    public static final class DefaultSSLContext extends CustomizedTLSContext {
        public DefaultSSLContext() throws Exception {
            if (DefaultManagersHolder.reservedException != null) {
                throw DefaultManagersHolder.reservedException;
            }
            try {
                super.engineInit(DefaultManagersHolder.keyManagers, DefaultManagersHolder.trustManagers, null);
            } catch (Exception e) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
                    SSLLogger.fine("default context init failed: ", e);
                }
                throw e;
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl, javax.net.ssl.SSLContextSpi
        protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
            throw new KeyManagementException("Default SSLContext is initialized automatically");
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static SSLContextImpl getDefaultImpl() throws Exception {
            if (DefaultSSLContextHolder.reservedException == null) {
                return DefaultSSLContextHolder.sslContext;
            }
            throw DefaultSSLContextHolder.reservedException;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$AbstractDTLSContext.class */
    private static abstract class AbstractDTLSContext extends SSLContextImpl {
        private static final List<ProtocolVersion> supportedProtocols = Arrays.asList(ProtocolVersion.DTLS12, ProtocolVersion.DTLS10);
        private static final List<ProtocolVersion> serverDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.DTLS12, ProtocolVersion.DTLS10});
        private static final List<CipherSuite> supportedCipherSuites = SSLContextImpl.getApplicableSupportedCipherSuites(supportedProtocols);
        private static final List<CipherSuite> serverDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(serverDefaultProtocols, false);

        private AbstractDTLSContext() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl, javax.net.ssl.SSLContextSpi
        protected /* bridge */ /* synthetic */ javax.net.ssl.SSLEngine engineCreateSSLEngine(String str, int i) {
            return super.engineCreateSSLEngine(str, i);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl, javax.net.ssl.SSLContextSpi
        protected /* bridge */ /* synthetic */ javax.net.ssl.SSLEngine engineCreateSSLEngine() {
            return super.engineCreateSSLEngine();
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getSupportedProtocolVersions() {
            return supportedProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getSupportedCipherSuites() {
            return supportedCipherSuites;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getServerDefaultProtocolVersions() {
            return serverDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getServerDefaultCipherSuites() {
            return serverDefaultCipherSuites;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        SSLEngine createSSLEngineImpl() {
            return new SSLEngineImpl(this);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        SSLEngine createSSLEngineImpl(String host, int port) {
            return new SSLEngineImpl(this, host, port);
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        boolean isDTLS() {
            return true;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$DTLS10Context.class */
    public static final class DTLS10Context extends AbstractDTLSContext {
        private static final List<ProtocolVersion> clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.DTLS10});
        private static final List<CipherSuite> clientDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(clientDefaultProtocols, true);

        public DTLS10Context() {
            super();
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$DTLS12Context.class */
    public static final class DTLS12Context extends AbstractDTLSContext {
        private static final List<ProtocolVersion> clientDefaultProtocols = SSLContextImpl.getAvailableProtocols(new ProtocolVersion[]{ProtocolVersion.DTLS12, ProtocolVersion.DTLS10});
        private static final List<CipherSuite> clientDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(clientDefaultProtocols, true);

        public DTLS12Context() {
            super();
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLContextImpl$CustomizedDTLSContext.class */
    private static class CustomizedDTLSContext extends AbstractDTLSContext {
        private static final List<ProtocolVersion> clientDefaultProtocols;
        private static final List<ProtocolVersion> serverDefaultProtocols;
        private static final List<CipherSuite> clientDefaultCipherSuites;
        private static final List<CipherSuite> serverDefaultCipherSuites;
        private static IllegalArgumentException reservedException;

        static {
            reservedException = null;
            reservedException = CustomizedSSLProtocols.reservedException;
            if (reservedException == null) {
                clientDefaultProtocols = customizedProtocols(true, CustomizedSSLProtocols.customizedClientProtocols);
                serverDefaultProtocols = customizedProtocols(false, CustomizedSSLProtocols.customizedServerProtocols);
                clientDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(clientDefaultProtocols, true);
                serverDefaultCipherSuites = SSLContextImpl.getApplicableEnabledCipherSuites(serverDefaultProtocols, false);
                return;
            }
            clientDefaultProtocols = null;
            serverDefaultProtocols = null;
            clientDefaultCipherSuites = null;
            serverDefaultCipherSuites = null;
        }

        private static List<ProtocolVersion> customizedProtocols(boolean client, List<ProtocolVersion> customized) {
            ProtocolVersion[] candidates;
            List<ProtocolVersion> refactored = new ArrayList<>();
            for (ProtocolVersion pv : customized) {
                if (pv.isDTLS) {
                    refactored.add(pv);
                }
            }
            if (refactored.isEmpty()) {
                candidates = new ProtocolVersion[]{ProtocolVersion.DTLS12, ProtocolVersion.DTLS10};
                if (!client) {
                    return Arrays.asList(candidates);
                }
            } else {
                ProtocolVersion[] candidates2 = new ProtocolVersion[customized.size()];
                candidates = (ProtocolVersion[]) customized.toArray(candidates2);
            }
            return SSLContextImpl.getAvailableProtocols(candidates);
        }

        protected CustomizedDTLSContext() {
            super();
            if (reservedException != null) {
                throw reservedException;
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl.AbstractDTLSContext, org.openjsse.sun.security.ssl.SSLContextImpl
        List<ProtocolVersion> getServerDefaultProtocolVersions() {
            return serverDefaultProtocols;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }

        @Override // org.openjsse.sun.security.ssl.SSLContextImpl.AbstractDTLSContext, org.openjsse.sun.security.ssl.SSLContextImpl
        List<CipherSuite> getServerDefaultCipherSuites() {
            return serverDefaultCipherSuites;
        }
    }
}