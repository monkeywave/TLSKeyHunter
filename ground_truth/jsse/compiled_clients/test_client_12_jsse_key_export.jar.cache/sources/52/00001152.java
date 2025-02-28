package org.openjsse.sun.security.ssl;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.openjsse.sun.security.ssl.SSLExtension;
import sun.security.action.GetIntegerAction;
import sun.security.action.GetPropertyAction;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLConfiguration.class */
public final class SSLConfiguration implements Cloneable {
    AlgorithmConstraints userSpecifiedAlgorithmConstraints = SSLAlgorithmConstraints.DEFAULT;
    List<ProtocolVersion> enabledProtocols;
    List<CipherSuite> enabledCipherSuites;
    ClientAuthType clientAuthType;
    String identificationProtocol;
    List<SNIServerName> serverNames;
    Collection<SNIMatcher> sniMatchers;
    String[] applicationProtocols;
    boolean preferLocalCipherSuites;
    boolean enableRetransmissions;
    int maximumPacketSize;
    List<SignatureScheme> signatureSchemes;
    ProtocolVersion maximumProtocolVersion;
    boolean isClientMode;
    boolean enableSessionCreation;
    BiFunction<SSLSocket, List<String>, String> socketAPSelector;
    BiFunction<SSLEngine, List<String>, String> engineAPSelector;
    HashMap<HandshakeCompletedListener, AccessControlContext> handshakeListeners;
    boolean noSniExtension;
    boolean noSniMatcher;
    static final boolean useExtendedMasterSecret;
    static final boolean allowLegacyResumption = Utilities.getBooleanProperty("jdk.tls.allowLegacyResumption", true);
    static final boolean allowLegacyMasterSecret = Utilities.getBooleanProperty("jdk.tls.allowLegacyMasterSecret", true);
    static final boolean useCompatibilityMode = Utilities.getBooleanProperty("jdk.tls.client.useCompatibilityMode", true);
    static final boolean acknowledgeCloseNotify = Utilities.getBooleanProperty("jdk.tls.acknowledgeCloseNotify", false);
    static final int maxHandshakeMessageSize = ((Integer) AccessController.doPrivileged((PrivilegedAction<Object>) new GetIntegerAction("jdk.tls.maxHandshakeMessageSize", 32768))).intValue();
    static final int maxCertificateChainLength = ((Integer) AccessController.doPrivileged((PrivilegedAction<Object>) new GetIntegerAction("jdk.tls.maxCertificateChainLength", 10))).intValue();

    static {
        boolean supportExtendedMasterSecret = Utilities.getBooleanProperty("jdk.tls.useExtendedMasterSecret", true);
        if (supportExtendedMasterSecret) {
            try {
                JsseJce.getKeyGenerator("SunTlsExtendedMasterSecret");
            } catch (NoSuchAlgorithmException e) {
                supportExtendedMasterSecret = false;
            }
        }
        useExtendedMasterSecret = supportExtendedMasterSecret;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLConfiguration(SSLContextImpl sslContext, boolean isClientMode) {
        List<SignatureScheme> list;
        this.enabledProtocols = sslContext.getDefaultProtocolVersions(!isClientMode);
        this.enabledCipherSuites = sslContext.getDefaultCipherSuites(!isClientMode);
        this.clientAuthType = ClientAuthType.CLIENT_AUTH_NONE;
        this.identificationProtocol = null;
        this.serverNames = Collections.emptyList();
        this.sniMatchers = Collections.emptyList();
        this.preferLocalCipherSuites = false;
        this.applicationProtocols = new String[0];
        this.enableRetransmissions = sslContext.isDTLS();
        this.maximumPacketSize = 0;
        if (isClientMode) {
            list = CustomizedClientSignatureSchemes.signatureSchemes;
        } else {
            list = CustomizedServerSignatureSchemes.signatureSchemes;
        }
        this.signatureSchemes = list;
        this.maximumProtocolVersion = ProtocolVersion.NONE;
        for (ProtocolVersion pv : this.enabledProtocols) {
            if (pv.compareTo(this.maximumProtocolVersion) > 0) {
                this.maximumProtocolVersion = pv;
            }
        }
        this.isClientMode = isClientMode;
        this.enableSessionCreation = true;
        this.socketAPSelector = null;
        this.engineAPSelector = null;
        this.handshakeListeners = null;
        this.noSniExtension = false;
        this.noSniMatcher = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLParameters getSSLParameters() {
        org.openjsse.javax.net.ssl.SSLParameters params = new org.openjsse.javax.net.ssl.SSLParameters();
        params.setAlgorithmConstraints(this.userSpecifiedAlgorithmConstraints);
        params.setProtocols(ProtocolVersion.toStringArray(this.enabledProtocols));
        params.setCipherSuites(CipherSuite.namesOf(this.enabledCipherSuites));
        switch (this.clientAuthType) {
            case CLIENT_AUTH_REQUIRED:
                params.setNeedClientAuth(true);
                break;
            case CLIENT_AUTH_REQUESTED:
                params.setWantClientAuth(true);
                break;
            default:
                params.setWantClientAuth(false);
                break;
        }
        params.setEndpointIdentificationAlgorithm(this.identificationProtocol);
        if (this.serverNames.isEmpty() && !this.noSniExtension) {
            params.setServerNames(null);
        } else {
            params.setServerNames(this.serverNames);
        }
        if (this.sniMatchers.isEmpty() && !this.noSniMatcher) {
            params.setSNIMatchers(null);
        } else {
            params.setSNIMatchers(this.sniMatchers);
        }
        params.setApplicationProtocols(this.applicationProtocols);
        params.setUseCipherSuitesOrder(this.preferLocalCipherSuites);
        params.setEnableRetransmissions(this.enableRetransmissions);
        params.setMaximumPacketSize(this.maximumPacketSize);
        return params;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setSSLParameters(SSLParameters params) {
        AlgorithmConstraints ac = params.getAlgorithmConstraints();
        if (ac != null) {
            this.userSpecifiedAlgorithmConstraints = ac;
        }
        String[] sa = params.getCipherSuites();
        if (sa != null) {
            this.enabledCipherSuites = CipherSuite.validValuesOf(sa);
        }
        String[] sa2 = params.getProtocols();
        if (sa2 != null) {
            this.enabledProtocols = ProtocolVersion.namesOf(sa2);
            this.maximumProtocolVersion = ProtocolVersion.NONE;
            for (ProtocolVersion pv : this.enabledProtocols) {
                if (pv.compareTo(this.maximumProtocolVersion) > 0) {
                    this.maximumProtocolVersion = pv;
                }
            }
        }
        if (params.getNeedClientAuth()) {
            this.clientAuthType = ClientAuthType.CLIENT_AUTH_REQUIRED;
        } else if (params.getWantClientAuth()) {
            this.clientAuthType = ClientAuthType.CLIENT_AUTH_REQUESTED;
        } else {
            this.clientAuthType = ClientAuthType.CLIENT_AUTH_NONE;
        }
        String s = params.getEndpointIdentificationAlgorithm();
        if (s != null) {
            this.identificationProtocol = s;
        }
        List<SNIServerName> sniNames = params.getServerNames();
        if (sniNames != null) {
            this.noSniExtension = sniNames.isEmpty();
            this.serverNames = sniNames;
        }
        Collection<SNIMatcher> matchers = params.getSNIMatchers();
        if (matchers != null) {
            this.noSniMatcher = matchers.isEmpty();
            this.sniMatchers = matchers;
        }
        if (params instanceof org.openjsse.javax.net.ssl.SSLParameters) {
            String[] sa3 = ((org.openjsse.javax.net.ssl.SSLParameters) params).getApplicationProtocols();
            if (sa3 != null) {
                this.applicationProtocols = sa3;
            }
            this.enableRetransmissions = ((org.openjsse.javax.net.ssl.SSLParameters) params).getEnableRetransmissions();
            this.maximumPacketSize = ((org.openjsse.javax.net.ssl.SSLParameters) params).getMaximumPacketSize();
        }
        this.preferLocalCipherSuites = params.getUseCipherSuitesOrder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (this.handshakeListeners == null) {
            this.handshakeListeners = new HashMap<>(4);
        }
        this.handshakeListeners.put(listener, AccessController.getContext());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (this.handshakeListeners == null) {
            throw new IllegalArgumentException("no listeners");
        }
        if (this.handshakeListeners.remove(listener) == null) {
            throw new IllegalArgumentException("listener not registered");
        }
        if (this.handshakeListeners.isEmpty()) {
            this.handshakeListeners = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isAvailable(SSLExtension extension) {
        for (ProtocolVersion protocolVersion : this.enabledProtocols) {
            if (extension.isAvailable(protocolVersion)) {
                if (this.isClientMode) {
                    if (SSLExtension.ClientExtensions.defaults.contains(extension)) {
                        return true;
                    }
                } else if (SSLExtension.ServerExtensions.defaults.contains(extension)) {
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isAvailable(SSLExtension extension, ProtocolVersion protocolVersion) {
        return extension.isAvailable(protocolVersion) && (!this.isClientMode ? !SSLExtension.ServerExtensions.defaults.contains(extension) : !SSLExtension.ClientExtensions.defaults.contains(extension));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLExtension[] getEnabledExtensions(SSLHandshake handshakeType) {
        SSLExtension[] values;
        List<SSLExtension> extensions = new ArrayList<>();
        for (SSLExtension extension : SSLExtension.values()) {
            if (extension.handshakeType == handshakeType && isAvailable(extension)) {
                extensions.add(extension);
            }
        }
        return (SSLExtension[]) extensions.toArray(new SSLExtension[0]);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLExtension[] getExclusiveExtensions(SSLHandshake handshakeType, List<SSLExtension> excluded) {
        SSLExtension[] values;
        List<SSLExtension> extensions = new ArrayList<>();
        for (SSLExtension extension : SSLExtension.values()) {
            if (extension.handshakeType == handshakeType && isAvailable(extension) && !excluded.contains(extension)) {
                extensions.add(extension);
            }
        }
        return (SSLExtension[]) extensions.toArray(new SSLExtension[0]);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLExtension[] getEnabledExtensions(SSLHandshake handshakeType, ProtocolVersion protocolVersion) {
        return getEnabledExtensions(handshakeType, Arrays.asList(protocolVersion));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLExtension[] getEnabledExtensions(SSLHandshake handshakeType, List<ProtocolVersion> activeProtocols) {
        SSLExtension[] values;
        List<SSLExtension> extensions = new ArrayList<>();
        for (SSLExtension extension : SSLExtension.values()) {
            if (extension.handshakeType == handshakeType && isAvailable(extension)) {
                Iterator<ProtocolVersion> it = activeProtocols.iterator();
                while (true) {
                    if (it.hasNext()) {
                        ProtocolVersion protocolVersion = it.next();
                        if (extension.isAvailable(protocolVersion)) {
                            extensions.add(extension);
                            break;
                        }
                    }
                }
            }
        }
        return (SSLExtension[]) extensions.toArray(new SSLExtension[0]);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void toggleClientMode() {
        List<SignatureScheme> list;
        this.isClientMode = !this.isClientMode;
        if (this.isClientMode) {
            list = CustomizedClientSignatureSchemes.signatureSchemes;
        } else {
            list = CustomizedServerSignatureSchemes.signatureSchemes;
        }
        this.signatureSchemes = list;
    }

    public Object clone() {
        try {
            SSLConfiguration config = (SSLConfiguration) super.clone();
            if (this.handshakeListeners != null) {
                config.handshakeListeners = (HashMap) this.handshakeListeners.clone();
            }
            return config;
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLConfiguration$CustomizedClientSignatureSchemes.class */
    public static final class CustomizedClientSignatureSchemes {
        private static List<SignatureScheme> signatureSchemes = SSLConfiguration.getCustomizedSignatureScheme("jdk.tls.client.SignatureSchemes");

        private CustomizedClientSignatureSchemes() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLConfiguration$CustomizedServerSignatureSchemes.class */
    public static final class CustomizedServerSignatureSchemes {
        private static List<SignatureScheme> signatureSchemes = SSLConfiguration.getCustomizedSignatureScheme("jdk.tls.server.SignatureSchemes");

        private CustomizedServerSignatureSchemes() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static List<SignatureScheme> getCustomizedSignatureScheme(String propertyName) {
        String property = GetPropertyAction.privilegedGetProperty(propertyName);
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
            SSLLogger.fine("System property " + propertyName + " is set to '" + property + "'", new Object[0]);
        }
        if (property != null && !property.isEmpty() && property.length() > 1 && property.charAt(0) == '\"' && property.charAt(property.length() - 1) == '\"') {
            property = property.substring(1, property.length() - 1);
        }
        if (property != null && !property.isEmpty()) {
            String[] signatureSchemeNames = property.split(",");
            List<SignatureScheme> signatureSchemes = new ArrayList<>(signatureSchemeNames.length);
            for (int i = 0; i < signatureSchemeNames.length; i++) {
                signatureSchemeNames[i] = signatureSchemeNames[i].trim();
                if (!signatureSchemeNames[i].isEmpty()) {
                    SignatureScheme scheme = SignatureScheme.nameOf(signatureSchemeNames[i]);
                    if (scheme != null && scheme.isAvailable) {
                        signatureSchemes.add(scheme);
                    } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,sslctx")) {
                        SSLLogger.fine("The current installed providers do not support signature scheme: " + signatureSchemeNames[i], new Object[0]);
                    }
                }
            }
            return signatureSchemes;
        }
        return Collections.emptyList();
    }
}