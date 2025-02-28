package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.AlgorithmConstraints;
import java.security.CryptoPrimitive;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import javax.crypto.SecretKey;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLHandshakeException;
import javax.security.auth.x500.X500Principal;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeContext.class */
public abstract class HandshakeContext implements ConnectionContext {
    static final boolean allowUnsafeRenegotiation = Utilities.getBooleanProperty("sun.security.ssl.allowUnsafeRenegotiation", false);
    static final boolean allowLegacyHelloMessages = Utilities.getBooleanProperty("sun.security.ssl.allowLegacyHelloMessages", true);
    LinkedHashMap<Byte, SSLConsumer> handshakeConsumers;
    final HashMap<Byte, HandshakeProducer> handshakeProducers;
    final SSLContextImpl sslContext;
    final TransportContext conContext;
    final SSLConfiguration sslConfig;
    final List<ProtocolVersion> activeProtocols;
    final List<CipherSuite> activeCipherSuites;
    final AlgorithmConstraints algorithmConstraints;
    final ProtocolVersion maximumActiveProtocol;
    final HandshakeOutStream handshakeOutput;
    final HandshakeHash handshakeHash;
    SSLSessionImpl handshakeSession;
    boolean handshakeFinished;
    boolean kickstartMessageDelivered;
    boolean isResumption;
    SSLSessionImpl resumingSession;
    final Queue<Map.Entry<Byte, ByteBuffer>> delegatedActions;
    volatile boolean taskDelegated;
    volatile Exception delegatedThrown;
    ProtocolVersion negotiatedProtocol;
    CipherSuite negotiatedCipherSuite;
    final List<SSLPossession> handshakePossessions;
    final List<SSLCredentials> handshakeCredentials;
    SSLKeyDerivation handshakeKeyDerivation;
    SSLKeyExchange handshakeKeyExchange;
    SecretKey baseReadSecret;
    SecretKey baseWriteSecret;
    int clientHelloVersion;
    String applicationProtocol;
    RandomCookie clientHelloRandom;
    RandomCookie serverHelloRandom;
    byte[] certRequestContext;
    final Map<SSLExtension, SSLExtension.SSLExtensionSpec> handshakeExtensions;
    int maxFragmentLength;
    List<SignatureScheme> localSupportedSignAlgs;
    List<SignatureScheme> peerRequestedSignatureSchemes;
    List<SignatureScheme> peerRequestedCertSignSchemes;
    X500Principal[] peerSupportedAuthorities;
    List<X500Principal> localSupportedAuthorities;
    List<SupportedGroupsExtension.NamedGroup> clientRequestedNamedGroups;
    SupportedGroupsExtension.NamedGroup serverSelectedNamedGroup;
    List<SNIServerName> requestedServerNames;
    SNIServerName negotiatedServerName;
    boolean staplingActive;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void kickstart() throws IOException;

    /* JADX INFO: Access modifiers changed from: protected */
    public HandshakeContext(SSLContextImpl sslContext, TransportContext conContext) throws IOException {
        this.taskDelegated = false;
        this.delegatedThrown = null;
        this.peerSupportedAuthorities = null;
        this.localSupportedAuthorities = null;
        this.staplingActive = false;
        this.sslContext = sslContext;
        this.conContext = conContext;
        this.sslConfig = (SSLConfiguration) conContext.sslConfig.clone();
        this.algorithmConstraints = new SSLAlgorithmConstraints(this.sslConfig.userSpecifiedAlgorithmConstraints);
        this.activeProtocols = getActiveProtocols(this.sslConfig.enabledProtocols, this.sslConfig.enabledCipherSuites, this.algorithmConstraints);
        if (this.activeProtocols.isEmpty()) {
            throw new SSLHandshakeException("No appropriate protocol (protocol is disabled or cipher suites are inappropriate)");
        }
        ProtocolVersion maximumVersion = ProtocolVersion.NONE;
        for (ProtocolVersion pv : this.activeProtocols) {
            if (maximumVersion == ProtocolVersion.NONE || pv.compare(maximumVersion) > 0) {
                maximumVersion = pv;
            }
        }
        this.maximumActiveProtocol = maximumVersion;
        this.activeCipherSuites = getActiveCipherSuites(this.activeProtocols, this.sslConfig.enabledCipherSuites, this.algorithmConstraints);
        if (this.activeCipherSuites.isEmpty()) {
            throw new SSLHandshakeException("No appropriate cipher suite");
        }
        this.handshakeConsumers = new LinkedHashMap<>();
        this.handshakeProducers = new HashMap<>();
        this.handshakeHash = conContext.inputRecord.handshakeHash;
        this.handshakeOutput = new HandshakeOutStream(conContext.outputRecord);
        this.handshakeFinished = false;
        this.kickstartMessageDelivered = false;
        this.delegatedActions = new LinkedList();
        this.handshakeExtensions = new HashMap();
        this.handshakePossessions = new LinkedList();
        this.handshakeCredentials = new LinkedList();
        this.requestedServerNames = null;
        this.negotiatedServerName = null;
        this.negotiatedCipherSuite = conContext.cipherSuite;
        initialize();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public HandshakeContext(TransportContext conContext) {
        this.taskDelegated = false;
        this.delegatedThrown = null;
        this.peerSupportedAuthorities = null;
        this.localSupportedAuthorities = null;
        this.staplingActive = false;
        this.sslContext = conContext.sslContext;
        this.conContext = conContext;
        this.sslConfig = conContext.sslConfig;
        this.negotiatedProtocol = conContext.protocolVersion;
        this.negotiatedCipherSuite = conContext.cipherSuite;
        this.handshakeOutput = new HandshakeOutStream(conContext.outputRecord);
        this.delegatedActions = new LinkedList();
        this.handshakeConsumers = new LinkedHashMap<>();
        this.handshakeProducers = null;
        this.handshakeHash = null;
        this.activeProtocols = null;
        this.activeCipherSuites = null;
        this.algorithmConstraints = null;
        this.maximumActiveProtocol = null;
        this.handshakeExtensions = Collections.emptyMap();
        this.handshakePossessions = null;
        this.handshakeCredentials = null;
    }

    private void initialize() {
        ProtocolVersion inputHelloVersion;
        ProtocolVersion outputHelloVersion;
        if (this.conContext.isNegotiated) {
            inputHelloVersion = this.conContext.protocolVersion;
            outputHelloVersion = this.conContext.protocolVersion;
        } else if (this.activeProtocols.contains(ProtocolVersion.SSL20Hello)) {
            inputHelloVersion = ProtocolVersion.SSL20Hello;
            if (this.maximumActiveProtocol.useTLS13PlusSpec()) {
                outputHelloVersion = this.maximumActiveProtocol;
            } else {
                outputHelloVersion = ProtocolVersion.SSL20Hello;
            }
        } else {
            inputHelloVersion = this.maximumActiveProtocol;
            outputHelloVersion = this.maximumActiveProtocol;
        }
        this.conContext.inputRecord.setHelloVersion(inputHelloVersion);
        this.conContext.outputRecord.setHelloVersion(outputHelloVersion);
        if (!this.conContext.isNegotiated) {
            this.conContext.protocolVersion = this.maximumActiveProtocol;
        }
        this.conContext.outputRecord.setVersion(this.conContext.protocolVersion);
    }

    private static List<ProtocolVersion> getActiveProtocols(List<ProtocolVersion> enabledProtocols, List<CipherSuite> enabledCipherSuites, AlgorithmConstraints algorithmConstraints) {
        boolean enabledSSL20Hello = false;
        ArrayList<ProtocolVersion> protocols = new ArrayList<>(4);
        for (ProtocolVersion protocol : enabledProtocols) {
            if (!enabledSSL20Hello && protocol == ProtocolVersion.SSL20Hello) {
                enabledSSL20Hello = true;
            } else if (algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), protocol.name, null)) {
                boolean found = false;
                Map<SupportedGroupsExtension.NamedGroupType, Boolean> cachedStatus = new EnumMap<>(SupportedGroupsExtension.NamedGroupType.class);
                Iterator<CipherSuite> it = enabledCipherSuites.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    CipherSuite suite = it.next();
                    if (suite.isAvailable() && suite.supports(protocol)) {
                        if (isActivatable(suite, algorithmConstraints, cachedStatus)) {
                            protocols.add(protocol);
                            found = true;
                            break;
                        }
                    } else if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Ignore unsupported cipher suite: " + suite + " for " + protocol, new Object[0]);
                    }
                }
                if (!found && SSLLogger.isOn && SSLLogger.isOn("handshake")) {
                    SSLLogger.fine("No available cipher suite for " + protocol, new Object[0]);
                }
            }
        }
        if (!protocols.isEmpty()) {
            if (enabledSSL20Hello) {
                protocols.add(ProtocolVersion.SSL20Hello);
            }
            Collections.sort(protocols);
        }
        return Collections.unmodifiableList(protocols);
    }

    private static List<CipherSuite> getActiveCipherSuites(List<ProtocolVersion> enabledProtocols, List<CipherSuite> enabledCipherSuites, AlgorithmConstraints algorithmConstraints) {
        List<CipherSuite> suites = new LinkedList<>();
        if (enabledProtocols != null && !enabledProtocols.isEmpty()) {
            Map<SupportedGroupsExtension.NamedGroupType, Boolean> cachedStatus = new EnumMap<>(SupportedGroupsExtension.NamedGroupType.class);
            for (CipherSuite suite : enabledCipherSuites) {
                if (suite.isAvailable()) {
                    boolean isSupported = false;
                    Iterator<ProtocolVersion> it = enabledProtocols.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        ProtocolVersion protocol = it.next();
                        if (suite.supports(protocol) && isActivatable(suite, algorithmConstraints, cachedStatus)) {
                            suites.add(suite);
                            isSupported = true;
                            break;
                        }
                    }
                    if (!isSupported && SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.finest("Ignore unsupported cipher suite: " + suite, new Object[0]);
                    }
                }
            }
        }
        return Collections.unmodifiableList(suites);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte getHandshakeType(TransportContext conContext, Plaintext plaintext) throws IOException {
        if (plaintext.contentType != ContentType.HANDSHAKE.f965id) {
            throw conContext.fatal(Alert.INTERNAL_ERROR, "Unexpected operation for record: " + ((int) plaintext.contentType));
        }
        if (plaintext.fragment == null || plaintext.fragment.remaining() < 4) {
            throw conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid handshake message: insufficient data");
        }
        byte handshakeType = (byte) Record.getInt8(plaintext.fragment);
        int handshakeLen = Record.getInt24(plaintext.fragment);
        if (handshakeLen != plaintext.fragment.remaining()) {
            throw conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid handshake message: insufficient handshake body");
        }
        return handshakeType;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatch(byte handshakeType, Plaintext plaintext) throws IOException {
        if (this.conContext.transport.useDelegatedTask()) {
            boolean hasDelegated = !this.delegatedActions.isEmpty();
            if (hasDelegated || (handshakeType != SSLHandshake.FINISHED.f987id && handshakeType != SSLHandshake.KEY_UPDATE.f987id && handshakeType != SSLHandshake.NEW_SESSION_TICKET.f987id)) {
                if (!hasDelegated) {
                    this.taskDelegated = false;
                    this.delegatedThrown = null;
                }
                ByteBuffer fragment = ByteBuffer.wrap(new byte[plaintext.fragment.remaining()]);
                fragment.put(plaintext.fragment);
                this.delegatedActions.add(new AbstractMap.SimpleImmutableEntry(Byte.valueOf(handshakeType), (ByteBuffer) fragment.rewind()));
                return;
            }
            dispatch(handshakeType, plaintext.fragment);
            return;
        }
        dispatch(handshakeType, plaintext.fragment);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatch(byte handshakeType, ByteBuffer fragment) throws IOException {
        SSLConsumer consumer;
        if (handshakeType == SSLHandshake.HELLO_REQUEST.f987id) {
            consumer = SSLHandshake.HELLO_REQUEST;
        } else {
            consumer = this.handshakeConsumers.get(Byte.valueOf(handshakeType));
        }
        if (consumer == null) {
            throw this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected handshake message: " + SSLHandshake.nameOf(handshakeType));
        }
        try {
            consumer.consume(this, fragment);
            this.handshakeHash.consume();
        } catch (UnsupportedOperationException unsoe) {
            throw this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported handshake message: " + SSLHandshake.nameOf(handshakeType), unsoe);
        } catch (BufferOverflowException | BufferUnderflowException be) {
            throw this.conContext.fatal(Alert.DECODE_ERROR, "Illegal handshake message: " + SSLHandshake.nameOf(handshakeType), be);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isNegotiable(CipherSuite cs) {
        return isNegotiable(this.activeCipherSuites, cs);
    }

    static final boolean isNegotiable(List<CipherSuite> proposed, CipherSuite cs) {
        return proposed.contains(cs) && cs.isNegotiable();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static final boolean isNegotiable(List<CipherSuite> proposed, ProtocolVersion protocolVersion, CipherSuite cs) {
        return proposed.contains(cs) && cs.isNegotiable() && cs.supports(protocolVersion);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isNegotiable(ProtocolVersion protocolVersion) {
        return this.activeProtocols.contains(protocolVersion);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setVersion(ProtocolVersion protocolVersion) {
        this.conContext.protocolVersion = protocolVersion;
    }

    private static boolean isActivatable(CipherSuite suite, AlgorithmConstraints algorithmConstraints, Map<SupportedGroupsExtension.NamedGroupType, Boolean> cachedStatus) {
        SupportedGroupsExtension.NamedGroupType groupType;
        boolean available;
        if (algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), suite.name, null)) {
            if (suite.keyExchange != null && (groupType = suite.keyExchange.groupType) != SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_NONE) {
                Boolean checkedStatus = cachedStatus.get(groupType);
                if (checkedStatus == null) {
                    available = SupportedGroupsExtension.SupportedGroups.isActivatable(algorithmConstraints, groupType);
                    cachedStatus.put(groupType, Boolean.valueOf(available));
                    if (!available && SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("No activated named group", new Object[0]);
                    }
                } else {
                    available = checkedStatus.booleanValue();
                }
                if (!available && SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("No active named group, ignore " + suite, new Object[0]);
                }
                return available;
            }
            return true;
        } else if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
            SSLLogger.fine("Ignore disabled cipher suite: " + suite, new Object[0]);
            return false;
        } else {
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<SNIServerName> getRequestedServerNames() {
        if (this.requestedServerNames == null) {
            return Collections.emptyList();
        }
        return this.requestedServerNames;
    }
}