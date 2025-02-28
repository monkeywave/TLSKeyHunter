package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.provider.SignatureSchemeInfo;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.CertificateStatusRequestItemV2;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.OCSPStatusRequest;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsDHGroupVerifier;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.TrustedAuthority;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.IPAddress;
import org.bouncycastle.util.encoders.Hex;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvTlsClient extends DefaultTlsClient implements ProvTlsPeer {
    private static final Logger LOG = Logger.getLogger(ProvTlsClient.class.getName());
    private static final boolean provClientEnableCA = PropertyUtils.getBooleanSystemProperty("jdk.tls.client.enableCAExtension", false);
    private static final boolean provClientEnableSessionResumption = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.client.enableSessionResumption", true);
    private static final boolean provClientEnableStatusRequest = PropertyUtils.getBooleanSystemProperty("jdk.tls.client.enableStatusRequestExtension", true);
    private static final boolean provClientEnableTrustedCAKeys = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.client.enableTrustedCAKeysExtension", false);
    private static final boolean provClientOmitSigAlgsCert = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.client.omitSigAlgsCertExtension", true);
    private static final boolean provEnableSNIExtension = PropertyUtils.getBooleanSystemProperty("jsse.enableSNIExtension", true);
    protected final String clientID;
    protected boolean handshakeComplete;
    protected final JsseSecurityParameters jsseSecurityParameters;
    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;
    protected ProvSSLSession sslSession;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvTlsClient(ProvTlsManager provTlsManager, ProvSSLParameters provSSLParameters) {
        super(provTlsManager.getContextData().getCrypto());
        this.jsseSecurityParameters = new JsseSecurityParameters();
        this.sslSession = null;
        this.handshakeComplete = false;
        this.clientID = JsseUtils.getPeerID("client", provTlsManager);
        this.manager = provTlsManager;
        this.sslParameters = provSSLParameters.copyForConnection();
    }

    private void handleKeyManagerMisses(LinkedHashMap<String, SignatureSchemeInfo> linkedHashMap, String str) {
        for (Map.Entry<String, SignatureSchemeInfo> entry : linkedHashMap.entrySet()) {
            String key = entry.getKey();
            if (key.equals(str)) {
                return;
            }
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINER)) {
                logger.finer(this.clientID + " found no credentials for signature scheme '" + entry.getValue() + "' (keyType '" + key + "')");
            }
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public boolean allowLegacyResumption() {
        return JsseUtils.allowLegacyResumption();
    }

    @Override // org.bouncycastle.tls.TlsClient
    public TlsAuthentication getAuthentication() throws IOException {
        return new TlsAuthentication() { // from class: org.bouncycastle.jsse.provider.ProvTlsClient.1
            @Override // org.bouncycastle.tls.TlsAuthentication
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                ContextData contextData = ProvTlsClient.this.manager.getContextData();
                SecurityParameters securityParametersHandshake = ProvTlsClient.this.context.getSecurityParametersHandshake();
                ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
                boolean isTLSv13 = TlsUtils.isTLSv13(negotiatedVersion);
                Vector<SignatureAndHashAlgorithm> serverSigAlgs = securityParametersHandshake.getServerSigAlgs();
                Vector<SignatureAndHashAlgorithm> serverSigAlgsCert = securityParametersHandshake.getServerSigAlgsCert();
                List<SignatureSchemeInfo> signatureSchemes = contextData.getSignatureSchemes(serverSigAlgs);
                List<SignatureSchemeInfo> signatureSchemes2 = serverSigAlgsCert != serverSigAlgs ? contextData.getSignatureSchemes(serverSigAlgsCert) : null;
                ProvTlsClient.this.jsseSecurityParameters.signatureSchemes.notifyPeerData(signatureSchemes, signatureSchemes2);
                if (ProvTlsClient.LOG.isLoggable(Level.FINEST)) {
                    ProvTlsClient.LOG.finest(JsseUtils.getSignatureAlgorithmsReport(ProvTlsClient.this.clientID + " peer signature_algorithms", signatureSchemes));
                    if (signatureSchemes2 != null) {
                        ProvTlsClient.LOG.finest(JsseUtils.getSignatureAlgorithmsReport(ProvTlsClient.this.clientID + " peer signature_algorithms_cert", signatureSchemes2));
                    }
                }
                if (DummyX509KeyManager.INSTANCE == contextData.getX509KeyManager()) {
                    return null;
                }
                X500Principal[] x500Principals = JsseUtils.toX500Principals(certificateRequest.getCertificateAuthorities());
                byte[] certificateRequestContext = certificateRequest.getCertificateRequestContext();
                if (isTLSv13 == (certificateRequestContext != null)) {
                    short[] certificateTypes = certificateRequest.getCertificateTypes();
                    if (isTLSv13 == (certificateTypes == null)) {
                        return isTLSv13 ? ProvTlsClient.this.selectClientCredentials13(x500Principals, certificateRequestContext) : TlsUtils.isSignatureAlgorithmsExtensionAllowed(negotiatedVersion) ? ProvTlsClient.this.selectClientCredentials12(x500Principals, certificateTypes) : ProvTlsClient.this.selectClientCredentialsLegacy(x500Principals, certificateTypes);
                    }
                    throw new TlsFatalAlert((short) 80);
                }
                throw new TlsFatalAlert((short) 80);
            }

            @Override // org.bouncycastle.tls.TlsAuthentication
            public void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException {
                if (tlsServerCertificate == null || tlsServerCertificate.getCertificate() == null || tlsServerCertificate.getCertificate().isEmpty()) {
                    throw new TlsFatalAlert((short) 40);
                }
                X509Certificate[] x509CertificateChain = JsseUtils.getX509CertificateChain(ProvTlsClient.this.getCrypto(), tlsServerCertificate.getCertificate());
                String authTypeServer = JsseUtils.getAuthTypeServer(ProvTlsClient.this.context.getSecurityParametersHandshake().getKeyExchangeAlgorithm());
                ProvTlsClient.this.jsseSecurityParameters.statusResponses = JsseUtils.getStatusResponses(tlsServerCertificate.getCertificateStatus());
                ProvTlsClient.this.manager.checkServerTrusted(x509CertificateChain, authTypeServer);
            }
        };
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected Vector<X500Name> getCertificateAuthorities() {
        if (provClientEnableCA) {
            return JsseUtils.getCertificateAuthorities(this.manager.getContextData().getX509TrustManager());
        }
        return null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected CertificateStatusRequest getCertificateStatusRequest() {
        if (provClientEnableStatusRequest) {
            return new CertificateStatusRequest((short) 1, new OCSPStatusRequest(null, null));
        }
        return null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public JcaTlsCrypto getCrypto() {
        return this.manager.getContextData().getCrypto();
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public TlsDHGroupVerifier getDHGroupVerifier() {
        return new ProvDHGroupVerifier();
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsPeer
    public String getID() {
        return this.clientID;
    }

    protected String[] getKeyTypesLegacy(short[] sArr) throws IOException {
        String[] strArr = new String[sArr.length];
        for (int i = 0; i < sArr.length; i++) {
            strArr[i] = JsseUtils.getKeyTypeLegacyClient(sArr[i]);
        }
        return strArr;
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public int getMaxCertificateChainLength() {
        return JsseUtils.getMaxCertificateChainLength();
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public int getMaxHandshakeMessageSize() {
        return JsseUtils.getMaxHandshakeMessageSize();
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected Vector<CertificateStatusRequestItemV2> getMultiCertStatusRequest() {
        if (provClientEnableStatusRequest) {
            OCSPStatusRequest oCSPStatusRequest = new OCSPStatusRequest(null, null);
            Vector<CertificateStatusRequestItemV2> vector = new Vector<>(2);
            vector.add(new CertificateStatusRequestItemV2((short) 2, oCSPStatusRequest));
            vector.add(new CertificateStatusRequestItemV2((short) 1, oCSPStatusRequest));
            return vector;
        }
        return null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected Vector<ProtocolName> getProtocolNames() {
        return JsseUtils.getProtocolNames(this.sslParameters.getApplicationProtocols());
    }

    protected SessionParameters getResumableSessionParameters(ProvSSLSession provSSLSession, TlsSession tlsSession) {
        SessionParameters exportSessionParameters;
        if (tlsSession == null || !tlsSession.isResumable() || (exportSessionParameters = tlsSession.exportSessionParameters()) == null || !Arrays.contains(getCipherSuites(), exportSessionParameters.getCipherSuite())) {
            return null;
        }
        ProtocolVersion negotiatedVersion = exportSessionParameters.getNegotiatedVersion();
        if (ProtocolVersion.contains(getProtocolVersions(), negotiatedVersion) && !TlsUtils.isTLSv13(negotiatedVersion)) {
            String endpointIdentificationAlgorithm = this.sslParameters.getEndpointIdentificationAlgorithm();
            if (endpointIdentificationAlgorithm != null) {
                String endpointIDAlgorithm = provSSLSession.getJsseSessionParameters().getEndpointIDAlgorithm();
                if (!endpointIdentificationAlgorithm.equalsIgnoreCase(endpointIDAlgorithm)) {
                    Logger logger = LOG;
                    if (logger.isLoggable(Level.FINER)) {
                        logger.finer(this.clientID + ": Session not resumable - endpoint ID algorithm mismatch; connection: " + endpointIdentificationAlgorithm + ", session: " + endpointIDAlgorithm);
                    }
                    return null;
                }
            }
            return exportSessionParameters;
        }
        return null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected Vector<ServerName> getSNIServerNames() {
        String peerHostSNI;
        if (provEnableSNIExtension) {
            List<BCSNIServerName> serverNames = this.sslParameters.getServerNames();
            if (serverNames == null && (peerHostSNI = this.manager.getPeerHostSNI()) != null && peerHostSNI.indexOf(46) > 0 && !IPAddress.isValid(peerHostSNI)) {
                try {
                    serverNames = Collections.singletonList(new BCSNIHostName(peerHostSNI));
                } catch (RuntimeException unused) {
                    LOG.fine(this.clientID + ": Failed to add peer host as default SNI host_name: " + peerHostSNI);
                }
            }
            if (serverNames == null || serverNames.isEmpty()) {
                return null;
            }
            Vector<ServerName> vector = new Vector<>(serverNames.size());
            for (BCSNIServerName bCSNIServerName : serverNames) {
                vector.add(new ServerName((short) bCSNIServerName.getType(), bCSNIServerName.getEncoded()));
            }
            return vector;
        }
        return null;
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsPeer
    public ProvSSLSession getSession() {
        return this.sslSession;
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public TlsSession getSessionToResume() {
        TlsSession tlsSession;
        SessionParameters resumableSessionParameters;
        if (provClientEnableSessionResumption) {
            ProvSSLSession sessionToResume = this.sslParameters.getSessionToResume();
            if (sessionToResume == null) {
                sessionToResume = this.manager.getContextData().getClientSessionContext().getSessionImpl(this.manager.getPeerHost(), this.manager.getPeerPort());
            }
            if (sessionToResume != null && (resumableSessionParameters = getResumableSessionParameters(sessionToResume, (tlsSession = sessionToResume.getTlsSession()))) != null) {
                this.sslSession = sessionToResume;
                if (!this.manager.getEnableSessionCreation()) {
                    this.cipherSuites = new int[]{resumableSessionParameters.getCipherSuite()};
                }
                return tlsSession;
            }
        }
        JsseUtils.checkSessionCreationEnabled(this.manager);
        return null;
    }

    @Override // org.bouncycastle.tls.DefaultTlsClient, org.bouncycastle.tls.AbstractTlsPeer
    protected int[] getSupportedCipherSuites() {
        return this.manager.getContextData().getContext().getActiveCipherSuites(getCrypto(), this.sslParameters, getProtocolVersions());
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected Vector<Integer> getSupportedGroups(Vector vector) {
        return NamedGroupInfo.getSupportedGroupsLocalClient(this.jsseSecurityParameters.namedGroups);
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected Vector<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithms() {
        return this.jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithms();
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected Vector<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithmsCert() {
        Vector<SignatureAndHashAlgorithm> localSignatureAndHashAlgorithmsCert = this.jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithmsCert();
        return (localSignatureAndHashAlgorithmsCert != null || provClientOmitSigAlgsCert) ? localSignatureAndHashAlgorithmsCert : this.jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithms();
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer
    protected ProtocolVersion[] getSupportedVersions() {
        return this.manager.getContextData().getContext().getActiveProtocolVersions(this.sslParameters);
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsPeer
    public TlsContext getTlsContext() {
        return this.context;
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient
    protected Vector<TrustedAuthority> getTrustedCAIndication() {
        Vector<X500Name> certificateAuthorities;
        if (!provClientEnableTrustedCAKeys || (certificateAuthorities = JsseUtils.getCertificateAuthorities(this.manager.getContextData().getX509TrustManager())) == null) {
            return null;
        }
        Vector<TrustedAuthority> vector = new Vector<>(certificateAuthorities.size());
        Iterator<X500Name> it = certificateAuthorities.iterator();
        while (it.hasNext()) {
            vector.add(new TrustedAuthority((short) 2, it.next()));
        }
        return vector;
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsPeer
    public synchronized boolean isHandshakeComplete() {
        return this.handshakeComplete;
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifyAlertRaised(short s, short s2, String str, Throwable th) {
        super.notifyAlertRaised(s, s2, str, th);
        Level level = s == 1 ? Level.FINE : s2 == 80 ? Level.WARNING : Level.INFO;
        Logger logger = LOG;
        if (logger.isLoggable(level)) {
            String alertRaisedLogMessage = JsseUtils.getAlertRaisedLogMessage(this.clientID, s, s2);
            if (str != null) {
                alertRaisedLogMessage = alertRaisedLogMessage + ": " + str;
            }
            logger.log(level, alertRaisedLogMessage, th);
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifyAlertReceived(short s, short s2) {
        super.notifyAlertReceived(s, s2);
        Level level = s == 1 ? Level.FINE : Level.INFO;
        Logger logger = LOG;
        if (logger.isLoggable(level)) {
            logger.log(level, JsseUtils.getAlertReceivedLogMessage(this.clientID, s, s2));
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifyConnectionClosed() {
        super.notifyConnectionClosed();
        Logger logger = LOG;
        if (logger.isLoggable(Level.INFO)) {
            logger.info(this.clientID + " disconnected from " + JsseUtils.getPeerReport(this.manager));
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifyHandshakeBeginning() throws IOException {
        super.notifyHandshakeBeginning();
        Logger logger = LOG;
        if (logger.isLoggable(Level.INFO)) {
            logger.info(this.clientID + " opening connection to " + JsseUtils.getPeerReport(this.manager));
        }
        ContextData contextData = this.manager.getContextData();
        ProtocolVersion[] protocolVersions = getProtocolVersions();
        this.jsseSecurityParameters.namedGroups = contextData.getNamedGroupsClient(this.sslParameters, protocolVersions);
        JsseSecurityParameters jsseSecurityParameters = this.jsseSecurityParameters;
        jsseSecurityParameters.signatureSchemes = contextData.getSignatureSchemesClient(this.sslParameters, protocolVersions, jsseSecurityParameters.namedGroups);
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public synchronized void notifyHandshakeComplete() throws IOException {
        super.notifyHandshakeComplete();
        boolean z = true;
        this.handshakeComplete = true;
        Logger logger = LOG;
        if (logger.isLoggable(Level.INFO)) {
            logger.info(this.clientID + " established connection with " + JsseUtils.getPeerReport(this.manager));
        }
        TlsSession session = this.context.getSession();
        ProvSSLSession provSSLSession = this.sslSession;
        if (provSSLSession == null || provSSLSession.getTlsSession() != session) {
            ProvSSLSessionContext clientSessionContext = this.manager.getContextData().getClientSessionContext();
            String peerHost = this.manager.getPeerHost();
            int peerPort = this.manager.getPeerPort();
            JsseSessionParameters jsseSessionParameters = new JsseSessionParameters(this.sslParameters.getEndpointIdentificationAlgorithm(), null);
            if (!provClientEnableSessionResumption || TlsUtils.isTLSv13(this.context)) {
                z = false;
            }
            this.sslSession = clientSessionContext.reportSession(peerHost, peerPort, session, jsseSessionParameters, z);
        }
        this.manager.notifyHandshakeComplete(new ProvSSLConnection(this));
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifySecureRenegotiation(boolean z) throws IOException {
        if (!z && !PropertyUtils.getBooleanSystemProperty("sun.security.ssl.allowLegacyHelloMessages", true)) {
            throw new TlsFatalAlert((short) 40);
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public void notifySelectedCipherSuite(int i) {
        String validateNegotiatedCipherSuite = this.manager.getContextData().getContext().validateNegotiatedCipherSuite(this.sslParameters, i);
        Logger logger = LOG;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine(this.clientID + " notified of selected cipher suite: " + validateNegotiatedCipherSuite);
        }
        super.notifySelectedCipherSuite(i);
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public void notifyServerVersion(ProtocolVersion protocolVersion) throws IOException {
        String validateNegotiatedProtocol = this.manager.getContextData().getContext().validateNegotiatedProtocol(this.sslParameters, protocolVersion);
        Logger logger = LOG;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine(this.clientID + " notified of selected protocol version: " + validateNegotiatedProtocol);
        }
        super.notifyServerVersion(protocolVersion);
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public void notifySessionID(byte[] bArr) {
        ProvSSLSession provSSLSession;
        if (TlsUtils.isNullOrEmpty(bArr) || (provSSLSession = this.sslSession) == null || !Arrays.areEqual(bArr, provSSLSession.getId())) {
            this.sslSession = null;
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine((TlsUtils.isNullOrEmpty(bArr) ? new StringBuilder().append(this.clientID).append(": Server did not specify a session ID") : new StringBuilder().append(this.clientID).append(": Server specified new session: ").append(Hex.toHexString(bArr))).toString());
            }
            JsseUtils.checkSessionCreationEnabled(this.manager);
        } else {
            Logger logger2 = LOG;
            if (logger2.isLoggable(Level.FINE)) {
                logger2.fine(this.clientID + ": Server resumed session: " + Hex.toHexString(bArr));
            }
        }
        ProvTlsManager provTlsManager = this.manager;
        provTlsManager.notifyHandshakeSession(provTlsManager.getContextData().getClientSessionContext(), this.context.getSecurityParametersHandshake(), this.jsseSecurityParameters, this.sslSession);
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public void notifySessionToResume(TlsSession tlsSession) {
        if (tlsSession == null) {
            JsseUtils.checkSessionCreationEnabled(this.manager);
        }
        super.notifySessionToResume(tlsSession);
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public void processServerExtensions(Hashtable hashtable) throws IOException {
        super.processServerExtensions(hashtable);
        if (this.context.getSecurityParametersHandshake().getClientServerNames() != null) {
            boolean hasServerNameExtensionServer = TlsExtensionsUtils.hasServerNameExtensionServer(hashtable);
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINER)) {
                logger.finer(this.clientID + ": Server accepted SNI?: " + hasServerNameExtensionServer);
            }
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public boolean requiresCloseNotify() {
        return JsseUtils.requireCloseNotify();
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public boolean requiresExtendedMasterSecret() {
        return !JsseUtils.allowLegacyMasterSecret();
    }

    protected TlsCredentials selectClientCredentials12(Principal[] principalArr, short[] sArr) throws IOException {
        short clientCertificateType;
        SignatureSchemeInfo.PerConnection perConnection = this.jsseSecurityParameters.signatureSchemes;
        LinkedHashMap<String, SignatureSchemeInfo> linkedHashMap = new LinkedHashMap<>();
        for (SignatureSchemeInfo signatureSchemeInfo : perConnection.getPeerSigSchemes()) {
            String keyType = signatureSchemeInfo.getKeyType();
            if (!linkedHashMap.containsKey(keyType) && (clientCertificateType = SignatureAlgorithm.getClientCertificateType(signatureSchemeInfo.getSignatureAlgorithm())) >= 0 && Arrays.contains(sArr, clientCertificateType) && signatureSchemeInfo.isSupportedPre13() && perConnection.hasLocalSignatureScheme(signatureSchemeInfo)) {
                linkedHashMap.put(keyType, signatureSchemeInfo);
            }
        }
        if (linkedHashMap.isEmpty()) {
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine(this.clientID + " (1.2) found no usable signature schemes");
            }
            return null;
        }
        BCX509Key chooseClientKey = this.manager.chooseClientKey((String[]) linkedHashMap.keySet().toArray(TlsUtils.EMPTY_STRINGS), principalArr);
        if (chooseClientKey == null) {
            handleKeyManagerMisses(linkedHashMap, null);
            Logger logger2 = LOG;
            if (logger2.isLoggable(Level.FINE)) {
                logger2.fine(this.clientID + " (1.2) did not select any credentials");
            }
            return null;
        }
        String keyType2 = chooseClientKey.getKeyType();
        handleKeyManagerMisses(linkedHashMap, keyType2);
        SignatureSchemeInfo signatureSchemeInfo2 = linkedHashMap.get(keyType2);
        if (signatureSchemeInfo2 != null) {
            Logger logger3 = LOG;
            if (logger3.isLoggable(Level.FINE)) {
                logger3.fine(this.clientID + " (1.2) selected credentials for signature scheme '" + signatureSchemeInfo2 + "' (keyType '" + keyType2 + "'), with private key algorithm '" + JsseUtils.getPrivateKeyAlgorithm(chooseClientKey.getPrivateKey()) + "'");
            }
            return JsseUtils.createCredentialedSigner(this.context, getCrypto(), chooseClientKey, signatureSchemeInfo2.getSignatureAndHashAlgorithm());
        }
        throw new TlsFatalAlert((short) 80, "Key manager returned invalid key type");
    }

    protected TlsCredentials selectClientCredentials13(Principal[] principalArr, byte[] bArr) throws IOException {
        SignatureSchemeInfo.PerConnection perConnection = this.jsseSecurityParameters.signatureSchemes;
        LinkedHashMap<String, SignatureSchemeInfo> linkedHashMap = new LinkedHashMap<>();
        for (SignatureSchemeInfo signatureSchemeInfo : perConnection.getPeerSigSchemes()) {
            String keyType13 = signatureSchemeInfo.getKeyType13();
            if (!linkedHashMap.containsKey(keyType13) && signatureSchemeInfo.isSupportedPost13() && perConnection.hasLocalSignatureScheme(signatureSchemeInfo)) {
                linkedHashMap.put(keyType13, signatureSchemeInfo);
            }
        }
        if (linkedHashMap.isEmpty()) {
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine(this.clientID + " (1.3) found no usable signature schemes");
            }
            return null;
        }
        BCX509Key chooseClientKey = this.manager.chooseClientKey((String[]) linkedHashMap.keySet().toArray(TlsUtils.EMPTY_STRINGS), principalArr);
        if (chooseClientKey == null) {
            handleKeyManagerMisses(linkedHashMap, null);
            Logger logger2 = LOG;
            if (logger2.isLoggable(Level.FINE)) {
                logger2.fine(this.clientID + " (1.3) did not select any credentials");
            }
            return null;
        }
        String keyType = chooseClientKey.getKeyType();
        handleKeyManagerMisses(linkedHashMap, keyType);
        SignatureSchemeInfo signatureSchemeInfo2 = linkedHashMap.get(keyType);
        if (signatureSchemeInfo2 != null) {
            Logger logger3 = LOG;
            if (logger3.isLoggable(Level.FINE)) {
                logger3.fine(this.clientID + " (1.3) selected credentials for signature scheme '" + signatureSchemeInfo2 + "' (keyType '" + keyType + "'), with private key algorithm '" + JsseUtils.getPrivateKeyAlgorithm(chooseClientKey.getPrivateKey()) + "'");
            }
            return JsseUtils.createCredentialedSigner13(this.context, getCrypto(), chooseClientKey, signatureSchemeInfo2.getSignatureAndHashAlgorithm(), bArr);
        }
        throw new TlsFatalAlert((short) 80, "Key manager returned invalid key type");
    }

    protected TlsCredentials selectClientCredentialsLegacy(Principal[] principalArr, short[] sArr) throws IOException {
        BCX509Key chooseClientKey;
        String[] keyTypesLegacy = getKeyTypesLegacy(sArr);
        if (keyTypesLegacy.length >= 1 && (chooseClientKey = this.manager.chooseClientKey(keyTypesLegacy, principalArr)) != null) {
            return JsseUtils.createCredentialedSigner(this.context, getCrypto(), chooseClientKey, null);
        }
        return null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public boolean shouldUseCompatibilityMode() {
        return JsseUtils.useCompatibilityMode();
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public boolean shouldUseExtendedMasterSecret() {
        return JsseUtils.useExtendedMasterSecret();
    }
}