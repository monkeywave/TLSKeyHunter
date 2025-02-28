package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.provider.NamedGroupInfo;
import org.bouncycastle.jsse.provider.SignatureSchemeInfo;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvTlsServer extends DefaultTlsServer implements ProvTlsPeer {
    private static final String PROPERTY_DEFAULT_DHE_PARAMETERS = "jdk.tls.server.defaultDHEParameters";
    private static final boolean provServerEnableStatusRequest = false;
    protected TlsCredentials credentials;
    protected boolean handshakeComplete;
    protected final JsseSecurityParameters jsseSecurityParameters;
    protected Set<String> keyManagerMissCache;
    protected final ProvTlsManager manager;
    protected BCSNIServerName matchedSNIServerName;
    protected final String serverID;
    protected final ProvSSLParameters sslParameters;
    protected ProvSSLSession sslSession;
    private static final Logger LOG = Logger.getLogger(ProvTlsServer.class.getName());
    private static final int provEphemeralDHKeySize = PropertyUtils.getIntegerSystemProperty("jdk.tls.ephemeralDHKeySize", 2048, 1024, 8192);
    private static final DHGroup[] provServerDefaultDHEParameters = getDefaultDHEParameters();
    private static final boolean provServerEnableCA = PropertyUtils.getBooleanSystemProperty("jdk.tls.server.enableCAExtension", true);
    private static final boolean provServerEnableSessionResumption = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.server.enableSessionResumption", true);
    private static final boolean provServerEnableTrustedCAKeys = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.server.enableTrustedCAKeysExtension", false);
    private static final boolean provServerOmitSigAlgsCert = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.server.omitSigAlgsCertExtension", true);

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvTlsServer(ProvTlsManager provTlsManager, ProvSSLParameters provSSLParameters) {
        super(provTlsManager.getContextData().getCrypto());
        this.jsseSecurityParameters = new JsseSecurityParameters();
        this.sslSession = null;
        this.matchedSNIServerName = null;
        this.keyManagerMissCache = null;
        this.credentials = null;
        this.handshakeComplete = false;
        this.serverID = JsseUtils.getPeerID("server", provTlsManager);
        this.manager = provTlsManager;
        this.sslParameters = provSSLParameters.copyForConnection();
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x008a A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private static org.bouncycastle.tls.crypto.DHGroup[] getDefaultDHEParameters() {
        /*
            java.lang.String r0 = "jdk.tls.server.defaultDHEParameters"
            java.lang.String r0 = org.bouncycastle.jsse.provider.PropertyUtils.getStringSecurityProperty(r0)
            r1 = 0
            if (r0 != 0) goto La
            return r1
        La:
            java.lang.String r0 = org.bouncycastle.jsse.provider.JsseUtils.removeAllWhitespace(r0)
            java.lang.String r0 = org.bouncycastle.jsse.provider.JsseUtils.stripDoubleQuotes(r0)
            int r2 = r0.length()
            r3 = 1
            if (r2 >= r3) goto L1a
            return r1
        L1a:
            java.util.ArrayList r3 = new java.util.ArrayList
            r3.<init>()
            r4 = -1
        L20:
            int r5 = r4 + 1
            if (r5 >= r2) goto La5
            r6 = 123(0x7b, float:1.72E-43)
            char r5 = r0.charAt(r5)
            if (r6 == r5) goto L2e
            goto La5
        L2e:
            int r4 = r4 + 2
            r5 = 44
            int r6 = r0.indexOf(r5, r4)
            if (r6 > r4) goto L39
            goto La5
        L39:
            int r7 = r6 + 1
            r8 = 125(0x7d, float:1.75E-43)
            int r8 = r0.indexOf(r8, r7)
            if (r8 > r7) goto L44
            goto La5
        L44:
            java.math.BigInteger r4 = parseDHParameter(r0, r4, r6)     // Catch: java.lang.Exception -> La5
            java.math.BigInteger r6 = parseDHParameter(r0, r7, r8)     // Catch: java.lang.Exception -> La5
            org.bouncycastle.tls.crypto.DHGroup r7 = org.bouncycastle.tls.TlsDHUtils.getStandardGroupForDHParameters(r4, r6)     // Catch: java.lang.Exception -> La5
            if (r7 == 0) goto L56
        L52:
            r3.add(r7)     // Catch: java.lang.Exception -> La5
            goto L86
        L56:
            r7 = 120(0x78, float:1.68E-43)
            boolean r7 = r4.isProbablePrime(r7)     // Catch: java.lang.Exception -> La5
            if (r7 != 0) goto L7f
            java.util.logging.Logger r6 = org.bouncycastle.jsse.provider.ProvTlsServer.LOG     // Catch: java.lang.Exception -> La5
            java.util.logging.Level r7 = java.util.logging.Level.WARNING     // Catch: java.lang.Exception -> La5
            java.lang.StringBuilder r9 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> La5
            r9.<init>()     // Catch: java.lang.Exception -> La5
            java.lang.String r10 = "Non-prime modulus ignored in security property [jdk.tls.server.defaultDHEParameters]: "
            java.lang.StringBuilder r9 = r9.append(r10)     // Catch: java.lang.Exception -> La5
            r10 = 16
            java.lang.String r4 = r4.toString(r10)     // Catch: java.lang.Exception -> La5
            java.lang.StringBuilder r4 = r9.append(r4)     // Catch: java.lang.Exception -> La5
            java.lang.String r4 = r4.toString()     // Catch: java.lang.Exception -> La5
            r6.log(r7, r4)     // Catch: java.lang.Exception -> La5
            goto L86
        L7f:
            org.bouncycastle.tls.crypto.DHGroup r7 = new org.bouncycastle.tls.crypto.DHGroup     // Catch: java.lang.Exception -> La5
            r9 = 0
            r7.<init>(r4, r1, r6, r9)     // Catch: java.lang.Exception -> La5
            goto L52
        L86:
            int r4 = r8 + 1
            if (r4 < r2) goto L9f
            int r0 = r3.size()
            org.bouncycastle.tls.crypto.DHGroup[] r0 = new org.bouncycastle.tls.crypto.DHGroup[r0]
            java.lang.Object[] r0 = r3.toArray(r0)
            org.bouncycastle.tls.crypto.DHGroup[] r0 = (org.bouncycastle.tls.crypto.DHGroup[]) r0
            org.bouncycastle.jsse.provider.ProvTlsServer$1 r1 = new org.bouncycastle.jsse.provider.ProvTlsServer$1
            r1.<init>()
            java.util.Arrays.sort(r0, r1)
            return r0
        L9f:
            char r6 = r0.charAt(r4)
            if (r5 == r6) goto L20
        La5:
            java.util.logging.Logger r0 = org.bouncycastle.jsse.provider.ProvTlsServer.LOG
            java.util.logging.Level r2 = java.util.logging.Level.WARNING
            java.lang.String r3 = "Invalid syntax for security property [jdk.tls.server.defaultDHEParameters]"
            r0.log(r2, r3)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jsse.provider.ProvTlsServer.getDefaultDHEParameters():org.bouncycastle.tls.crypto.DHGroup[]");
    }

    private void handleKeyManagerMisses(LinkedHashMap<String, SignatureSchemeInfo> linkedHashMap, String str) {
        for (Map.Entry<String, SignatureSchemeInfo> entry : linkedHashMap.entrySet()) {
            String key = entry.getKey();
            if (key.equals(str)) {
                return;
            }
            this.keyManagerMissCache.add(key);
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINER)) {
                logger.finer(this.serverID + " found no credentials for signature scheme '" + entry.getValue() + "' (keyType '" + key + "')");
            }
        }
    }

    private static BigInteger parseDHParameter(String str, int i, int i2) {
        return new BigInteger(str.substring(i, i2), 16);
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected boolean allowCertificateStatus() {
        return false;
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public boolean allowLegacyResumption() {
        return JsseUtils.allowLegacyResumption();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected boolean allowMultiCertStatus() {
        return false;
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected boolean allowTrustedCAIndication() {
        return this.jsseSecurityParameters.trustedIssuers != null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public CertificateRequest getCertificateRequest() throws IOException {
        if (isClientAuthEnabled()) {
            ContextData contextData = this.manager.getContextData();
            ProtocolVersion serverVersion = this.context.getServerVersion();
            Vector<SignatureAndHashAlgorithm> localSignatureAndHashAlgorithms = this.jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithms();
            Vector<X500Name> certificateAuthorities = provServerEnableCA ? JsseUtils.getCertificateAuthorities(contextData.getX509TrustManager()) : null;
            if (TlsUtils.isTLSv13(serverVersion)) {
                byte[] bArr = TlsUtils.EMPTY_BYTES;
                Vector<SignatureAndHashAlgorithm> localSignatureAndHashAlgorithmsCert = this.jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithmsCert();
                if (localSignatureAndHashAlgorithmsCert == null && !provServerOmitSigAlgsCert) {
                    localSignatureAndHashAlgorithmsCert = this.jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithms();
                }
                return new CertificateRequest(bArr, localSignatureAndHashAlgorithms, localSignatureAndHashAlgorithmsCert, certificateAuthorities);
            }
            return new CertificateRequest(new short[]{64, 1, 2}, localSignatureAndHashAlgorithms, certificateAuthorities);
        }
        return null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public CertificateStatus getCertificateStatus() throws IOException {
        return null;
    }

    @Override // org.bouncycastle.tls.DefaultTlsServer, org.bouncycastle.tls.TlsServer
    public TlsCredentials getCredentials() throws IOException {
        TlsCredentials tlsCredentials = this.credentials;
        if (tlsCredentials != null) {
            return tlsCredentials;
        }
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public JcaTlsCrypto getCrypto() {
        return this.manager.getContextData().getCrypto();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public TlsDHConfig getDHConfig() throws IOException {
        int max = Math.max(TlsDHUtils.getMinimumFiniteFieldBits(this.selectedCipherSuite), provEphemeralDHKeySize);
        NamedGroupInfo.DefaultedResult selectServerFFDHE = NamedGroupInfo.selectServerFFDHE(this.jsseSecurityParameters.namedGroups, max);
        int result = selectServerFFDHE.getResult();
        if (selectServerFFDHE.isDefaulted()) {
            DHGroup[] dHGroupArr = provServerDefaultDHEParameters;
            if (!TlsUtils.isNullOrEmpty(dHGroupArr) && !this.manager.getContextData().getContext().isFips()) {
                int length = dHGroupArr.length;
                int i = 0;
                while (true) {
                    if (i >= length) {
                        break;
                    }
                    DHGroup dHGroup = dHGroupArr[i];
                    int bitLength = dHGroup.getP().bitLength();
                    if (bitLength < max) {
                        i++;
                    } else if (result < 0 || bitLength <= NamedGroup.getFiniteFieldBits(result)) {
                        return new TlsDHConfig(dHGroup);
                    }
                }
            }
        }
        return TlsDHUtils.createNamedDHConfig(this.context, result);
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected String getDetailMessageNoCipherSuite() {
        StringBuilder sb = new StringBuilder(this.serverID);
        int[] iArr = this.offeredCipherSuites;
        if (TlsUtils.isNullOrEmpty(iArr)) {
            sb.append(" found no selectable cipher suite because none were offered.");
        } else {
            sb.append(" found no selectable cipher suite among the ");
            sb.append(iArr.length);
            sb.append(" offered: [");
            ProvSSLContextSpi context = this.manager.getContextData().getContext();
            JsseUtils.appendCipherSuiteDetail(sb, context, iArr[0]);
            for (int i = 1; i < iArr.length; i++) {
                sb.append(", ");
                JsseUtils.appendCipherSuiteDetail(sb, context, iArr[i]);
            }
            sb.append(']');
        }
        return sb.toString();
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsPeer
    public String getID() {
        return this.serverID;
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public int getMaxCertificateChainLength() {
        return JsseUtils.getMaxCertificateChainLength();
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public int getMaxHandshakeMessageSize() {
        return JsseUtils.getMaxHandshakeMessageSize();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected int getMaximumNegotiableCurveBits() {
        return NamedGroupInfo.getMaximumBitsServerECDH(this.jsseSecurityParameters.namedGroups).getResult();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected int getMaximumNegotiableFiniteFieldBits() {
        NamedGroupInfo.DefaultedResult maximumBitsServerFFDHE = NamedGroupInfo.getMaximumBitsServerFFDHE(this.jsseSecurityParameters.namedGroups);
        int result = maximumBitsServerFFDHE.getResult();
        if (maximumBitsServerFFDHE.isDefaulted()) {
            DHGroup[] dHGroupArr = provServerDefaultDHEParameters;
            if (!TlsUtils.isNullOrEmpty(dHGroupArr) && !this.manager.getContextData().getContext().isFips()) {
                result = Math.max(result, dHGroupArr[dHGroupArr.length - 1].getP().bitLength());
            }
        }
        if (result >= provEphemeralDHKeySize) {
            return result;
        }
        return 0;
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public byte[] getNewSessionID() {
        if (!provServerEnableSessionResumption || TlsUtils.isTLSv13(this.context)) {
            return null;
        }
        return this.context.getNonceGenerator().generateNonce(32);
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected Vector<ProtocolName> getProtocolNames() {
        return JsseUtils.getProtocolNames(this.sslParameters.getApplicationProtocols());
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public int getSelectedCipherSuite() throws IOException {
        ContextData contextData = this.manager.getContextData();
        SecurityParameters securityParametersHandshake = this.context.getSecurityParametersHandshake();
        this.jsseSecurityParameters.namedGroups.notifyPeerData(securityParametersHandshake.getClientSupportedGroups());
        ProtocolVersion serverVersion = this.context.getServerVersion();
        JsseSecurityParameters jsseSecurityParameters = this.jsseSecurityParameters;
        jsseSecurityParameters.signatureSchemes = contextData.getSignatureSchemesServer(this.sslParameters, serverVersion, jsseSecurityParameters.namedGroups);
        Vector<SignatureAndHashAlgorithm> clientSigAlgs = securityParametersHandshake.getClientSigAlgs();
        Vector<SignatureAndHashAlgorithm> clientSigAlgsCert = securityParametersHandshake.getClientSigAlgsCert();
        List<SignatureSchemeInfo> signatureSchemes = contextData.getSignatureSchemes(clientSigAlgs);
        List<SignatureSchemeInfo> signatureSchemes2 = clientSigAlgsCert != clientSigAlgs ? contextData.getSignatureSchemes(clientSigAlgsCert) : null;
        this.jsseSecurityParameters.signatureSchemes.notifyPeerData(signatureSchemes, signatureSchemes2);
        Logger logger = LOG;
        if (logger.isLoggable(Level.FINEST)) {
            logger.finest(JsseUtils.getSignatureAlgorithmsReport(this.serverID + " peer signature_algorithms", signatureSchemes));
            if (signatureSchemes2 != null) {
                logger.finest(JsseUtils.getSignatureAlgorithmsReport(this.serverID + " peer signature_algorithms_cert", signatureSchemes2));
            }
        }
        if (DummyX509KeyManager.INSTANCE != contextData.getX509KeyManager()) {
            this.keyManagerMissCache = new HashSet();
            int selectedCipherSuite = super.getSelectedCipherSuite();
            this.keyManagerMissCache = null;
            String validateNegotiatedCipherSuite = contextData.getContext().validateNegotiatedCipherSuite(this.sslParameters, selectedCipherSuite);
            if (logger.isLoggable(Level.FINE)) {
                logger.fine(this.serverID + " selected cipher suite: " + validateNegotiatedCipherSuite);
            }
            return selectedCipherSuite;
        }
        throw new TlsFatalAlert((short) 40);
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public Hashtable<Integer, byte[]> getServerExtensions() throws IOException {
        super.getServerExtensions();
        if (this.matchedSNIServerName != null) {
            TlsExtensionsUtils.addServerNameExtensionServer(this.serverExtensions);
        }
        return this.serverExtensions;
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public ProtocolVersion getServerVersion() throws IOException {
        ProtocolVersion serverVersion = super.getServerVersion();
        String validateNegotiatedProtocol = this.manager.getContextData().getContext().validateNegotiatedProtocol(this.sslParameters, serverVersion);
        Logger logger = LOG;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine(this.serverID + " selected protocol version: " + validateNegotiatedProtocol);
        }
        return serverVersion;
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsPeer
    public ProvSSLSession getSession() {
        return this.sslSession;
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public TlsSession getSessionToResume(byte[] bArr) {
        ProvSSLSession sessionImpl;
        ProvSSLSessionContext serverSessionContext = this.manager.getContextData().getServerSessionContext();
        if (provServerEnableSessionResumption && (sessionImpl = serverSessionContext.getSessionImpl(bArr)) != null) {
            TlsSession tlsSession = sessionImpl.getTlsSession();
            if (isResumable(sessionImpl, tlsSession)) {
                this.sslSession = sessionImpl;
                return tlsSession;
            }
        }
        JsseUtils.checkSessionCreationEnabled(this.manager);
        return null;
    }

    @Override // org.bouncycastle.tls.DefaultTlsServer, org.bouncycastle.tls.AbstractTlsPeer
    protected int[] getSupportedCipherSuites() {
        return this.manager.getContextData().getContext().getActiveCipherSuites(getCrypto(), this.sslParameters, getProtocolVersions());
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public int[] getSupportedGroups() throws IOException {
        ContextData contextData = this.manager.getContextData();
        ProtocolVersion serverVersion = this.context.getServerVersion();
        this.jsseSecurityParameters.namedGroups = contextData.getNamedGroupsServer(this.sslParameters, serverVersion);
        return NamedGroupInfo.getSupportedGroupsLocalServer(this.jsseSecurityParameters.namedGroups);
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer
    protected ProtocolVersion[] getSupportedVersions() {
        return this.manager.getContextData().getContext().getActiveProtocolVersions(this.sslParameters);
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsPeer
    public TlsContext getTlsContext() {
        return this.context;
    }

    protected boolean isClientAuthEnabled() {
        return this.sslParameters.getNeedClientAuth() || this.sslParameters.getWantClientAuth();
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsPeer
    public synchronized boolean isHandshakeComplete() {
        return this.handshakeComplete;
    }

    protected boolean isResumable(ProvSSLSession provSSLSession, TlsSession tlsSession) {
        SessionParameters exportSessionParameters;
        if (tlsSession != null && tlsSession.isResumable()) {
            ProtocolVersion negotiatedVersion = this.context.getSecurityParametersHandshake().getNegotiatedVersion();
            if (!TlsUtils.isTLSv13(negotiatedVersion) && (exportSessionParameters = tlsSession.exportSessionParameters()) != null && negotiatedVersion.equals(exportSessionParameters.getNegotiatedVersion()) && Arrays.contains(getCipherSuites(), exportSessionParameters.getCipherSuite()) && Arrays.contains(this.offeredCipherSuites, exportSessionParameters.getCipherSuite())) {
                if (this.sslParameters.getNeedClientAuth() && exportSessionParameters.getPeerCertificate() == null) {
                    return false;
                }
                String endpointIdentificationAlgorithm = this.sslParameters.getEndpointIdentificationAlgorithm();
                if (endpointIdentificationAlgorithm != null) {
                    String endpointIDAlgorithm = provSSLSession.getJsseSessionParameters().getEndpointIDAlgorithm();
                    if (!endpointIdentificationAlgorithm.equalsIgnoreCase(endpointIDAlgorithm)) {
                        Logger logger = LOG;
                        if (logger.isLoggable(Level.FINER)) {
                            logger.finer(this.serverID + ": Session not resumable - endpoint ID algorithm mismatch; connection: " + endpointIdentificationAlgorithm + ", session: " + endpointIDAlgorithm);
                        }
                        return false;
                    }
                }
                JsseSessionParameters jsseSessionParameters = provSSLSession.getJsseSessionParameters();
                BCSNIServerName bCSNIServerName = this.matchedSNIServerName;
                BCSNIServerName matchedSNIServerName = jsseSessionParameters.getMatchedSNIServerName();
                if (JsseUtils.equals(bCSNIServerName, matchedSNIServerName)) {
                    return true;
                }
                Logger logger2 = LOG;
                if (logger2.isLoggable(Level.FINEST)) {
                    logger2.finest(this.serverID + ": Session not resumable - SNI mismatch; connection: " + bCSNIServerName + ", session: " + matchedSNIServerName);
                }
                return false;
            }
        }
        return false;
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifyAlertRaised(short s, short s2, String str, Throwable th) {
        Level level = s == 1 ? Level.FINE : s2 == 80 ? Level.WARNING : Level.INFO;
        Logger logger = LOG;
        if (logger.isLoggable(level)) {
            String alertRaisedLogMessage = JsseUtils.getAlertRaisedLogMessage(this.serverID, s, s2);
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
            logger.log(level, JsseUtils.getAlertReceivedLogMessage(this.serverID, s, s2));
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public void notifyClientCertificate(Certificate certificate) throws IOException {
        if (!isClientAuthEnabled()) {
            throw new TlsFatalAlert((short) 80);
        }
        if (certificate != null && !certificate.isEmpty()) {
            this.manager.checkClientTrusted(JsseUtils.getX509CertificateChain(getCrypto(), certificate), "TLS-client-auth");
        } else if (this.sslParameters.getNeedClientAuth()) {
            throw new TlsFatalAlert(TlsUtils.isTLSv13(this.context) ? AlertDescription.certificate_required : (short) 40);
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifyConnectionClosed() {
        super.notifyConnectionClosed();
        Logger logger = LOG;
        if (logger.isLoggable(Level.INFO)) {
            logger.info(this.serverID + " disconnected from " + JsseUtils.getPeerReport(this.manager));
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifyHandshakeBeginning() throws IOException {
        super.notifyHandshakeBeginning();
        Logger logger = LOG;
        if (logger.isLoggable(Level.INFO)) {
            logger.info(this.serverID + " accepting connection from " + JsseUtils.getPeerReport(this.manager));
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public synchronized void notifyHandshakeComplete() throws IOException {
        super.notifyHandshakeComplete();
        boolean z = true;
        this.handshakeComplete = true;
        Logger logger = LOG;
        if (logger.isLoggable(Level.INFO)) {
            logger.info(this.serverID + " established connection with " + JsseUtils.getPeerReport(this.manager));
        }
        TlsSession session = this.context.getSession();
        ProvSSLSession provSSLSession = this.sslSession;
        if (provSSLSession == null || provSSLSession.getTlsSession() != session) {
            ProvSSLSessionContext serverSessionContext = this.manager.getContextData().getServerSessionContext();
            String peerHost = this.manager.getPeerHost();
            int peerPort = this.manager.getPeerPort();
            JsseSessionParameters jsseSessionParameters = new JsseSessionParameters(this.sslParameters.getEndpointIdentificationAlgorithm(), this.matchedSNIServerName);
            if (!provServerEnableSessionResumption || TlsUtils.isTLSv13(this.context)) {
                z = false;
            }
            this.sslSession = serverSessionContext.reportSession(peerHost, peerPort, session, jsseSessionParameters, z);
        }
        this.manager.notifyHandshakeComplete(new ProvSSLConnection(this));
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifySecureRenegotiation(boolean z) throws IOException {
        if (!z && !PropertyUtils.getBooleanSystemProperty("sun.security.ssl.allowLegacyHelloMessages", true)) {
            throw new TlsFatalAlert((short) 40);
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public void notifySession(TlsSession tlsSession) {
        byte[] sessionID = tlsSession.getSessionID();
        ProvSSLSession provSSLSession = this.sslSession;
        if (provSSLSession == null || provSSLSession.getTlsSession() != tlsSession) {
            this.sslSession = null;
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine((TlsUtils.isNullOrEmpty(sessionID) ? new StringBuilder().append(this.serverID).append(" did not specify a session ID") : new StringBuilder().append(this.serverID).append(" specified new session: ").append(Hex.toHexString(sessionID))).toString());
            }
            JsseUtils.checkSessionCreationEnabled(this.manager);
        } else {
            Logger logger2 = LOG;
            if (logger2.isLoggable(Level.FINE)) {
                logger2.fine(this.serverID + " resumed session: " + Hex.toHexString(sessionID));
            }
        }
        ProvTlsManager provTlsManager = this.manager;
        provTlsManager.notifyHandshakeSession(provTlsManager.getContextData().getServerSessionContext(), this.context.getSecurityParametersHandshake(), this.jsseSecurityParameters, this.sslSession);
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected boolean preferLocalCipherSuites() {
        return this.sslParameters.getUseCipherSuitesOrder();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public void processClientExtensions(Hashtable hashtable) throws IOException {
        Logger logger;
        StringBuilder append;
        super.processClientExtensions(hashtable);
        Vector clientServerNames = this.context.getSecurityParametersHandshake().getClientServerNames();
        if (clientServerNames != null) {
            Collection<BCSNIMatcher> sNIMatchers = this.sslParameters.getSNIMatchers();
            if (sNIMatchers == null || sNIMatchers.isEmpty()) {
                logger = LOG;
                if (logger.isLoggable(Level.FINE)) {
                    append = new StringBuilder().append(this.serverID).append(" ignored SNI (no matchers specified)");
                    logger.fine(append.toString());
                }
            } else {
                BCSNIServerName findMatchingSNIServerName = JsseUtils.findMatchingSNIServerName(clientServerNames, sNIMatchers);
                this.matchedSNIServerName = findMatchingSNIServerName;
                if (findMatchingSNIServerName == null) {
                    throw new TlsFatalAlert(AlertDescription.unrecognized_name);
                }
                logger = LOG;
                if (logger.isLoggable(Level.FINE)) {
                    append = new StringBuilder().append(this.serverID).append(" accepted SNI: ").append(this.matchedSNIServerName);
                    logger.fine(append.toString());
                }
            }
        }
        if (TlsUtils.isTLSv13(this.context)) {
            Vector certificateAuthoritiesExtension = TlsExtensionsUtils.getCertificateAuthoritiesExtension(hashtable);
            this.jsseSecurityParameters.trustedIssuers = JsseUtils.toX500Principals(certificateAuthoritiesExtension);
        } else if (provServerEnableTrustedCAKeys) {
            Vector vector = this.trustedCAKeys;
            this.jsseSecurityParameters.trustedIssuers = JsseUtils.getTrustedIssuers(vector);
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

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected boolean selectCipherSuite(int i) throws IOException {
        TlsCredentials tlsCredentials;
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(i);
        if (KeyExchangeAlgorithm.isAnonymous(keyExchangeAlgorithm)) {
            tlsCredentials = null;
        } else {
            tlsCredentials = selectCredentials(this.jsseSecurityParameters.trustedIssuers, keyExchangeAlgorithm);
            if (tlsCredentials == null) {
                String cipherSuiteName = ProvSSLContextSpi.getCipherSuiteName(i);
                Logger logger = LOG;
                if (logger.isLoggable(Level.FINER)) {
                    logger.finer(this.serverID + " found no credentials for cipher suite: " + cipherSuiteName);
                    return false;
                }
                return false;
            }
        }
        boolean selectCipherSuite = super.selectCipherSuite(i);
        if (selectCipherSuite) {
            this.credentials = tlsCredentials;
        }
        return selectCipherSuite;
    }

    protected TlsCredentials selectCredentials(Principal[] principalArr, int i) throws IOException {
        if (i != 0) {
            if (i == 1 || i == 3 || i == 5 || i == 17 || i == 19) {
                return (1 == i || !TlsUtils.isSignatureAlgorithmsExtensionAllowed(this.context.getServerVersion())) ? selectServerCredentialsLegacy(principalArr, i) : selectServerCredentials12(principalArr, i);
            }
            return null;
        }
        return selectServerCredentials13(principalArr, TlsUtils.EMPTY_BYTES);
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected int selectDH(int i) {
        throw new UnsupportedOperationException();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected int selectDHDefault(int i) {
        throw new UnsupportedOperationException();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected int selectECDH(int i) {
        return NamedGroupInfo.selectServerECDH(this.jsseSecurityParameters.namedGroups, i).getResult();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected int selectECDHDefault(int i) {
        throw new UnsupportedOperationException();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected ProtocolName selectProtocolName() throws IOException {
        if (this.sslParameters.getEngineAPSelector() == null && this.sslParameters.getSocketAPSelector() == null) {
            return super.selectProtocolName();
        }
        List<String> protocolNames = JsseUtils.getProtocolNames(this.clientProtocolNames);
        String selectApplicationProtocol = this.manager.selectApplicationProtocol(Collections.unmodifiableList(protocolNames));
        if (selectApplicationProtocol != null) {
            if (selectApplicationProtocol.length() < 1) {
                return null;
            }
            if (protocolNames.contains(selectApplicationProtocol)) {
                return ProtocolName.asUtf8Encoding(selectApplicationProtocol);
            }
            throw new TlsFatalAlert(AlertDescription.no_application_protocol);
        }
        throw new TlsFatalAlert(AlertDescription.no_application_protocol);
    }

    protected TlsCredentials selectServerCredentials12(Principal[] principalArr, int i) throws IOException {
        short legacySignatureAlgorithmServer = TlsUtils.getLegacySignatureAlgorithmServer(i);
        SignatureSchemeInfo.PerConnection perConnection = this.jsseSecurityParameters.signatureSchemes;
        LinkedHashMap<String, SignatureSchemeInfo> linkedHashMap = new LinkedHashMap<>();
        for (SignatureSchemeInfo signatureSchemeInfo : perConnection.getPeerSigSchemes()) {
            if (TlsUtils.isValidSignatureSchemeForServerKeyExchange(signatureSchemeInfo.getSignatureScheme(), i)) {
                String keyTypeLegacyServer = legacySignatureAlgorithmServer == signatureSchemeInfo.getSignatureAlgorithm() ? JsseUtils.getKeyTypeLegacyServer(i) : signatureSchemeInfo.getKeyType();
                if (!this.keyManagerMissCache.contains(keyTypeLegacyServer) && !linkedHashMap.containsKey(keyTypeLegacyServer) && signatureSchemeInfo.isSupportedPre13() && perConnection.hasLocalSignatureScheme(signatureSchemeInfo)) {
                    linkedHashMap.put(keyTypeLegacyServer, signatureSchemeInfo);
                }
            }
        }
        if (linkedHashMap.isEmpty()) {
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine(this.serverID + " (1.2) has no key types to try for KeyExchangeAlgorithm " + i);
            }
            return null;
        }
        BCX509Key chooseServerKey = this.manager.chooseServerKey((String[]) linkedHashMap.keySet().toArray(TlsUtils.EMPTY_STRINGS), principalArr);
        if (chooseServerKey == null) {
            handleKeyManagerMisses(linkedHashMap, null);
            Logger logger2 = LOG;
            if (logger2.isLoggable(Level.FINE)) {
                logger2.fine(this.serverID + " (1.2) did not select any credentials for KeyExchangeAlgorithm " + i);
            }
            return null;
        }
        String keyType = chooseServerKey.getKeyType();
        handleKeyManagerMisses(linkedHashMap, keyType);
        SignatureSchemeInfo signatureSchemeInfo2 = linkedHashMap.get(keyType);
        if (signatureSchemeInfo2 != null) {
            Logger logger3 = LOG;
            if (logger3.isLoggable(Level.FINE)) {
                logger3.fine(this.serverID + " (1.2) selected credentials for signature scheme '" + signatureSchemeInfo2 + "' (keyType '" + keyType + "'), with private key algorithm '" + JsseUtils.getPrivateKeyAlgorithm(chooseServerKey.getPrivateKey()) + "'");
            }
            return JsseUtils.createCredentialedSigner(this.context, getCrypto(), chooseServerKey, signatureSchemeInfo2.getSignatureAndHashAlgorithm());
        }
        throw new TlsFatalAlert((short) 80, "Key manager returned invalid key type");
    }

    protected TlsCredentials selectServerCredentials13(Principal[] principalArr, byte[] bArr) throws IOException {
        SignatureSchemeInfo.PerConnection perConnection = this.jsseSecurityParameters.signatureSchemes;
        LinkedHashMap<String, SignatureSchemeInfo> linkedHashMap = new LinkedHashMap<>();
        for (SignatureSchemeInfo signatureSchemeInfo : perConnection.getPeerSigSchemes()) {
            String keyType13 = signatureSchemeInfo.getKeyType13();
            if (!this.keyManagerMissCache.contains(keyType13) && !linkedHashMap.containsKey(keyType13) && signatureSchemeInfo.isSupportedPost13() && perConnection.hasLocalSignatureScheme(signatureSchemeInfo)) {
                linkedHashMap.put(keyType13, signatureSchemeInfo);
            }
        }
        if (linkedHashMap.isEmpty()) {
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine(this.serverID + " (1.3) found no usable signature schemes");
            }
            return null;
        }
        BCX509Key chooseServerKey = this.manager.chooseServerKey((String[]) linkedHashMap.keySet().toArray(TlsUtils.EMPTY_STRINGS), principalArr);
        if (chooseServerKey == null) {
            handleKeyManagerMisses(linkedHashMap, null);
            Logger logger2 = LOG;
            if (logger2.isLoggable(Level.FINE)) {
                logger2.fine(this.serverID + " (1.3) did not select any credentials");
            }
            return null;
        }
        String keyType = chooseServerKey.getKeyType();
        handleKeyManagerMisses(linkedHashMap, keyType);
        SignatureSchemeInfo signatureSchemeInfo2 = linkedHashMap.get(keyType);
        if (signatureSchemeInfo2 != null) {
            Logger logger3 = LOG;
            if (logger3.isLoggable(Level.FINE)) {
                logger3.fine(this.serverID + " (1.3) selected credentials for signature scheme '" + signatureSchemeInfo2 + "' (keyType '" + keyType + "'), with private key algorithm '" + JsseUtils.getPrivateKeyAlgorithm(chooseServerKey.getPrivateKey()) + "'");
            }
            return JsseUtils.createCredentialedSigner13(this.context, getCrypto(), chooseServerKey, signatureSchemeInfo2.getSignatureAndHashAlgorithm(), bArr);
        }
        throw new TlsFatalAlert((short) 80, "Key manager returned invalid key type");
    }

    protected TlsCredentials selectServerCredentialsLegacy(Principal[] principalArr, int i) throws IOException {
        String keyTypeLegacyServer = JsseUtils.getKeyTypeLegacyServer(i);
        if (this.keyManagerMissCache.contains(keyTypeLegacyServer)) {
            return null;
        }
        BCX509Key chooseServerKey = this.manager.chooseServerKey(new String[]{keyTypeLegacyServer}, principalArr);
        if (chooseServerKey != null) {
            return 1 == i ? JsseUtils.createCredentialedDecryptor(getCrypto(), chooseServerKey) : JsseUtils.createCredentialedSigner(this.context, getCrypto(), chooseServerKey, null);
        }
        this.keyManagerMissCache.add(keyTypeLegacyServer);
        return null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer
    protected boolean shouldSelectProtocolNameEarly() {
        return this.sslParameters.getEngineAPSelector() == null && this.sslParameters.getSocketAPSelector() == null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public boolean shouldUseExtendedMasterSecret() {
        return JsseUtils.useExtendedMasterSecret();
    }
}