package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.tls.OfferedPsks;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/* loaded from: classes2.dex */
public class TlsClientProtocol extends TlsProtocol {
    protected TlsAuthentication authentication;
    protected CertificateRequest certificateRequest;
    protected CertificateStatus certificateStatus;
    protected Hashtable clientAgreements;
    OfferedPsks.BindersConfig clientBinders;
    protected ClientHello clientHello;
    protected TlsKeyExchange keyExchange;
    protected TlsClient tlsClient;
    TlsClientContextImpl tlsClientContext;

    public TlsClientProtocol() {
        this.tlsClient = null;
        this.tlsClientContext = null;
        this.clientAgreements = null;
        this.clientBinders = null;
        this.clientHello = null;
        this.keyExchange = null;
        this.authentication = null;
        this.certificateStatus = null;
        this.certificateRequest = null;
    }

    public TlsClientProtocol(InputStream inputStream, OutputStream outputStream) {
        super(inputStream, outputStream);
        this.tlsClient = null;
        this.tlsClientContext = null;
        this.clientAgreements = null;
        this.clientBinders = null;
        this.clientHello = null;
        this.keyExchange = null;
        this.authentication = null;
        this.certificateStatus = null;
        this.certificateRequest = null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.tls.TlsProtocol
    public void beginHandshake(boolean z) throws IOException {
        super.beginHandshake(z);
        sendClientHello();
        this.connection_state = (short) 1;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.tls.TlsProtocol
    public void cleanupHandshake() {
        super.cleanupHandshake();
        this.clientAgreements = null;
        this.clientBinders = null;
        this.clientHello = null;
        this.keyExchange = null;
        this.authentication = null;
        this.certificateStatus = null;
        this.certificateRequest = null;
    }

    public void connect(TlsClient tlsClient) throws IOException {
        if (tlsClient == null) {
            throw new IllegalArgumentException("'tlsClient' cannot be null");
        }
        if (this.tlsClient != null) {
            throw new IllegalStateException("'connect' can only be called once");
        }
        this.tlsClient = tlsClient;
        TlsClientContextImpl tlsClientContextImpl = new TlsClientContextImpl(tlsClient.getCrypto());
        this.tlsClientContext = tlsClientContextImpl;
        tlsClient.init(tlsClientContextImpl);
        tlsClient.notifyCloseHandle(this);
        beginHandshake(false);
        if (this.blocking) {
            blockForHandshake();
        }
    }

    @Override // org.bouncycastle.tls.TlsProtocol
    protected TlsContext getContext() {
        return this.tlsClientContext;
    }

    @Override // org.bouncycastle.tls.TlsProtocol
    AbstractTlsContext getContextAdmin() {
        return this.tlsClientContext;
    }

    @Override // org.bouncycastle.tls.TlsProtocol
    protected TlsPeer getPeer() {
        return this.tlsClient;
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x0066  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected void handle13HandshakeMessage(short r8, org.bouncycastle.tls.HandshakeMessageInput r9) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 316
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsClientProtocol.handle13HandshakeMessage(short, org.bouncycastle.tls.HandshakeMessageInput):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0112  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x011d  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0144  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0158  */
    @Override // org.bouncycastle.tls.TlsProtocol
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected void handleHandshakeMessage(short r11, org.bouncycastle.tls.HandshakeMessageInput r12) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 738
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsClientProtocol.handleHandshakeMessage(short, org.bouncycastle.tls.HandshakeMessageInput):void");
    }

    protected void handleServerCertificate() throws IOException {
        TlsUtils.processServerCertificate(this.tlsClientContext, this.certificateStatus, this.keyExchange, this.authentication, this.clientExtensions, this.serverExtensions);
    }

    protected void handleSupplementalData(Vector vector) throws IOException {
        this.tlsClient.processServerSupplementalData(vector);
        this.connection_state = (short) 6;
        this.keyExchange = TlsUtils.initKeyExchangeClient(this.tlsClientContext, this.tlsClient);
    }

    protected void process13HelloRetryRequest(ServerHello serverHello) throws IOException {
        this.recordStream.setWriteVersion(ProtocolVersion.TLSv12);
        SecurityParameters securityParametersHandshake = this.tlsClientContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.isRenegotiating()) {
            throw new TlsFatalAlert((short) 80);
        }
        ProtocolVersion version = serverHello.getVersion();
        byte[] sessionID = serverHello.getSessionID();
        int cipherSuite = serverHello.getCipherSuite();
        if (!ProtocolVersion.TLSv12.equals(version) || !Arrays.areEqual(this.clientHello.getSessionID(), sessionID) || !TlsUtils.isValidCipherSuiteSelection(this.clientHello.getCipherSuites(), cipherSuite)) {
            throw new TlsFatalAlert((short) 47);
        }
        Hashtable extensions = serverHello.getExtensions();
        if (extensions == null) {
            throw new TlsFatalAlert((short) 47);
        }
        TlsUtils.checkExtensionData13(extensions, 6, (short) 47);
        Enumeration keys = extensions.keys();
        while (keys.hasMoreElements()) {
            Integer num = (Integer) keys.nextElement();
            if (44 != num.intValue() && TlsUtils.getExtensionData(this.clientExtensions, num) == null) {
                throw new TlsFatalAlert(AlertDescription.unsupported_extension);
            }
        }
        ProtocolVersion supportedVersionsExtensionServer = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
        if (supportedVersionsExtensionServer == null) {
            throw new TlsFatalAlert(AlertDescription.missing_extension);
        }
        if (!ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(supportedVersionsExtensionServer) || !ProtocolVersion.contains(this.tlsClientContext.getClientSupportedVersions(), supportedVersionsExtensionServer) || !TlsUtils.isValidVersionForCipherSuite(cipherSuite, supportedVersionsExtensionServer)) {
            throw new TlsFatalAlert((short) 47);
        }
        OfferedPsks.BindersConfig bindersConfig = this.clientBinders;
        if (bindersConfig != null && !Arrays.contains(bindersConfig.pskKeyExchangeModes, (short) 1)) {
            this.clientBinders = null;
            this.tlsClient.notifySelectedPSK(null);
        }
        int keyShareHelloRetryRequest = TlsExtensionsUtils.getKeyShareHelloRetryRequest(extensions);
        if (!TlsUtils.isValidKeyShareSelection(supportedVersionsExtensionServer, securityParametersHandshake.getClientSupportedGroups(), this.clientAgreements, keyShareHelloRetryRequest)) {
            throw new TlsFatalAlert((short) 47);
        }
        byte[] cookieExtension = TlsExtensionsUtils.getCookieExtension(extensions);
        securityParametersHandshake.negotiatedVersion = supportedVersionsExtensionServer;
        TlsUtils.negotiatedVersionTLSClient(this.tlsClientContext, this.tlsClient);
        securityParametersHandshake.resumedSession = false;
        securityParametersHandshake.sessionID = TlsUtils.EMPTY_BYTES;
        this.tlsClient.notifySessionID(TlsUtils.EMPTY_BYTES);
        TlsUtils.negotiatedCipherSuite(securityParametersHandshake, cipherSuite);
        this.tlsClient.notifySelectedCipherSuite(cipherSuite);
        this.clientAgreements = null;
        this.retryCookie = cookieExtension;
        this.retryGroup = keyShareHelloRetryRequest;
    }

    protected void process13ServerHello(ServerHello serverHello, boolean z) throws IOException {
        TlsSecret tlsSecret;
        TlsPSK tlsPSK;
        TlsSecret calculateSecret;
        SecurityParameters securityParametersHandshake = this.tlsClientContext.getSecurityParametersHandshake();
        ProtocolVersion version = serverHello.getVersion();
        byte[] sessionID = serverHello.getSessionID();
        int cipherSuite = serverHello.getCipherSuite();
        if (!ProtocolVersion.TLSv12.equals(version) || !Arrays.areEqual(this.clientHello.getSessionID(), sessionID)) {
            throw new TlsFatalAlert((short) 47);
        }
        Hashtable extensions = serverHello.getExtensions();
        if (extensions == null) {
            throw new TlsFatalAlert((short) 47);
        }
        TlsUtils.checkExtensionData13(extensions, 2, (short) 47);
        if (z) {
            ProtocolVersion supportedVersionsExtensionServer = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
            if (supportedVersionsExtensionServer == null) {
                throw new TlsFatalAlert(AlertDescription.missing_extension);
            }
            if (!securityParametersHandshake.getNegotiatedVersion().equals(supportedVersionsExtensionServer) || securityParametersHandshake.getCipherSuite() != cipherSuite) {
                throw new TlsFatalAlert((short) 47);
            }
        } else if (!TlsUtils.isValidCipherSuiteSelection(this.clientHello.getCipherSuites(), cipherSuite) || !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParametersHandshake.getNegotiatedVersion())) {
            throw new TlsFatalAlert((short) 47);
        } else {
            securityParametersHandshake.resumedSession = false;
            securityParametersHandshake.sessionID = TlsUtils.EMPTY_BYTES;
            this.tlsClient.notifySessionID(TlsUtils.EMPTY_BYTES);
            TlsUtils.negotiatedCipherSuite(securityParametersHandshake, cipherSuite);
            this.tlsClient.notifySelectedCipherSuite(cipherSuite);
        }
        this.clientHello = null;
        securityParametersHandshake.serverRandom = serverHello.getRandom();
        securityParametersHandshake.secureRenegotiation = false;
        securityParametersHandshake.extendedMasterSecret = true;
        securityParametersHandshake.statusRequestVersion = this.clientExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;
        int preSharedKeyServerHello = TlsExtensionsUtils.getPreSharedKeyServerHello(extensions);
        if (preSharedKeyServerHello >= 0) {
            OfferedPsks.BindersConfig bindersConfig = this.clientBinders;
            if (bindersConfig == null || preSharedKeyServerHello >= bindersConfig.psks.length) {
                throw new TlsFatalAlert((short) 47);
            }
            tlsPSK = this.clientBinders.psks[preSharedKeyServerHello];
            if (tlsPSK.getPRFAlgorithm() != securityParametersHandshake.getPRFAlgorithm()) {
                throw new TlsFatalAlert((short) 47);
            }
            tlsSecret = this.clientBinders.earlySecrets[preSharedKeyServerHello];
            this.selectedPSK13 = true;
        } else {
            tlsSecret = null;
            tlsPSK = null;
        }
        this.tlsClient.notifySelectedPSK(tlsPSK);
        KeyShareEntry keyShareServerHello = TlsExtensionsUtils.getKeyShareServerHello(extensions);
        if (keyShareServerHello == null) {
            if (z || tlsSecret == null || !Arrays.contains(this.clientBinders.pskKeyExchangeModes, (short) 0)) {
                throw new TlsFatalAlert((short) 47);
            }
            calculateSecret = null;
        } else if (tlsSecret != null && !Arrays.contains(this.clientBinders.pskKeyExchangeModes, (short) 1)) {
            throw new TlsFatalAlert((short) 47);
        } else {
            TlsAgreement tlsAgreement = (TlsAgreement) this.clientAgreements.get(Integers.valueOf(keyShareServerHello.getNamedGroup()));
            if (tlsAgreement == null) {
                throw new TlsFatalAlert((short) 47);
            }
            tlsAgreement.receivePeerValue(keyShareServerHello.getKeyExchange());
            calculateSecret = tlsAgreement.calculateSecret();
        }
        this.clientAgreements = null;
        this.clientBinders = null;
        TlsUtils.establish13PhaseSecrets(this.tlsClientContext, tlsSecret, calculateSecret);
        invalidateSession();
        this.tlsSession = TlsUtils.importSession(securityParametersHandshake.getSessionID(), null);
    }

    protected void process13ServerHelloCoda(ServerHello serverHello, boolean z) throws IOException {
        TlsUtils.establish13PhaseHandshake(this.tlsClientContext, TlsUtils.getCurrentPRFHash(this.handshakeHash), this.recordStream);
        if (!z) {
            this.recordStream.setIgnoreChangeCipherSpec(true);
            sendChangeCipherSpecMessage();
        }
        this.recordStream.enablePendingCipherWrite();
        this.recordStream.enablePendingCipherRead(false);
    }

    protected void processServerHello(ServerHello serverHello) throws IOException {
        Hashtable extensions = serverHello.getExtensions();
        ProtocolVersion version = serverHello.getVersion();
        ProtocolVersion supportedVersionsExtensionServer = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
        if (supportedVersionsExtensionServer != null) {
            if (!ProtocolVersion.TLSv12.equals(version) || !ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(supportedVersionsExtensionServer)) {
                throw new TlsFatalAlert((short) 47);
            }
            version = supportedVersionsExtensionServer;
        }
        SecurityParameters securityParametersHandshake = this.tlsClientContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.isRenegotiating()) {
            if (!version.equals(securityParametersHandshake.getNegotiatedVersion())) {
                throw new TlsFatalAlert((short) 47);
            }
        } else if (!ProtocolVersion.contains(this.tlsClientContext.getClientSupportedVersions(), version)) {
            throw new TlsFatalAlert((short) 70);
        } else {
            this.recordStream.setWriteVersion(version.isLaterVersionOf(ProtocolVersion.TLSv12) ? ProtocolVersion.TLSv12 : version);
            securityParametersHandshake.negotiatedVersion = version;
        }
        TlsUtils.negotiatedVersionTLSClient(this.tlsClientContext, this.tlsClient);
        boolean z = false;
        if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(version)) {
            process13ServerHello(serverHello, false);
            return;
        }
        int[] cipherSuites = this.clientHello.getCipherSuites();
        this.clientHello = null;
        this.retryCookie = null;
        this.retryGroup = -1;
        securityParametersHandshake.serverRandom = serverHello.getRandom();
        if (!this.tlsClientContext.getClientVersion().equals(version)) {
            TlsUtils.checkDowngradeMarker(version, securityParametersHandshake.getServerRandom());
        }
        byte[] sessionID = serverHello.getSessionID();
        securityParametersHandshake.sessionID = sessionID;
        this.tlsClient.notifySessionID(sessionID);
        securityParametersHandshake.resumedSession = sessionID.length > 0 && this.tlsSession != null && Arrays.areEqual(sessionID, this.tlsSession.getSessionID());
        if (securityParametersHandshake.isResumedSession() && (serverHello.getCipherSuite() != this.sessionParameters.getCipherSuite() || !securityParametersHandshake.getNegotiatedVersion().equals(this.sessionParameters.getNegotiatedVersion()))) {
            throw new TlsFatalAlert((short) 47, "ServerHello parameters do not match resumed session");
        }
        int cipherSuite = serverHello.getCipherSuite();
        if (!TlsUtils.isValidCipherSuiteSelection(cipherSuites, cipherSuite) || !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParametersHandshake.getNegotiatedVersion())) {
            throw new TlsFatalAlert((short) 47, "ServerHello selected invalid cipher suite");
        }
        TlsUtils.negotiatedCipherSuite(securityParametersHandshake, cipherSuite);
        this.tlsClient.notifySelectedCipherSuite(cipherSuite);
        this.serverExtensions = extensions;
        if (extensions != null) {
            Enumeration keys = extensions.keys();
            while (keys.hasMoreElements()) {
                Integer num = (Integer) keys.nextElement();
                if (!num.equals(EXT_RenegotiationInfo)) {
                    if (TlsUtils.getExtensionData(this.clientExtensions, num) == null) {
                        throw new TlsFatalAlert((short) AlertDescription.unsupported_extension, "Unrequested extension in ServerHello: " + ExtensionType.getText(num.intValue()));
                    }
                    securityParametersHandshake.isResumedSession();
                }
            }
        }
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_RenegotiationInfo);
        if (securityParametersHandshake.isRenegotiating()) {
            if (!securityParametersHandshake.isSecureRenegotiation()) {
                throw new TlsFatalAlert((short) 80);
            }
            if (extensionData == null) {
                throw new TlsFatalAlert((short) 40);
            }
            SecurityParameters securityParametersConnection = this.tlsClientContext.getSecurityParametersConnection();
            if (!Arrays.constantTimeAreEqual(extensionData, createRenegotiationInfo(TlsUtils.concat(securityParametersConnection.getLocalVerifyData(), securityParametersConnection.getPeerVerifyData())))) {
                throw new TlsFatalAlert((short) 40);
            }
        } else if (extensionData == null) {
            securityParametersHandshake.secureRenegotiation = false;
        } else {
            securityParametersHandshake.secureRenegotiation = true;
            if (!Arrays.constantTimeAreEqual(extensionData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                throw new TlsFatalAlert((short) 40);
            }
        }
        this.tlsClient.notifySecureRenegotiation(securityParametersHandshake.isSecureRenegotiation());
        if (TlsExtensionsUtils.hasExtendedMasterSecretExtension(this.clientExtensions)) {
            z = TlsExtensionsUtils.hasExtendedMasterSecretExtension(extensions);
            if (TlsUtils.isExtendedMasterSecretOptional(version)) {
                if (!z && this.tlsClient.requiresExtendedMasterSecret()) {
                    throw new TlsFatalAlert((short) 40, "Extended Master Secret extension is required");
                }
            } else if (z) {
                throw new TlsFatalAlert((short) 47, "Server sent an unexpected extended_master_secret extension negotiating " + version);
            }
        }
        securityParametersHandshake.extendedMasterSecret = z;
        if (securityParametersHandshake.isResumedSession() && securityParametersHandshake.isExtendedMasterSecret() != this.sessionParameters.isExtendedMasterSecret()) {
            throw new TlsFatalAlert((short) 40, "Server resumed session with mismatched extended_master_secret negotiation");
        }
        securityParametersHandshake.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(extensions);
        securityParametersHandshake.applicationProtocolSet = true;
        Hashtable hashtable = this.clientExtensions;
        if (securityParametersHandshake.isResumedSession()) {
            extensions = this.sessionParameters.readServerExtensions();
            hashtable = null;
        }
        if (extensions != null && !extensions.isEmpty()) {
            boolean hasEncryptThenMACExtension = TlsExtensionsUtils.hasEncryptThenMACExtension(extensions);
            if (hasEncryptThenMACExtension && !TlsUtils.isBlockCipherSuite(securityParametersHandshake.getCipherSuite())) {
                throw new TlsFatalAlert((short) 47);
            }
            securityParametersHandshake.encryptThenMAC = hasEncryptThenMACExtension;
            securityParametersHandshake.maxFragmentLength = TlsUtils.processMaxFragmentLengthExtension(hashtable, extensions, (short) 47);
            securityParametersHandshake.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(extensions);
            if (!securityParametersHandshake.isResumedSession()) {
                if (TlsUtils.hasExpectedEmptyExtensionData(extensions, TlsExtensionsUtils.EXT_status_request_v2, (short) 47)) {
                    securityParametersHandshake.statusRequestVersion = 2;
                } else if (TlsUtils.hasExpectedEmptyExtensionData(extensions, TlsExtensionsUtils.EXT_status_request, (short) 47)) {
                    securityParametersHandshake.statusRequestVersion = 1;
                }
                securityParametersHandshake.clientCertificateType = TlsUtils.processClientCertificateTypeExtension(hashtable, extensions, (short) 47);
                securityParametersHandshake.serverCertificateType = TlsUtils.processServerCertificateTypeExtension(hashtable, extensions, (short) 47);
                this.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(extensions, TlsProtocol.EXT_SessionTicket, (short) 47);
            }
        }
        if (hashtable != null) {
            this.tlsClient.processServerExtensions(extensions);
        }
        applyMaxFragmentLengthExtension(securityParametersHandshake.getMaxFragmentLength());
        if (securityParametersHandshake.isResumedSession()) {
            securityParametersHandshake.masterSecret = this.sessionMasterSecret;
            this.recordStream.setPendingCipher(TlsUtils.initCipher(this.tlsClientContext));
            return;
        }
        invalidateSession();
        this.tlsSession = TlsUtils.importSession(securityParametersHandshake.getSessionID(), null);
    }

    protected void receive13CertificateRequest(ByteArrayInputStream byteArrayInputStream, boolean z) throws IOException {
        if (z) {
            throw new TlsFatalAlert((short) 80);
        }
        if (this.selectedPSK13) {
            throw new TlsFatalAlert((short) 10);
        }
        CertificateRequest parse = CertificateRequest.parse(this.tlsClientContext, byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        if (!parse.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES)) {
            throw new TlsFatalAlert((short) 47);
        }
        this.certificateRequest = parse;
        TlsUtils.establishServerSigAlgs(this.tlsClientContext.getSecurityParametersHandshake(), parse);
    }

    protected void receive13EncryptedExtensions(ByteArrayInputStream byteArrayInputStream) throws IOException {
        byte[] readOpaque16 = TlsUtils.readOpaque16(byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        this.serverExtensions = readExtensionsData13(8, readOpaque16);
        Enumeration keys = this.serverExtensions.keys();
        while (keys.hasMoreElements()) {
            if (TlsUtils.getExtensionData(this.clientExtensions, (Integer) keys.nextElement()) == null) {
                throw new TlsFatalAlert(AlertDescription.unsupported_extension);
            }
        }
        SecurityParameters securityParametersHandshake = this.tlsClientContext.getSecurityParametersHandshake();
        securityParametersHandshake.getNegotiatedVersion();
        securityParametersHandshake.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(this.serverExtensions);
        securityParametersHandshake.applicationProtocolSet = true;
        Hashtable hashtable = this.clientExtensions;
        Hashtable hashtable2 = this.serverExtensions;
        if (securityParametersHandshake.isResumedSession()) {
            hashtable2 = this.sessionParameters.readServerExtensions();
            hashtable = null;
        }
        securityParametersHandshake.maxFragmentLength = TlsUtils.processMaxFragmentLengthExtension(hashtable, hashtable2, (short) 47);
        securityParametersHandshake.encryptThenMAC = false;
        securityParametersHandshake.truncatedHMac = false;
        if (!securityParametersHandshake.isResumedSession()) {
            securityParametersHandshake.statusRequestVersion = this.clientExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;
            securityParametersHandshake.clientCertificateType = TlsUtils.processClientCertificateTypeExtension13(hashtable, hashtable2, (short) 47);
            securityParametersHandshake.serverCertificateType = TlsUtils.processServerCertificateTypeExtension13(hashtable, hashtable2, (short) 47);
        }
        this.expectSessionTicket = false;
        if (hashtable != null) {
            this.tlsClient.processServerExtensions(this.serverExtensions);
        }
        applyMaxFragmentLengthExtension(securityParametersHandshake.getMaxFragmentLength());
    }

    protected void receive13NewSessionTicket(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (!isApplicationDataReady()) {
            throw new TlsFatalAlert((short) 10);
        }
        TlsUtils.readUint32(byteArrayInputStream);
        TlsUtils.readUint32(byteArrayInputStream);
        TlsUtils.readOpaque8(byteArrayInputStream);
        TlsUtils.readOpaque16(byteArrayInputStream);
        TlsUtils.readOpaque16(byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
    }

    protected void receive13ServerCertificate(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (this.selectedPSK13) {
            throw new TlsFatalAlert((short) 10);
        }
        this.authentication = TlsUtils.receive13ServerCertificate(this.tlsClientContext, this.tlsClient, byteArrayInputStream, this.serverExtensions);
        handleServerCertificate();
    }

    protected void receive13ServerCertificateVerify(ByteArrayInputStream byteArrayInputStream) throws IOException {
        Certificate peerCertificate = this.tlsClientContext.getSecurityParametersHandshake().getPeerCertificate();
        if (peerCertificate == null || peerCertificate.isEmpty()) {
            throw new TlsFatalAlert((short) 80);
        }
        CertificateVerify parse = CertificateVerify.parse(this.tlsClientContext, byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        TlsUtils.verify13CertificateVerifyServer(this.tlsClientContext, this.handshakeHash, parse);
    }

    protected void receive13ServerFinished(ByteArrayInputStream byteArrayInputStream) throws IOException {
        process13FinishedMessage(byteArrayInputStream);
    }

    protected void receiveCertificateRequest(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (this.authentication == null) {
            throw new TlsFatalAlert((short) 40);
        }
        CertificateRequest parse = CertificateRequest.parse(this.tlsClientContext, byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        this.certificateRequest = TlsUtils.validateCertificateRequest(parse, this.keyExchange);
    }

    protected void receiveNewSessionTicket(ByteArrayInputStream byteArrayInputStream) throws IOException {
        NewSessionTicket parse = NewSessionTicket.parse(byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        this.tlsClient.notifyNewSessionTicket(parse);
    }

    protected ServerHello receiveServerHelloMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        return ServerHello.parse(byteArrayInputStream);
    }

    protected void send13ClientHelloRetry() throws IOException {
        Hashtable extensions = this.clientHello.getExtensions();
        extensions.remove(TlsExtensionsUtils.EXT_cookie);
        extensions.remove(TlsExtensionsUtils.EXT_early_data);
        extensions.remove(TlsExtensionsUtils.EXT_key_share);
        extensions.remove(TlsExtensionsUtils.EXT_pre_shared_key);
        if (this.retryCookie != null) {
            TlsExtensionsUtils.addCookieExtension(extensions, this.retryCookie);
            this.retryCookie = null;
        }
        OfferedPsks.BindersConfig bindersConfig = this.clientBinders;
        if (bindersConfig != null) {
            OfferedPsks.BindersConfig addPreSharedKeyToClientHelloRetry = TlsUtils.addPreSharedKeyToClientHelloRetry(this.tlsClientContext, bindersConfig, extensions);
            this.clientBinders = addPreSharedKeyToClientHelloRetry;
            if (addPreSharedKeyToClientHelloRetry == null) {
                this.tlsClient.notifySelectedPSK(null);
            }
        }
        if (this.retryGroup < 0) {
            throw new TlsFatalAlert((short) 80);
        }
        this.clientAgreements = TlsUtils.addKeyShareToClientHelloRetry(this.tlsClientContext, extensions, this.retryGroup);
        this.recordStream.setIgnoreChangeCipherSpec(true);
        sendChangeCipherSpecMessage();
        sendClientHelloMessage();
    }

    protected void sendCertificateVerifyMessage(DigitallySigned digitallySigned) throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 15);
        digitallySigned.encode(handshakeMessageOutput);
        handshakeMessageOutput.send(this);
    }

    protected void sendClientHello() throws IOException {
        ProtocolVersion[] protocolVersions;
        RecordStream recordStream;
        ProtocolVersion protocolVersion;
        ProtocolVersion earliestTLS;
        ProtocolVersion latestTLS;
        byte[] bArr;
        ProtocolVersion protocolVersion2;
        SecurityParameters securityParametersHandshake = this.tlsClientContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.isRenegotiating()) {
            earliestTLS = this.tlsClientContext.getClientVersion();
            protocolVersions = earliestTLS.only();
            latestTLS = earliestTLS;
        } else {
            protocolVersions = this.tlsClient.getProtocolVersions();
            if (ProtocolVersion.contains(protocolVersions, ProtocolVersion.SSLv3)) {
                recordStream = this.recordStream;
                protocolVersion = ProtocolVersion.SSLv3;
            } else {
                recordStream = this.recordStream;
                protocolVersion = ProtocolVersion.TLSv10;
            }
            recordStream.setWriteVersion(protocolVersion);
            earliestTLS = ProtocolVersion.getEarliestTLS(protocolVersions);
            latestTLS = ProtocolVersion.getLatestTLS(protocolVersions);
            if (!ProtocolVersion.isSupportedTLSVersionClient(latestTLS)) {
                throw new TlsFatalAlert((short) 80);
            }
            this.tlsClientContext.setClientVersion(latestTLS);
        }
        this.tlsClientContext.setClientSupportedVersions(protocolVersions);
        boolean isEqualOrLaterVersionOf = ProtocolVersion.TLSv12.isEqualOrLaterVersionOf(earliestTLS);
        boolean isEqualOrEarlierVersionOf = ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(latestTLS);
        securityParametersHandshake.clientRandom = createRandomBlock(!isEqualOrEarlierVersionOf && this.tlsClient.shouldUseGMTUnixTime(), this.tlsClientContext);
        ProtocolVersion protocolVersion3 = null;
        TlsSession sessionToResume = isEqualOrLaterVersionOf ? this.tlsClient.getSessionToResume() : null;
        boolean isFallback = this.tlsClient.isFallback();
        int[] cipherSuites = this.tlsClient.getCipherSuites();
        this.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(this.tlsClient.getClientExtensions());
        boolean shouldUseExtendedMasterSecret = this.tlsClient.shouldUseExtendedMasterSecret();
        establishSession(sessionToResume);
        byte[] sessionID = TlsUtils.getSessionID(this.tlsSession);
        if (sessionID.length > 0 && !Arrays.contains(cipherSuites, this.sessionParameters.getCipherSuite())) {
            sessionID = TlsUtils.EMPTY_BYTES;
        }
        if (sessionID.length > 0) {
            protocolVersion3 = this.sessionParameters.getNegotiatedVersion();
            if (!ProtocolVersion.contains(protocolVersions, protocolVersion3)) {
                sessionID = TlsUtils.EMPTY_BYTES;
            }
        }
        if (sessionID.length > 0 && TlsUtils.isExtendedMasterSecretOptional(protocolVersion3)) {
            boolean isExtendedMasterSecret = this.sessionParameters.isExtendedMasterSecret();
            if (!shouldUseExtendedMasterSecret ? isExtendedMasterSecret : !(isExtendedMasterSecret || this.tlsClient.allowLegacyResumption())) {
                sessionID = TlsUtils.EMPTY_BYTES;
            }
        }
        if (sessionID.length < 1) {
            cancelSession();
        }
        this.tlsClient.notifySessionToResume(this.tlsSession);
        if (isEqualOrEarlierVersionOf) {
            ProtocolVersion protocolVersion4 = ProtocolVersion.TLSv12;
            TlsExtensionsUtils.addSupportedVersionsExtensionClient(this.clientExtensions, protocolVersions);
            if (sessionID.length < 1 && this.tlsClient.shouldUseCompatibilityMode()) {
                sessionID = this.tlsClientContext.getNonceGenerator().generateNonce(32);
            }
            bArr = sessionID;
            protocolVersion2 = protocolVersion4;
        } else {
            bArr = sessionID;
            protocolVersion2 = latestTLS;
        }
        this.tlsClientContext.setRSAPreMasterSecretVersion(protocolVersion2);
        securityParametersHandshake.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(this.clientExtensions);
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(latestTLS)) {
            TlsUtils.establishClientSigAlgs(securityParametersHandshake, this.clientExtensions);
        }
        securityParametersHandshake.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(this.clientExtensions);
        this.clientBinders = TlsUtils.addPreSharedKeyToClientHello(this.tlsClientContext, this.tlsClient, this.clientExtensions, cipherSuites);
        this.clientAgreements = TlsUtils.addKeyShareToClientHello(this.tlsClientContext, this.tlsClient, this.clientExtensions);
        if (shouldUseExtendedMasterSecret && TlsUtils.isExtendedMasterSecretOptional(protocolVersions)) {
            TlsExtensionsUtils.addExtendedMasterSecretExtension(this.clientExtensions);
        } else {
            this.clientExtensions.remove(TlsExtensionsUtils.EXT_extended_master_secret);
        }
        if (!securityParametersHandshake.isRenegotiating()) {
            boolean z = TlsUtils.getExtensionData(this.clientExtensions, EXT_RenegotiationInfo) == null;
            boolean contains = Arrays.contains(cipherSuites, 255);
            if (z && !contains) {
                cipherSuites = Arrays.append(cipherSuites, 255);
            }
        } else if (!securityParametersHandshake.isSecureRenegotiation()) {
            throw new TlsFatalAlert((short) 80);
        } else {
            this.clientExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(this.tlsClientContext.getSecurityParametersConnection().getLocalVerifyData()));
        }
        int[] append = (!isFallback || Arrays.contains(cipherSuites, (int) CipherSuite.TLS_FALLBACK_SCSV)) ? cipherSuites : Arrays.append(cipherSuites, (int) CipherSuite.TLS_FALLBACK_SCSV);
        OfferedPsks.BindersConfig bindersConfig = this.clientBinders;
        this.clientHello = new ClientHello(protocolVersion2, securityParametersHandshake.getClientRandom(), bArr, null, append, this.clientExtensions, bindersConfig != null ? bindersConfig.bindersSize : 0);
        sendClientHelloMessage();
    }

    protected void sendClientHelloMessage() throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 1);
        this.clientHello.encode(this.tlsClientContext, handshakeMessageOutput);
        handshakeMessageOutput.prepareClientHello(this.handshakeHash, this.clientHello.getBindersSize());
        if (this.clientBinders != null) {
            OfferedPsks.encodeBinders(handshakeMessageOutput, this.tlsClientContext.getCrypto(), this.handshakeHash, this.clientBinders);
        }
        handshakeMessageOutput.sendClientHello(this, this.handshakeHash, this.clientHello.getBindersSize());
    }

    protected void sendClientKeyExchange() throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 16);
        this.keyExchange.generateClientKeyExchange(handshakeMessageOutput);
        handshakeMessageOutput.send(this);
    }

    protected void skip13CertificateRequest() throws IOException {
        this.certificateRequest = null;
    }

    protected void skip13ServerCertificate() throws IOException {
        if (!this.selectedPSK13) {
            throw new TlsFatalAlert((short) 10);
        }
        this.authentication = TlsUtils.skip13ServerCertificate(this.tlsClientContext);
    }
}