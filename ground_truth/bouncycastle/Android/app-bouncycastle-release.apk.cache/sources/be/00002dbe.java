package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.OfferedPsks;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class TlsServerProtocol extends TlsProtocol {
    protected CertificateRequest certificateRequest;
    protected TlsKeyExchange keyExchange;
    protected int[] offeredCipherSuites;
    protected TlsServer tlsServer;
    TlsServerContextImpl tlsServerContext;

    public TlsServerProtocol() {
        this.tlsServer = null;
        this.tlsServerContext = null;
        this.offeredCipherSuites = null;
        this.keyExchange = null;
        this.certificateRequest = null;
    }

    public TlsServerProtocol(InputStream inputStream, OutputStream outputStream) {
        super(inputStream, outputStream);
        this.tlsServer = null;
        this.tlsServerContext = null;
        this.offeredCipherSuites = null;
        this.keyExchange = null;
        this.certificateRequest = null;
    }

    public void accept(TlsServer tlsServer) throws IOException {
        if (tlsServer == null) {
            throw new IllegalArgumentException("'tlsServer' cannot be null");
        }
        if (this.tlsServer != null) {
            throw new IllegalStateException("'accept' can only be called once");
        }
        this.tlsServer = tlsServer;
        TlsServerContextImpl tlsServerContextImpl = new TlsServerContextImpl(tlsServer.getCrypto());
        this.tlsServerContext = tlsServerContextImpl;
        tlsServer.init(tlsServerContextImpl);
        tlsServer.notifyCloseHandle(this);
        beginHandshake(false);
        if (this.blocking) {
            blockForHandshake();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.tls.TlsProtocol
    public void cleanupHandshake() {
        super.cleanupHandshake();
        this.offeredCipherSuites = null;
        this.keyExchange = null;
        this.certificateRequest = null;
    }

    protected boolean expectCertificateVerifyMessage() {
        Certificate peerCertificate;
        if (this.certificateRequest == null || (peerCertificate = this.tlsServerContext.getSecurityParametersHandshake().getPeerCertificate()) == null || peerCertificate.isEmpty()) {
            return false;
        }
        TlsKeyExchange tlsKeyExchange = this.keyExchange;
        return tlsKeyExchange == null || tlsKeyExchange.requiresCertificateVerify();
    }

    protected ServerHello generate13HelloRetryRequest(ClientHello clientHello) throws IOException {
        if (this.retryGroup >= 0) {
            SecurityParameters securityParametersHandshake = this.tlsServerContext.getSecurityParametersHandshake();
            ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
            Hashtable hashtable = new Hashtable();
            TlsExtensionsUtils.addSupportedVersionsExtensionServer(hashtable, negotiatedVersion);
            if (this.retryGroup >= 0) {
                TlsExtensionsUtils.addKeyShareHelloRetryRequest(hashtable, this.retryGroup);
            }
            if (this.retryCookie != null) {
                TlsExtensionsUtils.addCookieExtension(hashtable, this.retryCookie);
            }
            TlsUtils.checkExtensionData13(hashtable, 6, (short) 80);
            return new ServerHello(clientHello.getSessionID(), securityParametersHandshake.getCipherSuite(), hashtable);
        }
        throw new TlsFatalAlert((short) 80);
    }

    protected ServerHello generate13ServerHello(ClientHello clientHello, HandshakeMessageInput handshakeMessageInput, boolean z) throws IOException {
        KeyShareEntry keyShareEntry;
        TlsAgreement createKem;
        SecurityParameters securityParametersHandshake = this.tlsServerContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.isRenegotiating()) {
            throw new TlsFatalAlert((short) 80);
        }
        byte[] sessionID = clientHello.getSessionID();
        Hashtable extensions = clientHello.getExtensions();
        if (extensions != null) {
            ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
            TlsCrypto crypto = this.tlsServerContext.getCrypto();
            OfferedPsks.SelectedConfig selectPreSharedKey = TlsUtils.selectPreSharedKey(this.tlsServerContext, this.tlsServer, extensions, handshakeMessageInput, this.handshakeHash, z);
            Vector keyShareClientHello = TlsExtensionsUtils.getKeyShareClientHello(extensions);
            TlsSecret tlsSecret = null;
            if (!z) {
                securityParametersHandshake.serverRandom = createRandomBlock(false, this.tlsServerContext);
                if (!negotiatedVersion.equals(ProtocolVersion.getLatestTLS(this.tlsServer.getProtocolVersions()))) {
                    TlsUtils.writeDowngradeMarker(negotiatedVersion, securityParametersHandshake.getServerRandom());
                }
                this.clientExtensions = extensions;
                securityParametersHandshake.secureRenegotiation = false;
                TlsExtensionsUtils.getPaddingExtension(extensions);
                securityParametersHandshake.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(extensions);
                TlsUtils.establishClientSigAlgs(securityParametersHandshake, extensions);
                if (selectPreSharedKey == null && securityParametersHandshake.getClientSigAlgs() == null) {
                    throw new TlsFatalAlert(AlertDescription.missing_extension);
                }
                this.tlsServer.processClientExtensions(extensions);
                securityParametersHandshake.resumedSession = false;
                this.tlsSession = TlsUtils.importSession(TlsUtils.EMPTY_BYTES, null);
                this.sessionParameters = null;
                this.sessionMasterSecret = null;
                securityParametersHandshake.sessionID = this.tlsSession.getSessionID();
                this.tlsServer.notifySession(this.tlsSession);
                TlsUtils.negotiatedVersionTLSServer(this.tlsServerContext);
                int selectedCipherSuite = this.tlsServer.getSelectedCipherSuite();
                if (!TlsUtils.isValidCipherSuiteSelection(this.offeredCipherSuites, selectedCipherSuite) || !TlsUtils.isValidVersionForCipherSuite(selectedCipherSuite, negotiatedVersion)) {
                    throw new TlsFatalAlert((short) 80);
                }
                TlsUtils.negotiatedCipherSuite(securityParametersHandshake, selectedCipherSuite);
                int[] clientSupportedGroups = securityParametersHandshake.getClientSupportedGroups();
                int[] serverSupportedGroups = securityParametersHandshake.getServerSupportedGroups();
                KeyShareEntry selectKeyShare = TlsUtils.selectKeyShare(crypto, negotiatedVersion, keyShareClientHello, clientSupportedGroups, serverSupportedGroups);
                if (selectKeyShare == null) {
                    this.retryGroup = TlsUtils.selectKeyShareGroup(crypto, negotiatedVersion, clientSupportedGroups, serverSupportedGroups);
                    if (this.retryGroup >= 0) {
                        this.retryCookie = this.tlsServerContext.getNonceGenerator().generateNonce(16);
                        return generate13HelloRetryRequest(clientHello);
                    }
                    throw new TlsFatalAlert((short) 40);
                }
                selectKeyShare.getNamedGroup();
                int i = serverSupportedGroups[0];
                keyShareEntry = selectKeyShare;
            } else if (this.retryGroup < 0) {
                throw new TlsFatalAlert((short) 80);
            } else {
                if (selectPreSharedKey == null) {
                    if (securityParametersHandshake.getClientSigAlgs() == null) {
                        throw new TlsFatalAlert(AlertDescription.missing_extension);
                    }
                } else if (selectPreSharedKey.psk.getPRFAlgorithm() != securityParametersHandshake.getPRFAlgorithm()) {
                    throw new TlsFatalAlert((short) 47);
                }
                if (!Arrays.areEqual(this.retryCookie, TlsExtensionsUtils.getCookieExtension(extensions))) {
                    throw new TlsFatalAlert((short) 47);
                }
                this.retryCookie = null;
                keyShareEntry = TlsUtils.selectKeyShare(keyShareClientHello, this.retryGroup);
                if (keyShareEntry == null) {
                    throw new TlsFatalAlert((short) 47);
                }
            }
            Hashtable hashtable = new Hashtable();
            Hashtable ensureExtensionsInitialised = TlsExtensionsUtils.ensureExtensionsInitialised(this.tlsServer.getServerExtensions());
            this.tlsServer.getServerExtensionsForConnection(ensureExtensionsInitialised);
            ProtocolVersion protocolVersion = ProtocolVersion.TLSv12;
            TlsExtensionsUtils.addSupportedVersionsExtensionServer(hashtable, negotiatedVersion);
            securityParametersHandshake.extendedMasterSecret = true;
            securityParametersHandshake.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(ensureExtensionsInitialised);
            securityParametersHandshake.applicationProtocolSet = true;
            if (!ensureExtensionsInitialised.isEmpty()) {
                securityParametersHandshake.maxFragmentLength = TlsUtils.processMaxFragmentLengthExtension(securityParametersHandshake.isResumedSession() ? null : extensions, ensureExtensionsInitialised, (short) 80);
                if (!securityParametersHandshake.isResumedSession()) {
                    securityParametersHandshake.clientCertificateType = TlsUtils.processClientCertificateTypeExtension13(extensions, ensureExtensionsInitialised, (short) 80);
                    securityParametersHandshake.serverCertificateType = TlsUtils.processServerCertificateTypeExtension13(extensions, ensureExtensionsInitialised, (short) 80);
                }
            }
            securityParametersHandshake.encryptThenMAC = false;
            securityParametersHandshake.truncatedHMac = false;
            securityParametersHandshake.statusRequestVersion = extensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;
            this.expectSessionTicket = false;
            if (selectPreSharedKey != null) {
                tlsSecret = selectPreSharedKey.earlySecret;
                this.selectedPSK13 = true;
                TlsExtensionsUtils.addPreSharedKeyServerHello(hashtable, selectPreSharedKey.index);
            }
            int namedGroup = keyShareEntry.getNamedGroup();
            if (NamedGroup.refersToAnECDHCurve(namedGroup)) {
                createKem = crypto.createECDomain(new TlsECConfig(namedGroup)).createECDH();
            } else if (NamedGroup.refersToASpecificFiniteField(namedGroup)) {
                createKem = crypto.createDHDomain(new TlsDHConfig(namedGroup, true)).createDH();
            } else if (!NamedGroup.refersToASpecificKem(namedGroup)) {
                throw new TlsFatalAlert((short) 80);
            } else {
                createKem = crypto.createKemDomain(new TlsKemConfig(namedGroup, true)).createKem();
            }
            createKem.receivePeerValue(keyShareEntry.getKeyExchange());
            TlsExtensionsUtils.addKeyShareServerHello(hashtable, new KeyShareEntry(namedGroup, createKem.generateEphemeral()));
            TlsUtils.establish13PhaseSecrets(this.tlsServerContext, tlsSecret, createKem.calculateSecret());
            this.serverExtensions = ensureExtensionsInitialised;
            applyMaxFragmentLengthExtension(securityParametersHandshake.getMaxFragmentLength());
            TlsUtils.checkExtensionData13(hashtable, 2, (short) 80);
            return new ServerHello(protocolVersion, securityParametersHandshake.getServerRandom(), sessionID, securityParametersHandshake.getCipherSuite(), hashtable);
        }
        throw new TlsFatalAlert(AlertDescription.missing_extension);
    }

    /* JADX WARN: Removed duplicated region for block: B:105:0x024b  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0276  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x027d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected org.bouncycastle.tls.ServerHello generateServerHello(org.bouncycastle.tls.ClientHello r13, org.bouncycastle.tls.HandshakeMessageInput r14) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 948
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsServerProtocol.generateServerHello(org.bouncycastle.tls.ClientHello, org.bouncycastle.tls.HandshakeMessageInput):org.bouncycastle.tls.ServerHello");
    }

    @Override // org.bouncycastle.tls.TlsProtocol
    protected TlsContext getContext() {
        return this.tlsServerContext;
    }

    @Override // org.bouncycastle.tls.TlsProtocol
    AbstractTlsContext getContextAdmin() {
        return this.tlsServerContext;
    }

    @Override // org.bouncycastle.tls.TlsProtocol
    protected TlsPeer getPeer() {
        return this.tlsServer;
    }

    protected void handle13HandshakeMessage(short s, HandshakeMessageInput handshakeMessageInput) throws IOException {
        if (!isTLSv13ConnectionState()) {
            throw new TlsFatalAlert((short) 80);
        }
        if (s == 1) {
            short s2 = this.connection_state;
            if (s2 == 0) {
                throw new TlsFatalAlert((short) 80);
            }
            if (s2 != 2) {
                throw new TlsFatalAlert((short) 10);
            }
            ClientHello receiveClientHelloMessage = receiveClientHelloMessage(handshakeMessageInput);
            this.connection_state = (short) 3;
            ServerHello generate13ServerHello = generate13ServerHello(receiveClientHelloMessage, handshakeMessageInput, true);
            sendServerHelloMessage(generate13ServerHello);
            this.connection_state = (short) 4;
            send13ServerHelloCoda(generate13ServerHello, true);
        } else if (s == 11) {
            if (this.connection_state != 20) {
                throw new TlsFatalAlert((short) 10);
            }
            receive13ClientCertificate(handshakeMessageInput);
            this.connection_state = (short) 15;
        } else if (s == 15) {
            if (this.connection_state != 15) {
                throw new TlsFatalAlert((short) 10);
            }
            receive13ClientCertificateVerify(handshakeMessageInput);
            handshakeMessageInput.updateHash(this.handshakeHash);
            this.connection_state = (short) 17;
        } else if (s != 20) {
            if (s != 24) {
                throw new TlsFatalAlert((short) 10);
            }
            receive13KeyUpdate(handshakeMessageInput);
        } else {
            short s3 = this.connection_state;
            if (s3 != 15) {
                if (s3 != 17) {
                    if (s3 != 20) {
                        throw new TlsFatalAlert((short) 10);
                    }
                    skip13ClientCertificate();
                }
                receive13ClientFinished(handshakeMessageInput);
                this.connection_state = (short) 18;
                this.recordStream.setIgnoreChangeCipherSpec(false);
                this.recordStream.enablePendingCipherRead(false);
                completeHandshake();
            }
            skip13ClientCertificateVerify();
            receive13ClientFinished(handshakeMessageInput);
            this.connection_state = (short) 18;
            this.recordStream.setIgnoreChangeCipherSpec(false);
            this.recordStream.enablePendingCipherRead(false);
            completeHandshake();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x0018, code lost:
        if (r0 != 14) goto L15;
     */
    @Override // org.bouncycastle.tls.TlsProtocol
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void handleAlertWarningMessage(short r3) throws java.io.IOException {
        /*
            r2 = this;
            r0 = 41
            if (r0 != r3) goto L2b
            org.bouncycastle.tls.CertificateRequest r0 = r2.certificateRequest
            if (r0 == 0) goto L2b
            org.bouncycastle.tls.TlsServerContextImpl r0 = r2.tlsServerContext
            boolean r0 = org.bouncycastle.tls.TlsUtils.isSSL(r0)
            if (r0 == 0) goto L2b
            short r0 = r2.connection_state
            r1 = 12
            if (r0 == r1) goto L1b
            r1 = 14
            if (r0 == r1) goto L21
            goto L2b
        L1b:
            org.bouncycastle.tls.TlsServer r3 = r2.tlsServer
            r0 = 0
            r3.processClientSupplementalData(r0)
        L21:
            org.bouncycastle.tls.Certificate r3 = org.bouncycastle.tls.Certificate.EMPTY_CHAIN
            r2.notifyClientCertificate(r3)
            r3 = 15
            r2.connection_state = r3
            return
        L2b:
            super.handleAlertWarningMessage(r3)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsServerProtocol.handleAlertWarningMessage(short):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:156:0x02ad, code lost:
        if (r11.tlsServerContext.getCrypto().hasAnyStreamVerifiers(r0.getServerSigAlgs()) != false) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x02c0, code lost:
        if (r11.tlsServerContext.getCrypto().hasAnyStreamVerifiersLegacy(r11.certificateRequest.getCertificateTypes()) != false) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x02c2, code lost:
        r11.handshakeHash.forceBuffering();
     */
    @Override // org.bouncycastle.tls.TlsProtocol
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected void handleHandshakeMessage(short r12, org.bouncycastle.tls.HandshakeMessageInput r13) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 744
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsServerProtocol.handleHandshakeMessage(short, org.bouncycastle.tls.HandshakeMessageInput):void");
    }

    protected void notifyClientCertificate(Certificate certificate) throws IOException {
        if (this.certificateRequest == null) {
            throw new TlsFatalAlert((short) 80);
        }
        TlsUtils.processClientCertificate(this.tlsServerContext, certificate, this.keyExchange, this.tlsServer);
    }

    protected void receive13ClientCertificate(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (this.certificateRequest == null) {
            throw new TlsFatalAlert((short) 10);
        }
        Certificate parse = Certificate.parse(new Certificate.ParseOptions().setCertificateType(this.tlsServerContext.getSecurityParametersHandshake().getClientCertificateType()).setMaxChainLength(this.tlsServer.getMaxCertificateChainLength()), this.tlsServerContext, byteArrayInputStream, null);
        assertEmpty(byteArrayInputStream);
        notifyClientCertificate(parse);
    }

    protected void receive13ClientCertificateVerify(ByteArrayInputStream byteArrayInputStream) throws IOException {
        Certificate peerCertificate = this.tlsServerContext.getSecurityParametersHandshake().getPeerCertificate();
        if (peerCertificate == null || peerCertificate.isEmpty()) {
            throw new TlsFatalAlert((short) 80);
        }
        CertificateVerify parse = CertificateVerify.parse(this.tlsServerContext, byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        TlsUtils.verify13CertificateVerifyClient(this.tlsServerContext, this.handshakeHash, parse);
    }

    protected void receive13ClientFinished(ByteArrayInputStream byteArrayInputStream) throws IOException {
        process13FinishedMessage(byteArrayInputStream);
    }

    protected void receiveCertificateMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (this.certificateRequest == null) {
            throw new TlsFatalAlert((short) 10);
        }
        Certificate parse = Certificate.parse(new Certificate.ParseOptions().setCertificateType(this.tlsServerContext.getSecurityParametersHandshake().getClientCertificateType()).setMaxChainLength(this.tlsServer.getMaxCertificateChainLength()), this.tlsServerContext, byteArrayInputStream, null);
        assertEmpty(byteArrayInputStream);
        notifyClientCertificate(parse);
    }

    protected void receiveCertificateVerifyMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        DigitallySigned parse = DigitallySigned.parse(this.tlsServerContext, byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        TlsUtils.verifyCertificateVerifyClient(this.tlsServerContext, this.certificateRequest, parse, this.handshakeHash);
        this.handshakeHash.stopTracking();
    }

    protected ClientHello receiveClientHelloMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        return ClientHello.parse(byteArrayInputStream, null);
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        this.keyExchange.processClientKeyExchange(byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        boolean isSSL = TlsUtils.isSSL(this.tlsServerContext);
        if (isSSL) {
            establishMasterSecret(this.tlsServerContext, this.keyExchange);
        }
        this.tlsServerContext.getSecurityParametersHandshake().sessionHash = TlsUtils.getCurrentPRFHash(this.handshakeHash);
        if (!isSSL) {
            establishMasterSecret(this.tlsServerContext, this.keyExchange);
        }
        this.recordStream.setPendingCipher(TlsUtils.initCipher(this.tlsServerContext));
        if (expectCertificateVerifyMessage()) {
            return;
        }
        this.handshakeHash.stopTracking();
    }

    protected void send13EncryptedExtensionsMessage(Hashtable hashtable) throws IOException {
        byte[] writeExtensionsData = writeExtensionsData(hashtable);
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 8);
        TlsUtils.writeOpaque16(writeExtensionsData, handshakeMessageOutput);
        handshakeMessageOutput.send(this);
    }

    protected void send13ServerHelloCoda(ServerHello serverHello, boolean z) throws IOException {
        SecurityParameters securityParametersHandshake = this.tlsServerContext.getSecurityParametersHandshake();
        TlsUtils.establish13PhaseHandshake(this.tlsServerContext, TlsUtils.getCurrentPRFHash(this.handshakeHash), this.recordStream);
        this.recordStream.enablePendingCipherWrite();
        this.recordStream.enablePendingCipherRead(true);
        send13EncryptedExtensionsMessage(this.serverExtensions);
        this.connection_state = (short) 5;
        if (!this.selectedPSK13) {
            CertificateRequest certificateRequest = this.tlsServer.getCertificateRequest();
            this.certificateRequest = certificateRequest;
            if (certificateRequest != null) {
                if (!certificateRequest.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES)) {
                    throw new TlsFatalAlert((short) 80);
                }
                TlsUtils.establishServerSigAlgs(securityParametersHandshake, this.certificateRequest);
                sendCertificateRequestMessage(this.certificateRequest);
                this.connection_state = (short) 11;
            }
            TlsCredentialedSigner establish13ServerCredentials = TlsUtils.establish13ServerCredentials(this.tlsServer);
            if (establish13ServerCredentials == null) {
                throw new TlsFatalAlert((short) 80);
            }
            send13CertificateMessage(establish13ServerCredentials.getCertificate());
            securityParametersHandshake.tlsServerEndPoint = null;
            this.connection_state = (short) 7;
            send13CertificateVerifyMessage(TlsUtils.generate13CertificateVerify(this.tlsServerContext, establish13ServerCredentials, this.handshakeHash));
            this.connection_state = (short) 17;
        }
        send13FinishedMessage();
        this.connection_state = (short) 20;
        TlsUtils.establish13PhaseApplication(this.tlsServerContext, TlsUtils.getCurrentPRFHash(this.handshakeHash), this.recordStream);
        this.recordStream.enablePendingCipherWrite();
    }

    protected void sendCertificateRequestMessage(CertificateRequest certificateRequest) throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 13);
        certificateRequest.encode(this.tlsServerContext, handshakeMessageOutput);
        handshakeMessageOutput.send(this);
    }

    protected void sendCertificateStatusMessage(CertificateStatus certificateStatus) throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 22);
        certificateStatus.encode(handshakeMessageOutput);
        handshakeMessageOutput.send(this);
    }

    protected void sendHelloRequestMessage() throws IOException {
        HandshakeMessageOutput.send(this, (short) 0, TlsUtils.EMPTY_BYTES);
    }

    protected void sendNewSessionTicketMessage(NewSessionTicket newSessionTicket) throws IOException {
        if (newSessionTicket == null) {
            throw new TlsFatalAlert((short) 80);
        }
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 4);
        newSessionTicket.encode(handshakeMessageOutput);
        handshakeMessageOutput.send(this);
    }

    protected void sendServerHelloDoneMessage() throws IOException {
        HandshakeMessageOutput.send(this, (short) 14, TlsUtils.EMPTY_BYTES);
    }

    protected void sendServerHelloMessage(ServerHello serverHello) throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 2);
        serverHello.encode(this.tlsServerContext, handshakeMessageOutput);
        handshakeMessageOutput.send(this);
    }

    protected void sendServerKeyExchangeMessage(byte[] bArr) throws IOException {
        HandshakeMessageOutput.send(this, (short) 12, bArr);
    }

    protected void skip13ClientCertificate() throws IOException {
        if (this.certificateRequest != null) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    protected void skip13ClientCertificateVerify() throws IOException {
        if (expectCertificateVerifyMessage()) {
            throw new TlsFatalAlert((short) 10);
        }
    }
}