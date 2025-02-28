package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class DTLSServerProtocol extends DTLSProtocol {
    protected boolean verifyRequests = true;

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes2.dex */
    public static class ServerHandshakeState {
        TlsServer server = null;
        TlsServerContextImpl serverContext = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        TlsSecret sessionMasterSecret = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        ClientHello clientHello = null;
        Hashtable serverExtensions = null;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        TlsCredentials serverCredentials = null;
        CertificateRequest certificateRequest = null;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = 2;

        protected ServerHandshakeState() {
        }
    }

    protected void abortServerHandshake(ServerHandshakeState serverHandshakeState, DTLSRecordLayer dTLSRecordLayer, short s) {
        dTLSRecordLayer.fail(s);
        invalidateSession(serverHandshakeState);
    }

    public DTLSTransport accept(TlsServer tlsServer, DatagramTransport datagramTransport) throws IOException {
        return accept(tlsServer, datagramTransport, null);
    }

    public DTLSTransport accept(TlsServer tlsServer, DatagramTransport datagramTransport, DTLSRequest dTLSRequest) throws IOException {
        if (tlsServer != null) {
            if (datagramTransport != null) {
                TlsServerContextImpl tlsServerContextImpl = new TlsServerContextImpl(tlsServer.getCrypto());
                ServerHandshakeState serverHandshakeState = new ServerHandshakeState();
                serverHandshakeState.server = tlsServer;
                serverHandshakeState.serverContext = tlsServerContextImpl;
                tlsServer.init(tlsServerContextImpl);
                tlsServerContextImpl.handshakeBeginning(tlsServer);
                SecurityParameters securityParametersHandshake = tlsServerContextImpl.getSecurityParametersHandshake();
                securityParametersHandshake.extendedPadding = tlsServer.shouldUseExtendedPadding();
                DTLSRecordLayer dTLSRecordLayer = new DTLSRecordLayer(tlsServerContextImpl, tlsServer, datagramTransport);
                tlsServer.notifyCloseHandle(dTLSRecordLayer);
                try {
                    try {
                        try {
                            return serverHandshake(serverHandshakeState, dTLSRecordLayer, dTLSRequest);
                        } catch (TlsFatalAlert e) {
                            abortServerHandshake(serverHandshakeState, dTLSRecordLayer, e.getAlertDescription());
                            throw e;
                        } catch (IOException e2) {
                            abortServerHandshake(serverHandshakeState, dTLSRecordLayer, (short) 80);
                            throw e2;
                        }
                    } catch (RuntimeException e3) {
                        abortServerHandshake(serverHandshakeState, dTLSRecordLayer, (short) 80);
                        throw new TlsFatalAlert((short) 80, (Throwable) e3);
                    }
                } finally {
                    securityParametersHandshake.clear();
                }
            }
            throw new IllegalArgumentException("'transport' cannot be null");
        }
        throw new IllegalArgumentException("'server' cannot be null");
    }

    protected void cancelSession(ServerHandshakeState serverHandshakeState) {
        if (serverHandshakeState.sessionMasterSecret != null) {
            serverHandshakeState.sessionMasterSecret.destroy();
            serverHandshakeState.sessionMasterSecret = null;
        }
        if (serverHandshakeState.sessionParameters != null) {
            serverHandshakeState.sessionParameters.clear();
            serverHandshakeState.sessionParameters = null;
        }
        serverHandshakeState.tlsSession = null;
    }

    protected boolean establishSession(ServerHandshakeState serverHandshakeState, TlsSession tlsSession) {
        SessionParameters exportSessionParameters;
        ProtocolVersion negotiatedVersion;
        TlsSecret sessionMasterSecret;
        serverHandshakeState.tlsSession = null;
        serverHandshakeState.sessionParameters = null;
        serverHandshakeState.sessionMasterSecret = null;
        if (tlsSession == null || !tlsSession.isResumable() || (exportSessionParameters = tlsSession.exportSessionParameters()) == null || (negotiatedVersion = exportSessionParameters.getNegotiatedVersion()) == null || !negotiatedVersion.isDTLS()) {
            return false;
        }
        if ((exportSessionParameters.isExtendedMasterSecret() || TlsUtils.isExtendedMasterSecretOptional(negotiatedVersion)) && (sessionMasterSecret = TlsUtils.getSessionMasterSecret(serverHandshakeState.serverContext.getCrypto(), exportSessionParameters.getMasterSecret())) != null) {
            serverHandshakeState.tlsSession = tlsSession;
            serverHandshakeState.sessionParameters = exportSessionParameters;
            serverHandshakeState.sessionMasterSecret = sessionMasterSecret;
            return true;
        }
        return false;
    }

    protected boolean expectCertificateVerifyMessage(ServerHandshakeState serverHandshakeState) {
        Certificate peerCertificate;
        if (serverHandshakeState.certificateRequest == null || (peerCertificate = serverHandshakeState.serverContext.getSecurityParametersHandshake().getPeerCertificate()) == null || peerCertificate.isEmpty()) {
            return false;
        }
        return serverHandshakeState.keyExchange == null || serverHandshakeState.keyExchange.requiresCertificateVerify();
    }

    protected byte[] generateCertificateRequest(ServerHandshakeState serverHandshakeState, CertificateRequest certificateRequest) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        certificateRequest.encode(serverHandshakeState.serverContext, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected byte[] generateCertificateStatus(ServerHandshakeState serverHandshakeState, CertificateStatus certificateStatus) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        certificateStatus.encode(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected byte[] generateNewSessionTicket(ServerHandshakeState serverHandshakeState, NewSessionTicket newSessionTicket) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        newSessionTicket.encode(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00b5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected byte[] generateServerHello(org.bouncycastle.tls.DTLSServerProtocol.ServerHandshakeState r12, org.bouncycastle.tls.DTLSRecordLayer r13) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 533
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.DTLSServerProtocol.generateServerHello(org.bouncycastle.tls.DTLSServerProtocol$ServerHandshakeState, org.bouncycastle.tls.DTLSRecordLayer):byte[]");
    }

    public boolean getVerifyRequests() {
        return this.verifyRequests;
    }

    protected void invalidateSession(ServerHandshakeState serverHandshakeState) {
        if (serverHandshakeState.tlsSession != null) {
            serverHandshakeState.tlsSession.invalidate();
        }
        cancelSession(serverHandshakeState);
    }

    protected void notifyClientCertificate(ServerHandshakeState serverHandshakeState, Certificate certificate) throws IOException {
        if (serverHandshakeState.certificateRequest == null) {
            throw new TlsFatalAlert((short) 80);
        }
        TlsUtils.processClientCertificate(serverHandshakeState.serverContext, certificate, serverHandshakeState.keyExchange, serverHandshakeState.server);
    }

    protected void processCertificateVerify(ServerHandshakeState serverHandshakeState, byte[] bArr, TlsHandshakeHash tlsHandshakeHash) throws IOException {
        if (serverHandshakeState.certificateRequest == null) {
            throw new IllegalStateException();
        }
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        TlsServerContextImpl tlsServerContextImpl = serverHandshakeState.serverContext;
        DigitallySigned parse = DigitallySigned.parse(tlsServerContextImpl, byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        TlsUtils.verifyCertificateVerifyClient(tlsServerContextImpl, serverHandshakeState.certificateRequest, parse, tlsHandshakeHash);
    }

    protected void processClientCertificate(ServerHandshakeState serverHandshakeState, byte[] bArr) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        Certificate parse = Certificate.parse(new Certificate.ParseOptions().setCertificateType(serverHandshakeState.serverContext.getSecurityParametersHandshake().getClientCertificateType()).setMaxChainLength(serverHandshakeState.server.getMaxCertificateChainLength()), serverHandshakeState.serverContext, byteArrayInputStream, null);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        notifyClientCertificate(serverHandshakeState, parse);
    }

    protected void processClientHello(ServerHandshakeState serverHandshakeState, ClientHello clientHello) throws IOException {
        serverHandshakeState.clientHello = clientHello;
        ProtocolVersion version = clientHello.getVersion();
        int[] cipherSuites = clientHello.getCipherSuites();
        Hashtable extensions = clientHello.getExtensions();
        TlsServer tlsServer = serverHandshakeState.server;
        TlsServerContextImpl tlsServerContextImpl = serverHandshakeState.serverContext;
        SecurityParameters securityParametersHandshake = tlsServerContextImpl.getSecurityParametersHandshake();
        if (!version.isDTLS()) {
            throw new TlsFatalAlert((short) 47);
        }
        tlsServerContextImpl.setRSAPreMasterSecretVersion(version);
        tlsServerContextImpl.setClientSupportedVersions(TlsExtensionsUtils.getSupportedVersionsExtensionClient(extensions));
        if (tlsServerContextImpl.getClientSupportedVersions() == null) {
            if (version.isLaterVersionOf(ProtocolVersion.DTLSv12)) {
                version = ProtocolVersion.DTLSv12;
            }
            tlsServerContextImpl.setClientSupportedVersions(version.downTo(ProtocolVersion.DTLSv10));
        } else {
            version = ProtocolVersion.getLatestDTLS(tlsServerContextImpl.getClientSupportedVersions());
        }
        if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_DTLS.isEqualOrEarlierVersionOf(version)) {
            throw new TlsFatalAlert((short) 70);
        }
        tlsServerContextImpl.setClientVersion(version);
        tlsServer.notifyClientVersion(tlsServerContextImpl.getClientVersion());
        securityParametersHandshake.clientRandom = clientHello.getRandom();
        tlsServer.notifyFallback(Arrays.contains(cipherSuites, (int) CipherSuite.TLS_FALLBACK_SCSV));
        tlsServer.notifyOfferedCipherSuites(cipherSuites);
        byte[] extensionData = TlsUtils.getExtensionData(extensions, TlsProtocol.EXT_RenegotiationInfo);
        if (Arrays.contains(cipherSuites, 255)) {
            securityParametersHandshake.secureRenegotiation = true;
        }
        if (extensionData != null) {
            securityParametersHandshake.secureRenegotiation = true;
            if (!Arrays.constantTimeAreEqual(extensionData, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                throw new TlsFatalAlert((short) 40);
            }
        }
        tlsServer.notifySecureRenegotiation(securityParametersHandshake.isSecureRenegotiation());
        if (extensions != null) {
            TlsExtensionsUtils.getPaddingExtension(extensions);
            securityParametersHandshake.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(extensions);
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(version)) {
                TlsUtils.establishClientSigAlgs(securityParametersHandshake, extensions);
            }
            securityParametersHandshake.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(extensions);
            HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(extensions);
            if (heartbeatExtension != null) {
                if (1 == heartbeatExtension.getMode()) {
                    serverHandshakeState.heartbeat = tlsServer.getHeartbeat();
                }
                serverHandshakeState.heartbeatPolicy = tlsServer.getHeartbeatPolicy();
            }
            tlsServer.processClientExtensions(extensions);
        }
    }

    protected void processClientHello(ServerHandshakeState serverHandshakeState, byte[] bArr) throws IOException {
        processClientHello(serverHandshakeState, ClientHello.parse(new ByteArrayInputStream(bArr), NullOutputStream.INSTANCE));
    }

    protected void processClientKeyExchange(ServerHandshakeState serverHandshakeState, byte[] bArr) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        serverHandshakeState.keyExchange.processClientKeyExchange(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
    }

    protected void processClientSupplementalData(ServerHandshakeState serverHandshakeState, byte[] bArr) throws IOException {
        serverHandshakeState.server.processClientSupplementalData(TlsProtocol.readSupplementalDataMessage(new ByteArrayInputStream(bArr)));
    }

    /* JADX WARN: Code restructure failed: missing block: B:61:0x01b1, code lost:
        if (r7.getCrypto().hasAnyStreamVerifiers(r8.getServerSigAlgs()) != false) goto L54;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x01c2, code lost:
        if (r7.getCrypto().hasAnyStreamVerifiersLegacy(r13.certificateRequest.getCertificateTypes()) != false) goto L54;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x01c4, code lost:
        r9.getHandshakeHash().forceBuffering();
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected org.bouncycastle.tls.DTLSTransport serverHandshake(org.bouncycastle.tls.DTLSServerProtocol.ServerHandshakeState r13, org.bouncycastle.tls.DTLSRecordLayer r14, org.bouncycastle.tls.DTLSRequest r15) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 833
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.DTLSServerProtocol.serverHandshake(org.bouncycastle.tls.DTLSServerProtocol$ServerHandshakeState, org.bouncycastle.tls.DTLSRecordLayer, org.bouncycastle.tls.DTLSRequest):org.bouncycastle.tls.DTLSTransport");
    }

    public void setVerifyRequests(boolean z) {
        this.verifyRequests = z;
    }
}