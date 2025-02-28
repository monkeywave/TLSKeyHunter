package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.tls.DTLSReliableHandshake;
import org.bouncycastle.tls.OfferedPsks;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class DTLSClientProtocol extends DTLSProtocol {

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes2.dex */
    public static class ClientHandshakeState {
        TlsClient client = null;
        TlsClientContextImpl clientContext = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        TlsSecret sessionMasterSecret = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        int[] offeredCipherSuites = null;
        Hashtable clientExtensions = null;
        Hashtable serverExtensions = null;
        boolean expectSessionTicket = false;
        Hashtable clientAgreements = null;
        OfferedPsks.BindersConfig clientBinders = null;
        TlsKeyExchange keyExchange = null;
        TlsAuthentication authentication = null;
        CertificateStatus certificateStatus = null;
        CertificateRequest certificateRequest = null;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = 2;

        protected ClientHandshakeState() {
        }
    }

    protected static byte[] patchClientHelloWithCookie(byte[] bArr, byte[] bArr2) throws IOException {
        short readUint8 = TlsUtils.readUint8(bArr, 34);
        int i = 35 + readUint8;
        int i2 = readUint8 + 36;
        byte[] bArr3 = new byte[bArr.length + bArr2.length];
        System.arraycopy(bArr, 0, bArr3, 0, i);
        TlsUtils.checkUint8(bArr2.length);
        TlsUtils.writeUint8(bArr2.length, bArr3, i);
        System.arraycopy(bArr2, 0, bArr3, i2, bArr2.length);
        System.arraycopy(bArr, i2, bArr3, bArr2.length + i2, bArr.length - i2);
        return bArr3;
    }

    protected void abortClientHandshake(ClientHandshakeState clientHandshakeState, DTLSRecordLayer dTLSRecordLayer, short s) {
        dTLSRecordLayer.fail(s);
        invalidateSession(clientHandshakeState);
    }

    protected void cancelSession(ClientHandshakeState clientHandshakeState) {
        if (clientHandshakeState.sessionMasterSecret != null) {
            clientHandshakeState.sessionMasterSecret.destroy();
            clientHandshakeState.sessionMasterSecret = null;
        }
        if (clientHandshakeState.sessionParameters != null) {
            clientHandshakeState.sessionParameters.clear();
            clientHandshakeState.sessionParameters = null;
        }
        clientHandshakeState.tlsSession = null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    protected DTLSTransport clientHandshake(ClientHandshakeState clientHandshakeState, DTLSRecordLayer dTLSRecordLayer) throws IOException {
        DTLSReliableHandshake.Message receiveMessage;
        Certificate certificate;
        TlsCredentialedSigner tlsCredentialedSigner;
        SignatureAndHashAlgorithm signatureAndHashAlgorithm;
        TlsStreamSigner tlsStreamSigner;
        TlsCredentials tlsCredentials;
        TlsClient tlsClient = clientHandshakeState.client;
        TlsClientContextImpl tlsClientContextImpl = clientHandshakeState.clientContext;
        SecurityParameters securityParametersHandshake = tlsClientContextImpl.getSecurityParametersHandshake();
        DTLSReliableHandshake dTLSReliableHandshake = new DTLSReliableHandshake(tlsClientContextImpl, dTLSRecordLayer, tlsClient.getHandshakeTimeoutMillis(), tlsClient.getHandshakeResendTimeMillis(), null);
        byte[] generateClientHello = generateClientHello(clientHandshakeState);
        dTLSRecordLayer.setWriteVersion(ProtocolVersion.DTLSv10);
        dTLSReliableHandshake.sendMessage((short) 1, generateClientHello);
        while (true) {
            receiveMessage = dTLSReliableHandshake.receiveMessage();
            if (receiveMessage.getType() != 3) {
                break;
            }
            byte[] patchClientHelloWithCookie = patchClientHelloWithCookie(generateClientHello, processHelloVerifyRequest(clientHandshakeState, receiveMessage.getBody()));
            dTLSReliableHandshake.resetAfterHelloVerifyRequestClient();
            dTLSReliableHandshake.sendMessage((short) 1, patchClientHelloWithCookie);
        }
        if (receiveMessage.getType() == 2) {
            ProtocolVersion readVersion = dTLSRecordLayer.getReadVersion();
            reportServerVersion(clientHandshakeState, readVersion);
            dTLSRecordLayer.setWriteVersion(readVersion);
            processServerHello(clientHandshakeState, receiveMessage.getBody());
            applyMaxFragmentLengthExtension(dTLSRecordLayer, securityParametersHandshake.getMaxFragmentLength());
            dTLSReliableHandshake.getHandshakeHash().notifyPRFDetermined();
            if (securityParametersHandshake.isResumedSession()) {
                securityParametersHandshake.masterSecret = clientHandshakeState.sessionMasterSecret;
                dTLSRecordLayer.initPendingEpoch(TlsUtils.initCipher(tlsClientContextImpl));
                securityParametersHandshake.peerVerifyData = TlsUtils.calculateVerifyData(tlsClientContextImpl, dTLSReliableHandshake.getHandshakeHash(), true);
                processFinished(dTLSReliableHandshake.receiveMessageBody((short) 20), securityParametersHandshake.getPeerVerifyData());
                securityParametersHandshake.localVerifyData = TlsUtils.calculateVerifyData(tlsClientContextImpl, dTLSReliableHandshake.getHandshakeHash(), false);
                dTLSReliableHandshake.sendMessage((short) 20, securityParametersHandshake.getLocalVerifyData());
                dTLSReliableHandshake.finish();
                if (securityParametersHandshake.isExtendedMasterSecret()) {
                    securityParametersHandshake.tlsUnique = securityParametersHandshake.getPeerVerifyData();
                }
                securityParametersHandshake.localCertificate = clientHandshakeState.sessionParameters.getLocalCertificate();
                securityParametersHandshake.peerCertificate = clientHandshakeState.sessionParameters.getPeerCertificate();
                securityParametersHandshake.pskIdentity = clientHandshakeState.sessionParameters.getPSKIdentity();
                securityParametersHandshake.srpIdentity = clientHandshakeState.sessionParameters.getSRPIdentity();
                tlsClientContextImpl.handshakeComplete(tlsClient, clientHandshakeState.tlsSession);
                dTLSRecordLayer.initHeartbeat(clientHandshakeState.heartbeat, 1 == clientHandshakeState.heartbeatPolicy);
                return new DTLSTransport(dTLSRecordLayer);
            }
            invalidateSession(clientHandshakeState);
            clientHandshakeState.tlsSession = TlsUtils.importSession(securityParametersHandshake.getSessionID(), null);
            DTLSReliableHandshake.Message receiveMessage2 = dTLSReliableHandshake.receiveMessage();
            if (receiveMessage2.getType() == 23) {
                processServerSupplementalData(clientHandshakeState, receiveMessage2.getBody());
                receiveMessage2 = dTLSReliableHandshake.receiveMessage();
            } else {
                tlsClient.processServerSupplementalData(null);
            }
            clientHandshakeState.keyExchange = TlsUtils.initKeyExchangeClient(tlsClientContextImpl, tlsClient);
            if (receiveMessage2.getType() == 11) {
                processServerCertificate(clientHandshakeState, receiveMessage2.getBody());
                receiveMessage2 = dTLSReliableHandshake.receiveMessage();
            } else {
                clientHandshakeState.authentication = null;
            }
            if (receiveMessage2.getType() == 22) {
                if (securityParametersHandshake.getStatusRequestVersion() < 1) {
                    throw new TlsFatalAlert((short) 10);
                }
                processCertificateStatus(clientHandshakeState, receiveMessage2.getBody());
                receiveMessage2 = dTLSReliableHandshake.receiveMessage();
            }
            DTLSReliableHandshake.Message message = receiveMessage2;
            TlsUtils.processServerCertificate(tlsClientContextImpl, clientHandshakeState.certificateStatus, clientHandshakeState.keyExchange, clientHandshakeState.authentication, clientHandshakeState.clientExtensions, clientHandshakeState.serverExtensions);
            if (message.getType() == 12) {
                processServerKeyExchange(clientHandshakeState, message.getBody());
                message = dTLSReliableHandshake.receiveMessage();
            } else {
                clientHandshakeState.keyExchange.skipServerKeyExchange();
            }
            if (message.getType() == 13) {
                processCertificateRequest(clientHandshakeState, message.getBody());
                TlsUtils.establishServerSigAlgs(securityParametersHandshake, clientHandshakeState.certificateRequest);
                message = dTLSReliableHandshake.receiveMessage();
            }
            if (message.getType() == 14) {
                if (message.getBody().length == 0) {
                    if (clientHandshakeState.certificateRequest != null) {
                        tlsCredentials = TlsUtils.establishClientCredentials(clientHandshakeState.authentication, clientHandshakeState.certificateRequest);
                        if (tlsCredentials != null) {
                            certificate = tlsCredentials.getCertificate();
                            if (tlsCredentials instanceof TlsCredentialedSigner) {
                                tlsCredentialedSigner = (TlsCredentialedSigner) tlsCredentials;
                                signatureAndHashAlgorithm = TlsUtils.getSignatureAndHashAlgorithm(securityParametersHandshake.getNegotiatedVersion(), tlsCredentialedSigner);
                                tlsStreamSigner = tlsCredentialedSigner.getStreamSigner();
                                if (ProtocolVersion.DTLSv12.equals(securityParametersHandshake.getNegotiatedVersion())) {
                                    TlsUtils.verifySupportedSignatureAlgorithm(securityParametersHandshake.getServerSigAlgs(), signatureAndHashAlgorithm, (short) 80);
                                    if (tlsStreamSigner == null) {
                                        TlsUtils.trackHashAlgorithmClient(dTLSReliableHandshake.getHandshakeHash(), signatureAndHashAlgorithm);
                                    }
                                }
                                if (tlsStreamSigner != null) {
                                    dTLSReliableHandshake.getHandshakeHash().forceBuffering();
                                }
                            } else {
                                tlsCredentialedSigner = null;
                            }
                        } else {
                            certificate = null;
                            tlsCredentialedSigner = null;
                        }
                        signatureAndHashAlgorithm = tlsCredentialedSigner;
                        tlsStreamSigner = signatureAndHashAlgorithm;
                    } else {
                        certificate = null;
                        tlsCredentialedSigner = null;
                        signatureAndHashAlgorithm = 0;
                        tlsStreamSigner = null;
                        tlsCredentials = null;
                    }
                    dTLSReliableHandshake.getHandshakeHash().sealHashAlgorithms();
                    if (tlsCredentials == null) {
                        clientHandshakeState.keyExchange.skipClientCredentials();
                    } else {
                        clientHandshakeState.keyExchange.processClientCredentials(tlsCredentials);
                    }
                    Vector clientSupplementalData = tlsClient.getClientSupplementalData();
                    if (clientSupplementalData != null) {
                        dTLSReliableHandshake.sendMessage((short) 23, generateSupplementalData(clientSupplementalData));
                    }
                    if (clientHandshakeState.certificateRequest != null) {
                        sendCertificateMessage(tlsClientContextImpl, dTLSReliableHandshake, certificate, null);
                    }
                    dTLSReliableHandshake.sendMessage((short) 16, generateClientKeyExchange(clientHandshakeState));
                    securityParametersHandshake.sessionHash = TlsUtils.getCurrentPRFHash(dTLSReliableHandshake.getHandshakeHash());
                    TlsProtocol.establishMasterSecret(tlsClientContextImpl, clientHandshakeState.keyExchange);
                    dTLSRecordLayer.initPendingEpoch(TlsUtils.initCipher(tlsClientContextImpl));
                    if (tlsCredentialedSigner != null) {
                        dTLSReliableHandshake.sendMessage((short) 15, generateCertificateVerify(clientHandshakeState, TlsUtils.generateCertificateVerifyClient(tlsClientContextImpl, tlsCredentialedSigner, signatureAndHashAlgorithm, tlsStreamSigner, dTLSReliableHandshake.getHandshakeHash())));
                    }
                    dTLSReliableHandshake.prepareToFinish();
                    securityParametersHandshake.localVerifyData = TlsUtils.calculateVerifyData(tlsClientContextImpl, dTLSReliableHandshake.getHandshakeHash(), false);
                    dTLSReliableHandshake.sendMessage((short) 20, securityParametersHandshake.getLocalVerifyData());
                    if (clientHandshakeState.expectSessionTicket) {
                        DTLSReliableHandshake.Message receiveMessage3 = dTLSReliableHandshake.receiveMessage();
                        if (receiveMessage3.getType() != 4) {
                            throw new TlsFatalAlert((short) 10);
                        }
                        securityParametersHandshake.sessionID = TlsUtils.EMPTY_BYTES;
                        invalidateSession(clientHandshakeState);
                        clientHandshakeState.tlsSession = TlsUtils.importSession(securityParametersHandshake.getSessionID(), null);
                        processNewSessionTicket(clientHandshakeState, receiveMessage3.getBody());
                    }
                    securityParametersHandshake.peerVerifyData = TlsUtils.calculateVerifyData(tlsClientContextImpl, dTLSReliableHandshake.getHandshakeHash(), true);
                    processFinished(dTLSReliableHandshake.receiveMessageBody((short) 20), securityParametersHandshake.getPeerVerifyData());
                    dTLSReliableHandshake.finish();
                    clientHandshakeState.sessionMasterSecret = securityParametersHandshake.getMasterSecret();
                    clientHandshakeState.sessionParameters = new SessionParameters.Builder().setCipherSuite(securityParametersHandshake.getCipherSuite()).setExtendedMasterSecret(securityParametersHandshake.isExtendedMasterSecret()).setLocalCertificate(securityParametersHandshake.getLocalCertificate()).setMasterSecret(tlsClientContextImpl.getCrypto().adoptSecret(clientHandshakeState.sessionMasterSecret)).setNegotiatedVersion(securityParametersHandshake.getNegotiatedVersion()).setPeerCertificate(securityParametersHandshake.getPeerCertificate()).setPSKIdentity(securityParametersHandshake.getPSKIdentity()).setSRPIdentity(securityParametersHandshake.getSRPIdentity()).setServerExtensions(clientHandshakeState.serverExtensions).build();
                    clientHandshakeState.tlsSession = TlsUtils.importSession(securityParametersHandshake.getSessionID(), clientHandshakeState.sessionParameters);
                    securityParametersHandshake.tlsUnique = securityParametersHandshake.getLocalVerifyData();
                    tlsClientContextImpl.handshakeComplete(tlsClient, clientHandshakeState.tlsSession);
                    dTLSRecordLayer.initHeartbeat(clientHandshakeState.heartbeat, 1 == clientHandshakeState.heartbeatPolicy);
                    return new DTLSTransport(dTLSRecordLayer);
                }
                throw new TlsFatalAlert((short) 50);
            }
            throw new TlsFatalAlert((short) 10);
        }
        throw new TlsFatalAlert((short) 10);
    }

    public DTLSTransport connect(TlsClient tlsClient, DatagramTransport datagramTransport) throws IOException {
        if (tlsClient != null) {
            if (datagramTransport != null) {
                TlsClientContextImpl tlsClientContextImpl = new TlsClientContextImpl(tlsClient.getCrypto());
                ClientHandshakeState clientHandshakeState = new ClientHandshakeState();
                clientHandshakeState.client = tlsClient;
                clientHandshakeState.clientContext = tlsClientContextImpl;
                tlsClient.init(tlsClientContextImpl);
                tlsClientContextImpl.handshakeBeginning(tlsClient);
                SecurityParameters securityParametersHandshake = tlsClientContextImpl.getSecurityParametersHandshake();
                securityParametersHandshake.extendedPadding = tlsClient.shouldUseExtendedPadding();
                DTLSRecordLayer dTLSRecordLayer = new DTLSRecordLayer(tlsClientContextImpl, tlsClient, datagramTransport);
                tlsClient.notifyCloseHandle(dTLSRecordLayer);
                try {
                    try {
                        try {
                            return clientHandshake(clientHandshakeState, dTLSRecordLayer);
                        } catch (TlsFatalAlert e) {
                            abortClientHandshake(clientHandshakeState, dTLSRecordLayer, e.getAlertDescription());
                            throw e;
                        } catch (IOException e2) {
                            abortClientHandshake(clientHandshakeState, dTLSRecordLayer, (short) 80);
                            throw e2;
                        }
                    } catch (RuntimeException e3) {
                        abortClientHandshake(clientHandshakeState, dTLSRecordLayer, (short) 80);
                        throw new TlsFatalAlert((short) 80, (Throwable) e3);
                    }
                } finally {
                    securityParametersHandshake.clear();
                }
            }
            throw new IllegalArgumentException("'transport' cannot be null");
        }
        throw new IllegalArgumentException("'client' cannot be null");
    }

    protected boolean establishSession(ClientHandshakeState clientHandshakeState, TlsSession tlsSession) {
        SessionParameters exportSessionParameters;
        ProtocolVersion negotiatedVersion;
        TlsSecret sessionMasterSecret;
        clientHandshakeState.tlsSession = null;
        clientHandshakeState.sessionParameters = null;
        clientHandshakeState.sessionMasterSecret = null;
        if (tlsSession == null || !tlsSession.isResumable() || (exportSessionParameters = tlsSession.exportSessionParameters()) == null || (negotiatedVersion = exportSessionParameters.getNegotiatedVersion()) == null || !negotiatedVersion.isDTLS()) {
            return false;
        }
        if ((exportSessionParameters.isExtendedMasterSecret() || TlsUtils.isExtendedMasterSecretOptional(negotiatedVersion)) && (sessionMasterSecret = TlsUtils.getSessionMasterSecret(clientHandshakeState.clientContext.getCrypto(), exportSessionParameters.getMasterSecret())) != null) {
            clientHandshakeState.tlsSession = tlsSession;
            clientHandshakeState.sessionParameters = exportSessionParameters;
            clientHandshakeState.sessionMasterSecret = sessionMasterSecret;
            return true;
        }
        return false;
    }

    protected byte[] generateCertificateVerify(ClientHandshakeState clientHandshakeState, DigitallySigned digitallySigned) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        digitallySigned.encode(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected byte[] generateClientHello(ClientHandshakeState clientHandshakeState) throws IOException {
        ProtocolVersion protocolVersion;
        ProtocolVersion protocolVersion2;
        TlsClient tlsClient = clientHandshakeState.client;
        TlsClientContextImpl tlsClientContextImpl = clientHandshakeState.clientContext;
        SecurityParameters securityParametersHandshake = tlsClientContextImpl.getSecurityParametersHandshake();
        ProtocolVersion[] protocolVersions = tlsClient.getProtocolVersions();
        ProtocolVersion earliestDTLS = ProtocolVersion.getEarliestDTLS(protocolVersions);
        ProtocolVersion latestDTLS = ProtocolVersion.getLatestDTLS(protocolVersions);
        if (ProtocolVersion.isSupportedDTLSVersionClient(latestDTLS)) {
            tlsClientContextImpl.setClientVersion(latestDTLS);
            tlsClientContextImpl.setClientSupportedVersions(protocolVersions);
            boolean isEqualOrLaterVersionOf = ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(earliestDTLS);
            boolean isEqualOrEarlierVersionOf = ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(latestDTLS);
            securityParametersHandshake.clientRandom = TlsProtocol.createRandomBlock(!isEqualOrEarlierVersionOf && tlsClient.shouldUseGMTUnixTime(), tlsClientContextImpl);
            TlsSession sessionToResume = isEqualOrLaterVersionOf ? tlsClient.getSessionToResume() : null;
            boolean isFallback = tlsClient.isFallback();
            clientHandshakeState.offeredCipherSuites = tlsClient.getCipherSuites();
            clientHandshakeState.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(tlsClient.getClientExtensions());
            boolean shouldUseExtendedMasterSecret = tlsClient.shouldUseExtendedMasterSecret();
            establishSession(clientHandshakeState, sessionToResume);
            byte[] sessionID = TlsUtils.getSessionID(clientHandshakeState.tlsSession);
            if (sessionID.length > 0 && !Arrays.contains(clientHandshakeState.offeredCipherSuites, clientHandshakeState.sessionParameters.getCipherSuite())) {
                sessionID = TlsUtils.EMPTY_BYTES;
            }
            if (sessionID.length > 0) {
                protocolVersion = clientHandshakeState.sessionParameters.getNegotiatedVersion();
                if (!ProtocolVersion.contains(protocolVersions, protocolVersion)) {
                    sessionID = TlsUtils.EMPTY_BYTES;
                }
            } else {
                protocolVersion = null;
            }
            if (sessionID.length > 0 && TlsUtils.isExtendedMasterSecretOptional(protocolVersion)) {
                boolean isExtendedMasterSecret = clientHandshakeState.sessionParameters.isExtendedMasterSecret();
                if (!shouldUseExtendedMasterSecret ? isExtendedMasterSecret : !(isExtendedMasterSecret || tlsClient.allowLegacyResumption())) {
                    sessionID = TlsUtils.EMPTY_BYTES;
                }
            }
            if (sessionID.length < 1) {
                cancelSession(clientHandshakeState);
            }
            tlsClient.notifySessionToResume(clientHandshakeState.tlsSession);
            if (isEqualOrEarlierVersionOf) {
                ProtocolVersion protocolVersion3 = ProtocolVersion.DTLSv12;
                TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientHandshakeState.clientExtensions, protocolVersions);
                protocolVersion2 = protocolVersion3;
            } else {
                protocolVersion2 = latestDTLS;
            }
            tlsClientContextImpl.setRSAPreMasterSecretVersion(protocolVersion2);
            securityParametersHandshake.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientHandshakeState.clientExtensions);
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(latestDTLS)) {
                TlsUtils.establishClientSigAlgs(securityParametersHandshake, clientHandshakeState.clientExtensions);
            }
            securityParametersHandshake.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientHandshakeState.clientExtensions);
            clientHandshakeState.clientBinders = null;
            clientHandshakeState.clientAgreements = TlsUtils.addKeyShareToClientHello(tlsClientContextImpl, tlsClient, clientHandshakeState.clientExtensions);
            if (shouldUseExtendedMasterSecret && TlsUtils.isExtendedMasterSecretOptional(protocolVersions)) {
                TlsExtensionsUtils.addExtendedMasterSecretExtension(clientHandshakeState.clientExtensions);
            } else {
                clientHandshakeState.clientExtensions.remove(TlsExtensionsUtils.EXT_extended_master_secret);
            }
            boolean z = TlsUtils.getExtensionData(clientHandshakeState.clientExtensions, TlsProtocol.EXT_RenegotiationInfo) == null;
            boolean contains = Arrays.contains(clientHandshakeState.offeredCipherSuites, 255);
            if (z && !contains) {
                clientHandshakeState.offeredCipherSuites = Arrays.append(clientHandshakeState.offeredCipherSuites, 255);
            }
            if (isFallback && !Arrays.contains(clientHandshakeState.offeredCipherSuites, (int) CipherSuite.TLS_FALLBACK_SCSV)) {
                clientHandshakeState.offeredCipherSuites = Arrays.append(clientHandshakeState.offeredCipherSuites, (int) CipherSuite.TLS_FALLBACK_SCSV);
            }
            clientHandshakeState.heartbeat = tlsClient.getHeartbeat();
            clientHandshakeState.heartbeatPolicy = tlsClient.getHeartbeatPolicy();
            if (clientHandshakeState.heartbeat != null || 1 == clientHandshakeState.heartbeatPolicy) {
                TlsExtensionsUtils.addHeartbeatExtension(clientHandshakeState.clientExtensions, new HeartbeatExtension(clientHandshakeState.heartbeatPolicy));
            }
            ClientHello clientHello = new ClientHello(protocolVersion2, securityParametersHandshake.getClientRandom(), sessionID, TlsUtils.EMPTY_BYTES, clientHandshakeState.offeredCipherSuites, clientHandshakeState.clientExtensions, clientHandshakeState.clientBinders != null ? clientHandshakeState.clientBinders.bindersSize : 0);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            clientHello.encode(tlsClientContextImpl, byteArrayOutputStream);
            return byteArrayOutputStream.toByteArray();
        }
        throw new TlsFatalAlert((short) 80);
    }

    protected byte[] generateClientKeyExchange(ClientHandshakeState clientHandshakeState) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        clientHandshakeState.keyExchange.generateClientKeyExchange(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected void invalidateSession(ClientHandshakeState clientHandshakeState) {
        if (clientHandshakeState.tlsSession != null) {
            clientHandshakeState.tlsSession.invalidate();
        }
        cancelSession(clientHandshakeState);
    }

    protected void processCertificateRequest(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        if (clientHandshakeState.authentication == null) {
            throw new TlsFatalAlert((short) 40);
        }
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        CertificateRequest parse = CertificateRequest.parse(clientHandshakeState.clientContext, byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        clientHandshakeState.certificateRequest = TlsUtils.validateCertificateRequest(parse, clientHandshakeState.keyExchange);
    }

    protected void processCertificateStatus(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        clientHandshakeState.certificateStatus = CertificateStatus.parse(clientHandshakeState.clientContext, byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
    }

    protected byte[] processHelloVerifyRequest(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        ProtocolVersion readVersion = TlsUtils.readVersion(byteArrayInputStream);
        byte[] readOpaque8 = TlsUtils.readOpaque8(byteArrayInputStream, 0, ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(readVersion) ? 255 : 32);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        if (readVersion.isEqualOrEarlierVersionOf(clientHandshakeState.clientContext.getClientVersion())) {
            return readOpaque8;
        }
        throw new TlsFatalAlert((short) 47);
    }

    protected void processNewSessionTicket(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        NewSessionTicket parse = NewSessionTicket.parse(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        clientHandshakeState.client.notifyNewSessionTicket(parse);
    }

    protected void processServerCertificate(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        clientHandshakeState.authentication = TlsUtils.receiveServerCertificate(clientHandshakeState.clientContext, clientHandshakeState.client, new ByteArrayInputStream(bArr), clientHandshakeState.serverExtensions);
    }

    protected void processServerHello(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        byte[] connectionIDExtension;
        TlsClient tlsClient = clientHandshakeState.client;
        TlsClientContextImpl tlsClientContextImpl = clientHandshakeState.clientContext;
        SecurityParameters securityParametersHandshake = tlsClientContextImpl.getSecurityParametersHandshake();
        ServerHello parse = ServerHello.parse(new ByteArrayInputStream(bArr));
        Hashtable extensions = parse.getExtensions();
        ProtocolVersion version = parse.getVersion();
        ProtocolVersion supportedVersionsExtensionServer = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
        if (supportedVersionsExtensionServer != null) {
            if (!ProtocolVersion.DTLSv12.equals(version) || !ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(supportedVersionsExtensionServer)) {
                throw new TlsFatalAlert((short) 47);
            }
            version = supportedVersionsExtensionServer;
        }
        reportServerVersion(clientHandshakeState, version);
        int[] iArr = clientHandshakeState.offeredCipherSuites;
        securityParametersHandshake.serverRandom = parse.getRandom();
        if (!tlsClientContextImpl.getClientVersion().equals(version)) {
            TlsUtils.checkDowngradeMarker(version, securityParametersHandshake.getServerRandom());
        }
        byte[] sessionID = parse.getSessionID();
        securityParametersHandshake.sessionID = sessionID;
        tlsClient.notifySessionID(sessionID);
        boolean z = false;
        securityParametersHandshake.resumedSession = sessionID.length > 0 && clientHandshakeState.tlsSession != null && Arrays.areEqual(sessionID, clientHandshakeState.tlsSession.getSessionID());
        if (securityParametersHandshake.isResumedSession() && (parse.getCipherSuite() != clientHandshakeState.sessionParameters.getCipherSuite() || !securityParametersHandshake.getNegotiatedVersion().equals(clientHandshakeState.sessionParameters.getNegotiatedVersion()))) {
            throw new TlsFatalAlert((short) 47, "ServerHello parameters do not match resumed session");
        }
        int validateSelectedCipherSuite = validateSelectedCipherSuite(parse.getCipherSuite(), (short) 47);
        if (!TlsUtils.isValidCipherSuiteSelection(iArr, validateSelectedCipherSuite) || !TlsUtils.isValidVersionForCipherSuite(validateSelectedCipherSuite, securityParametersHandshake.getNegotiatedVersion())) {
            throw new TlsFatalAlert((short) 47, "ServerHello selected invalid cipher suite");
        }
        TlsUtils.negotiatedCipherSuite(securityParametersHandshake, validateSelectedCipherSuite);
        tlsClient.notifySelectedCipherSuite(validateSelectedCipherSuite);
        clientHandshakeState.serverExtensions = extensions;
        if (extensions != null) {
            Enumeration keys = extensions.keys();
            while (keys.hasMoreElements()) {
                Integer num = (Integer) keys.nextElement();
                if (!num.equals(TlsProtocol.EXT_RenegotiationInfo)) {
                    if (TlsUtils.getExtensionData(clientHandshakeState.clientExtensions, num) == null) {
                        throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                    }
                    securityParametersHandshake.isResumedSession();
                }
            }
        }
        byte[] extensionData = TlsUtils.getExtensionData(extensions, TlsProtocol.EXT_RenegotiationInfo);
        if (extensionData == null) {
            securityParametersHandshake.secureRenegotiation = false;
        } else {
            securityParametersHandshake.secureRenegotiation = true;
            if (!Arrays.constantTimeAreEqual(extensionData, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                throw new TlsFatalAlert((short) 40);
            }
        }
        tlsClient.notifySecureRenegotiation(securityParametersHandshake.isSecureRenegotiation());
        if (TlsExtensionsUtils.hasExtendedMasterSecretExtension(clientHandshakeState.clientExtensions)) {
            z = TlsExtensionsUtils.hasExtendedMasterSecretExtension(extensions);
            if (TlsUtils.isExtendedMasterSecretOptional(version)) {
                if (!z && tlsClient.requiresExtendedMasterSecret()) {
                    throw new TlsFatalAlert((short) 40, "Extended Master Secret extension is required");
                }
            } else if (z) {
                throw new TlsFatalAlert((short) 47, "Server sent an unexpected extended_master_secret extension negotiating " + version);
            }
        }
        securityParametersHandshake.extendedMasterSecret = z;
        if (securityParametersHandshake.isResumedSession() && securityParametersHandshake.isExtendedMasterSecret() != clientHandshakeState.sessionParameters.isExtendedMasterSecret()) {
            throw new TlsFatalAlert((short) 40, "Server resumed session with mismatched extended_master_secret negotiation");
        }
        securityParametersHandshake.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(extensions);
        securityParametersHandshake.applicationProtocolSet = true;
        if (ProtocolVersion.DTLSv12.equals(securityParametersHandshake.getNegotiatedVersion()) && (connectionIDExtension = TlsExtensionsUtils.getConnectionIDExtension(extensions)) != null) {
            byte[] connectionIDExtension2 = TlsExtensionsUtils.getConnectionIDExtension(clientHandshakeState.clientExtensions);
            if (connectionIDExtension2 == null) {
                throw new TlsFatalAlert((short) 80);
            }
            securityParametersHandshake.connectionIDLocal = connectionIDExtension;
            securityParametersHandshake.connectionIDPeer = connectionIDExtension2;
        }
        HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(extensions);
        Hashtable hashtable = null;
        if (heartbeatExtension == null) {
            clientHandshakeState.heartbeat = null;
            clientHandshakeState.heartbeatPolicy = (short) 2;
        } else if (1 != heartbeatExtension.getMode()) {
            clientHandshakeState.heartbeat = null;
        }
        Hashtable hashtable2 = clientHandshakeState.clientExtensions;
        if (securityParametersHandshake.isResumedSession()) {
            extensions = clientHandshakeState.sessionParameters.readServerExtensions();
        } else {
            hashtable = hashtable2;
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
                clientHandshakeState.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(extensions, TlsProtocol.EXT_SessionTicket, (short) 47);
            }
        }
        if (hashtable != null) {
            tlsClient.processServerExtensions(extensions);
        }
    }

    protected void processServerKeyExchange(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        clientHandshakeState.keyExchange.processServerKeyExchange(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
    }

    protected void processServerSupplementalData(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        clientHandshakeState.client.processServerSupplementalData(TlsProtocol.readSupplementalDataMessage(new ByteArrayInputStream(bArr)));
    }

    protected void reportServerVersion(ClientHandshakeState clientHandshakeState, ProtocolVersion protocolVersion) throws IOException {
        TlsClientContextImpl tlsClientContextImpl = clientHandshakeState.clientContext;
        SecurityParameters securityParametersHandshake = tlsClientContextImpl.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
        if (negotiatedVersion != null) {
            if (!negotiatedVersion.equals(protocolVersion)) {
                throw new TlsFatalAlert((short) 47);
            }
        } else if (!ProtocolVersion.contains(tlsClientContextImpl.getClientSupportedVersions(), protocolVersion)) {
            throw new TlsFatalAlert((short) 70);
        } else {
            securityParametersHandshake.negotiatedVersion = protocolVersion;
            TlsUtils.negotiatedVersionDTLSClient(tlsClientContextImpl, clientHandshakeState.client);
        }
    }
}