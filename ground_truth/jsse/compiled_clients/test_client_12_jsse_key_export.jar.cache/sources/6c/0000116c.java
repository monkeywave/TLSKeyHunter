package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLKeyException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSession;
import org.openjsse.javax.net.ssl.SSLEngine;
import org.openjsse.javax.net.ssl.SSLEngineResult;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLEngineImpl.class */
public final class SSLEngineImpl extends SSLEngine implements SSLTransport {
    private final SSLContextImpl sslContext;
    final TransportContext conContext;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLEngineImpl(SSLContextImpl sslContext) {
        this(sslContext, null, -1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLEngineImpl(SSLContextImpl sslContext, String host, int port) {
        super(host, port);
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        if (sslContext.isDTLS()) {
            this.conContext = new TransportContext(sslContext, this, new DTLSInputRecord(handshakeHash), new DTLSOutputRecord(handshakeHash));
        } else {
            this.conContext = new TransportContext(sslContext, this, new SSLEngineInputRecord(handshakeHash), new SSLEngineOutputRecord(handshakeHash));
        }
        if (host != null) {
            this.conContext.sslConfig.serverNames = Utilities.addToSNIServerNameList(this.conContext.sslConfig.serverNames, host);
        }
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void beginHandshake() throws SSLException {
        if (this.conContext.isUnsureMode) {
            throw new IllegalStateException("Client/Server mode has not yet been set.");
        }
        try {
            this.conContext.kickstart();
        } catch (IOException ioe) {
            throw this.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Couldn't kickstart handshaking", ioe);
        } catch (Exception ex) {
            throw this.conContext.fatal(Alert.INTERNAL_ERROR, "Fail to begin handshake", ex);
        }
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLEngineResult wrap(ByteBuffer[] appData, int offset, int length, ByteBuffer netData) throws SSLException {
        return wrap(appData, offset, length, new ByteBuffer[]{netData}, 0, 1);
    }

    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws SSLException {
        if (this.conContext.isUnsureMode) {
            throw new IllegalStateException("Client/Server mode has not yet been set.");
        }
        checkTaskThrown();
        checkParams(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
        try {
            return writeRecord(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
        } catch (SSLProtocolException spe) {
            throw this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, spe);
        } catch (IOException ioe) {
            throw this.conContext.fatal(Alert.INTERNAL_ERROR, "problem wrapping app data", ioe);
        } catch (Exception ex) {
            throw this.conContext.fatal(Alert.INTERNAL_ERROR, "Fail to wrap application data", ex);
        }
    }

    private SSLEngineResult writeRecord(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws IOException {
        SSLEngineResult.HandshakeStatus hsStatus;
        if (isOutboundDone()) {
            return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.CLOSED, getHandshakeStatus(), 0, 0, -1L, this.conContext.needUnwrapAgain());
        }
        HandshakeContext hc = this.conContext.handshakeContext;
        SSLEngineResult.HandshakeStatus hsStatus2 = null;
        if (!this.conContext.isNegotiated && !this.conContext.isBroken && !this.conContext.isInboundClosed() && !this.conContext.isOutboundClosed()) {
            this.conContext.kickstart();
            hsStatus2 = getHandshakeStatus();
            if (hsStatus2 == SSLEngineResult.HandshakeStatus.NEED_UNWRAP && !needUnwrapAgain() && (!this.sslContext.isDTLS() || hc == null || !hc.sslConfig.enableRetransmissions || this.conContext.outputRecord.firstMessage)) {
                return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.OK, hsStatus2, 0, 0, -1L, needUnwrapAgain());
            }
        }
        if (hsStatus2 == null) {
            hsStatus2 = getHandshakeStatus();
        }
        if (hsStatus2 == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.OK, hsStatus2, 0, 0);
        }
        int dstsRemains = 0;
        for (int i = dstsOffset; i < dstsOffset + dstsLength; i++) {
            dstsRemains += dsts[i].remaining();
        }
        if (dstsRemains < this.conContext.conSession.getPacketBufferSize()) {
            return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0, -1L, needUnwrapAgain());
        }
        int srcsRemains = 0;
        for (int i2 = srcsOffset; i2 < srcsOffset + srcsLength; i2++) {
            srcsRemains += srcs[i2].remaining();
        }
        Ciphertext ciphertext = null;
        try {
            if (!this.conContext.outputRecord.isEmpty() || (hc != null && hc.sslConfig.enableRetransmissions && hc.sslContext.isDTLS() && hsStatus2 == SSLEngineResult.HandshakeStatus.NEED_UNWRAP && !needUnwrapAgain())) {
                ciphertext = encode(null, 0, 0, dsts, dstsOffset, dstsLength);
            }
            if (ciphertext == null && srcsRemains != 0) {
                ciphertext = encode(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
            }
            SSLEngineResult.Status status = isOutboundDone() ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
            if (ciphertext != null && ciphertext.handshakeStatus != null) {
                hsStatus = ciphertext.handshakeStatus;
            } else {
                hsStatus = getHandshakeStatus();
                if (ciphertext == null && !this.conContext.isNegotiated && this.conContext.isInboundClosed() && hsStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    status = SSLEngineResult.Status.CLOSED;
                }
            }
            int deltaSrcs = srcsRemains;
            for (int i3 = srcsOffset; i3 < srcsOffset + srcsLength; i3++) {
                deltaSrcs -= srcs[i3].remaining();
            }
            int deltaDsts = dstsRemains;
            for (int i4 = dstsOffset; i4 < dstsOffset + dstsLength; i4++) {
                deltaDsts -= dsts[i4].remaining();
            }
            return new org.openjsse.javax.net.ssl.SSLEngineResult(status, hsStatus, deltaSrcs, deltaDsts, ciphertext != null ? ciphertext.recordSN : -1L, needUnwrapAgain());
        } catch (IOException ioe) {
            if (ioe instanceof SSLException) {
                throw ioe;
            }
            throw new SSLException("Write problems", ioe);
        }
    }

    private Ciphertext encode(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws IOException {
        try {
            Ciphertext ciphertext = this.conContext.outputRecord.encode(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
            if (ciphertext == null) {
                return null;
            }
            boolean needRetransmission = this.conContext.sslContext.isDTLS() && this.conContext.handshakeContext != null && this.conContext.handshakeContext.sslConfig.enableRetransmissions;
            SSLEngineResult.HandshakeStatus hsStatus = tryToFinishHandshake(ciphertext.contentType);
            if (needRetransmission && hsStatus == SSLEngineResult.HandshakeStatus.FINISHED && this.conContext.sslContext.isDTLS() && ciphertext.handshakeType == SSLHandshake.FINISHED.f987id) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,verbose")) {
                    SSLLogger.finest("retransmit the last flight messages", new Object[0]);
                }
                this.conContext.outputRecord.launchRetransmission();
                hsStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }
            if (hsStatus == null) {
                hsStatus = this.conContext.getHandshakeStatus();
            }
            if (this.conContext.outputRecord.seqNumIsHuge() || this.conContext.outputRecord.writeCipher.atKeyLimit()) {
                hsStatus = tryKeyUpdate(hsStatus);
            }
            ciphertext.handshakeStatus = hsStatus;
            return ciphertext;
        } catch (SSLHandshakeException she) {
            throw this.conContext.fatal(Alert.HANDSHAKE_FAILURE, she);
        } catch (IOException e) {
            throw this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, e);
        }
    }

    private SSLEngineResult.HandshakeStatus tryToFinishHandshake(byte contentType) {
        SSLEngineResult.HandshakeStatus hsStatus = null;
        if (contentType == ContentType.HANDSHAKE.f965id && this.conContext.outputRecord.isEmpty()) {
            if (this.conContext.handshakeContext == null) {
                hsStatus = SSLEngineResult.HandshakeStatus.FINISHED;
            } else if (this.conContext.isPostHandshakeContext()) {
                hsStatus = this.conContext.finishPostHandshake();
            } else if (this.conContext.handshakeContext.handshakeFinished) {
                hsStatus = this.conContext.finishHandshake();
            }
        }
        return hsStatus;
    }

    private SSLEngineResult.HandshakeStatus tryKeyUpdate(SSLEngineResult.HandshakeStatus currentHandshakeStatus) throws IOException {
        if (this.conContext.handshakeContext == null && !this.conContext.isOutboundClosed() && !this.conContext.isInboundClosed() && !this.conContext.isBroken) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.finest("trigger key update", new Object[0]);
            }
            beginHandshake();
            return this.conContext.getHandshakeStatus();
        }
        return currentHandshakeStatus;
    }

    private static void checkParams(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) {
        if (srcs == null || dsts == null) {
            throw new IllegalArgumentException("source or destination buffer is null");
        }
        if (dstsOffset < 0 || dstsLength < 0 || dstsOffset > dsts.length - dstsLength) {
            throw new IndexOutOfBoundsException("index out of bound of the destination buffers");
        }
        if (srcsOffset < 0 || srcsLength < 0 || srcsOffset > srcs.length - srcsLength) {
            throw new IndexOutOfBoundsException("index out of bound of the source buffers");
        }
        for (int i = dstsOffset; i < dstsOffset + dstsLength; i++) {
            if (dsts[i] == null) {
                throw new IllegalArgumentException("destination buffer[" + i + "] == null");
            }
            if (dsts[i].isReadOnly()) {
                throw new ReadOnlyBufferException();
            }
        }
        for (int i2 = srcsOffset; i2 < srcsOffset + srcsLength; i2++) {
            if (srcs[i2] == null) {
                throw new IllegalArgumentException("source buffer[" + i2 + "] == null");
            }
        }
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized org.openjsse.javax.net.ssl.SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        return unwrap(new ByteBuffer[]{src}, 0, 1, dsts, offset, length);
    }

    public synchronized org.openjsse.javax.net.ssl.SSLEngineResult unwrap(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws SSLException {
        if (this.conContext.isUnsureMode) {
            throw new IllegalStateException("Client/Server mode has not yet been set.");
        }
        checkTaskThrown();
        checkParams(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
        try {
            return readRecord(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
        } catch (SSLProtocolException spe) {
            throw this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, spe.getMessage(), spe);
        } catch (IOException ioe) {
            throw this.conContext.fatal(Alert.INTERNAL_ERROR, "problem unwrapping net record", ioe);
        } catch (Exception ex) {
            throw this.conContext.fatal(Alert.INTERNAL_ERROR, "Fail to unwrap network record", ex);
        }
    }

    private org.openjsse.javax.net.ssl.SSLEngineResult readRecord(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws IOException {
        SSLEngineResult.HandshakeStatus hsStatus;
        SSLEngineResult.HandshakeStatus hsStatus2;
        if (isInboundDone()) {
            return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.CLOSED, getHandshakeStatus(), 0, 0, -1L, needUnwrapAgain());
        }
        SSLEngineResult.HandshakeStatus hsStatus3 = null;
        if (!this.conContext.isNegotiated && !this.conContext.isBroken && !this.conContext.isInboundClosed() && !this.conContext.isOutboundClosed()) {
            this.conContext.kickstart();
            hsStatus3 = getHandshakeStatus();
            if (hsStatus3 == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.OK, hsStatus3, 0, 0);
            }
        }
        if (hsStatus3 == null) {
            hsStatus3 = getHandshakeStatus();
        }
        if (hsStatus3 == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.OK, hsStatus3, 0, 0);
        }
        boolean needUnwrapAgain = needUnwrapAgain();
        if (hsStatus3 == SSLEngineResult.HandshakeStatus.NEED_UNWRAP && needUnwrapAgain) {
            try {
                Plaintext plainText = decode(null, 0, 0, dsts, dstsOffset, dstsLength);
                SSLEngineResult.Status status = isInboundDone() ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
                if (plainText.handshakeStatus != null) {
                    hsStatus2 = plainText.handshakeStatus;
                } else {
                    hsStatus2 = getHandshakeStatus();
                }
                return new org.openjsse.javax.net.ssl.SSLEngineResult(status, hsStatus2, 0, 0, plainText.recordSN, needUnwrapAgain);
            } catch (IOException ioe) {
                if (ioe instanceof SSLException) {
                    throw ioe;
                }
                throw new SSLException("readRecord", ioe);
            }
        }
        int srcsRemains = 0;
        for (int i = srcsOffset; i < srcsOffset + srcsLength; i++) {
            srcsRemains += srcs[i].remaining();
        }
        if (srcsRemains == 0) {
            return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, hsStatus3, 0, 0, -1L, needUnwrapAgain);
        }
        try {
            int packetLen = this.conContext.inputRecord.bytesInCompletePacket(srcs, srcsOffset, srcsLength);
            if (packetLen > this.conContext.conSession.getPacketBufferSize()) {
                if (packetLen <= (this.sslContext.isDTLS() ? DTLSRecord.maxRecordSize : SSLRecord.maxLargeRecordSize) && !this.sslContext.isDTLS()) {
                    this.conContext.conSession.expandBufferSizes();
                }
                int largestRecordSize = this.conContext.conSession.getPacketBufferSize();
                if (packetLen > largestRecordSize) {
                    throw new SSLProtocolException("Input record too big: max = " + largestRecordSize + " len = " + packetLen);
                }
            }
            int dstsRemains = 0;
            for (int i2 = dstsOffset; i2 < dstsOffset + dstsLength; i2++) {
                dstsRemains += dsts[i2].remaining();
            }
            if (this.conContext.isNegotiated) {
                int FragLen = this.conContext.inputRecord.estimateFragmentSize(packetLen);
                if (FragLen > dstsRemains) {
                    return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, hsStatus3, 0, 0, -1L, needUnwrapAgain);
                }
            }
            if (packetLen == -1 || srcsRemains < packetLen) {
                return new org.openjsse.javax.net.ssl.SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, hsStatus3, 0, 0, -1L, needUnwrapAgain);
            }
            try {
                Plaintext plainText2 = decode(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
                SSLEngineResult.Status status2 = isInboundDone() ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
                if (plainText2.handshakeStatus != null) {
                    hsStatus = plainText2.handshakeStatus;
                } else {
                    hsStatus = getHandshakeStatus();
                }
                int deltaNet = srcsRemains;
                for (int i3 = srcsOffset; i3 < srcsOffset + srcsLength; i3++) {
                    deltaNet -= srcs[i3].remaining();
                }
                int deltaApp = dstsRemains;
                for (int i4 = dstsOffset; i4 < dstsOffset + dstsLength; i4++) {
                    deltaApp -= dsts[i4].remaining();
                }
                return new org.openjsse.javax.net.ssl.SSLEngineResult(status2, hsStatus, deltaNet, deltaApp, plainText2.recordSN, needUnwrapAgain);
            } catch (IOException ioe2) {
                if (ioe2 instanceof SSLException) {
                    throw ioe2;
                }
                throw new SSLException("readRecord", ioe2);
            }
        } catch (SSLException ssle) {
            if (this.sslContext.isDTLS()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,verbose")) {
                    SSLLogger.finest("Discard invalid DTLS records", ssle);
                }
                SSLEngineResult.Status status3 = isInboundDone() ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
                if (hsStatus3 == null) {
                    hsStatus3 = getHandshakeStatus();
                }
                return new org.openjsse.javax.net.ssl.SSLEngineResult(status3, hsStatus3, 0, 0, -1L, needUnwrapAgain);
            }
            throw ssle;
        }
    }

    private Plaintext decode(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws IOException {
        Plaintext pt = SSLTransport.decode(this.conContext, srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
        if (pt != Plaintext.PLAINTEXT_NULL) {
            SSLEngineResult.HandshakeStatus hsStatus = tryToFinishHandshake(pt.contentType);
            if (hsStatus == null) {
                pt.handshakeStatus = this.conContext.getHandshakeStatus();
            } else {
                pt.handshakeStatus = hsStatus;
            }
            if (this.conContext.inputRecord.seqNumIsHuge() || this.conContext.inputRecord.readCipher.atKeyLimit()) {
                pt.handshakeStatus = tryKeyUpdate(pt.handshakeStatus);
            }
        }
        return pt;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized Runnable getDelegatedTask() {
        if (this.conContext.handshakeContext != null && !this.conContext.handshakeContext.taskDelegated && !this.conContext.handshakeContext.delegatedActions.isEmpty()) {
            this.conContext.handshakeContext.taskDelegated = true;
            return new DelegatedTask(this);
        }
        return null;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void closeInbound() throws SSLException {
        if (isInboundDone()) {
            return;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.finest("Closing inbound of SSLEngine", new Object[0]);
        }
        if (!this.conContext.isInputCloseNotified && (this.conContext.isNegotiated || this.conContext.handshakeContext != null)) {
            throw this.conContext.fatal(Alert.INTERNAL_ERROR, "closing inbound before receiving peer's close_notify");
        }
        this.conContext.closeInbound();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean isInboundDone() {
        return this.conContext.isInboundClosed();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void closeOutbound() {
        if (this.conContext.isOutboundClosed()) {
            return;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.finest("Closing outbound of SSLEngine", new Object[0]);
        }
        this.conContext.closeOutbound();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean isOutboundDone() {
        return this.conContext.isOutboundDone();
    }

    @Override // javax.net.ssl.SSLEngine
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(this.sslContext.getSupportedCipherSuites());
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(this.conContext.sslConfig.enabledCipherSuites);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setEnabledCipherSuites(String[] suites) {
        this.conContext.sslConfig.enabledCipherSuites = CipherSuite.validValuesOf(suites);
    }

    @Override // javax.net.ssl.SSLEngine
    public String[] getSupportedProtocols() {
        return ProtocolVersion.toStringArray(this.sslContext.getSupportedProtocolVersions());
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized String[] getEnabledProtocols() {
        return ProtocolVersion.toStringArray(this.conContext.sslConfig.enabledProtocols);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("Protocols cannot be null");
        }
        this.conContext.sslConfig.enabledProtocols = ProtocolVersion.namesOf(protocols);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLSession getSession() {
        return this.conContext.conSession;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLSession getHandshakeSession() {
        if (this.conContext.handshakeContext == null) {
            return null;
        }
        return this.conContext.handshakeContext.handshakeSession;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return this.conContext.getHandshakeStatus();
    }

    @Override // org.openjsse.javax.net.ssl.SSLEngine
    public synchronized boolean needUnwrapAgain() {
        return this.conContext.needUnwrapAgain();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setUseClientMode(boolean mode) {
        this.conContext.setUseClientMode(mode);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean getUseClientMode() {
        return this.conContext.sslConfig.isClientMode;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setNeedClientAuth(boolean need) {
        this.conContext.sslConfig.clientAuthType = need ? ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean getNeedClientAuth() {
        return this.conContext.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setWantClientAuth(boolean want) {
        this.conContext.sslConfig.clientAuthType = want ? ClientAuthType.CLIENT_AUTH_REQUESTED : ClientAuthType.CLIENT_AUTH_NONE;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean getWantClientAuth() {
        return this.conContext.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setEnableSessionCreation(boolean flag) {
        this.conContext.sslConfig.enableSessionCreation = flag;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean getEnableSessionCreation() {
        return this.conContext.sslConfig.enableSessionCreation;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLParameters getSSLParameters() {
        return this.conContext.sslConfig.getSSLParameters();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setSSLParameters(SSLParameters params) {
        this.conContext.sslConfig.setSSLParameters(params);
        if (this.conContext.sslConfig.maximumPacketSize != 0) {
            this.conContext.outputRecord.changePacketSize(this.conContext.sslConfig.maximumPacketSize);
        }
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized String getApplicationProtocol() {
        return this.conContext.applicationProtocol;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized String getHandshakeApplicationProtocol() {
        if (this.conContext.handshakeContext == null) {
            return null;
        }
        return this.conContext.handshakeContext.applicationProtocol;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setHandshakeApplicationProtocolSelector(BiFunction<javax.net.ssl.SSLEngine, List<String>, String> selector) {
        this.conContext.sslConfig.engineAPSelector = selector;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized BiFunction<javax.net.ssl.SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return this.conContext.sslConfig.engineAPSelector;
    }

    @Override // org.openjsse.sun.security.ssl.SSLTransport
    public boolean useDelegatedTask() {
        return true;
    }

    private synchronized void checkTaskThrown() throws SSLException {
        Exception exc = null;
        HandshakeContext hc = this.conContext.handshakeContext;
        if (hc != null && hc.delegatedThrown != null) {
            exc = hc.delegatedThrown;
            hc.delegatedThrown = null;
        }
        if (this.conContext.delegatedThrown != null) {
            if (exc != null) {
                if (this.conContext.delegatedThrown == exc) {
                    this.conContext.delegatedThrown = null;
                }
            } else {
                exc = this.conContext.delegatedThrown;
                this.conContext.delegatedThrown = null;
            }
        }
        if (exc == null) {
            return;
        }
        if (exc instanceof SSLException) {
            throw ((SSLException) exc);
        }
        if (exc instanceof RuntimeException) {
            throw ((RuntimeException) exc);
        }
        throw getTaskThrown(exc);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static SSLException getTaskThrown(Exception taskThrown) {
        String msg = taskThrown.getMessage();
        if (msg == null) {
            msg = "Delegated task threw Exception or Error";
        }
        if (taskThrown instanceof RuntimeException) {
            throw new RuntimeException(msg, taskThrown);
        }
        if (taskThrown instanceof SSLHandshakeException) {
            return (SSLHandshakeException) new SSLHandshakeException(msg).initCause(taskThrown);
        }
        if (taskThrown instanceof SSLKeyException) {
            return (SSLKeyException) new SSLKeyException(msg).initCause(taskThrown);
        }
        if (taskThrown instanceof SSLPeerUnverifiedException) {
            return (SSLPeerUnverifiedException) new SSLPeerUnverifiedException(msg).initCause(taskThrown);
        }
        if (taskThrown instanceof SSLProtocolException) {
            return (SSLProtocolException) new SSLProtocolException(msg).initCause(taskThrown);
        }
        if (taskThrown instanceof SSLException) {
            return (SSLException) taskThrown;
        }
        return new SSLException(msg, taskThrown);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLEngineImpl$DelegatedTask.class */
    private static class DelegatedTask implements Runnable {
        private final SSLEngineImpl engine;

        DelegatedTask(SSLEngineImpl engineInstance) {
            this.engine = engineInstance;
        }

        @Override // java.lang.Runnable
        public void run() {
            synchronized (this.engine) {
                HandshakeContext hc = this.engine.conContext.handshakeContext;
                if (hc == null || hc.delegatedActions.isEmpty()) {
                    return;
                }
                try {
                    AccessController.doPrivileged(new DelegatedAction(hc), this.engine.conContext.acc);
                } catch (RuntimeException rte) {
                    if (this.engine.conContext.delegatedThrown == null) {
                        this.engine.conContext.delegatedThrown = rte;
                    }
                    HandshakeContext hc2 = this.engine.conContext.handshakeContext;
                    if (hc2 != null) {
                        hc2.delegatedThrown = rte;
                    } else if (this.engine.conContext.closeReason != null) {
                        this.engine.conContext.closeReason = rte;
                    }
                } catch (PrivilegedActionException pae) {
                    Exception reportedException = pae.getException();
                    if (this.engine.conContext.delegatedThrown == null) {
                        this.engine.conContext.delegatedThrown = reportedException;
                    }
                    HandshakeContext hc3 = this.engine.conContext.handshakeContext;
                    if (hc3 != null) {
                        hc3.delegatedThrown = reportedException;
                    } else if (this.engine.conContext.closeReason != null) {
                        this.engine.conContext.closeReason = SSLEngineImpl.getTaskThrown(reportedException);
                    }
                }
                HandshakeContext hc4 = this.engine.conContext.handshakeContext;
                if (hc4 != null) {
                    hc4.taskDelegated = false;
                }
            }
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLEngineImpl$DelegatedTask$DelegatedAction.class */
        private static class DelegatedAction implements PrivilegedExceptionAction<Void> {
            final HandshakeContext context;

            DelegatedAction(HandshakeContext context) {
                this.context = context;
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedExceptionAction
            public Void run() throws Exception {
                while (!this.context.delegatedActions.isEmpty()) {
                    Map.Entry<Byte, ByteBuffer> me = this.context.delegatedActions.poll();
                    if (me != null) {
                        this.context.dispatch(me.getKey().byteValue(), me.getValue());
                    }
                }
                return null;
            }
        }
    }
}