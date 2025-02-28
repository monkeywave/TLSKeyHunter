package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.openjsse.javax.net.ssl.SSLSocket;
import org.openjsse.sun.security.ssl.Alert;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/TransportContext.class */
public class TransportContext implements ConnectionContext {
    final SSLTransport transport;
    final Map<Byte, SSLConsumer> consumers;
    final AccessControlContext acc;
    final SSLContextImpl sslContext;
    final SSLConfiguration sslConfig;
    final InputRecord inputRecord;
    final OutputRecord outputRecord;
    boolean isUnsureMode;
    boolean isNegotiated;
    boolean isBroken;
    boolean isInputCloseNotified;
    boolean peerUserCanceled;
    Exception closeReason;
    Exception delegatedThrown;
    SSLSessionImpl conSession;
    ProtocolVersion protocolVersion;
    String applicationProtocol;
    HandshakeContext handshakeContext;
    boolean secureRenegotiation;
    byte[] clientVerifyData;
    byte[] serverVerifyData;
    List<SupportedGroupsExtension.NamedGroup> serverRequestedNamedGroups;
    CipherSuite cipherSuite;
    private static final byte[] emptyByteArray = new byte[0];

    /* JADX INFO: Access modifiers changed from: package-private */
    public TransportContext(SSLContextImpl sslContext, SSLTransport transport, InputRecord inputRecord, OutputRecord outputRecord) {
        this(sslContext, transport, new SSLConfiguration(sslContext, false), inputRecord, outputRecord, true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TransportContext(SSLContextImpl sslContext, SSLTransport transport, InputRecord inputRecord, OutputRecord outputRecord, boolean isClientMode) {
        this(sslContext, transport, new SSLConfiguration(sslContext, isClientMode), inputRecord, outputRecord, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TransportContext(SSLContextImpl sslContext, SSLTransport transport, SSLConfiguration sslConfig, InputRecord inputRecord, OutputRecord outputRecord) {
        this(sslContext, transport, (SSLConfiguration) sslConfig.clone(), inputRecord, outputRecord, false);
    }

    private TransportContext(SSLContextImpl sslContext, SSLTransport transport, SSLConfiguration sslConfig, InputRecord inputRecord, OutputRecord outputRecord, boolean isUnsureMode) {
        this.isNegotiated = false;
        this.isBroken = false;
        this.isInputCloseNotified = false;
        this.peerUserCanceled = false;
        this.closeReason = null;
        this.delegatedThrown = null;
        this.applicationProtocol = null;
        this.handshakeContext = null;
        this.secureRenegotiation = false;
        this.transport = transport;
        this.sslContext = sslContext;
        this.inputRecord = inputRecord;
        this.outputRecord = outputRecord;
        this.sslConfig = sslConfig;
        if (this.sslConfig.maximumPacketSize == 0) {
            this.sslConfig.maximumPacketSize = outputRecord.getMaxPacketSize();
        }
        this.isUnsureMode = isUnsureMode;
        this.conSession = new SSLSessionImpl();
        this.protocolVersion = this.sslConfig.maximumProtocolVersion;
        this.clientVerifyData = emptyByteArray;
        this.serverVerifyData = emptyByteArray;
        this.acc = AccessController.getContext();
        this.consumers = new HashMap();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatch(Plaintext plaintext) throws IOException {
        if (plaintext == null) {
            return;
        }
        ContentType ct = ContentType.valueOf(plaintext.contentType);
        if (ct == null) {
            throw fatal(Alert.UNEXPECTED_MESSAGE, "Unknown content type: " + ((int) plaintext.contentType));
        }
        switch (ct) {
            case HANDSHAKE:
                byte type = HandshakeContext.getHandshakeType(this, plaintext);
                if (this.handshakeContext == null) {
                    if (type == SSLHandshake.KEY_UPDATE.f987id || type == SSLHandshake.NEW_SESSION_TICKET.f987id) {
                        if (!this.isNegotiated) {
                            throw fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected unnegotiated post-handshake message: " + SSLHandshake.nameOf(type));
                        }
                        if (!PostHandshakeContext.isConsumable(this, type)) {
                            throw fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected post-handshake message: " + SSLHandshake.nameOf(type));
                        }
                        this.handshakeContext = new PostHandshakeContext(this);
                    } else {
                        this.handshakeContext = this.sslConfig.isClientMode ? new ClientHandshakeContext(this.sslContext, this) : new ServerHandshakeContext(this.sslContext, this);
                        this.outputRecord.initHandshaker();
                    }
                }
                this.handshakeContext.dispatch(type, plaintext);
                return;
            case ALERT:
                Alert.alertConsumer.consume(this, plaintext.fragment);
                return;
            default:
                SSLConsumer consumer = this.consumers.get(Byte.valueOf(plaintext.contentType));
                if (consumer != null) {
                    consumer.consume(this, plaintext.fragment);
                    return;
                }
                throw fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected content: " + ((int) plaintext.contentType));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void kickstart() throws IOException {
        if (this.isUnsureMode) {
            throw new IllegalStateException("Client/Server mode not yet set.");
        }
        if (this.outputRecord.isClosed() || this.inputRecord.isClosed() || this.isBroken) {
            if (this.closeReason != null) {
                throw new SSLException("Cannot kickstart, the connection is broken or closed", this.closeReason);
            }
            throw new SSLException("Cannot kickstart, the connection is broken or closed");
        }
        if (this.handshakeContext == null) {
            if (this.isNegotiated && this.protocolVersion.useTLS13PlusSpec()) {
                this.handshakeContext = new PostHandshakeContext(this);
            } else {
                this.handshakeContext = this.sslConfig.isClientMode ? new ClientHandshakeContext(this.sslContext, this) : new ServerHandshakeContext(this.sslContext, this);
                this.outputRecord.initHandshaker();
            }
        }
        if (this.isNegotiated || this.sslConfig.isClientMode) {
            this.handshakeContext.kickstart();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isPostHandshakeContext() {
        return this.handshakeContext != null && (this.handshakeContext instanceof PostHandshakeContext);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void warning(Alert alert) {
        if (this.isNegotiated || this.handshakeContext != null) {
            try {
                this.outputRecord.encodeAlert(Alert.Level.WARNING.level, alert.f960id);
            } catch (IOException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("Warning: failed to send warning alert " + alert, ioe);
                }
            }
        }
    }

    void closeNotify(boolean isUserCanceled) throws IOException {
        if (this.transport instanceof SSLSocketImpl) {
            ((SSLSocketImpl) this.transport).closeNotify(isUserCanceled);
            return;
        }
        synchronized (this.outputRecord) {
            if (isUserCanceled) {
                warning(Alert.USER_CANCELED);
            }
            warning(Alert.CLOSE_NOTIFY);
            this.outputRecord.close();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLException fatal(Alert alert, String diagnostic) throws SSLException {
        return fatal(alert, diagnostic, null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLException fatal(Alert alert, Throwable cause) throws SSLException {
        return fatal(alert, null, cause);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLException fatal(Alert alert, String diagnostic, Throwable cause) throws SSLException {
        return fatal(alert, diagnostic, false, cause);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLException fatal(Alert alert, String diagnostic, boolean recvFatalAlert, Throwable cause) throws SSLException {
        if (this.closeReason != null) {
            if (cause == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("Closed transport, general or untracked problem", new Object[0]);
                }
                throw alert.createSSLException("Closed transport, general or untracked problem");
            } else if (cause instanceof SSLException) {
                throw ((SSLException) cause);
            } else {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("Closed transport, unexpected rethrowing", cause);
                }
                throw alert.createSSLException("Unexpected rethrowing", cause);
            }
        }
        if (diagnostic == null) {
            if (cause == null) {
                diagnostic = "General/Untracked problem";
            } else {
                diagnostic = cause.getMessage();
            }
        }
        if (cause == null) {
            cause = alert.createSSLException(diagnostic);
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.severe("Fatal (" + alert + "): " + diagnostic, cause);
        }
        if (cause instanceof SSLException) {
            this.closeReason = (SSLException) cause;
        } else {
            this.closeReason = alert.createSSLException(diagnostic, cause);
        }
        try {
            this.inputRecord.close();
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("Fatal: input record closure failed", ioe);
            }
            this.closeReason.addSuppressed(ioe);
        }
        if (this.conSession != null) {
            this.conSession.invalidate();
        }
        if (this.handshakeContext != null && this.handshakeContext.handshakeSession != null) {
            this.handshakeContext.handshakeSession.invalidate();
        }
        if (!recvFatalAlert && !isOutboundClosed() && !this.isBroken && (this.isNegotiated || this.handshakeContext != null)) {
            try {
                this.outputRecord.encodeAlert(Alert.Level.FATAL.level, alert.f960id);
            } catch (IOException ioe2) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("Fatal: failed to send fatal alert " + alert, ioe2);
                }
                this.closeReason.addSuppressed(ioe2);
            }
        }
        try {
            this.outputRecord.close();
        } catch (IOException ioe3) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("Fatal: output record closure failed", ioe3);
            }
            this.closeReason.addSuppressed(ioe3);
        }
        if (this.handshakeContext != null) {
            this.handshakeContext = null;
        }
        try {
            try {
                this.transport.shutdown();
                this.isBroken = true;
            } catch (IOException ioe4) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("Fatal: transport closure failed", ioe4);
                }
                this.closeReason.addSuppressed(ioe4);
                this.isBroken = true;
            }
            if (this.closeReason instanceof SSLException) {
                throw ((SSLException) this.closeReason);
            }
            throw ((RuntimeException) this.closeReason);
        } catch (Throwable th) {
            this.isBroken = true;
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setUseClientMode(boolean useClientMode) {
        if (this.handshakeContext != null || this.isNegotiated) {
            throw new IllegalArgumentException("Cannot change mode after SSL traffic has started");
        }
        if (this.sslConfig.isClientMode != useClientMode) {
            if (this.sslContext.isDefaultProtocolVesions(this.sslConfig.enabledProtocols)) {
                this.sslConfig.enabledProtocols = this.sslContext.getDefaultProtocolVersions(!useClientMode);
            }
            if (this.sslContext.isDefaultCipherSuiteList(this.sslConfig.enabledCipherSuites)) {
                this.sslConfig.enabledCipherSuites = this.sslContext.getDefaultCipherSuites(!useClientMode);
            }
            this.sslConfig.toggleClientMode();
        }
        this.isUnsureMode = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isOutboundDone() {
        return this.outputRecord.isClosed() && this.outputRecord.isEmpty();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isOutboundClosed() {
        return this.outputRecord.isClosed();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isInboundClosed() {
        return this.inputRecord.isClosed();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void closeInbound() throws SSLException {
        if (isInboundClosed()) {
            return;
        }
        try {
            if (!this.isInputCloseNotified) {
                initiateInboundClose();
            } else {
                passiveInboundClose();
            }
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("inbound closure failed", ioe);
            }
        }
    }

    private void passiveInboundClose() throws IOException {
        ProtocolVersion pv;
        if (!isInboundClosed()) {
            this.inputRecord.close();
        }
        if (!isOutboundClosed()) {
            boolean needCloseNotify = SSLConfiguration.acknowledgeCloseNotify;
            if (!needCloseNotify) {
                if (this.isNegotiated) {
                    if (!this.protocolVersion.useTLS13PlusSpec()) {
                        needCloseNotify = true;
                    }
                } else if (this.handshakeContext != null && ((pv = this.handshakeContext.negotiatedProtocol) == null || !pv.useTLS13PlusSpec())) {
                    needCloseNotify = true;
                }
            }
            if (needCloseNotify) {
                closeNotify(false);
            }
        }
    }

    private void initiateInboundClose() throws IOException {
        if (!isInboundClosed()) {
            this.inputRecord.close();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void closeOutbound() {
        if (isOutboundClosed()) {
            return;
        }
        try {
            initiateOutboundClose();
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound closure failed", ioe);
            }
        }
    }

    private void initiateOutboundClose() throws IOException {
        boolean useUserCanceled = false;
        if (!this.isNegotiated && this.handshakeContext != null && !this.peerUserCanceled) {
            useUserCanceled = true;
        }
        closeNotify(useUserCanceled);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        if (!this.outputRecord.isEmpty()) {
            return SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }
        if (isOutboundClosed() && isInboundClosed()) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        if (this.handshakeContext != null) {
            if (!this.handshakeContext.delegatedActions.isEmpty()) {
                return SSLEngineResult.HandshakeStatus.NEED_TASK;
            }
            if (!isInboundClosed()) {
                return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            }
            if (!isOutboundClosed()) {
                return SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }
        }
        return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean needUnwrapAgain() {
        if (this.outputRecord.isEmpty()) {
            return ((isOutboundClosed() && isInboundClosed()) || this.handshakeContext == null || !this.handshakeContext.delegatedActions.isEmpty() || isInboundClosed() || !this.sslContext.isDTLS() || this.inputRecord.isEmpty() || getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) ? false : true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLEngineResult.HandshakeStatus finishHandshake() {
        if (this.protocolVersion.useTLS13PlusSpec()) {
            this.outputRecord.f977tc = this;
            this.inputRecord.f973tc = this;
            this.cipherSuite = this.handshakeContext.negotiatedCipherSuite;
            this.inputRecord.readCipher.baseSecret = this.handshakeContext.baseReadSecret;
            this.outputRecord.writeCipher.baseSecret = this.handshakeContext.baseWriteSecret;
        }
        this.handshakeContext = null;
        this.outputRecord.handshakeHash.finish();
        this.inputRecord.finishHandshake();
        this.outputRecord.finishHandshake();
        this.isNegotiated = true;
        if ((this.transport instanceof SSLSocket) && this.sslConfig.handshakeListeners != null && !this.sslConfig.handshakeListeners.isEmpty()) {
            HandshakeCompletedEvent hce = new HandshakeCompletedEvent((SSLSocket) this.transport, this.conSession);
            Thread thread = new Thread(null, new NotifyHandshake(this.sslConfig.handshakeListeners, hce), "HandshakeCompletedNotify-Thread", 0L);
            thread.start();
        }
        return SSLEngineResult.HandshakeStatus.FINISHED;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLEngineResult.HandshakeStatus finishPostHandshake() {
        this.handshakeContext = null;
        return SSLEngineResult.HandshakeStatus.FINISHED;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/TransportContext$NotifyHandshake.class */
    public static class NotifyHandshake implements Runnable {
        private final Set<Map.Entry<HandshakeCompletedListener, AccessControlContext>> targets;
        private final HandshakeCompletedEvent event;

        NotifyHandshake(Map<HandshakeCompletedListener, AccessControlContext> listeners, HandshakeCompletedEvent event) {
            this.targets = new HashSet(listeners.entrySet());
            this.event = event;
        }

        @Override // java.lang.Runnable
        public void run() {
            for (Map.Entry<HandshakeCompletedListener, AccessControlContext> entry : this.targets) {
                final HandshakeCompletedListener listener = entry.getKey();
                AccessControlContext acc = entry.getValue();
                AccessController.doPrivileged(new PrivilegedAction<Void>() { // from class: org.openjsse.sun.security.ssl.TransportContext.NotifyHandshake.1
                    /* JADX WARN: Can't rename method to resolve collision */
                    @Override // java.security.PrivilegedAction
                    public Void run() {
                        listener.handshakeCompleted(NotifyHandshake.this.event);
                        return null;
                    }
                }, acc);
            }
        }
    }
}