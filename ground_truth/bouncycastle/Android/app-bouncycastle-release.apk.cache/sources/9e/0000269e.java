package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import org.bouncycastle.jsse.BCApplicationProtocolSelector;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.tls.RecordPreview;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvSSLEngine extends SSLEngine implements BCSSLEngine, ProvTlsManager {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    private static final Logger LOG = Logger.getLogger(ProvSSLEngine.class.getName());
    protected boolean closedEarly;
    protected ProvSSLConnection connection;
    protected final ContextData contextData;
    protected SSLException deferredException;
    protected boolean enableSessionCreation;
    protected ProvSSLSessionHandshake handshakeSession;
    protected boolean initialHandshakeBegun;
    protected TlsProtocol protocol;
    protected ProvTlsPeer protocolPeer;
    protected boolean returnedFinished;
    protected final ProvSSLParameters sslParameters;
    protected boolean useClientMode;
    protected boolean useClientModeSet;

    /* renamed from: org.bouncycastle.jsse.provider.ProvSSLEngine$1 */
    /* loaded from: classes2.dex */
    static /* synthetic */ class C13151 {
        static final /* synthetic */ int[] $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus;

        static {
            int[] iArr = new int[SSLEngineResult.HandshakeStatus.values().length];
            $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus = iArr;
            try {
                iArr[SSLEngineResult.HandshakeStatus.NEED_UNWRAP.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLEngine(ContextData contextData) {
        this(contextData, null, -1);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLEngine(ContextData contextData, String str, int i) {
        super(str, i);
        this.enableSessionCreation = true;
        this.useClientMode = true;
        this.useClientModeSet = false;
        this.closedEarly = false;
        this.initialHandshakeBegun = false;
        this.returnedFinished = false;
        this.protocol = null;
        this.protocolPeer = null;
        this.connection = null;
        this.handshakeSession = null;
        this.deferredException = null;
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    private RecordPreview getRecordPreview(ByteBuffer byteBuffer) throws IOException {
        if (byteBuffer.remaining() < 5) {
            return null;
        }
        byte[] bArr = new byte[5];
        int position = byteBuffer.position();
        byteBuffer.get(bArr);
        byteBuffer.position(position);
        return this.protocol.previewInputRecord(bArr);
    }

    private SSLEngineResult.Status getStatus() {
        return this.protocol.isClosed() ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
    }

    private int getTotalRemaining(ByteBuffer[] byteBufferArr, int i, int i2, int i3) {
        int i4 = 0;
        for (int i5 = 0; i5 < i2; i5++) {
            int remaining = byteBufferArr[i + i5].remaining();
            if (remaining >= i3 - i4) {
                return i3;
            }
            i4 += remaining;
        }
        return i4;
    }

    private boolean hasInsufficientSpace(ByteBuffer[] byteBufferArr, int i, int i2, int i3) {
        return getTotalRemaining(byteBufferArr, i, i2, i3) < i3;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void beginHandshake() throws SSLException {
        if (!this.useClientModeSet) {
            throw new IllegalStateException("Client/Server mode must be set before the handshake can begin");
        }
        if (this.closedEarly) {
            throw new SSLException("Connection is already closed");
        }
        if (this.initialHandshakeBegun) {
            throw new UnsupportedOperationException("Renegotiation not supported");
        }
        this.initialHandshakeBegun = true;
        try {
            if (this.useClientMode) {
                TlsClientProtocol tlsClientProtocol = new TlsClientProtocol();
                this.protocol = tlsClientProtocol;
                ProvTlsClient provTlsClient = new ProvTlsClient(this, this.sslParameters);
                this.protocolPeer = provTlsClient;
                tlsClientProtocol.connect(provTlsClient);
            } else {
                TlsServerProtocol tlsServerProtocol = new TlsServerProtocol();
                this.protocol = tlsServerProtocol;
                ProvTlsServer provTlsServer = new ProvTlsServer(this, this.sslParameters);
                this.protocolPeer = provTlsServer;
                tlsServerProtocol.accept(provTlsServer);
            }
        } catch (SSLException e) {
            throw e;
        } catch (IOException e2) {
            throw new SSLException(e2);
        }
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) throws IOException {
        try {
            this.contextData.getX509TrustManager().checkClientTrusted((X509Certificate[]) x509CertificateArr.clone(), str, this);
        } catch (CertificateException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws IOException {
        try {
            this.contextData.getX509TrustManager().checkServerTrusted((X509Certificate[]) x509CertificateArr.clone(), str, this);
        } catch (CertificateException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public BCX509Key chooseClientKey(String[] strArr, Principal[] principalArr) {
        return getContextData().getX509KeyManager().chooseEngineClientKeyBC(strArr, (Principal[]) JsseUtils.clone(principalArr), this);
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public BCX509Key chooseServerKey(String[] strArr, Principal[] principalArr) {
        return getContextData().getX509KeyManager().chooseEngineServerKeyBC(strArr, (Principal[]) JsseUtils.clone(principalArr), this);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void closeInbound() throws SSLException {
        if (!this.closedEarly) {
            TlsProtocol tlsProtocol = this.protocol;
            if (tlsProtocol == null) {
                this.closedEarly = true;
            } else {
                try {
                    tlsProtocol.closeInput();
                } catch (IOException e) {
                    throw new SSLException(e);
                }
            }
        }
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void closeOutbound() {
        if (!this.closedEarly) {
            TlsProtocol tlsProtocol = this.protocol;
            if (tlsProtocol == null) {
                this.closedEarly = true;
            } else {
                try {
                    tlsProtocol.close();
                } catch (IOException e) {
                    LOG.log(Level.WARNING, "Failed to close outbound", (Throwable) e);
                }
            }
        }
    }

    @Override // javax.net.ssl.SSLEngine, org.bouncycastle.jsse.BCSSLEngine
    public synchronized String getApplicationProtocol() {
        ProvSSLConnection provSSLConnection;
        provSSLConnection = this.connection;
        return provSSLConnection == null ? null : provSSLConnection.getApplicationProtocol();
    }

    @Override // org.bouncycastle.jsse.BCSSLEngine
    public synchronized BCApplicationProtocolSelector<SSLEngine> getBCHandshakeApplicationProtocolSelector() {
        return this.sslParameters.getEngineAPSelector();
    }

    @Override // org.bouncycastle.jsse.BCSSLEngine
    public synchronized BCExtendedSSLSession getBCHandshakeSession() {
        return this.handshakeSession;
    }

    @Override // org.bouncycastle.jsse.BCSSLEngine
    public BCExtendedSSLSession getBCSession() {
        return getSessionImpl();
    }

    @Override // org.bouncycastle.jsse.BCSSLEngine
    public synchronized BCSSLConnection getConnection() {
        return this.connection;
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public ContextData getContextData() {
        return this.contextData;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized Runnable getDelegatedTask() {
        return null;
    }

    @Override // javax.net.ssl.SSLEngine, org.bouncycastle.jsse.provider.ProvTlsManager
    public synchronized boolean getEnableSessionCreation() {
        return this.enableSessionCreation;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized String[] getEnabledCipherSuites() {
        return this.sslParameters.getCipherSuites();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized String[] getEnabledProtocols() {
        return this.sslParameters.getProtocols();
    }

    @Override // javax.net.ssl.SSLEngine, org.bouncycastle.jsse.BCSSLEngine
    public synchronized String getHandshakeApplicationProtocol() {
        ProvSSLSessionHandshake provSSLSessionHandshake;
        provSSLSessionHandshake = this.handshakeSession;
        return provSSLSessionHandshake == null ? null : provSSLSessionHandshake.getApplicationProtocol();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLSession getHandshakeSession() {
        ProvSSLSessionHandshake provSSLSessionHandshake;
        provSSLSessionHandshake = this.handshakeSession;
        return provSSLSessionHandshake == null ? null : provSSLSessionHandshake.getExportSSLSession();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        TlsProtocol tlsProtocol = this.protocol;
        if (tlsProtocol != null) {
            if (tlsProtocol.getAvailableOutputBytes() <= 0 && this.deferredException == null) {
                if (this.protocol.isHandshaking()) {
                    return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                }
            }
            return SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }
        return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
    }

    @Override // org.bouncycastle.jsse.BCSSLEngine
    public synchronized BCSSLParameters getParameters() {
        return SSLParametersUtil.getParameters(this.sslParameters);
    }

    @Override // javax.net.ssl.SSLEngine, org.bouncycastle.jsse.provider.ProvTlsManager
    public String getPeerHost() {
        return super.getPeerHost();
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public String getPeerHostSNI() {
        return super.getPeerHost();
    }

    @Override // javax.net.ssl.SSLEngine, org.bouncycastle.jsse.provider.ProvTlsManager
    public int getPeerPort() {
        return super.getPeerPort();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLParameters getSSLParameters() {
        return SSLParametersUtil.getSSLParameters(this.sslParameters);
    }

    @Override // javax.net.ssl.SSLEngine
    public SSLSession getSession() {
        return getSessionImpl().getExportSSLSession();
    }

    ProvSSLSession getSessionImpl() {
        ProvSSLConnection provSSLConnection = this.connection;
        return provSSLConnection == null ? ProvSSLSession.NULL_SESSION : provSSLConnection.getSession();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized String[] getSupportedCipherSuites() {
        return this.contextData.getContext().getSupportedCipherSuites();
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized String[] getSupportedProtocols() {
        return this.contextData.getContext().getSupportedProtocols();
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public int getTransportID() {
        return System.identityHashCode(this);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean getUseClientMode() {
        return this.useClientMode;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized boolean getWantClientAuth() {
        return this.sslParameters.getWantClientAuth();
    }

    /* JADX WARN: Code restructure failed: missing block: B:8:0x000d, code lost:
        if (r0.isClosed() != false) goto L14;
     */
    @Override // javax.net.ssl.SSLEngine
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public synchronized boolean isInboundDone() {
        /*
            r1 = this;
            monitor-enter(r1)
            boolean r0 = r1.closedEarly     // Catch: java.lang.Throwable -> L15
            if (r0 != 0) goto L12
            org.bouncycastle.tls.TlsProtocol r0 = r1.protocol     // Catch: java.lang.Throwable -> L15
            if (r0 == 0) goto L10
            boolean r0 = r0.isClosed()     // Catch: java.lang.Throwable -> L15
            if (r0 == 0) goto L10
            goto L12
        L10:
            r0 = 0
            goto L13
        L12:
            r0 = 1
        L13:
            monitor-exit(r1)
            return r0
        L15:
            r0 = move-exception
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L15
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jsse.provider.ProvSSLEngine.isInboundDone():boolean");
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0016, code lost:
        if (r2.protocol.getAvailableOutputBytes() < 1) goto L13;
     */
    @Override // javax.net.ssl.SSLEngine
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public synchronized boolean isOutboundDone() {
        /*
            r2 = this;
            monitor-enter(r2)
            boolean r0 = r2.closedEarly     // Catch: java.lang.Throwable -> L1c
            r1 = 1
            if (r0 != 0) goto L1a
            org.bouncycastle.tls.TlsProtocol r0 = r2.protocol     // Catch: java.lang.Throwable -> L1c
            if (r0 == 0) goto L19
            boolean r0 = r0.isClosed()     // Catch: java.lang.Throwable -> L1c
            if (r0 == 0) goto L19
            org.bouncycastle.tls.TlsProtocol r0 = r2.protocol     // Catch: java.lang.Throwable -> L1c
            int r0 = r0.getAvailableOutputBytes()     // Catch: java.lang.Throwable -> L1c
            if (r0 >= r1) goto L19
            goto L1a
        L19:
            r1 = 0
        L1a:
            monitor-exit(r2)
            return r1
        L1c:
            r0 = move-exception
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L1c
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jsse.provider.ProvSSLEngine.isOutboundDone():boolean");
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public synchronized void notifyHandshakeComplete(ProvSSLConnection provSSLConnection) {
        ProvSSLSessionHandshake provSSLSessionHandshake = this.handshakeSession;
        if (provSSLSessionHandshake != null) {
            if (!provSSLSessionHandshake.isValid()) {
                provSSLConnection.getSession().invalidate();
            }
            this.handshakeSession.getJsseSecurityParameters().clear();
        }
        this.handshakeSession = null;
        this.connection = provSSLConnection;
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public synchronized void notifyHandshakeSession(ProvSSLSessionContext provSSLSessionContext, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, ProvSSLSession provSSLSession) {
        String peerHost = getPeerHost();
        int peerPort = getPeerPort();
        if (provSSLSession != null) {
            this.handshakeSession = new ProvSSLSessionResumed(provSSLSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters, provSSLSession.getTlsSession(), provSSLSession.getJsseSessionParameters());
        } else {
            this.handshakeSession = new ProvSSLSessionHandshake(provSSLSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters);
        }
    }

    @Override // org.bouncycastle.jsse.provider.ProvTlsManager
    public synchronized String selectApplicationProtocol(List<String> list) {
        return this.sslParameters.getEngineAPSelector().select(this, list);
    }

    @Override // org.bouncycastle.jsse.BCSSLEngine
    public synchronized void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLEngine> bCApplicationProtocolSelector) {
        this.sslParameters.setEngineAPSelector(bCApplicationProtocolSelector);
    }

    @Override // org.bouncycastle.jsse.BCSSLEngine
    public synchronized void setBCSessionToResume(BCExtendedSSLSession bCExtendedSSLSession) {
        try {
            if (bCExtendedSSLSession == null) {
                throw new NullPointerException("'session' cannot be null");
            }
            if (!(bCExtendedSSLSession instanceof ProvSSLSession)) {
                throw new IllegalArgumentException("Session-to-resume must be a session returned from 'getBCSession'");
            }
            if (this.initialHandshakeBegun) {
                throw new IllegalArgumentException("Session-to-resume cannot be set after the handshake has begun");
            }
            this.sslParameters.setSessionToResume((ProvSSLSession) bCExtendedSSLSession);
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setEnableSessionCreation(boolean z) {
        this.enableSessionCreation = z;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setEnabledCipherSuites(String[] strArr) {
        this.sslParameters.setCipherSuites(strArr);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setEnabledProtocols(String[] strArr) {
        this.sslParameters.setProtocols(strArr);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setNeedClientAuth(boolean z) {
        this.sslParameters.setNeedClientAuth(z);
    }

    @Override // org.bouncycastle.jsse.BCSSLEngine
    public synchronized void setParameters(BCSSLParameters bCSSLParameters) {
        SSLParametersUtil.setParameters(this.sslParameters, bCSSLParameters);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setSSLParameters(SSLParameters sSLParameters) {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sSLParameters);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setUseClientMode(boolean z) {
        if (this.initialHandshakeBegun) {
            throw new IllegalArgumentException("Client/Server mode cannot be changed after the handshake has begun");
        }
        if (this.useClientMode != z) {
            this.contextData.getContext().updateDefaultSSLParameters(this.sslParameters, z);
            this.useClientMode = z;
        }
        this.useClientModeSet = true;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setWantClientAuth(boolean z) {
        this.sslParameters.setWantClientAuth(z);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBufferArr, int i, int i2) throws SSLException {
        int i3;
        SSLEngineResult.HandshakeStatus handshakeStatus = getHandshakeStatus();
        int i4 = 0;
        if (isInboundDone()) {
            return new SSLEngineResult(SSLEngineResult.Status.CLOSED, handshakeStatus, 0, 0);
        }
        if (!this.initialHandshakeBegun) {
            beginHandshake();
        }
        int i5 = C13151.$SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[handshakeStatus.ordinal()];
        if (i5 != 1 && i5 != 2) {
            return new SSLEngineResult(SSLEngineResult.Status.OK, handshakeStatus, 0, 0);
        }
        try {
            RecordPreview recordPreview = getRecordPreview(byteBuffer);
            if (recordPreview != null && byteBuffer.remaining() >= recordPreview.getRecordSize()) {
                if (hasInsufficientSpace(byteBufferArr, i, i2, recordPreview.getContentLimit())) {
                    return new SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, handshakeStatus, 0, 0);
                }
                i3 = recordPreview.getRecordSize();
                try {
                    byte[] bArr = new byte[i3];
                    byteBuffer.get(bArr);
                    this.protocol.offerInput(bArr, 0, i3);
                    int availableInputBytes = this.protocol.getAvailableInputBytes();
                    int i6 = 0;
                    while (availableInputBytes > 0) {
                        ByteBuffer byteBuffer2 = byteBufferArr[i + i4];
                        int min = Math.min(byteBuffer2.remaining(), availableInputBytes);
                        if (min > 0) {
                            this.protocol.readInput(byteBuffer2, min);
                            i6 += min;
                            availableInputBytes -= min;
                        }
                        i4++;
                    }
                    SSLEngineResult.HandshakeStatus handshakeStatus2 = getHandshakeStatus();
                    if (handshakeStatus2 == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING && !this.returnedFinished && this.protocolPeer.isHandshakeComplete()) {
                        this.returnedFinished = true;
                        handshakeStatus2 = SSLEngineResult.HandshakeStatus.FINISHED;
                    }
                    return new SSLEngineResult(getStatus(), handshakeStatus2, i3, i6);
                } catch (IOException e) {
                    e = e;
                    if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        this.deferredException = new SSLException(e);
                        return new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_WRAP, i3, 0);
                    }
                    throw new SSLException(e);
                }
            }
            return new SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, handshakeStatus, 0, 0);
        } catch (IOException e2) {
            e = e2;
            i3 = 0;
        }
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLEngineResult wrap(ByteBuffer[] byteBufferArr, int i, int i2, ByteBuffer byteBuffer) throws SSLException {
        int i3;
        int i4;
        SSLException sSLException = this.deferredException;
        if (sSLException != null) {
            this.deferredException = null;
            throw sSLException;
        }
        int i5 = 0;
        if (this.closedEarly) {
            return new SSLEngineResult(SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }
        if (!this.initialHandshakeBegun) {
            beginHandshake();
        }
        int availableOutputBytes = this.protocol.getAvailableOutputBytes();
        if (availableOutputBytes > 0) {
            int remaining = byteBuffer.remaining();
            if (remaining >= availableOutputBytes) {
                i4 = availableOutputBytes;
            } else {
                i4 = this.protocol.previewOutputRecord();
                if (remaining < i4) {
                    return new SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, SSLEngineResult.HandshakeStatus.NEED_WRAP, 0, 0);
                }
            }
            this.protocol.readOutput(byteBuffer, i4);
            if (i4 < availableOutputBytes) {
                return new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_WRAP, 0, i4);
            }
        } else if (this.protocol.isConnected()) {
            try {
                int totalRemaining = getTotalRemaining(byteBufferArr, i, i2, this.protocol.getApplicationDataLimit());
                if (totalRemaining > 0) {
                    RecordPreview previewOutputRecord = this.protocol.previewOutputRecord(totalRemaining);
                    int contentLimit = previewOutputRecord.getContentLimit();
                    if (byteBuffer.remaining() < previewOutputRecord.getRecordSize()) {
                        return new SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
                    }
                    byte[] bArr = new byte[contentLimit];
                    int i6 = 0;
                    for (int i7 = 0; i7 < i2 && i6 < contentLimit; i7++) {
                        ByteBuffer byteBuffer2 = byteBufferArr[i + i7];
                        int min = Math.min(byteBuffer2.remaining(), contentLimit - i6);
                        if (min > 0) {
                            byteBuffer2.get(bArr, i6, min);
                            i6 += min;
                        }
                    }
                    this.protocol.writeApplicationData(bArr, 0, i6);
                    int availableOutputBytes2 = this.protocol.getAvailableOutputBytes();
                    this.protocol.readOutput(byteBuffer, availableOutputBytes2);
                    i3 = availableOutputBytes2;
                    i5 = i6;
                } else {
                    i3 = 0;
                }
                return new SSLEngineResult(getStatus(), SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, i5, i3);
            } catch (IOException e) {
                throw new SSLException(e);
            }
        } else {
            i4 = 0;
        }
        if (this.protocol.isHandshaking()) {
            return new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, i4);
        }
        SSLEngineResult.HandshakeStatus handshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        if (!this.returnedFinished && this.protocolPeer.isHandshakeComplete()) {
            this.returnedFinished = true;
            handshakeStatus = SSLEngineResult.HandshakeStatus.FINISHED;
        }
        return new SSLEngineResult(getStatus(), handshakeStatus, 0, i4);
    }
}