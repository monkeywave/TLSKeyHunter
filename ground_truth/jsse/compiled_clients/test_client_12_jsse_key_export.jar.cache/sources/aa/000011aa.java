package org.openjsse.sun.security.ssl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiFunction;
import javassist.bytecode.AccessFlag;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSocketImpl.class */
public final class SSLSocketImpl extends BaseSSLSocketImpl implements SSLTransport {
    final SSLContextImpl sslContext;
    final TransportContext conContext;
    private final AppInputStream appInput;
    private final AppOutputStream appOutput;
    private String peerHost;
    private boolean autoClose;
    private boolean isConnected;
    private volatile boolean tlsIsClosed;
    private final ReentrantLock socketLock;
    private final ReentrantLock handshakeLock;
    private static final boolean trustNameService = Utilities.getBooleanProperty("jdk.tls.trustNameService", false);

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public /* bridge */ /* synthetic */ void setSoTimeout(int i) throws SocketException {
        super.setSoTimeout(i);
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, javax.net.ssl.SSLSocket, java.net.Socket
    public /* bridge */ /* synthetic */ String toString() {
        return super.toString();
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public /* bridge */ /* synthetic */ void setPerformancePreferences(int i, int i2, int i3) {
        super.setPerformancePreferences(i, i2, i3);
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public /* bridge */ /* synthetic */ SocketAddress getRemoteSocketAddress() {
        return super.getRemoteSocketAddress();
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public /* bridge */ /* synthetic */ SocketAddress getLocalSocketAddress() {
        return super.getLocalSocketAddress();
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public /* bridge */ /* synthetic */ void bind(SocketAddress socketAddress) throws IOException {
        super.bind(socketAddress);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketImpl(SSLContextImpl sslContext) {
        this.appInput = new AppInputStream();
        this.appOutput = new AppOutputStream();
        this.isConnected = false;
        this.tlsIsClosed = false;
        this.socketLock = new ReentrantLock();
        this.handshakeLock = new ReentrantLock();
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        this.conContext = new TransportContext(sslContext, (SSLTransport) this, (InputRecord) new SSLSocketInputRecord(handshakeHash), (OutputRecord) new SSLSocketOutputRecord(handshakeHash), true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketImpl(SSLContextImpl sslContext, SSLConfiguration sslConfig) {
        this.appInput = new AppInputStream();
        this.appOutput = new AppOutputStream();
        this.isConnected = false;
        this.tlsIsClosed = false;
        this.socketLock = new ReentrantLock();
        this.handshakeLock = new ReentrantLock();
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        this.conContext = new TransportContext(sslContext, this, sslConfig, new SSLSocketInputRecord(handshakeHash), new SSLSocketOutputRecord(handshakeHash));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketImpl(SSLContextImpl sslContext, String peerHost, int peerPort) throws IOException, UnknownHostException {
        this.appInput = new AppInputStream();
        this.appOutput = new AppOutputStream();
        this.isConnected = false;
        this.tlsIsClosed = false;
        this.socketLock = new ReentrantLock();
        this.handshakeLock = new ReentrantLock();
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        this.conContext = new TransportContext(sslContext, (SSLTransport) this, (InputRecord) new SSLSocketInputRecord(handshakeHash), (OutputRecord) new SSLSocketOutputRecord(handshakeHash), true);
        this.peerHost = peerHost;
        SocketAddress socketAddress = peerHost != null ? new InetSocketAddress(peerHost, peerPort) : new InetSocketAddress(InetAddress.getByName(null), peerPort);
        connect(socketAddress, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketImpl(SSLContextImpl sslContext, InetAddress address, int peerPort) throws IOException {
        this.appInput = new AppInputStream();
        this.appOutput = new AppOutputStream();
        this.isConnected = false;
        this.tlsIsClosed = false;
        this.socketLock = new ReentrantLock();
        this.handshakeLock = new ReentrantLock();
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        this.conContext = new TransportContext(sslContext, (SSLTransport) this, (InputRecord) new SSLSocketInputRecord(handshakeHash), (OutputRecord) new SSLSocketOutputRecord(handshakeHash), true);
        SocketAddress socketAddress = new InetSocketAddress(address, peerPort);
        connect(socketAddress, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketImpl(SSLContextImpl sslContext, String peerHost, int peerPort, InetAddress localAddr, int localPort) throws IOException, UnknownHostException {
        this.appInput = new AppInputStream();
        this.appOutput = new AppOutputStream();
        this.isConnected = false;
        this.tlsIsClosed = false;
        this.socketLock = new ReentrantLock();
        this.handshakeLock = new ReentrantLock();
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        this.conContext = new TransportContext(sslContext, (SSLTransport) this, (InputRecord) new SSLSocketInputRecord(handshakeHash), (OutputRecord) new SSLSocketOutputRecord(handshakeHash), true);
        this.peerHost = peerHost;
        bind(new InetSocketAddress(localAddr, localPort));
        SocketAddress socketAddress = peerHost != null ? new InetSocketAddress(peerHost, peerPort) : new InetSocketAddress(InetAddress.getByName(null), peerPort);
        connect(socketAddress, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketImpl(SSLContextImpl sslContext, InetAddress peerAddr, int peerPort, InetAddress localAddr, int localPort) throws IOException {
        this.appInput = new AppInputStream();
        this.appOutput = new AppOutputStream();
        this.isConnected = false;
        this.tlsIsClosed = false;
        this.socketLock = new ReentrantLock();
        this.handshakeLock = new ReentrantLock();
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        this.conContext = new TransportContext(sslContext, (SSLTransport) this, (InputRecord) new SSLSocketInputRecord(handshakeHash), (OutputRecord) new SSLSocketOutputRecord(handshakeHash), true);
        bind(new InetSocketAddress(localAddr, localPort));
        SocketAddress socketAddress = new InetSocketAddress(peerAddr, peerPort);
        connect(socketAddress, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketImpl(SSLContextImpl sslContext, Socket sock, InputStream consumed, boolean autoClose) throws IOException {
        super(sock, consumed);
        this.appInput = new AppInputStream();
        this.appOutput = new AppOutputStream();
        this.isConnected = false;
        this.tlsIsClosed = false;
        this.socketLock = new ReentrantLock();
        this.handshakeLock = new ReentrantLock();
        if (!sock.isConnected()) {
            throw new SocketException("Underlying socket is not connected");
        }
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        this.conContext = new TransportContext(sslContext, (SSLTransport) this, (InputRecord) new SSLSocketInputRecord(handshakeHash), (OutputRecord) new SSLSocketOutputRecord(handshakeHash), false);
        this.autoClose = autoClose;
        doneConnect();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketImpl(SSLContextImpl sslContext, Socket sock, String peerHost, int port, boolean autoClose) throws IOException {
        super(sock);
        this.appInput = new AppInputStream();
        this.appOutput = new AppOutputStream();
        this.isConnected = false;
        this.tlsIsClosed = false;
        this.socketLock = new ReentrantLock();
        this.handshakeLock = new ReentrantLock();
        if (!sock.isConnected()) {
            throw new SocketException("Underlying socket is not connected");
        }
        this.sslContext = sslContext;
        HandshakeHash handshakeHash = new HandshakeHash();
        this.conContext = new TransportContext(sslContext, (SSLTransport) this, (InputRecord) new SSLSocketInputRecord(handshakeHash), (OutputRecord) new SSLSocketOutputRecord(handshakeHash), true);
        this.peerHost = peerHost;
        this.autoClose = autoClose;
        doneConnect();
    }

    @Override // java.net.Socket
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (isLayered()) {
            throw new SocketException("Already connected");
        }
        if (!(endpoint instanceof InetSocketAddress)) {
            throw new SocketException("Cannot handle non-Inet socket addresses.");
        }
        super.connect(endpoint, timeout);
        doneConnect();
    }

    @Override // javax.net.ssl.SSLSocket
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(this.sslContext.getSupportedCipherSuites());
    }

    @Override // javax.net.ssl.SSLSocket
    public String[] getEnabledCipherSuites() {
        this.socketLock.lock();
        try {
            return CipherSuite.namesOf(this.conContext.sslConfig.enabledCipherSuites);
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void setEnabledCipherSuites(String[] suites) {
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.enabledCipherSuites = CipherSuite.validValuesOf(suites);
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public String[] getSupportedProtocols() {
        return ProtocolVersion.toStringArray(this.sslContext.getSupportedProtocolVersions());
    }

    @Override // javax.net.ssl.SSLSocket
    public String[] getEnabledProtocols() {
        this.socketLock.lock();
        try {
            return ProtocolVersion.toStringArray(this.conContext.sslConfig.enabledProtocols);
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void setEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("Protocols cannot be null");
        }
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.enabledProtocols = ProtocolVersion.namesOf(protocols);
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public SSLSession getSession() {
        try {
            ensureNegotiated(false);
            return this.conContext.conSession;
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("handshake")) {
                SSLLogger.severe("handshake failed", ioe);
            }
            return new SSLSessionImpl();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public SSLSession getHandshakeSession() {
        this.socketLock.lock();
        try {
            return this.conContext.handshakeContext == null ? null : this.conContext.handshakeContext.handshakeSession;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener is null");
        }
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.addHandshakeCompletedListener(listener);
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener is null");
        }
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.removeHandshakeCompletedListener(listener);
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void startHandshake() throws IOException {
        startHandshake(true);
    }

    private void startHandshake(boolean resumable) throws IOException {
        if (!this.isConnected) {
            throw new SocketException("Socket is not connected");
        }
        if (this.conContext.isBroken || this.conContext.isInboundClosed() || this.conContext.isOutboundClosed()) {
            throw new SocketException("Socket has been closed or broken");
        }
        this.handshakeLock.lock();
        try {
            if (this.conContext.isBroken || this.conContext.isInboundClosed() || this.conContext.isOutboundClosed()) {
                throw new SocketException("Socket has been closed or broken");
            }
            try {
                try {
                    try {
                        this.conContext.kickstart();
                        if (!this.conContext.isNegotiated) {
                            readHandshakeRecord();
                        }
                    } catch (InterruptedIOException iioe) {
                        if (resumable) {
                            handleException(iioe);
                        } else {
                            throw this.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Couldn't kickstart handshaking", iioe);
                        }
                    } catch (IOException ioe) {
                        throw this.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Couldn't kickstart handshaking", ioe);
                    }
                } catch (SocketException se) {
                    handleException(se);
                }
            } catch (Exception oe) {
                handleException(oe);
            }
        } finally {
            this.handshakeLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void setUseClientMode(boolean mode) {
        this.socketLock.lock();
        try {
            this.conContext.setUseClientMode(mode);
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public boolean getUseClientMode() {
        this.socketLock.lock();
        try {
            return this.conContext.sslConfig.isClientMode;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void setNeedClientAuth(boolean need) {
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.clientAuthType = need ? ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public boolean getNeedClientAuth() {
        this.socketLock.lock();
        try {
            return this.conContext.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void setWantClientAuth(boolean want) {
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.clientAuthType = want ? ClientAuthType.CLIENT_AUTH_REQUESTED : ClientAuthType.CLIENT_AUTH_NONE;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public boolean getWantClientAuth() {
        this.socketLock.lock();
        try {
            return this.conContext.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void setEnableSessionCreation(boolean flag) {
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.enableSessionCreation = flag;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public boolean getEnableSessionCreation() {
        this.socketLock.lock();
        try {
            return this.conContext.sslConfig.enableSessionCreation;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // java.net.Socket
    public boolean isClosed() {
        return this.tlsIsClosed;
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        if (isClosed()) {
            return;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.fine("duplex close of SSLSocket", new Object[0]);
        }
        try {
            try {
                if (isConnected()) {
                    if (!isOutputShutdown()) {
                        duplexCloseOutput();
                    }
                    if (!isInputShutdown()) {
                        duplexCloseInput();
                    }
                }
                try {
                    if (isClosed()) {
                        return;
                    }
                    closeSocket(false);
                } catch (IOException ioe) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.warning("SSLSocket close failed", ioe);
                    }
                } finally {
                }
            } catch (IOException ioe2) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("SSLSocket duplex close failed", ioe2);
                }
                try {
                    if (isClosed()) {
                        return;
                    }
                    closeSocket(false);
                } catch (IOException ioe3) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.warning("SSLSocket close failed", ioe3);
                    }
                } finally {
                }
            }
        } catch (Throwable th) {
            if (!isClosed()) {
                try {
                    try {
                        closeSocket(false);
                    } catch (IOException ioe4) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                            SSLLogger.warning("SSLSocket close failed", ioe4);
                        }
                        this.tlsIsClosed = true;
                        throw th;
                    }
                } catch (Throwable th2) {
                    throw th2;
                }
            }
            throw th;
        }
    }

    private void duplexCloseOutput() throws IOException {
        boolean useUserCanceled = false;
        boolean hasCloseReceipt = false;
        if (this.conContext.isNegotiated) {
            if (!this.conContext.protocolVersion.useTLS13PlusSpec()) {
                hasCloseReceipt = true;
            } else {
                useUserCanceled = true;
            }
        } else if (this.conContext.handshakeContext != null) {
            useUserCanceled = true;
            ProtocolVersion pv = this.conContext.handshakeContext.negotiatedProtocol;
            if (pv == null || !pv.useTLS13PlusSpec()) {
                hasCloseReceipt = true;
            }
        }
        closeNotify(useUserCanceled);
        if (!isInputShutdown()) {
            bruteForceCloseInput(hasCloseReceipt);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void closeNotify(boolean useUserCanceled) throws IOException {
        boolean z;
        boolean isLayered;
        try {
            synchronized (this.conContext.outputRecord) {
                if (useUserCanceled) {
                    this.conContext.warning(Alert.USER_CANCELED);
                }
                this.conContext.warning(Alert.CLOSE_NOTIFY);
            }
            if (!z) {
                if (isLayered) {
                    return;
                }
            }
        } finally {
            if (!this.conContext.isOutboundClosed()) {
                this.conContext.outputRecord.close();
            }
            if ((this.autoClose || !isLayered()) && !super.isOutputShutdown()) {
                super.shutdownOutput();
            }
        }
    }

    private void duplexCloseInput() throws IOException {
        boolean hasCloseReceipt = false;
        if (this.conContext.isNegotiated && !this.conContext.protocolVersion.useTLS13PlusSpec()) {
            hasCloseReceipt = true;
        }
        bruteForceCloseInput(hasCloseReceipt);
    }

    private void bruteForceCloseInput(boolean hasCloseReceipt) throws IOException {
        boolean isInputShutdown;
        if (hasCloseReceipt) {
            try {
                shutdown();
                if (!isInputShutdown) {
                    return;
                }
                return;
            } finally {
                if (!isInputShutdown()) {
                    shutdownInput(false);
                }
            }
        }
        if (!this.conContext.isInboundClosed()) {
            try {
                this.appInput.deplete();
            } finally {
                this.conContext.inputRecord.close();
            }
        }
        if ((this.autoClose || !isLayered()) && !super.isInputShutdown()) {
            super.shutdownInput();
        }
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public void shutdownInput() throws IOException {
        shutdownInput(true);
    }

    private void shutdownInput(boolean checkCloseNotify) throws IOException {
        boolean z;
        boolean isLayered;
        if (isInputShutdown()) {
            return;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.fine("close inbound of SSLSocket", new Object[0]);
        }
        if (checkCloseNotify) {
            try {
                if (!this.conContext.isInputCloseNotified && (this.conContext.isNegotiated || this.conContext.handshakeContext != null)) {
                    throw new SSLException("closing inbound before receiving peer's close_notify");
                }
            } finally {
                this.conContext.closeInbound();
                if ((this.autoClose || !isLayered()) && !super.isInputShutdown()) {
                    super.shutdownInput();
                }
            }
        }
        if (!z) {
            if (isLayered) {
                return;
            }
        }
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public boolean isInputShutdown() {
        return this.conContext.isInboundClosed() && ((!this.autoClose && isLayered()) || super.isInputShutdown());
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public void shutdownOutput() throws IOException {
        if (isOutputShutdown()) {
            return;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.fine("close outbound of SSLSocket", new Object[0]);
        }
        this.conContext.closeOutbound();
        if ((this.autoClose || !isLayered()) && !super.isOutputShutdown()) {
            super.shutdownOutput();
        }
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public boolean isOutputShutdown() {
        return this.conContext.isOutboundClosed() && ((!this.autoClose && isLayered()) || super.isOutputShutdown());
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public InputStream getInputStream() throws IOException {
        this.socketLock.lock();
        try {
            if (isClosed()) {
                throw new SocketException("Socket is closed");
            }
            if (!this.isConnected) {
                throw new SocketException("Socket is not connected");
            }
            if (this.conContext.isInboundClosed() || isInputShutdown()) {
                throw new SocketException("Socket input is already shutdown");
            }
            return this.appInput;
        } finally {
            this.socketLock.unlock();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void ensureNegotiated(boolean resumable) throws IOException {
        if (this.conContext.isNegotiated || this.conContext.isBroken || this.conContext.isInboundClosed() || this.conContext.isOutboundClosed()) {
            return;
        }
        this.handshakeLock.lock();
        try {
            if (this.conContext.isNegotiated || this.conContext.isBroken || this.conContext.isInboundClosed() || this.conContext.isOutboundClosed()) {
                return;
            }
            startHandshake(resumable);
        } finally {
            this.handshakeLock.unlock();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSocketImpl$AppInputStream.class */
    public class AppInputStream extends InputStream {
        private volatile boolean isClosing;
        private volatile boolean hasDepleted;
        private final byte[] oneByte = new byte[1];
        private final ReentrantLock readLock = new ReentrantLock();
        private volatile boolean appDataIsAvailable = false;
        private ByteBuffer buffer = ByteBuffer.allocate(AccessFlag.SYNTHETIC);

        AppInputStream() {
        }

        @Override // java.io.InputStream
        public int available() throws IOException {
            if (!this.appDataIsAvailable || checkEOF()) {
                return 0;
            }
            return this.buffer.remaining();
        }

        @Override // java.io.InputStream
        public int read() throws IOException {
            int n = read(this.oneByte, 0, 1);
            if (n <= 0) {
                return -1;
            }
            return this.oneByte[0] & 255;
        }

        @Override // java.io.InputStream
        public int read(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException("the target buffer is null");
            }
            if (off < 0 || len < 0 || len > b.length - off) {
                throw new IndexOutOfBoundsException("buffer length: " + b.length + ", offset; " + off + ", bytes to read:" + len);
            }
            if (len == 0) {
                return 0;
            }
            if (checkEOF()) {
                return -1;
            }
            if (!SSLSocketImpl.this.conContext.isNegotiated && !SSLSocketImpl.this.conContext.isBroken && !SSLSocketImpl.this.conContext.isInboundClosed() && !SSLSocketImpl.this.conContext.isOutboundClosed()) {
                SSLSocketImpl.this.ensureNegotiated(true);
            }
            if (!SSLSocketImpl.this.conContext.isNegotiated || SSLSocketImpl.this.conContext.isBroken || SSLSocketImpl.this.conContext.isInboundClosed()) {
                throw new SocketException("Connection or inbound has closed");
            }
            if (this.hasDepleted) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("The input stream has been depleted", new Object[0]);
                    return -1;
                }
                return -1;
            }
            this.readLock.lock();
            try {
                if (SSLSocketImpl.this.conContext.isBroken || SSLSocketImpl.this.conContext.isInboundClosed()) {
                    throw new SocketException("Connection or inbound has closed");
                }
                if (this.hasDepleted) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.fine("The input stream is closing", new Object[0]);
                    }
                    try {
                        if (this.isClosing) {
                            readLockedDeplete();
                        }
                        return -1;
                    } finally {
                        this.readLock.unlock();
                    }
                }
                int remains = available();
                if (remains > 0) {
                    int howmany = Math.min(remains, len);
                    this.buffer.get(b, off, howmany);
                    try {
                        if (this.isClosing) {
                            readLockedDeplete();
                        }
                        this.readLock.unlock();
                        return howmany;
                    } finally {
                        this.readLock.unlock();
                    }
                }
                this.appDataIsAvailable = false;
                try {
                    ByteBuffer bb = SSLSocketImpl.this.readApplicationRecord(this.buffer);
                    if (bb == null) {
                        try {
                            if (this.isClosing) {
                                readLockedDeplete();
                            }
                            this.readLock.unlock();
                            return -1;
                        } finally {
                            this.readLock.unlock();
                        }
                    }
                    this.buffer = bb;
                    bb.flip();
                    int volume = Math.min(len, bb.remaining());
                    this.buffer.get(b, off, volume);
                    this.appDataIsAvailable = true;
                    try {
                        if (this.isClosing) {
                            readLockedDeplete();
                        }
                        this.readLock.unlock();
                        return volume;
                    } finally {
                        this.readLock.unlock();
                    }
                } catch (Exception e) {
                    SSLSocketImpl.this.handleException(e);
                    try {
                        if (this.isClosing) {
                            readLockedDeplete();
                        }
                        this.readLock.unlock();
                        return -1;
                    } finally {
                        this.readLock.unlock();
                    }
                }
            } catch (Throwable th) {
                try {
                    if (this.isClosing) {
                        readLockedDeplete();
                    }
                    this.readLock.unlock();
                    throw th;
                } finally {
                    this.readLock.unlock();
                }
            }
        }

        @Override // java.io.InputStream
        public long skip(long n) throws IOException {
            byte[] skipArray = new byte[256];
            long skipped = 0;
            this.readLock.lock();
            while (n > 0) {
                try {
                    int len = (int) Math.min(n, skipArray.length);
                    int r = read(skipArray, 0, len);
                    if (r <= 0) {
                        break;
                    }
                    n -= r;
                    skipped += r;
                } finally {
                    this.readLock.unlock();
                }
            }
            return skipped;
        }

        @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.finest("Closing input stream", new Object[0]);
            }
            try {
                SSLSocketImpl.this.close();
            } catch (IOException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("input stream close failed", ioe);
                }
            }
        }

        private boolean checkEOF() throws IOException {
            if (SSLSocketImpl.this.conContext.isBroken) {
                if (SSLSocketImpl.this.conContext.closeReason == null) {
                    return true;
                }
                throw new SSLException("Connection has closed: " + SSLSocketImpl.this.conContext.closeReason, SSLSocketImpl.this.conContext.closeReason);
            } else if (SSLSocketImpl.this.conContext.isInboundClosed()) {
                return true;
            } else {
                if (SSLSocketImpl.this.conContext.isInputCloseNotified) {
                    if (SSLSocketImpl.this.conContext.closeReason == null) {
                        return true;
                    }
                    throw new SSLException("Connection has closed: " + SSLSocketImpl.this.conContext.closeReason, SSLSocketImpl.this.conContext.closeReason);
                }
                return false;
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void deplete() {
            if (SSLSocketImpl.this.conContext.isInboundClosed() || this.isClosing) {
                return;
            }
            this.isClosing = true;
            if (this.readLock.tryLock()) {
                try {
                    readLockedDeplete();
                } finally {
                    this.readLock.unlock();
                }
            }
        }

        private void readLockedDeplete() {
            if (this.hasDepleted || SSLSocketImpl.this.conContext.isInboundClosed() || !(SSLSocketImpl.this.conContext.inputRecord instanceof SSLSocketInputRecord)) {
                return;
            }
            SSLSocketInputRecord socketInputRecord = (SSLSocketInputRecord) SSLSocketImpl.this.conContext.inputRecord;
            try {
                socketInputRecord.deplete(SSLSocketImpl.this.conContext.isNegotiated && SSLSocketImpl.this.getSoTimeout() > 0);
            } catch (Exception ex) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("input stream close depletion failed", ex);
                }
            } finally {
                this.hasDepleted = true;
            }
        }
    }

    @Override // org.openjsse.sun.security.ssl.BaseSSLSocketImpl, java.net.Socket
    public OutputStream getOutputStream() throws IOException {
        this.socketLock.lock();
        try {
            if (isClosed()) {
                throw new SocketException("Socket is closed");
            }
            if (!this.isConnected) {
                throw new SocketException("Socket is not connected");
            }
            if (this.conContext.isOutboundDone() || isOutputShutdown()) {
                throw new SocketException("Socket output is already shutdown");
            }
            return this.appOutput;
        } finally {
            this.socketLock.unlock();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSocketImpl$AppOutputStream.class */
    private class AppOutputStream extends OutputStream {
        private final byte[] oneByte;

        private AppOutputStream() {
            this.oneByte = new byte[1];
        }

        @Override // java.io.OutputStream
        public void write(int i) throws IOException {
            this.oneByte[0] = (byte) i;
            write(this.oneByte, 0, 1);
        }

        @Override // java.io.OutputStream
        public void write(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException("the source buffer is null");
            }
            if (off < 0 || len < 0 || len > b.length - off) {
                throw new IndexOutOfBoundsException("buffer length: " + b.length + ", offset; " + off + ", bytes to read:" + len);
            }
            if (len == 0) {
                return;
            }
            if (!SSLSocketImpl.this.conContext.isNegotiated && !SSLSocketImpl.this.conContext.isBroken && !SSLSocketImpl.this.conContext.isInboundClosed() && !SSLSocketImpl.this.conContext.isOutboundClosed()) {
                SSLSocketImpl.this.ensureNegotiated(true);
            }
            if (!SSLSocketImpl.this.conContext.isNegotiated || SSLSocketImpl.this.conContext.isBroken || SSLSocketImpl.this.conContext.isOutboundClosed()) {
                throw new SocketException("Connection or outbound has closed");
            }
            try {
                SSLSocketImpl.this.conContext.outputRecord.deliver(b, off, len);
                if (SSLSocketImpl.this.conContext.outputRecord.seqNumIsHuge() || SSLSocketImpl.this.conContext.outputRecord.writeCipher.atKeyLimit()) {
                    SSLSocketImpl.this.tryKeyUpdate();
                }
            } catch (SSLHandshakeException she) {
                throw SSLSocketImpl.this.conContext.fatal(Alert.HANDSHAKE_FAILURE, she);
            } catch (SSLException ssle) {
                throw SSLSocketImpl.this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ssle);
            }
        }

        @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.finest("Closing output stream", new Object[0]);
            }
            try {
                SSLSocketImpl.this.close();
            } catch (IOException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("output stream close failed", ioe);
                }
            }
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public SSLParameters getSSLParameters() {
        this.socketLock.lock();
        try {
            return this.conContext.sslConfig.getSSLParameters();
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void setSSLParameters(SSLParameters params) {
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.setSSLParameters(params);
            if (this.conContext.sslConfig.maximumPacketSize != 0) {
                this.conContext.outputRecord.changePacketSize(this.conContext.sslConfig.maximumPacketSize);
            }
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public String getApplicationProtocol() {
        this.socketLock.lock();
        try {
            return this.conContext.applicationProtocol;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public String getHandshakeApplicationProtocol() {
        this.socketLock.lock();
        try {
            if (this.conContext.handshakeContext != null) {
                return this.conContext.handshakeContext.applicationProtocol;
            }
            return null;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public void setHandshakeApplicationProtocolSelector(BiFunction<SSLSocket, List<String>, String> selector) {
        this.socketLock.lock();
        try {
            this.conContext.sslConfig.socketAPSelector = selector;
        } finally {
            this.socketLock.unlock();
        }
    }

    @Override // javax.net.ssl.SSLSocket
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        this.socketLock.lock();
        try {
            return this.conContext.sslConfig.socketAPSelector;
        } finally {
            this.socketLock.unlock();
        }
    }

    private int readHandshakeRecord() throws IOException {
        while (!this.conContext.isInboundClosed()) {
            try {
                Plaintext plainText = decode(null);
                if (plainText.contentType == ContentType.HANDSHAKE.f965id && this.conContext.isNegotiated) {
                    return 0;
                }
            } catch (InterruptedIOException | SocketException | SSLException se) {
                throw se;
            } catch (IOException ioe) {
                throw new SSLException("readHandshakeRecord", ioe);
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public ByteBuffer readApplicationRecord(ByteBuffer buffer) throws IOException {
        while (!this.conContext.isInboundClosed()) {
            buffer.clear();
            int inLen = this.conContext.inputRecord.bytesInCompletePacket();
            if (inLen < 0) {
                handleEOF(null);
                return null;
            } else if (inLen > 33093) {
                throw new SSLProtocolException("Illegal packet size: " + inLen);
            } else {
                if (inLen > buffer.remaining()) {
                    buffer = ByteBuffer.allocate(inLen);
                }
                try {
                    this.socketLock.lock();
                    try {
                        Plaintext plainText = decode(buffer);
                        this.socketLock.unlock();
                        if (plainText.contentType == ContentType.APPLICATION_DATA.f965id && buffer.position() > 0) {
                            return buffer;
                        }
                    } finally {
                    }
                } catch (InterruptedIOException | SocketException | SSLException se) {
                    throw se;
                } catch (IOException ioe) {
                    if (!(ioe instanceof SSLException)) {
                        throw new SSLException("readApplicationRecord", ioe);
                    }
                    throw ioe;
                }
            }
        }
        return null;
    }

    private Plaintext decode(ByteBuffer destination) throws IOException {
        Plaintext plainText;
        try {
            if (destination == null) {
                plainText = SSLTransport.decode(this.conContext, null, 0, 0, null, 0, 0);
            } else {
                plainText = SSLTransport.decode(this.conContext, null, 0, 0, new ByteBuffer[]{destination}, 0, 1);
            }
        } catch (EOFException eofe) {
            plainText = handleEOF(eofe);
        }
        if (plainText != Plaintext.PLAINTEXT_NULL && (this.conContext.inputRecord.seqNumIsHuge() || this.conContext.inputRecord.readCipher.atKeyLimit())) {
            tryKeyUpdate();
        }
        return plainText;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void tryKeyUpdate() throws IOException {
        if (this.conContext.handshakeContext == null && !this.conContext.isOutboundClosed() && !this.conContext.isInboundClosed() && !this.conContext.isBroken) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.finest("trigger key update", new Object[0]);
            }
            startHandshake();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void doneConnect() throws IOException {
        this.socketLock.lock();
        try {
            if (this.peerHost == null || this.peerHost.isEmpty()) {
                boolean useNameService = trustNameService && this.conContext.sslConfig.isClientMode;
                useImplicitHost(useNameService);
            } else {
                this.conContext.sslConfig.serverNames = Utilities.addToSNIServerNameList(this.conContext.sslConfig.serverNames, this.peerHost);
            }
            InputStream sockInput = super.getInputStream();
            this.conContext.inputRecord.setReceiverStream(sockInput);
            OutputStream sockOutput = super.getOutputStream();
            this.conContext.inputRecord.setDeliverStream(sockOutput);
            this.conContext.outputRecord.setDeliverStream(sockOutput);
            this.isConnected = true;
        } finally {
            this.socketLock.unlock();
        }
    }

    private void useImplicitHost(boolean useNameService) {
        InetAddress inetAddress = getInetAddress();
        if (inetAddress == null) {
            return;
        }
        String originalHostname = HostNameAccessor.getOriginalHostName(inetAddress);
        if (originalHostname != null && originalHostname.length() != 0) {
            this.peerHost = originalHostname;
            if (this.conContext.sslConfig.serverNames.isEmpty() && !this.conContext.sslConfig.noSniExtension) {
                this.conContext.sslConfig.serverNames = Utilities.addToSNIServerNameList(this.conContext.sslConfig.serverNames, this.peerHost);
            }
        } else if (!useNameService) {
            this.peerHost = inetAddress.getHostAddress();
        } else {
            this.peerHost = getInetAddress().getHostName();
        }
    }

    public void setHost(String host) {
        this.socketLock.lock();
        try {
            this.peerHost = host;
            this.conContext.sslConfig.serverNames = Utilities.addToSNIServerNameList(this.conContext.sslConfig.serverNames, host);
        } finally {
            this.socketLock.unlock();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleException(Exception cause) throws IOException {
        Alert alert;
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.warning("handling exception", cause);
        }
        if (cause instanceof InterruptedIOException) {
            throw ((IOException) cause);
        }
        boolean isSSLException = cause instanceof SSLException;
        if (isSSLException) {
            if (cause instanceof SSLHandshakeException) {
                alert = Alert.HANDSHAKE_FAILURE;
            } else {
                alert = Alert.UNEXPECTED_MESSAGE;
            }
        } else if (cause instanceof IOException) {
            alert = Alert.UNEXPECTED_MESSAGE;
        } else {
            alert = Alert.INTERNAL_ERROR;
        }
        if (cause instanceof SocketException) {
            try {
                this.conContext.fatal(alert, cause);
            } catch (Exception e) {
            }
            throw ((SocketException) cause);
        }
        throw this.conContext.fatal(alert, cause);
    }

    private Plaintext handleEOF(EOFException eofe) throws IOException {
        SSLException ssle;
        if (requireCloseNotify || this.conContext.handshakeContext != null) {
            if (this.conContext.handshakeContext != null) {
                ssle = new SSLHandshakeException("Remote host terminated the handshake");
            } else {
                ssle = new SSLProtocolException("Remote host terminated the connection");
            }
            if (eofe != null) {
                ssle.initCause(eofe);
            }
            throw ssle;
        }
        this.conContext.isInputCloseNotified = true;
        shutdownInput();
        return Plaintext.PLAINTEXT_NULL;
    }

    @Override // org.openjsse.sun.security.ssl.SSLTransport
    public String getPeerHost() {
        return this.peerHost;
    }

    @Override // org.openjsse.sun.security.ssl.SSLTransport
    public int getPeerPort() {
        return getPort();
    }

    @Override // org.openjsse.sun.security.ssl.SSLTransport
    public boolean useDelegatedTask() {
        return false;
    }

    @Override // org.openjsse.sun.security.ssl.SSLTransport
    public void shutdown() throws IOException {
        if (!isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("close the underlying socket", new Object[0]);
            }
            try {
                if (this.conContext.isInputCloseNotified) {
                    closeSocket(false);
                } else {
                    closeSocket(true);
                }
            } finally {
                this.tlsIsClosed = true;
            }
        }
    }

    private void closeSocket(boolean selfInitiated) throws IOException {
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.fine("close the SSL connection " + (selfInitiated ? "(initiative)" : "(passive)"), new Object[0]);
        }
        if (this.autoClose || !isLayered()) {
            super.close();
        } else if (selfInitiated && !this.conContext.isInboundClosed() && !isInputShutdown()) {
            waitForClose();
        }
    }

    private void waitForClose() throws IOException {
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.fine("wait for close_notify or alert", new Object[0]);
        }
        while (!this.conContext.isInboundClosed()) {
            try {
                Plaintext plainText = decode(null);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest("discard plaintext while waiting for close", plainText);
                }
            } catch (Exception e) {
                handleException(e);
            }
        }
    }
}