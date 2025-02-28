package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import org.openjsse.javax.net.ssl.SSLSocket;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/BaseSSLSocketImpl.class */
public abstract class BaseSSLSocketImpl extends SSLSocket {
    private final Socket self;
    private final InputStream consumedInput;
    private static final String PROP_NAME = "com.sun.net.ssl.requireCloseNotify";
    static final boolean requireCloseNotify = Utilities.getBooleanProperty(PROP_NAME, false);

    /* JADX INFO: Access modifiers changed from: package-private */
    public BaseSSLSocketImpl() {
        this.self = this;
        this.consumedInput = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BaseSSLSocketImpl(Socket socket) {
        this.self = socket;
        this.consumedInput = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BaseSSLSocketImpl(Socket socket, InputStream consumed) {
        this.self = socket;
        this.consumedInput = consumed;
    }

    @Override // java.net.Socket
    public final SocketChannel getChannel() {
        if (this.self == this) {
            return super.getChannel();
        }
        return this.self.getChannel();
    }

    @Override // java.net.Socket
    public void bind(SocketAddress bindpoint) throws IOException {
        if (this.self == this) {
            super.bind(bindpoint);
            return;
        }
        throw new IOException("Underlying socket should already be connected");
    }

    @Override // java.net.Socket
    public SocketAddress getLocalSocketAddress() {
        if (this.self == this) {
            return super.getLocalSocketAddress();
        }
        return this.self.getLocalSocketAddress();
    }

    @Override // java.net.Socket
    public SocketAddress getRemoteSocketAddress() {
        if (this.self == this) {
            return super.getRemoteSocketAddress();
        }
        return this.self.getRemoteSocketAddress();
    }

    @Override // java.net.Socket
    public final void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, 0);
    }

    @Override // java.net.Socket
    public final boolean isConnected() {
        if (this.self == this) {
            return super.isConnected();
        }
        return this.self.isConnected();
    }

    @Override // java.net.Socket
    public final boolean isBound() {
        if (this.self == this) {
            return super.isBound();
        }
        return this.self.isBound();
    }

    @Override // java.net.Socket
    public void shutdownInput() throws IOException {
        if (this.self == this) {
            super.shutdownInput();
        } else {
            this.self.shutdownInput();
        }
    }

    @Override // java.net.Socket
    public void shutdownOutput() throws IOException {
        if (this.self == this) {
            super.shutdownOutput();
        } else {
            this.self.shutdownOutput();
        }
    }

    @Override // java.net.Socket
    public boolean isInputShutdown() {
        if (this.self == this) {
            return super.isInputShutdown();
        }
        return this.self.isInputShutdown();
    }

    @Override // java.net.Socket
    public boolean isOutputShutdown() {
        if (this.self == this) {
            return super.isOutputShutdown();
        }
        return this.self.isOutputShutdown();
    }

    protected final void finalize() throws Throwable {
        try {
            try {
                close();
            } catch (IOException e) {
                try {
                    if (this.self == this) {
                        super.close();
                    }
                } catch (IOException e2) {
                }
            }
        } finally {
            super.finalize();
        }
    }

    @Override // java.net.Socket
    public final InetAddress getInetAddress() {
        if (this.self == this) {
            return super.getInetAddress();
        }
        return this.self.getInetAddress();
    }

    @Override // java.net.Socket
    public final InetAddress getLocalAddress() {
        if (this.self == this) {
            return super.getLocalAddress();
        }
        return this.self.getLocalAddress();
    }

    @Override // java.net.Socket
    public final int getPort() {
        if (this.self == this) {
            return super.getPort();
        }
        return this.self.getPort();
    }

    @Override // java.net.Socket
    public final int getLocalPort() {
        if (this.self == this) {
            return super.getLocalPort();
        }
        return this.self.getLocalPort();
    }

    @Override // java.net.Socket
    public final void setTcpNoDelay(boolean value) throws SocketException {
        if (this.self == this) {
            super.setTcpNoDelay(value);
        } else {
            this.self.setTcpNoDelay(value);
        }
    }

    @Override // java.net.Socket
    public final boolean getTcpNoDelay() throws SocketException {
        if (this.self == this) {
            return super.getTcpNoDelay();
        }
        return this.self.getTcpNoDelay();
    }

    @Override // java.net.Socket
    public final void setSoLinger(boolean flag, int linger) throws SocketException {
        if (this.self == this) {
            super.setSoLinger(flag, linger);
        } else {
            this.self.setSoLinger(flag, linger);
        }
    }

    @Override // java.net.Socket
    public final int getSoLinger() throws SocketException {
        if (this.self == this) {
            return super.getSoLinger();
        }
        return this.self.getSoLinger();
    }

    @Override // java.net.Socket
    public final void sendUrgentData(int data) throws SocketException {
        throw new SocketException("This method is not supported by SSLSockets");
    }

    @Override // java.net.Socket
    public final void setOOBInline(boolean on) throws SocketException {
        throw new SocketException("This method is ineffective, since sending urgent data is not supported by SSLSockets");
    }

    @Override // java.net.Socket
    public final boolean getOOBInline() throws SocketException {
        throw new SocketException("This method is ineffective, since sending urgent data is not supported by SSLSockets");
    }

    @Override // java.net.Socket
    public final int getSoTimeout() throws SocketException {
        if (this.self == this) {
            return super.getSoTimeout();
        }
        return this.self.getSoTimeout();
    }

    @Override // java.net.Socket
    public final void setSendBufferSize(int size) throws SocketException {
        if (this.self == this) {
            super.setSendBufferSize(size);
        } else {
            this.self.setSendBufferSize(size);
        }
    }

    @Override // java.net.Socket
    public final int getSendBufferSize() throws SocketException {
        if (this.self == this) {
            return super.getSendBufferSize();
        }
        return this.self.getSendBufferSize();
    }

    @Override // java.net.Socket
    public final void setReceiveBufferSize(int size) throws SocketException {
        if (this.self == this) {
            super.setReceiveBufferSize(size);
        } else {
            this.self.setReceiveBufferSize(size);
        }
    }

    @Override // java.net.Socket
    public final int getReceiveBufferSize() throws SocketException {
        if (this.self == this) {
            return super.getReceiveBufferSize();
        }
        return this.self.getReceiveBufferSize();
    }

    @Override // java.net.Socket
    public final void setKeepAlive(boolean on) throws SocketException {
        if (this.self == this) {
            super.setKeepAlive(on);
        } else {
            this.self.setKeepAlive(on);
        }
    }

    @Override // java.net.Socket
    public final boolean getKeepAlive() throws SocketException {
        if (this.self == this) {
            return super.getKeepAlive();
        }
        return this.self.getKeepAlive();
    }

    @Override // java.net.Socket
    public final void setTrafficClass(int tc) throws SocketException {
        if (this.self == this) {
            super.setTrafficClass(tc);
        } else {
            this.self.setTrafficClass(tc);
        }
    }

    @Override // java.net.Socket
    public final int getTrafficClass() throws SocketException {
        if (this.self == this) {
            return super.getTrafficClass();
        }
        return this.self.getTrafficClass();
    }

    @Override // java.net.Socket
    public final void setReuseAddress(boolean on) throws SocketException {
        if (this.self == this) {
            super.setReuseAddress(on);
        } else {
            this.self.setReuseAddress(on);
        }
    }

    @Override // java.net.Socket
    public final boolean getReuseAddress() throws SocketException {
        if (this.self == this) {
            return super.getReuseAddress();
        }
        return this.self.getReuseAddress();
    }

    @Override // java.net.Socket
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        if (this.self == this) {
            super.setPerformancePreferences(connectionTime, latency, bandwidth);
        } else {
            this.self.setPerformancePreferences(connectionTime, latency, bandwidth);
        }
    }

    @Override // javax.net.ssl.SSLSocket, java.net.Socket
    public String toString() {
        if (this.self == this) {
            return super.toString();
        }
        return this.self.toString();
    }

    @Override // java.net.Socket
    public InputStream getInputStream() throws IOException {
        if (this.self == this) {
            return super.getInputStream();
        }
        if (this.consumedInput != null) {
            return new SequenceInputStream(this.consumedInput, this.self.getInputStream());
        }
        return this.self.getInputStream();
    }

    @Override // java.net.Socket
    public OutputStream getOutputStream() throws IOException {
        if (this.self == this) {
            return super.getOutputStream();
        }
        return this.self.getOutputStream();
    }

    @Override // java.net.Socket, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        if (this.self == this) {
            super.close();
        } else {
            this.self.close();
        }
    }

    @Override // java.net.Socket
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        if (this.self == this) {
            super.setSoTimeout(timeout);
        } else {
            this.self.setSoTimeout(timeout);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isLayered() {
        return this.self != this;
    }
}