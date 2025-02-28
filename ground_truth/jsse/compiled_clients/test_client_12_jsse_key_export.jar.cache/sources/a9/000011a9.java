package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocketFactory;
import org.openjsse.sun.security.ssl.SSLContextImpl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSocketFactoryImpl.class */
public final class SSLSocketFactoryImpl extends SSLSocketFactory {
    private final SSLContextImpl context;

    public SSLSocketFactoryImpl() throws Exception {
        this.context = SSLContextImpl.DefaultSSLContext.getDefaultImpl();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketFactoryImpl(SSLContextImpl context) {
        this.context = context;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket() {
        return new SSLSocketImpl(this.context);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return new SSLSocketImpl(this.context, host, port);
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return new SSLSocketImpl(this.context, s, host, port, autoClose);
    }

    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException {
        if (s == null) {
            throw new NullPointerException("the existing socket cannot be null");
        }
        return new SSLSocketImpl(this.context, s, consumed, autoClose);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return new SSLSocketImpl(this.context, address, port);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String host, int port, InetAddress clientAddress, int clientPort) throws IOException {
        return new SSLSocketImpl(this.context, host, port, clientAddress, clientPort);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort) throws IOException {
        return new SSLSocketImpl(this.context, address, port, clientAddress, clientPort);
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public String[] getDefaultCipherSuites() {
        return CipherSuite.namesOf(this.context.getDefaultCipherSuites(false));
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(this.context.getSupportedCipherSuites());
    }
}