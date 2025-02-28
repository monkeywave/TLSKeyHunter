package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import org.openjsse.sun.security.ssl.SSLContextImpl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLServerSocketFactoryImpl.class */
public final class SSLServerSocketFactoryImpl extends SSLServerSocketFactory {
    private static final int DEFAULT_BACKLOG = 50;
    private final SSLContextImpl context;

    public SSLServerSocketFactoryImpl() throws Exception {
        this.context = SSLContextImpl.DefaultSSLContext.getDefaultImpl();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLServerSocketFactoryImpl(SSLContextImpl context) {
        this.context = context;
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket() throws IOException {
        return new SSLServerSocketImpl(this.context);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int port) throws IOException {
        return new SSLServerSocketImpl(this.context, port, 50);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return new SSLServerSocketImpl(this.context, port, backlog);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        return new SSLServerSocketImpl(this.context, port, backlog, ifAddress);
    }

    @Override // javax.net.ssl.SSLServerSocketFactory
    public String[] getDefaultCipherSuites() {
        return CipherSuite.namesOf(this.context.getDefaultCipherSuites(true));
    }

    @Override // javax.net.ssl.SSLServerSocketFactory
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(this.context.getSupportedCipherSuites());
    }
}