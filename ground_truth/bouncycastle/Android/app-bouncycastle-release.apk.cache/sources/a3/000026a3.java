package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

/* loaded from: classes2.dex */
class ProvSSLServerSocketFactory extends SSLServerSocketFactory {
    protected final ContextData contextData;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvSSLServerSocketFactory(ContextData contextData) {
        this.contextData = contextData;
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket() throws IOException {
        return new ProvSSLServerSocket(this.contextData);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int i) throws IOException {
        return new ProvSSLServerSocket(this.contextData, i);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int i, int i2) throws IOException {
        return new ProvSSLServerSocket(this.contextData, i, i2);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int i, int i2, InetAddress inetAddress) throws IOException {
        return new ProvSSLServerSocket(this.contextData, i, i2, inetAddress);
    }

    @Override // javax.net.ssl.SSLServerSocketFactory
    public String[] getDefaultCipherSuites() {
        return this.contextData.getContext().getDefaultCipherSuites(false);
    }

    @Override // javax.net.ssl.SSLServerSocketFactory
    public String[] getSupportedCipherSuites() {
        return this.contextData.getContext().getSupportedCipherSuites();
    }
}