package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

/* loaded from: classes2.dex */
public class SSLServerSocketFactoryImpl extends ProvSSLServerSocketFactory {
    public SSLServerSocketFactoryImpl() throws Exception {
        super(DefaultSSLContextSpi.getDefaultInstance().getContextData());
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLServerSocketFactory, javax.net.ServerSocketFactory
    public /* bridge */ /* synthetic */ ServerSocket createServerSocket() throws IOException {
        return super.createServerSocket();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLServerSocketFactory, javax.net.ServerSocketFactory
    public /* bridge */ /* synthetic */ ServerSocket createServerSocket(int i) throws IOException {
        return super.createServerSocket(i);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLServerSocketFactory, javax.net.ServerSocketFactory
    public /* bridge */ /* synthetic */ ServerSocket createServerSocket(int i, int i2) throws IOException {
        return super.createServerSocket(i, i2);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLServerSocketFactory, javax.net.ServerSocketFactory
    public /* bridge */ /* synthetic */ ServerSocket createServerSocket(int i, int i2, InetAddress inetAddress) throws IOException {
        return super.createServerSocket(i, i2, inetAddress);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLServerSocketFactory, javax.net.ssl.SSLServerSocketFactory
    public /* bridge */ /* synthetic */ String[] getDefaultCipherSuites() {
        return super.getDefaultCipherSuites();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLServerSocketFactory, javax.net.ssl.SSLServerSocketFactory
    public /* bridge */ /* synthetic */ String[] getSupportedCipherSuites() {
        return super.getSupportedCipherSuites();
    }
}