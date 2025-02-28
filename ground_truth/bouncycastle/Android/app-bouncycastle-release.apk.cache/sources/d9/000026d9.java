package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

/* loaded from: classes2.dex */
public class SSLSocketFactoryImpl extends ProvSSLSocketFactory {
    public SSLSocketFactoryImpl() throws Exception {
        super(DefaultSSLContextSpi.getDefaultInstance().getContextData());
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory, javax.net.SocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket() throws IOException {
        return super.createSocket();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory, javax.net.SocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(String str, int i) throws IOException, UnknownHostException {
        return super.createSocket(str, i);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory, javax.net.SocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(String str, int i, InetAddress inetAddress, int i2) throws IOException, UnknownHostException {
        return super.createSocket(str, i, inetAddress, i2);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory, javax.net.SocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return super.createSocket(inetAddress, i);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory, javax.net.SocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress2, int i2) throws IOException {
        return super.createSocket(inetAddress, i, inetAddress2, i2);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(Socket socket, InputStream inputStream, boolean z) throws IOException {
        return super.createSocket(socket, inputStream, z);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory, javax.net.ssl.SSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(Socket socket, String str, int i, boolean z) throws IOException {
        return super.createSocket(socket, str, i, z);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory, javax.net.ssl.SSLSocketFactory
    public /* bridge */ /* synthetic */ String[] getDefaultCipherSuites() {
        return super.getDefaultCipherSuites();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSocketFactory, javax.net.ssl.SSLSocketFactory
    public /* bridge */ /* synthetic */ String[] getSupportedCipherSuites() {
        return super.getSupportedCipherSuites();
    }
}