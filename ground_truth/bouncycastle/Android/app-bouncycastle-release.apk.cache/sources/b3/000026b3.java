package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocketFactory;

/* loaded from: classes2.dex */
class ProvSSLSocketFactory extends SSLSocketFactory {
    protected final ContextData contextData;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvSSLSocketFactory(ContextData contextData) {
        this.contextData = contextData;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket() throws IOException {
        return SSLSocketUtil.create(this.contextData);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String str, int i) throws IOException, UnknownHostException {
        return SSLSocketUtil.create(this.contextData, str, i);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String str, int i, InetAddress inetAddress, int i2) throws IOException, UnknownHostException {
        return SSLSocketUtil.create(this.contextData, str, i, inetAddress, i2);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return SSLSocketUtil.create(this.contextData, inetAddress, i);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress2, int i2) throws IOException {
        return SSLSocketUtil.create(this.contextData, inetAddress, i, inetAddress2, i2);
    }

    public Socket createSocket(Socket socket, InputStream inputStream, boolean z) throws IOException {
        return SSLSocketUtil.create(this.contextData, socket, inputStream, z);
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public Socket createSocket(Socket socket, String str, int i, boolean z) throws IOException {
        return SSLSocketUtil.create(this.contextData, socket, str, i, z);
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public String[] getDefaultCipherSuites() {
        return this.contextData.getContext().getDefaultCipherSuites(true);
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public String[] getSupportedCipherSuites() {
        return this.contextData.getContext().getSupportedCipherSuites();
    }
}