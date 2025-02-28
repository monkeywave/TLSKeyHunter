package org.bouncycastle.jsse.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocketFactory;

/* loaded from: classes2.dex */
public class CustomSSLSocketFactory extends SSLSocketFactory {
    protected final SSLSocketFactory delegate;

    public CustomSSLSocketFactory(SSLSocketFactory sSLSocketFactory) {
        if (sSLSocketFactory == null) {
            throw new NullPointerException("'delegate' cannot be null");
        }
        this.delegate = sSLSocketFactory;
    }

    protected Socket configureSocket(Socket socket) {
        return socket;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket() throws IOException {
        return configureSocket(this.delegate.createSocket());
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String str, int i) throws IOException, UnknownHostException {
        return configureSocket(this.delegate.createSocket(str, i));
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String str, int i, InetAddress inetAddress, int i2) throws IOException, UnknownHostException {
        return configureSocket(this.delegate.createSocket(str, i, inetAddress, i2));
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return configureSocket(this.delegate.createSocket(inetAddress, i));
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress2, int i2) throws IOException {
        return configureSocket(this.delegate.createSocket(inetAddress, i, inetAddress2, i2));
    }

    public Socket createSocket(Socket socket, InputStream inputStream, boolean z) throws IOException {
        return configureSocket(this.delegate.createSocket(socket, inputStream, z));
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public Socket createSocket(Socket socket, String str, int i, boolean z) throws IOException {
        return configureSocket(this.delegate.createSocket(socket, str, i, z));
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public String[] getDefaultCipherSuites() {
        return this.delegate.getDefaultCipherSuites();
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public String[] getSupportedCipherSuites() {
        return this.delegate.getSupportedCipherSuites();
    }
}