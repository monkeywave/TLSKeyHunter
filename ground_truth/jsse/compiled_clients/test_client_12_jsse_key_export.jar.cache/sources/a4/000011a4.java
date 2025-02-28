package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLServerSocketImpl.class */
final class SSLServerSocketImpl extends SSLServerSocket {
    private final SSLContextImpl sslContext;
    private final SSLConfiguration sslConfig;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLServerSocketImpl(SSLContextImpl sslContext) throws IOException {
        this.sslContext = sslContext;
        this.sslConfig = new SSLConfiguration(sslContext, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLServerSocketImpl(SSLContextImpl sslContext, int port, int backlog) throws IOException {
        super(port, backlog);
        this.sslContext = sslContext;
        this.sslConfig = new SSLConfiguration(sslContext, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLServerSocketImpl(SSLContextImpl sslContext, int port, int backlog, InetAddress address) throws IOException {
        super(port, backlog, address);
        this.sslContext = sslContext;
        this.sslConfig = new SSLConfiguration(sslContext, false);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(this.sslConfig.enabledCipherSuites);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setEnabledCipherSuites(String[] suites) {
        this.sslConfig.enabledCipherSuites = CipherSuite.validValuesOf(suites);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(this.sslContext.getSupportedCipherSuites());
    }

    @Override // javax.net.ssl.SSLServerSocket
    public String[] getSupportedProtocols() {
        return ProtocolVersion.toStringArray(this.sslContext.getSupportedProtocolVersions());
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized String[] getEnabledProtocols() {
        return ProtocolVersion.toStringArray(this.sslConfig.enabledProtocols);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("Protocols cannot be null");
        }
        this.sslConfig.enabledProtocols = ProtocolVersion.namesOf(protocols);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setNeedClientAuth(boolean need) {
        this.sslConfig.clientAuthType = need ? ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized boolean getNeedClientAuth() {
        return this.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setWantClientAuth(boolean want) {
        this.sslConfig.clientAuthType = want ? ClientAuthType.CLIENT_AUTH_REQUESTED : ClientAuthType.CLIENT_AUTH_NONE;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized boolean getWantClientAuth() {
        return this.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setUseClientMode(boolean useClientMode) {
        if (this.sslConfig.isClientMode != useClientMode) {
            if (this.sslContext.isDefaultProtocolVesions(this.sslConfig.enabledProtocols)) {
                this.sslConfig.enabledProtocols = this.sslContext.getDefaultProtocolVersions(!useClientMode);
            }
            if (this.sslContext.isDefaultCipherSuiteList(this.sslConfig.enabledCipherSuites)) {
                this.sslConfig.enabledCipherSuites = this.sslContext.getDefaultCipherSuites(!useClientMode);
            }
            this.sslConfig.toggleClientMode();
        }
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized boolean getUseClientMode() {
        return this.sslConfig.isClientMode;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setEnableSessionCreation(boolean flag) {
        this.sslConfig.enableSessionCreation = flag;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized boolean getEnableSessionCreation() {
        return this.sslConfig.enableSessionCreation;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized SSLParameters getSSLParameters() {
        return this.sslConfig.getSSLParameters();
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setSSLParameters(SSLParameters params) {
        this.sslConfig.setSSLParameters(params);
    }

    @Override // java.net.ServerSocket
    public Socket accept() throws IOException {
        SSLSocketImpl s = new SSLSocketImpl(this.sslContext, this.sslConfig);
        implAccept(s);
        s.doneConnect();
        return s;
    }

    @Override // javax.net.ssl.SSLServerSocket, java.net.ServerSocket
    public String toString() {
        return "[SSL: " + super.toString() + "]";
    }
}