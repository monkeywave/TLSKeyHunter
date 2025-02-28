package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvSSLServerSocket extends SSLServerSocket {
    protected final ContextData contextData;
    protected boolean enableSessionCreation;
    protected final ProvSSLParameters sslParameters;
    protected boolean useClientMode;

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLServerSocket(ContextData contextData) throws IOException {
        this.enableSessionCreation = true;
        this.useClientMode = false;
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLServerSocket(ContextData contextData, int i) throws IOException {
        super(i);
        this.enableSessionCreation = true;
        this.useClientMode = false;
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLServerSocket(ContextData contextData, int i, int i2) throws IOException {
        super(i, i2);
        this.enableSessionCreation = true;
        this.useClientMode = false;
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLServerSocket(ContextData contextData, int i, int i2, InetAddress inetAddress) throws IOException {
        super(i, i2, inetAddress);
        this.enableSessionCreation = true;
        this.useClientMode = false;
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    @Override // java.net.ServerSocket
    public synchronized Socket accept() throws IOException {
        ProvSSLSocketDirect create;
        create = SSLSocketUtil.create(this.contextData, this.enableSessionCreation, this.useClientMode, this.sslParameters.copy());
        implAccept(create);
        create.notifyConnected();
        return create;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized boolean getEnableSessionCreation() {
        return this.enableSessionCreation;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized String[] getEnabledCipherSuites() {
        return this.sslParameters.getCipherSuites();
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized String[] getEnabledProtocols() {
        return this.sslParameters.getProtocols();
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized SSLParameters getSSLParameters() {
        return SSLParametersUtil.getSSLParameters(this.sslParameters);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized String[] getSupportedCipherSuites() {
        return this.contextData.getContext().getSupportedCipherSuites();
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized String[] getSupportedProtocols() {
        return this.contextData.getContext().getSupportedProtocols();
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized boolean getUseClientMode() {
        return this.useClientMode;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized boolean getWantClientAuth() {
        return this.sslParameters.getWantClientAuth();
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setEnableSessionCreation(boolean z) {
        this.enableSessionCreation = z;
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setEnabledCipherSuites(String[] strArr) {
        this.sslParameters.setCipherSuites(strArr);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setEnabledProtocols(String[] strArr) {
        this.sslParameters.setProtocols(strArr);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setNeedClientAuth(boolean z) {
        this.sslParameters.setNeedClientAuth(z);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setSSLParameters(SSLParameters sSLParameters) {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sSLParameters);
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setUseClientMode(boolean z) {
        if (this.useClientMode != z) {
            this.contextData.getContext().updateDefaultSSLParameters(this.sslParameters, z);
            this.useClientMode = z;
        }
    }

    @Override // javax.net.ssl.SSLServerSocket
    public synchronized void setWantClientAuth(boolean z) {
        this.sslParameters.setWantClientAuth(z);
    }
}