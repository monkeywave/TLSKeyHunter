package org.openjsse.sun.net.www.protocol.https;

import java.io.IOException;
import java.net.Proxy;
import java.net.SecureCacheResponse;
import java.net.URL;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import sun.net.www.http.HttpClient;
import sun.net.www.protocol.http.HttpURLConnection;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/net/www/protocol/https/AbstractDelegateHttpsURLConnection.class */
public abstract class AbstractDelegateHttpsURLConnection extends HttpURLConnection {
    protected abstract SSLSocketFactory getSSLSocketFactory();

    protected abstract HostnameVerifier getHostnameVerifier();

    protected AbstractDelegateHttpsURLConnection(URL url, sun.net.www.protocol.http.Handler handler) throws IOException {
        this(url, null, handler);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public AbstractDelegateHttpsURLConnection(URL url, Proxy p, sun.net.www.protocol.http.Handler handler) throws IOException {
        super(url, p, handler);
    }

    public void setNewClient(URL url) throws IOException {
        setNewClient(url, false);
    }

    public void setNewClient(URL url, boolean useCache) throws IOException {
        int readTimeout = getReadTimeout();
        this.http = HttpsClient.New(getSSLSocketFactory(), url, getHostnameVerifier(), null, -1, useCache, getConnectTimeout(), this);
        this.http.setReadTimeout(readTimeout);
        ((HttpsClient) this.http).afterConnect();
    }

    public void setProxiedClient(URL url, String proxyHost, int proxyPort) throws IOException {
        setProxiedClient(url, proxyHost, proxyPort, false);
    }

    public void setProxiedClient(URL url, String proxyHost, int proxyPort, boolean useCache) throws IOException {
        proxiedConnect(url, proxyHost, proxyPort, useCache);
        if (!this.http.isCachedConnection()) {
            doTunneling();
        }
        ((HttpsClient) this.http).afterConnect();
    }

    protected void proxiedConnect(URL url, String proxyHost, int proxyPort, boolean useCache) throws IOException {
        if (this.connected) {
            return;
        }
        int readTimeout = getReadTimeout();
        this.http = HttpsClient.New(getSSLSocketFactory(), url, getHostnameVerifier(), proxyHost, proxyPort, useCache, getConnectTimeout(), this);
        this.http.setReadTimeout(readTimeout);
        this.connected = true;
    }

    public boolean isConnected() {
        return this.connected;
    }

    public void setConnected(boolean conn) {
        this.connected = conn;
    }

    public void connect() throws IOException {
        if (this.connected) {
            return;
        }
        plainConnect();
        if (this.cachedResponse != null) {
            return;
        }
        if (!this.http.isCachedConnection() && this.http.needsTunneling()) {
            doTunneling();
        }
        ((HttpsClient) this.http).afterConnect();
    }

    protected HttpClient getNewHttpClient(URL url, Proxy p, int connectTimeout) throws IOException {
        return HttpsClient.New(getSSLSocketFactory(), url, getHostnameVerifier(), p, true, connectTimeout, (HttpURLConnection) this);
    }

    protected HttpClient getNewHttpClient(URL url, Proxy p, int connectTimeout, boolean useCache) throws IOException {
        return HttpsClient.New(getSSLSocketFactory(), url, getHostnameVerifier(), p, useCache, connectTimeout, this);
    }

    public String getCipherSuite() {
        if (this.cachedResponse != null) {
            return ((SecureCacheResponse) this.cachedResponse).getCipherSuite();
        }
        if (this.http == null) {
            throw new IllegalStateException("connection not yet open");
        }
        return ((HttpsClient) this.http).getCipherSuite();
    }

    public Certificate[] getLocalCertificates() {
        if (this.cachedResponse != null) {
            List<Certificate> l = ((SecureCacheResponse) this.cachedResponse).getLocalCertificateChain();
            if (l == null) {
                return null;
            }
            return (Certificate[]) l.toArray(new Certificate[0]);
        } else if (this.http == null) {
            throw new IllegalStateException("connection not yet open");
        } else {
            return ((HttpsClient) this.http).getLocalCertificates();
        }
    }

    public Certificate[] getServerCertificates() throws SSLPeerUnverifiedException {
        if (this.cachedResponse != null) {
            List<Certificate> l = ((SecureCacheResponse) this.cachedResponse).getServerCertificateChain();
            if (l == null) {
                return null;
            }
            return (Certificate[]) l.toArray(new Certificate[0]);
        } else if (this.http == null) {
            throw new IllegalStateException("connection not yet open");
        } else {
            return ((HttpsClient) this.http).getServerCertificates();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (this.cachedResponse != null) {
            return ((SecureCacheResponse) this.cachedResponse).getPeerPrincipal();
        }
        if (this.http == null) {
            throw new IllegalStateException("connection not yet open");
        }
        return ((HttpsClient) this.http).getPeerPrincipal();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Principal getLocalPrincipal() {
        if (this.cachedResponse != null) {
            return ((SecureCacheResponse) this.cachedResponse).getLocalPrincipal();
        }
        if (this.http == null) {
            throw new IllegalStateException("connection not yet open");
        }
        return ((HttpsClient) this.http).getLocalPrincipal();
    }
}