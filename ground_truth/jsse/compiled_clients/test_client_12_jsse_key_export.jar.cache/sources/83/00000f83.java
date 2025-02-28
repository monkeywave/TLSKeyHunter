package org.openjsse.sun.net.www.protocol.https;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.StringTokenizer;
import java.util.Vector;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.openjsse.sun.security.ssl.SSLSocketImpl;
import sun.net.www.http.HttpClient;
import sun.net.www.protocol.http.HttpURLConnection;
import sun.security.action.GetPropertyAction;
import sun.security.util.HostnameChecker;
import sun.util.logging.PlatformLogger;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/net/www/protocol/https/HttpsClient.class */
public final class HttpsClient extends HttpClient implements HandshakeCompletedListener {
    private static final int httpsPortNumber = 443;
    private static final String defaultHVCanonicalName = "javax.net.ssl.HttpsURLConnection.DefaultHostnameVerifier";

    /* renamed from: hv */
    private HostnameVerifier f955hv;
    private SSLSocketFactory sslSocketFactory;
    private SSLSession session;
    static final /* synthetic */ boolean $assertionsDisabled;

    static {
        $assertionsDisabled = !HttpsClient.class.desiredAssertionStatus();
    }

    protected int getDefaultPort() {
        return httpsPortNumber;
    }

    private String[] getCipherSuites() {
        String[] ciphers;
        String cipherString = GetPropertyAction.privilegedGetProperty("https.cipherSuites");
        if (cipherString == null || "".equals(cipherString)) {
            ciphers = null;
        } else {
            Vector<String> v = new Vector<>();
            StringTokenizer tokenizer = new StringTokenizer(cipherString, ",");
            while (tokenizer.hasMoreTokens()) {
                v.addElement(tokenizer.nextToken());
            }
            ciphers = new String[v.size()];
            for (int i = 0; i < ciphers.length; i++) {
                ciphers[i] = v.elementAt(i);
            }
        }
        return ciphers;
    }

    private String[] getProtocols() {
        String[] protocols;
        String protocolString = GetPropertyAction.privilegedGetProperty("https.protocols");
        if (protocolString == null || "".equals(protocolString)) {
            protocols = null;
        } else {
            Vector<String> v = new Vector<>();
            StringTokenizer tokenizer = new StringTokenizer(protocolString, ",");
            while (tokenizer.hasMoreTokens()) {
                v.addElement(tokenizer.nextToken());
            }
            protocols = new String[v.size()];
            for (int i = 0; i < protocols.length; i++) {
                protocols[i] = v.elementAt(i);
            }
        }
        return protocols;
    }

    private String getUserAgent() {
        String userAgent = GetPropertyAction.privilegedGetProperty("https.agent");
        userAgent = (userAgent == null || userAgent.length() == 0) ? "JSSE" : "JSSE";
        return userAgent;
    }

    private HttpsClient(SSLSocketFactory sf, URL url) throws IOException {
        this(sf, url, (String) null, -1);
    }

    HttpsClient(SSLSocketFactory sf, URL url, String proxyHost, int proxyPort) throws IOException {
        this(sf, url, proxyHost, proxyPort, -1);
    }

    HttpsClient(SSLSocketFactory sf, URL url, String proxyHost, int proxyPort, int connectTimeout) throws IOException {
        this(sf, url, proxyHost == null ? null : HttpClient.newHttpProxy(proxyHost, proxyPort, "https"), connectTimeout);
    }

    HttpsClient(SSLSocketFactory sf, URL url, Proxy proxy, int connectTimeout) throws IOException {
        PlatformLogger logger = HttpURLConnection.getHttpLogger();
        if (logger.isLoggable(PlatformLogger.Level.FINEST)) {
            logger.finest("Creating new HttpsClient with url:" + url + " and proxy:" + proxy + " with connect timeout:" + connectTimeout);
        }
        this.proxy = proxy;
        setSSLSocketFactory(sf);
        this.proxyDisabled = true;
        this.host = url.getHost();
        this.url = url;
        this.port = url.getPort();
        if (this.port == -1) {
            this.port = getDefaultPort();
        }
        setConnectTimeout(connectTimeout);
        openServer();
    }

    static HttpClient New(SSLSocketFactory sf, URL url, HostnameVerifier hv, HttpURLConnection httpuc) throws IOException {
        return New(sf, url, hv, true, httpuc);
    }

    static HttpClient New(SSLSocketFactory sf, URL url, HostnameVerifier hv, boolean useCache, HttpURLConnection httpuc) throws IOException {
        return New(sf, url, hv, (String) null, -1, useCache, httpuc);
    }

    static HttpClient New(SSLSocketFactory sf, URL url, HostnameVerifier hv, String proxyHost, int proxyPort, HttpURLConnection httpuc) throws IOException {
        return New(sf, url, hv, proxyHost, proxyPort, true, httpuc);
    }

    static HttpClient New(SSLSocketFactory sf, URL url, HostnameVerifier hv, String proxyHost, int proxyPort, boolean useCache, HttpURLConnection httpuc) throws IOException {
        return New(sf, url, hv, proxyHost, proxyPort, useCache, -1, httpuc);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static HttpClient New(SSLSocketFactory sf, URL url, HostnameVerifier hv, String proxyHost, int proxyPort, boolean useCache, int connectTimeout, HttpURLConnection httpuc) throws IOException {
        return New(sf, url, hv, proxyHost == null ? null : HttpClient.newHttpProxy(proxyHost, proxyPort, "https"), useCache, connectTimeout, httpuc);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static HttpClient New(SSLSocketFactory sf, URL url, HostnameVerifier hv, Proxy p, boolean useCache, int connectTimeout, HttpURLConnection httpuc) throws IOException {
        if (p == null) {
            p = Proxy.NO_PROXY;
        }
        PlatformLogger logger = HttpURLConnection.getHttpLogger();
        if (logger.isLoggable(PlatformLogger.Level.FINEST)) {
            logger.finest("Looking for HttpClient for URL " + url + " and proxy value of " + p);
        }
        HttpsClient ret = null;
        if (useCache) {
            ret = (HttpsClient) kac.get(url, sf);
            if (ret != null && httpuc != null && httpuc.streaming() && httpuc.getRequestMethod() == "POST" && !ret.available()) {
                ret = null;
            }
            if (ret != null) {
                boolean compatible = (ret.proxy != null && ret.proxy.equals(p)) || (ret.proxy == null && p == Proxy.NO_PROXY);
                if (compatible) {
                    synchronized (ret) {
                        ret.cachedHttpClient = true;
                        if (!$assertionsDisabled && !ret.inCache) {
                            throw new AssertionError();
                        }
                        ret.inCache = false;
                        if (httpuc != null && ret.needsTunneling()) {
                            httpuc.setTunnelState(HttpURLConnection.TunnelState.TUNNELING);
                        }
                        if (logger.isLoggable(PlatformLogger.Level.FINEST)) {
                            logger.finest("KeepAlive stream retrieved from the cache, " + ret);
                        }
                    }
                } else {
                    synchronized (ret) {
                        if (logger.isLoggable(PlatformLogger.Level.FINEST)) {
                            logger.finest("Not returning this connection to cache: " + ret);
                        }
                        ret.inCache = false;
                        ret.closeServer();
                    }
                    ret = null;
                }
            }
        }
        if (ret == null) {
            ret = new HttpsClient(sf, url, p, connectTimeout);
        } else {
            SecurityManager security = System.getSecurityManager();
            if (security != null) {
                if (ret.proxy == Proxy.NO_PROXY || ret.proxy == null) {
                    security.checkConnect(InetAddress.getByName(url.getHost()).getHostAddress(), url.getPort());
                } else {
                    security.checkConnect(url.getHost(), url.getPort());
                }
            }
            ret.url = url;
        }
        ret.setHostnameVerifier(hv);
        return ret;
    }

    void setHostnameVerifier(HostnameVerifier hv) {
        this.f955hv = hv;
    }

    void setSSLSocketFactory(SSLSocketFactory sf) {
        this.sslSocketFactory = sf;
    }

    SSLSocketFactory getSSLSocketFactory() {
        return this.sslSocketFactory;
    }

    protected Socket createSocket() throws IOException {
        try {
            return this.sslSocketFactory.createSocket();
        } catch (SocketException se) {
            Throwable t = se.getCause();
            if (t != null && (t instanceof UnsupportedOperationException)) {
                return super.createSocket();
            }
            throw se;
        }
    }

    public boolean needsTunneling() {
        return (this.proxy == null || this.proxy.type() == Proxy.Type.DIRECT || this.proxy.type() == Proxy.Type.SOCKS) ? false : true;
    }

    public void afterConnect() throws IOException, UnknownHostException {
        SSLSocket s;
        if (!isCachedConnection()) {
            SSLSocketFactory factory = this.sslSocketFactory;
            try {
                if (!(this.serverSocket instanceof SSLSocket)) {
                    s = (SSLSocket) factory.createSocket(this.serverSocket, this.host, this.port, true);
                } else {
                    s = (SSLSocket) this.serverSocket;
                    if (s instanceof SSLSocketImpl) {
                        ((SSLSocketImpl) s).setHost(this.host);
                    }
                }
            } catch (IOException ex) {
                try {
                    s = (SSLSocket) factory.createSocket(this.host, this.port);
                } catch (IOException e) {
                    throw ex;
                }
            }
            String[] protocols = getProtocols();
            String[] ciphers = getCipherSuites();
            if (protocols != null) {
                s.setEnabledProtocols(protocols);
            }
            if (ciphers != null) {
                s.setEnabledCipherSuites(ciphers);
            }
            s.addHandshakeCompletedListener(this);
            boolean needToCheckSpoofing = true;
            String identification = s.getSSLParameters().getEndpointIdentificationAlgorithm();
            if (identification != null && identification.length() != 0) {
                if (identification.equalsIgnoreCase("HTTPS")) {
                    needToCheckSpoofing = false;
                }
            } else {
                boolean isDefaultHostnameVerifier = false;
                if (this.f955hv != null) {
                    String canonicalName = this.f955hv.getClass().getCanonicalName();
                    if (canonicalName != null && canonicalName.equalsIgnoreCase(defaultHVCanonicalName)) {
                        isDefaultHostnameVerifier = true;
                    }
                } else {
                    isDefaultHostnameVerifier = true;
                }
                if (isDefaultHostnameVerifier) {
                    SSLParameters paramaters = s.getSSLParameters();
                    paramaters.setEndpointIdentificationAlgorithm("HTTPS");
                    s.setSSLParameters(paramaters);
                    needToCheckSpoofing = false;
                }
            }
            s.startHandshake();
            this.session = s.getSession();
            this.serverSocket = s;
            try {
                this.serverOutput = new PrintStream(new BufferedOutputStream(this.serverSocket.getOutputStream()), false, encoding);
                if (needToCheckSpoofing) {
                    checkURLSpoofing(this.f955hv);
                    return;
                }
                return;
            } catch (UnsupportedEncodingException e2) {
                throw new InternalError(encoding + " encoding not found");
            }
        }
        this.session = ((SSLSocket) this.serverSocket).getSession();
    }

    private void checkURLSpoofing(HostnameVerifier hostnameVerifier) throws IOException {
        String host = this.url.getHost();
        if (host != null && host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        String cipher = this.session.getCipherSuite();
        try {
            HostnameChecker checker = HostnameChecker.getInstance((byte) 1);
            Certificate[] peerCerts = this.session.getPeerCertificates();
            if (peerCerts[0] instanceof X509Certificate) {
                X509Certificate peerCert = (X509Certificate) peerCerts[0];
                checker.match(host, peerCert);
                return;
            }
            throw new SSLPeerUnverifiedException("");
        } catch (CertificateException | SSLPeerUnverifiedException e) {
            if (cipher != null && cipher.indexOf("_anon_") != -1) {
                return;
            }
            if (hostnameVerifier != null && hostnameVerifier.verify(host, this.session)) {
                return;
            }
            this.serverSocket.close();
            this.session.invalidate();
            throw new IOException("HTTPS hostname wrong:  should be <" + this.url.getHost() + ">");
        }
    }

    protected void putInKeepAliveCache() {
        if (this.inCache) {
            if (!$assertionsDisabled) {
                throw new AssertionError("Duplicate put to keep alive cache");
            }
            return;
        }
        this.inCache = true;
        kac.put(this.url, this.sslSocketFactory, this);
    }

    public void closeIdleConnection() {
        HttpClient http = kac.get(this.url, this.sslSocketFactory);
        if (http != null) {
            http.closeServer();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getCipherSuite() {
        return this.session.getCipherSuite();
    }

    public Certificate[] getLocalCertificates() {
        return this.session.getLocalCertificates();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Certificate[] getServerCertificates() throws SSLPeerUnverifiedException {
        return this.session.getPeerCertificates();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        Principal principal;
        try {
            principal = this.session.getPeerPrincipal();
        } catch (AbstractMethodError e) {
            Certificate[] certs = this.session.getPeerCertificates();
            principal = ((X509Certificate) certs[0]).getSubjectX500Principal();
        }
        return principal;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Principal getLocalPrincipal() {
        Principal principal;
        try {
            principal = this.session.getLocalPrincipal();
        } catch (AbstractMethodError e) {
            principal = null;
            Certificate[] certs = this.session.getLocalCertificates();
            if (certs != null) {
                principal = ((X509Certificate) certs[0]).getSubjectX500Principal();
            }
        }
        return principal;
    }

    @Override // javax.net.ssl.HandshakeCompletedListener
    public void handshakeCompleted(HandshakeCompletedEvent event) {
        this.session = event.getSession();
    }

    public String getProxyHostUsed() {
        if (!needsTunneling()) {
            return null;
        }
        return super.getProxyHostUsed();
    }

    public int getProxyPortUsed() {
        if (this.proxy == null || this.proxy.type() == Proxy.Type.DIRECT || this.proxy.type() == Proxy.Type.SOCKS) {
            return -1;
        }
        return ((InetSocketAddress) this.proxy.address()).getPort();
    }
}