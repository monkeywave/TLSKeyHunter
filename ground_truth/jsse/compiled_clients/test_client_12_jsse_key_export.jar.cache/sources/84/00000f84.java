package org.openjsse.sun.net.www.protocol.https;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.URL;
import java.security.Permission;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import org.openjsse.sun.net.util.IPAddressUtil;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/net/www/protocol/https/HttpsURLConnectionImpl.class */
public class HttpsURLConnectionImpl extends HttpsURLConnection {
    protected DelegateHttpsURLConnection delegate;

    HttpsURLConnectionImpl(URL u, Handler handler) throws IOException {
        this(u, null, handler);
    }

    static URL checkURL(URL u) throws IOException {
        if (u != null && u.toExternalForm().indexOf(10) > -1) {
            throw new MalformedURLException("Illegal character in URL");
        }
        String s = IPAddressUtil.checkAuthority(u);
        if (s != null) {
            throw new MalformedURLException(s);
        }
        return u;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public HttpsURLConnectionImpl(URL u, Proxy p, Handler handler) throws IOException {
        super(checkURL(u));
        this.delegate = new DelegateHttpsURLConnection(this.url, p, handler, this);
    }

    protected HttpsURLConnectionImpl(URL u) throws IOException {
        super(u);
    }

    protected void setNewClient(URL url) throws IOException {
        this.delegate.setNewClient(url, false);
    }

    protected void setNewClient(URL url, boolean useCache) throws IOException {
        this.delegate.setNewClient(url, useCache);
    }

    protected void setProxiedClient(URL url, String proxyHost, int proxyPort) throws IOException {
        this.delegate.setProxiedClient(url, proxyHost, proxyPort);
    }

    protected void setProxiedClient(URL url, String proxyHost, int proxyPort, boolean useCache) throws IOException {
        this.delegate.setProxiedClient(url, proxyHost, proxyPort, useCache);
    }

    @Override // java.net.URLConnection
    public void connect() throws IOException {
        this.delegate.connect();
    }

    protected boolean isConnected() {
        return this.delegate.isConnected();
    }

    protected void setConnected(boolean conn) {
        this.delegate.setConnected(conn);
    }

    @Override // javax.net.ssl.HttpsURLConnection
    public String getCipherSuite() {
        return this.delegate.getCipherSuite();
    }

    @Override // javax.net.ssl.HttpsURLConnection
    public Certificate[] getLocalCertificates() {
        return this.delegate.getLocalCertificates();
    }

    @Override // javax.net.ssl.HttpsURLConnection
    public Certificate[] getServerCertificates() throws SSLPeerUnverifiedException {
        return this.delegate.getServerCertificates();
    }

    @Override // javax.net.ssl.HttpsURLConnection
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return this.delegate.getPeerPrincipal();
    }

    @Override // javax.net.ssl.HttpsURLConnection
    public Principal getLocalPrincipal() {
        return this.delegate.getLocalPrincipal();
    }

    @Override // java.net.URLConnection
    public synchronized OutputStream getOutputStream() throws IOException {
        return this.delegate.getOutputStream();
    }

    @Override // java.net.URLConnection
    public synchronized InputStream getInputStream() throws IOException {
        return this.delegate.getInputStream();
    }

    @Override // java.net.HttpURLConnection
    public InputStream getErrorStream() {
        return this.delegate.getErrorStream();
    }

    @Override // java.net.HttpURLConnection
    public void disconnect() {
        this.delegate.disconnect();
    }

    @Override // java.net.HttpURLConnection
    public boolean usingProxy() {
        return this.delegate.usingProxy();
    }

    @Override // java.net.URLConnection
    public Map<String, List<String>> getHeaderFields() {
        return this.delegate.getHeaderFields();
    }

    @Override // java.net.URLConnection
    public String getHeaderField(String name) {
        return this.delegate.getHeaderField(name);
    }

    @Override // java.net.HttpURLConnection, java.net.URLConnection
    public String getHeaderField(int n) {
        return this.delegate.getHeaderField(n);
    }

    @Override // java.net.HttpURLConnection, java.net.URLConnection
    public String getHeaderFieldKey(int n) {
        return this.delegate.getHeaderFieldKey(n);
    }

    @Override // java.net.URLConnection
    public void setRequestProperty(String key, String value) {
        this.delegate.setRequestProperty(key, value);
    }

    @Override // java.net.URLConnection
    public void addRequestProperty(String key, String value) {
        this.delegate.addRequestProperty(key, value);
    }

    @Override // java.net.HttpURLConnection
    public int getResponseCode() throws IOException {
        return this.delegate.getResponseCode();
    }

    @Override // java.net.URLConnection
    public String getRequestProperty(String key) {
        return this.delegate.getRequestProperty(key);
    }

    @Override // java.net.URLConnection
    public Map<String, List<String>> getRequestProperties() {
        return this.delegate.getRequestProperties();
    }

    @Override // java.net.HttpURLConnection
    public void setInstanceFollowRedirects(boolean shouldFollow) {
        this.delegate.setInstanceFollowRedirects(shouldFollow);
    }

    @Override // java.net.HttpURLConnection
    public boolean getInstanceFollowRedirects() {
        return this.delegate.getInstanceFollowRedirects();
    }

    @Override // java.net.HttpURLConnection
    public void setRequestMethod(String method) throws ProtocolException {
        this.delegate.setRequestMethod(method);
    }

    @Override // java.net.HttpURLConnection
    public String getRequestMethod() {
        return this.delegate.getRequestMethod();
    }

    @Override // java.net.HttpURLConnection
    public String getResponseMessage() throws IOException {
        return this.delegate.getResponseMessage();
    }

    @Override // java.net.HttpURLConnection, java.net.URLConnection
    public long getHeaderFieldDate(String name, long Default) {
        return this.delegate.getHeaderFieldDate(name, Default);
    }

    @Override // java.net.HttpURLConnection, java.net.URLConnection
    public Permission getPermission() throws IOException {
        return this.delegate.getPermission();
    }

    @Override // java.net.URLConnection
    public URL getURL() {
        return this.delegate.getURL();
    }

    @Override // java.net.URLConnection
    public int getContentLength() {
        return this.delegate.getContentLength();
    }

    @Override // java.net.URLConnection
    public long getContentLengthLong() {
        return this.delegate.getContentLengthLong();
    }

    @Override // java.net.URLConnection
    public String getContentType() {
        return this.delegate.getContentType();
    }

    @Override // java.net.URLConnection
    public String getContentEncoding() {
        return this.delegate.getContentEncoding();
    }

    @Override // java.net.URLConnection
    public long getExpiration() {
        return this.delegate.getExpiration();
    }

    @Override // java.net.URLConnection
    public long getDate() {
        return this.delegate.getDate();
    }

    @Override // java.net.URLConnection
    public long getLastModified() {
        return this.delegate.getLastModified();
    }

    @Override // java.net.URLConnection
    public int getHeaderFieldInt(String name, int Default) {
        return this.delegate.getHeaderFieldInt(name, Default);
    }

    @Override // java.net.URLConnection
    public long getHeaderFieldLong(String name, long Default) {
        return this.delegate.getHeaderFieldLong(name, Default);
    }

    @Override // java.net.URLConnection
    public Object getContent() throws IOException {
        return this.delegate.getContent();
    }

    @Override // java.net.URLConnection
    public Object getContent(Class[] classes) throws IOException {
        return this.delegate.getContent(classes);
    }

    @Override // java.net.URLConnection
    public String toString() {
        return this.delegate.toString();
    }

    @Override // java.net.URLConnection
    public void setDoInput(boolean doinput) {
        this.delegate.setDoInput(doinput);
    }

    @Override // java.net.URLConnection
    public boolean getDoInput() {
        return this.delegate.getDoInput();
    }

    @Override // java.net.URLConnection
    public void setDoOutput(boolean dooutput) {
        this.delegate.setDoOutput(dooutput);
    }

    @Override // java.net.URLConnection
    public boolean getDoOutput() {
        return this.delegate.getDoOutput();
    }

    @Override // java.net.URLConnection
    public void setAllowUserInteraction(boolean allowuserinteraction) {
        this.delegate.setAllowUserInteraction(allowuserinteraction);
    }

    @Override // java.net.URLConnection
    public boolean getAllowUserInteraction() {
        return this.delegate.getAllowUserInteraction();
    }

    @Override // java.net.URLConnection
    public void setUseCaches(boolean usecaches) {
        this.delegate.setUseCaches(usecaches);
    }

    @Override // java.net.URLConnection
    public boolean getUseCaches() {
        return this.delegate.getUseCaches();
    }

    @Override // java.net.URLConnection
    public void setIfModifiedSince(long ifmodifiedsince) {
        this.delegate.setIfModifiedSince(ifmodifiedsince);
    }

    @Override // java.net.URLConnection
    public long getIfModifiedSince() {
        return this.delegate.getIfModifiedSince();
    }

    @Override // java.net.URLConnection
    public boolean getDefaultUseCaches() {
        return this.delegate.getDefaultUseCaches();
    }

    @Override // java.net.URLConnection
    public void setDefaultUseCaches(boolean defaultusecaches) {
        this.delegate.setDefaultUseCaches(defaultusecaches);
    }

    protected void finalize() throws Throwable {
        this.delegate.dispose();
    }

    public boolean equals(Object obj) {
        return this == obj || ((obj instanceof HttpsURLConnectionImpl) && this.delegate.equals(((HttpsURLConnectionImpl) obj).delegate));
    }

    public int hashCode() {
        return this.delegate.hashCode();
    }

    @Override // java.net.URLConnection
    public void setConnectTimeout(int timeout) {
        this.delegate.setConnectTimeout(timeout);
    }

    @Override // java.net.URLConnection
    public int getConnectTimeout() {
        return this.delegate.getConnectTimeout();
    }

    @Override // java.net.URLConnection
    public void setReadTimeout(int timeout) {
        this.delegate.setReadTimeout(timeout);
    }

    @Override // java.net.URLConnection
    public int getReadTimeout() {
        return this.delegate.getReadTimeout();
    }

    @Override // java.net.HttpURLConnection
    public void setFixedLengthStreamingMode(int contentLength) {
        this.delegate.setFixedLengthStreamingMode(contentLength);
    }

    @Override // java.net.HttpURLConnection
    public void setFixedLengthStreamingMode(long contentLength) {
        this.delegate.setFixedLengthStreamingMode(contentLength);
    }

    @Override // java.net.HttpURLConnection
    public void setChunkedStreamingMode(int chunklen) {
        this.delegate.setChunkedStreamingMode(chunklen);
    }
}