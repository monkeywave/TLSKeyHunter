package org.bouncycastle.jsse.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

/* loaded from: classes2.dex */
public class URLConnectionUtil {
    protected final SSLSocketFactory sslSocketFactory;

    public URLConnectionUtil() {
        this(null);
    }

    public URLConnectionUtil(SSLSocketFactory sSLSocketFactory) {
        this.sslSocketFactory = sSLSocketFactory;
    }

    protected URLConnection configureConnection(URL url, URLConnection uRLConnection) {
        if (uRLConnection instanceof HttpsURLConnection) {
            HttpsURLConnection httpsURLConnection = (HttpsURLConnection) uRLConnection;
            SSLSocketFactory sSLSocketFactory = this.sslSocketFactory;
            if (sSLSocketFactory == null) {
                sSLSocketFactory = httpsURLConnection.getSSLSocketFactory();
            }
            httpsURLConnection.setSSLSocketFactory(createSSLSocketFactory(sSLSocketFactory, url));
            return httpsURLConnection;
        }
        return uRLConnection;
    }

    protected SSLSocketFactory createSSLSocketFactory(SSLSocketFactory sSLSocketFactory, URL url) {
        return new SetHostSocketFactory(sSLSocketFactory, url);
    }

    public URLConnection openConnection(URL url) throws IOException {
        return configureConnection(url, url.openConnection());
    }

    public URLConnection openConnection(URL url, Proxy proxy) throws IOException {
        return configureConnection(url, url.openConnection(proxy));
    }

    public InputStream openInputStream(URL url) throws IOException {
        return openConnection(url).getInputStream();
    }

    public InputStream openStream(URL url) throws IOException {
        return openConnection(url).getInputStream();
    }
}