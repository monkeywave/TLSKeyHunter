package org.openjsse.sun.net.www.protocol.https;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/net/www/protocol/https/DelegateHttpsURLConnection.class */
public class DelegateHttpsURLConnection extends AbstractDelegateHttpsURLConnection {
    public HttpsURLConnection httpsURLConnection;

    DelegateHttpsURLConnection(URL url, sun.net.www.protocol.http.Handler handler, HttpsURLConnection httpsURLConnection) throws IOException {
        this(url, null, handler, httpsURLConnection);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DelegateHttpsURLConnection(URL url, Proxy p, sun.net.www.protocol.http.Handler handler, HttpsURLConnection httpsURLConnection) throws IOException {
        super(url, p, handler);
        this.httpsURLConnection = httpsURLConnection;
    }

    @Override // org.openjsse.sun.net.www.protocol.https.AbstractDelegateHttpsURLConnection
    protected SSLSocketFactory getSSLSocketFactory() {
        return this.httpsURLConnection.getSSLSocketFactory();
    }

    @Override // org.openjsse.sun.net.www.protocol.https.AbstractDelegateHttpsURLConnection
    protected HostnameVerifier getHostnameVerifier() {
        return this.httpsURLConnection.getHostnameVerifier();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void dispose() throws Throwable {
        super/*java.lang.Object*/.finalize();
    }
}