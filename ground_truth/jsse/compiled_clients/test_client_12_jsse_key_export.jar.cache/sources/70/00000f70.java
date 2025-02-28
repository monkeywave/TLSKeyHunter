package org.openjsse.com.sun.net.ssl.internal.www.protocol.https;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/internal/www/protocol/https/Handler.class */
public class Handler extends sun.net.www.protocol.https.Handler {
    public Handler() {
    }

    public Handler(String proxy, int port) {
        super(proxy, port);
    }

    protected URLConnection openConnection(URL u) throws IOException {
        return openConnection(u, null);
    }

    protected URLConnection openConnection(URL u, Proxy p) throws IOException {
        return new HttpsURLConnectionOldImpl(u, p, this);
    }
}