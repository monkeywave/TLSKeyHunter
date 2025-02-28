package org.bouncycastle.jsse.util;

import java.net.Socket;
import java.net.URL;
import java.util.Collections;
import java.util.concurrent.Callable;
import java.util.logging.Logger;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/* loaded from: classes2.dex */
public class SNISocketFactory extends CustomSSLSocketFactory {
    private static final Logger LOG = Logger.getLogger(SNISocketFactory.class.getName());
    protected static final ThreadLocal<SNISocketFactory> threadLocal = new ThreadLocal<>();
    protected final URL url;

    public SNISocketFactory(SSLSocketFactory sSLSocketFactory, URL url) {
        super(sSLSocketFactory);
        this.url = url;
    }

    public static SocketFactory getDefault() {
        SNISocketFactory sNISocketFactory = threadLocal.get();
        return sNISocketFactory != null ? sNISocketFactory : SSLSocketFactory.getDefault();
    }

    public <V> V call(Callable<V> callable) throws Exception {
        try {
            ThreadLocal<SNISocketFactory> threadLocal2 = threadLocal;
            threadLocal2.set(this);
            V call = callable.call();
            threadLocal2.remove();
            return call;
        } catch (Throwable th) {
            threadLocal.remove();
            throw th;
        }
    }

    @Override // org.bouncycastle.jsse.util.CustomSSLSocketFactory
    protected Socket configureSocket(Socket socket) {
        if (socket instanceof BCSSLSocket) {
            BCSSLSocket bCSSLSocket = (BCSSLSocket) socket;
            BCSNIHostName bCSNIHostName = getBCSNIHostName();
            if (bCSNIHostName != null) {
                LOG.fine("Setting SNI on socket: " + bCSNIHostName);
                BCSSLParameters bCSSLParameters = new BCSSLParameters();
                bCSSLParameters.setServerNames(Collections.singletonList(bCSNIHostName));
                bCSSLSocket.setParameters(bCSSLParameters);
            }
        }
        return socket;
    }

    protected BCSNIHostName getBCSNIHostName() {
        return SNIUtil.getBCSNIHostName(this.url);
    }
}