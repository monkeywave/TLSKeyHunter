package org.bouncycastle.jsse.util;

import java.net.Socket;
import java.net.URL;
import java.util.concurrent.Callable;
import java.util.logging.Logger;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import org.bouncycastle.jsse.BCSSLSocket;

/* loaded from: classes2.dex */
public class SetHostSocketFactory extends CustomSSLSocketFactory {
    private static final Logger LOG = Logger.getLogger(SetHostSocketFactory.class.getName());
    protected static final ThreadLocal<SetHostSocketFactory> threadLocal = new ThreadLocal<>();
    protected final String host;

    public SetHostSocketFactory(SSLSocketFactory sSLSocketFactory, String str) {
        super(sSLSocketFactory);
        this.host = str;
    }

    public SetHostSocketFactory(SSLSocketFactory sSLSocketFactory, URL url) {
        this(sSLSocketFactory, url == null ? null : url.getHost());
    }

    public static SocketFactory getDefault() {
        SetHostSocketFactory setHostSocketFactory = threadLocal.get();
        return setHostSocketFactory != null ? setHostSocketFactory : SSLSocketFactory.getDefault();
    }

    public <V> V call(Callable<V> callable) throws Exception {
        try {
            ThreadLocal<SetHostSocketFactory> threadLocal2 = threadLocal;
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
        if (this.host != null && (socket instanceof BCSSLSocket)) {
            LOG.fine("Setting host on socket: " + this.host);
            ((BCSSLSocket) socket).setHost(this.host);
        }
        return socket;
    }
}