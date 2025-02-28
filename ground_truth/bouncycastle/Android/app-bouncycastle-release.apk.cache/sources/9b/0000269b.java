package org.bouncycastle.jsse.provider;

import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.tls.TlsContext;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvSSLConnection implements BCSSLConnection {
    private static final AtomicLong CONNECTION_IDS = new AtomicLong(0);
    protected final ProvTlsPeer tlsPeer;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvSSLConnection(ProvTlsPeer provTlsPeer) {
        this.tlsPeer = provTlsPeer;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static long allocateConnectionID() {
        return CONNECTION_IDS.incrementAndGet();
    }

    public byte[] exportKeyingMaterial(String str, byte[] bArr, int i) {
        return getTlsContext().exportKeyingMaterial(str, bArr, i);
    }

    @Override // org.bouncycastle.jsse.BCSSLConnection
    public String getApplicationProtocol() {
        return JsseUtils.getApplicationProtocol(getTlsContext().getSecurityParametersConnection());
    }

    @Override // org.bouncycastle.jsse.BCSSLConnection
    public byte[] getChannelBinding(String str) {
        TlsContext tlsContext;
        int i;
        if (str.equals("tls-exporter")) {
            tlsContext = getTlsContext();
            i = 3;
        } else if (str.equals("tls-server-end-point")) {
            tlsContext = getTlsContext();
            i = 0;
        } else if (!str.equals("tls-unique")) {
            throw new UnsupportedOperationException();
        } else {
            tlsContext = getTlsContext();
            i = 1;
        }
        return tlsContext.exportChannelBinding(i);
    }

    @Override // org.bouncycastle.jsse.BCSSLConnection
    public String getID() {
        return this.tlsPeer.getID();
    }

    @Override // org.bouncycastle.jsse.BCSSLConnection
    public ProvSSLSession getSession() {
        return this.tlsPeer.getSession();
    }

    protected TlsContext getTlsContext() {
        return this.tlsPeer.getTlsContext();
    }
}