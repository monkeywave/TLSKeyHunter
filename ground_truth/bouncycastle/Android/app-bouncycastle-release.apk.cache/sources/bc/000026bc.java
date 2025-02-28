package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.TlsContext;

/* loaded from: classes2.dex */
interface ProvTlsPeer {
    String getID();

    ProvSSLSession getSession();

    TlsContext getTlsContext();

    boolean isHandshakeComplete();
}