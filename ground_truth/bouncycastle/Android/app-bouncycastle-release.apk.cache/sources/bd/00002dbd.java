package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCrypto;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class TlsServerContextImpl extends AbstractTlsContext implements TlsServerContext {
    /* JADX INFO: Access modifiers changed from: package-private */
    public TlsServerContextImpl(TlsCrypto tlsCrypto) {
        super(tlsCrypto, 0);
    }

    @Override // org.bouncycastle.tls.TlsContext
    public boolean isServer() {
        return true;
    }
}