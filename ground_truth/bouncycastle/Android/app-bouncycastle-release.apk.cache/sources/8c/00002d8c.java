package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCrypto;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class TlsClientContextImpl extends AbstractTlsContext implements TlsClientContext {
    /* JADX INFO: Access modifiers changed from: package-private */
    public TlsClientContextImpl(TlsCrypto tlsCrypto) {
        super(tlsCrypto, 1);
    }

    @Override // org.bouncycastle.tls.TlsContext
    public boolean isServer() {
        return false;
    }
}