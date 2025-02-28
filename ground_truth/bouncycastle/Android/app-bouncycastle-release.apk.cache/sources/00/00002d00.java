package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes2.dex */
public abstract class AbstractTlsKeyExchange implements TlsKeyExchange {
    protected TlsContext context;
    protected int keyExchange;

    /* JADX INFO: Access modifiers changed from: protected */
    public AbstractTlsKeyExchange(int i) {
        this.keyExchange = i;
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public byte[] generateServerKeyExchange() throws IOException {
        if (requiresServerKeyExchange()) {
            throw new TlsFatalAlert((short) 80);
        }
        return null;
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public short[] getClientCertificateTypes() {
        return null;
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void init(TlsContext tlsContext) {
        this.context = tlsContext;
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processClientCertificate(Certificate certificate) throws IOException {
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processClientKeyExchange(InputStream inputStream) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processServerCertificate(Certificate certificate) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processServerKeyExchange(InputStream inputStream) throws IOException {
        if (!requiresServerKeyExchange()) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public boolean requiresCertificateVerify() {
        return true;
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public boolean requiresServerKeyExchange() {
        return false;
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void skipClientCredentials() throws IOException {
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void skipServerKeyExchange() throws IOException {
        if (requiresServerKeyExchange()) {
            throw new TlsFatalAlert((short) 10);
        }
    }
}